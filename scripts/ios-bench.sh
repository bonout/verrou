#!/usr/bin/env bash
# Measurements of the iPhone app (Debug build) on a fake vault of 2,000
# items, in a windowless simulator:
#
#   1. cold launch up to the home screen of the open vault, RUNS times
#      (apple/VerrouiOS/Demo/PhoneBenchDriver.swift), then opening the list
#      and each keystroke of a search up to the next frame;
#   2. hitches while scrolling the list (XCUITest,
#      XCTOSSignpostMetric.scrollingAndDecelerationMetric);
#   3. unlock (same driver): from success to the vault shown and usable,
#      then to the lock screen's removal;
#   4. cold launch with Face ID against a throwaway Vaultwarden
#      (apple/VerrouiOS/Demo/LaunchBenchDriver.swift): Face ID requested,
#      succeeded, home visible and interactive, lock screen removed, duration
#      of the first sync and longest main thread stall during it; once with
#      a server that answers right away, once with a slow server (the relay
#      holds each connection SLOW_SECONDS seconds: VPN coming up, first
#      address unreachable).
#
#   scripts/ios-bench.sh
#   APPS="/path/before.app /path/after.app" SKIP_BUILD=1 scripts/ios-bench.sh
#
# Variables: OUT (default target/ios-bench), SKIP_BUILD=1, RUNS (default 6),
# MOCK_SIZE (default 2000), SKIP_SCROLL=1, SKIP_MOCK=1, SKIP_LAUNCH=1,
# LAUNCH_RUNS (default 4), SLOW_SECONDS (default 8), VW_CONTAINER and VW_PORT
# (default verrou-vw-bench, 8128), SIM_DEVICE_TYPE, SIM_RUNTIME.
# APPS: several builds of the app, installed in turn for each measurement
# (before/after comparison, with the Mac loaded the same way for both);
# results per build.
# Simulator timings depend on the Mac: compare two builds on the same
# machine, at the same time.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
OUT="${OUT:-$ROOT/target/ios-bench}"
DERIVED="$ROOT/target/xcode-ios.noindex"
APP="$DERIVED/Build/Products/Debug-iphonesimulator/Verrou.app"
RUNS="${RUNS:-6}"
LAUNCH_RUNS="${LAUNCH_RUNS:-4}"
SLOW_SECONDS="${SLOW_SECONDS:-8}"
read -r -a APP_LIST <<< "${APPS:-$APP}"
CONTAINER="${VW_CONTAINER:-verrou-vw-bench}"
VW_PORT="${VW_PORT:-8128}"
WORK="$(mktemp -d)"
RELAY_PID=""
STARTED_SERVER=0
MOCK_SIZE="${MOCK_SIZE:-2000}"
SIM_DEVICE_TYPE="${SIM_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro}"
SIM_RUNTIME="${SIM_RUNTIME:-$(xcrun simctl list runtimes -j | python3 -I -c '
import json, sys
runtimes = [r for r in json.load(sys.stdin)["runtimes"] if r["platform"] == "iOS" and r["isAvailable"]]
print(runtimes[-1]["identifier"])')}"
DEV=""

cleanup() {
  [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
  [[ $STARTED_SERVER == 1 ]] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  if [[ -n "$DEV" ]]; then
    xcrun simctl shutdown "$DEV" >/dev/null 2>&1 || true
    xcrun simctl delete "$DEV" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  HOST="$(uname -m | sed 's/arm64/aarch64/')-apple-darwin"
  SIM="$( [[ "$(uname -m)" == arm64 ]] && echo aarch64-apple-ios-sim || echo x86_64-apple-ios )"
  PROFILE="${PROFILE:-release}" PLATFORMS=all TARGETS="$HOST" IOS_TARGETS="" SIM_TARGETS="$SIM" scripts/build-apple.sh
  (cd apple && xcodegen generate --quiet)
  xcodebuild -project apple/Verrou.xcodeproj -packageAuthorizationProvider netrc -scheme VerrouiOS -configuration Debug \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath "$DERIVED" \
    ARCHS="$(uname -m)" build-for-testing -quiet
fi

DEV="$(xcrun simctl create "Verrou Bench" "$SIM_DEVICE_TYPE" "$SIM_RUNTIME")"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl spawn "$DEV" defaults write -g AppleLanguages -array en-US
xcrun simctl spawn "$DEV" defaults write -g AppleLocale -string en_US
xcrun simctl shutdown "$DEV"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl spawn "$DEV" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit.enrollmentChanged
xcrun simctl install "$DEV" "${APP_LIST[0]}"
# The simulator finishes starting its services before the measurements.
sleep 20

rm -rf "$OUT" && mkdir -p "$OUT"
INSTALLED="${APP_LIST[0]}"
install_app() {
  if [[ "$1" != "$INSTALLED" ]]; then
    xcrun simctl uninstall "$DEV" app.verrou.ios >/dev/null 2>&1 || true
    xcrun simctl install "$DEV" "$1"
    INSTALLED="$1"
  fi
}

if [[ "${SKIP_MOCK:-0}" != 1 ]]; then
for run in $(seq "$RUNS"); do
  for index in "${!APP_LIST[@]}"; do
  install_app "${APP_LIST[$index]}"
  log="$OUT/run-$run-app$index.log"
  SIMCTL_CHILD_VERROU_MOCK=1 SIMCTL_CHILD_VERROU_MOCK_SIZE="$MOCK_SIZE" SIMCTL_CHILD_VERROU_BENCH=1 \
    xcrun simctl launch --console-pty --terminate-running-process "$DEV" app.verrou.ios \
    > "$log" 2>&1 &
  launch_pid=$!
  # The driver quits the app after BENCH_DONE; three minutes at most.
  for _ in $(seq 900); do kill -0 "$launch_pid" 2>/dev/null || break; sleep 0.2; done
  kill "$launch_pid" 2>/dev/null || true
  xcrun simctl terminate "$DEV" app.verrou.ios >/dev/null 2>&1 || true
  grep -q '^BENCH_DONE' "$log" || { echo "measurement $run unfinished:" >&2; tail -20 "$log" >&2; exit 1; }
  sleep 2
  done
done

for index in "${!APP_LIST[@]}"; do
echo "== build $index: ${APP_LIST[$index]}"
python3 -I - "$OUT" "$RUNS" "$index" <<'PY'
import re, statistics, sys, pathlib
out, runs, index = pathlib.Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
launch, launch_cpu, lists, list_cpu, keys, key_cpu, built, usable, gone = [], [], [], [], [], [], [], [], []
for run in range(1, runs + 1):
    text = (out / f"run-{run}-app{index}.log").read_text(errors="replace")
    m = re.search(r"BENCH LAUNCH .*\+(\d+) ms from launch, process CPU (\d+) ms", text)
    if m and run > 1:  # the first launch fills the system caches
        launch.append(int(m.group(1)))
        launch_cpu.append(int(m.group(2)))
    m = re.search(r"BENCH LIST opening .*CPU ([\d.]+) ms", text)
    if m:
        list_cpu.append(float(m.group(1)))
    m = re.search(r"BENCH LIST shown in (\d+) ms", text)
    if m:
        lists.append(int(m.group(1)))
    for ms, cpu, rows in re.findall(r"BENCH KEY .*: ([\d.]+) ms \(CPU ([\d.]+) ms\), (\d+) rows", text):
        keys.append(float(ms))
        key_cpu.append(float(cpu))
        built.append(int(rows))
    for ms_usable, ms_gone in re.findall(r"BENCH UNLOCK .*usable in (\d+) ms, lock screen removed in (\d+) ms", text):
        usable.append(int(ms_usable))
        gone.append(int(ms_gone))
keys.sort()
p95 = keys[min(len(keys) - 1, int(len(keys) * 0.95))]
print(f"cold launch → open home: median {statistics.median(launch):.0f} ms (min {min(launch)}, max {max(launch)}, {len(launch)} launches)")
print(f"  process CPU at the same moment: median {statistics.median(launch_cpu):.0f} ms")
print(f"opening \"All items\": median {statistics.median(lists):.0f} ms (main thread CPU: median {statistics.median(list_cpu):.0f} ms)")
print(f"search keystroke: median {statistics.median(keys):.2f} ms, p95 {p95:.2f} ms, max {keys[-1]:.2f} ms ({len(keys)} keystrokes), rows built per keystroke: median {statistics.median(built):.0f}")
print(f"  main thread CPU per keystroke: median {statistics.median(key_cpu):.2f} ms")
if usable:
    print(f"unlock → vault usable: median {statistics.median(usable):.0f} ms (max {max(usable)}, {len(usable)} unlocks), lock screen removed: median {statistics.median(gone):.0f} ms")
PY

done
fi

# 4. Cold launch with Face ID, against Vaultwarden
if [[ "${SKIP_LAUNCH:-0}" != 1 ]]; then
  if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker run -d --name "$CONTAINER" -p "127.0.0.1:$VW_PORT:80" \
      -e I_REALLY_WANT_VOLATILE_STORAGE=true -e SIGNUPS_ALLOWED=true \
      -e DOMAIN="http://localhost:$VW_PORT" -e LOGIN_RATELIMIT_MAX_BURST=1000 \
      -e LOGIN_RATELIMIT_SECONDS=1 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
      vaultwarden/server:1.37.4 >/dev/null
    STARTED_SERVER=1
  fi
  for _ in $(seq 60); do curl -fs "http://localhost:$VW_PORT/alive" >/dev/null && break; sleep 1; done
  SEED="$(VERROU_TEST_SERVER="http://localhost:$VW_PORT" VERROU_SEED_EMAIL="bench-$(date +%s)@verrou.test" \
    cargo test -q -p verrou-vaultwarden --test server -- --ignored --nocapture seed_walkthrough_account 2>/dev/null)"
  BENCH_EMAIL="$(sed -n 's/^SEED_EMAIL=//p' <<< "$SEED")"
  BENCH_PASSWORD="$(sed -n 's/^SEED_PASSWORD=//p' <<< "$SEED")"
  BENCH_TOTP="$(sed -n 's/^SEED_TOTP=//p' <<< "$SEED")"
  [[ -n "$BENCH_TOTP" ]] || { echo "could not create the measurement account" >&2; exit 1; }

  # TCP relay: with the "slow" file, each new connection waits SLOW_SECONDS
  # seconds before being connected to the server.
  RELAY_PORT="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  cat > "$WORK/relay.py" <<'RELAY'
import asyncio, os, sys
listen, upstream, flag = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
async def handle(client_reader, client_writer):
    try:
        with open(flag) as f:
            await asyncio.sleep(float(f.read().strip() or 0))
    except OSError:
        pass
    try:
        server_reader, server_writer = await asyncio.open_connection("127.0.0.1", upstream)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(pipe(client_reader, server_writer), pipe(server_reader, client_writer))
async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", listen)
    async with server:
        await server.serve_forever()
asyncio.run(main())
RELAY
  python3 -I "$WORK/relay.py" "$RELAY_PORT" "$VW_PORT" "$WORK/slow" &
  RELAY_PID=$!
  for _ in $(seq 20); do nc -z 127.0.0.1 "$RELAY_PORT" 2>/dev/null && break; sleep 0.25; done

  # Launches the app and follows it until `BENCH_DONE` (or `BENCH_SETUP_DONE`);
  # accepts Face ID as soon as it is requested.
  launch_measured() {
    local log="$1"; shift
    env "$@" xcrun simctl launch --console-pty --terminate-running-process "$DEV" app.verrou.ios > "$log" 2>&1 &
    local pid=$! matched=0
    for _ in $(seq 600); do
      kill -0 "$pid" 2>/dev/null || break
      if [[ $matched == 0 ]] && grep -q "^PERF Face ID requested" "$log" 2>/dev/null; then
        sleep 0.4
        xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit_Sim.pearl.match
        matched=1
      fi
      sleep 0.1
    done
    kill "$pid" 2>/dev/null || true
    xcrun simctl terminate "$DEV" app.verrou.ios >/dev/null 2>&1 || true
    grep -qE '^BENCH_(SETUP_)?DONE' "$log" || { echo "measurement unfinished ($log):" >&2; tail -20 "$log" >&2; exit 1; }
  }

  for run in $(seq "$LAUNCH_RUNS"); do
    for index in "${!APP_LIST[@]}"; do
      install_app "${APP_LIST[$index]}"
      rm -f "$WORK/slow"
      launch_measured "$OUT/launch-setup-$run-app$index.log" SIMCTL_CHILD_VERROU_BENCH_LAUNCH=setup \
        SIMCTL_CHILD_VERROU_BENCH_SERVER="http://localhost:$RELAY_PORT" SIMCTL_CHILD_VERROU_BENCH_EMAIL="$BENCH_EMAIL" \
        SIMCTL_CHILD_VERROU_BENCH_PASSWORD="$BENCH_PASSWORD" SIMCTL_CHILD_VERROU_BENCH_TOTP="$BENCH_TOTP"
      sleep 2
      for scenario in fast slow; do
        if [[ $scenario == slow ]]; then echo "$SLOW_SECONDS" > "$WORK/slow"; else rm -f "$WORK/slow"; fi
        launch_measured "$OUT/launch-$scenario-$run-app$index.log" SIMCTL_CHILD_VERROU_BENCH_LAUNCH=measure
        sleep 2
      done
    done
  done
  rm -f "$WORK/slow"

  for index in "${!APP_LIST[@]}"; do
    echo "== launch with Face ID, build $index: ${APP_LIST[$index]}"
    python3 -I - "$OUT" "$index" <<'PY'
import re, statistics, sys, pathlib
out, index = pathlib.Path(sys.argv[1]), sys.argv[2]
patterns = {
    "lock screen shown (ms from launch)": r"PERF lock screen shown at \+(\d+) ms",
    "Face ID requested (ms from launch)": r"PERF Face ID requested at \+(\d+) ms",
    "home visible (ms after Face ID)": r"PERF home visible at \+(\d+) ms after",
    "home interactive (ms after Face ID)": r"PERF home interactive at .*\(\+(\d+) ms after",
    "lock screen removed (ms after Face ID)": None,
    "first sync (ms)": r"PERF sync: (\d+) ms",
    "longest main thread stall during the sync (ms)": r"PERF longest main thread stall during the first sync: (\d+) ms",
}
for scenario in ("fast", "slow"):
    print(f"  {'immediate' if scenario == 'fast' else 'slow'} server:")
    values = {name: [] for name in patterns}
    for log in sorted(out.glob(f"launch-{scenario}-*-app{index}.log")):
        text = log.read_text(errors="replace")
        for name, pattern in patterns.items():
            if pattern is None:
                ok = re.search(r"PERF Face ID succeeded at \+(\d+) ms", text)
                gone = re.search(r"PERF lock screen removed at \+(\d+) ms", text)
                if ok and gone:
                    values[name].append(int(gone.group(1)) - int(ok.group(1)))
                continue
            m = re.search(pattern, text)
            if m:
                values[name].append(int(m.group(1)))
    for name, found in values.items():
        if found:
            print(f"    {name}: median {statistics.median(found):.0f} (min {min(found)}, max {max(found)}, {len(found)} launches)")
        else:
            print(f"    {name}: —")
PY
  done
fi

if [[ "${SKIP_SCROLL:-0}" != 1 ]]; then
  xcodebuild test-without-building -project apple/Verrou.xcodeproj -scheme VerrouiOS \
    -destination "id=$DEV" -derivedDataPath "$DERIVED" \
    -only-testing:VerrouiOSUITests/ScrollPerformanceUITests > "$OUT/scroll.log" 2>&1 || {
      tail -30 "$OUT/scroll.log" >&2; echo "scrolling measurement FAILED" >&2; exit 1; }
  grep -E "measured \[" "$OUT/scroll.log" | sed -E 's/.*measured \[([^]]*)\].*average: ([0-9.]+).*relative standard deviation: ([0-9.]+%).*/scrolling: \1 = \2 (relative deviation \3)/' || true
fi
