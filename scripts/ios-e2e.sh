#!/usr/bin/env bash
# End-to-end walk through the iPhone app (Debug build) in a windowless
# simulator, against a throwaway Vaultwarden.
#
#   scripts/ios-e2e.sh
#
# What the script does:
#   1. builds the Rust core (this machine's macOS + simulator), then the
#      iPhone app for the simulator, ad hoc signed (unless SKIP_BUILD=1);
#   2. starts a throwaway Vaultwarden in Docker (container verrou-vw-ios,
#      port 8118), unless VERROU_E2E_SERVER already points to a server, and
#      creates the walk's account in it (crates/verrou-vaultwarden/tests/server.rs,
#      seed_walkthrough_account), plus a second account, invited into the
#      shared vault the walk creates;
#   3. puts a TCP relay (free port) in between, which the script cuts to
#      simulate a network loss;
#   4. creates a "Verrou E2E" simulator (iPhone 17 Pro), boots it without
#      opening Simulator.app, switches it to English, enrolls a Face ID face,
#      installs and launches the app with the end-to-end driver
#      (apple/VerrouiOS/Demo/EndToEndDriver.swift);
#   5. answers the driver (screenshots, Face ID match, network cut or
#      restored) then deletes the simulator, relay and container.
#
# The driver can also ask for a text size (`E2E_TEXT <size>`,
# `simctl ui content_size`), to check the large sizes, and for the
# appearance (`E2E_APPEARANCE light|dark`), for dark mode screenshots.
#
# QR codes: scripts/ios-qr-fixtures.swift generates screenshots of two-factor
# QR codes, added to the simulator's photo library (`simctl addmedia`); the
# driver reads them through the Photos picker's path (the simulator has no
# camera), checks the preview, the saving and the code shown.
# `E2E_ONLY=otp`: sign-in then this step only.
#
# Variables: OUT (screenshots, default target/ios-e2e), SKIP_BUILD=1, E2E_ONLY=otp,
# KEEP_SIMULATOR=1, KEEP_SERVER=1, SIM_DEVICE_TYPE, SIM_RUNTIME, VW_CONTAINER
# and VW_PORT (another container, for two runs in parallel),
# VERROU_E2E_SERVER (+ _EMAIL, _PASSWORD, _TOTP: an account already set up).
#
# Everything happens without a window: `simctl boot` doesn't launch
# Simulator.app and the screenshots (`simctl io screenshot`) aren't displayed
# anywhere.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
OUT="${OUT:-$ROOT/target/ios-e2e}"
DERIVED="$ROOT/target/xcode-ios.noindex"
APP="$DERIVED/Build/Products/Debug-iphonesimulator/Verrou.app"
SIM_DEVICE_TYPE="${SIM_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro}"
SIM_RUNTIME="${SIM_RUNTIME:-$(xcrun simctl list runtimes -j | python3 -I -c '
import json, sys
runtimes = [r for r in json.load(sys.stdin)["runtimes"] if r["platform"] == "iOS" and r["isAvailable"]]
print(runtimes[-1]["identifier"])')}"
CONTAINER="${VW_CONTAINER:-verrou-vw-ios}"
VW_PORT="${VW_PORT:-8118}"
# Free port for the relay (the same during the whole walk).
RELAY_PORT="${RELAY_PORT:-$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"
WORK="$(mktemp -d)"
LOG="$WORK/app.log"
DEV=""
RELAY_PID=""
STARTED_SERVER=0

cleanup() {
  [[ -n "$RELAY_PID" ]] && kill "$RELAY_PID" 2>/dev/null || true
  if [[ -n "$DEV" && "${KEEP_SIMULATOR:-0}" != 1 ]]; then
    xcrun simctl shutdown "$DEV" >/dev/null 2>&1 || true
    xcrun simctl delete "$DEV" >/dev/null 2>&1 || true
  fi
  if [[ $STARTED_SERVER == 1 && "${KEEP_SERVER:-0}" != 1 ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# 1. Build
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  HOST="$(uname -m | sed 's/arm64/aarch64/')-apple-darwin"
  SIM="$( [[ "$(uname -m)" == arm64 ]] && echo aarch64-apple-ios-sim || echo x86_64-apple-ios )"
  # Rust in release: in debug, the Bitwarden SDK's futures overflow the
  # 512 KB stack of Swift Concurrency threads (write then sync:
  # EXC_BAD_ACCESS on the guard page).
  PROFILE="${PROFILE:-release}" PLATFORMS=all TARGETS="$HOST" IOS_TARGETS="" SIM_TARGETS="$SIM" scripts/build-apple.sh
  (cd apple && xcodegen generate --quiet)
  xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS -configuration Debug \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath "$DERIVED" \
    ARCHS="$(uname -m)" build -quiet
fi

# 2. Server and account
if [[ -z "${VERROU_E2E_SERVER:-}" ]]; then
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
  EMAIL="ios-$(date +%s)@verrou.test"
  SEED="$(VERROU_TEST_SERVER="http://localhost:$VW_PORT" VERROU_SEED_EMAIL="$EMAIL" \
    cargo test -q -p verrou-vaultwarden --test server -- --ignored --nocapture seed_walkthrough_account 2>/dev/null)"
  VERROU_E2E_EMAIL="$(sed -n 's/^SEED_EMAIL=//p' <<< "$SEED")"
  VERROU_E2E_PASSWORD="$(sed -n 's/^SEED_PASSWORD=//p' <<< "$SEED")"
  VERROU_E2E_TOTP="$(sed -n 's/^SEED_TOTP=//p' <<< "$SEED")"
  [[ -n "$VERROU_E2E_TOTP" ]] || { echo "could not create the walk's account" >&2; exit 1; }
  # Second account: the member invited into the shared vault.
  MEMBER_SEED="$(VERROU_TEST_SERVER="http://localhost:$VW_PORT" VERROU_SEED_EMAIL="membre-$EMAIL" \
    cargo test -q -p verrou-vaultwarden --test server -- --ignored --nocapture seed_walkthrough_account 2>/dev/null)"
  VERROU_E2E_MEMBER_EMAIL="$(sed -n 's/^SEED_EMAIL=//p' <<< "$MEMBER_SEED")"
  VERROU_E2E_MEMBER_PASSWORD="$(sed -n 's/^SEED_PASSWORD=//p' <<< "$MEMBER_SEED")"
  VERROU_E2E_MEMBER_TOTP="$(sed -n 's/^SEED_TOTP=//p' <<< "$MEMBER_SEED")"
  [[ -n "$VERROU_E2E_MEMBER_TOTP" ]] || { echo "could not create the member's account" >&2; exit 1; }
  UPSTREAM_PORT=$VW_PORT
else
  UPSTREAM_PORT="$(python3 -I -c 'import sys, urllib.parse; print(urllib.parse.urlparse(sys.argv[1]).port or 80)' "$VERROU_E2E_SERVER")"
fi

# 3. TCP relay: cutting it simulates a network loss (connection refused).
cat > "$WORK/relay.py" <<'PY'
import asyncio, sys
listen, upstream = int(sys.argv[1]), int(sys.argv[2])
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
PY
start_relay() {
  python3 -I "$WORK/relay.py" "$RELAY_PORT" "$UPSTREAM_PORT" &
  RELAY_PID=$!
  for _ in $(seq 20); do nc -z 127.0.0.1 "$RELAY_PORT" 2>/dev/null && return; sleep 0.25; done
  echo "could not start the relay on port $RELAY_PORT" >&2
  exit 1
}
stop_relay() {
  kill "$RELAY_PID" 2>/dev/null || true
  wait "$RELAY_PID" 2>/dev/null || true
  RELAY_PID=""
}
start_relay

# 4. Windowless simulator, in English, with Face ID enrolled
DEV="$(xcrun simctl create "Verrou E2E" "$SIM_DEVICE_TYPE" "$SIM_RUNTIME")"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl spawn "$DEV" defaults write -g AppleLanguages -array en-US
xcrun simctl spawn "$DEV" defaults write -g AppleLocale -string en_US
# No swipe keyboard introduction on the screenshots.
xcrun simctl spawn "$DEV" defaults write com.apple.Preferences DidShowContinuousPathIntroduction -bool true
xcrun simctl shutdown "$DEV"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl status_bar "$DEV" override --time "9:41" --dataNetwork wifi --wifiBars 3 \
  --cellularMode active --cellularBars 4 --batteryState charged --batteryLevel 100
xcrun simctl spawn "$DEV" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit.enrollmentChanged
xcrun simctl install "$DEV" "$APP"
# Two-factor QR codes: generated screenshots, added to the photo library
# (picked in Photos on the simulator, or on the device) and read by the
# driver through the same path as the Photos picker.
QR_DIR="$WORK/qr"
xcrun swift "$ROOT/scripts/ios-qr-fixtures.swift" "$QR_DIR" >/dev/null
xcrun simctl addmedia "$DEV" "$QR_DIR"/qr-*.png
# Lets the first boot's notifications go by before the screenshots.
sleep 8

rm -rf "$OUT" && mkdir -p "$OUT" "$WORK/ack"
# A local server also goes through the relay (network cut); a remote
# server is reached directly.
APP_SERVER="http://localhost:$RELAY_PORT"
if [[ -n "${VERROU_E2E_SERVER:-}" ]] && ! grep -qE '^https?://(localhost|127\.0\.0\.1)(:|/|$)' <<< "$VERROU_E2E_SERVER"; then
  APP_SERVER="$VERROU_E2E_SERVER"
fi
SIMCTL_CHILD_VERROU_E2E_SERVER="$APP_SERVER" \
SIMCTL_CHILD_VERROU_E2E_EMAIL="$VERROU_E2E_EMAIL" \
SIMCTL_CHILD_VERROU_E2E_PASSWORD="$VERROU_E2E_PASSWORD" \
SIMCTL_CHILD_VERROU_E2E_TOTP="$VERROU_E2E_TOTP" \
SIMCTL_CHILD_VERROU_E2E_MEMBER_EMAIL="${VERROU_E2E_MEMBER_EMAIL:-}" \
SIMCTL_CHILD_VERROU_E2E_MEMBER_PASSWORD="${VERROU_E2E_MEMBER_PASSWORD:-}" \
SIMCTL_CHILD_VERROU_E2E_MEMBER_TOTP="${VERROU_E2E_MEMBER_TOTP:-}" \
SIMCTL_CHILD_VERROU_E2E_ACK="$WORK/ack" \
SIMCTL_CHILD_VERROU_E2E_QR_DIR="$QR_DIR" \
SIMCTL_CHILD_VERROU_E2E_ONLY="${E2E_ONLY:-}" \
  xcrun simctl launch --console --terminate-running-process "$DEV" app.verrou.ios > "$LOG" 2>&1 &
LAUNCH_PID=$!

# 5. Answers to the driver
handled=0
status=2
deadline=$((SECONDS + 900))
while (( SECONDS < deadline )) && [[ $status == 2 ]]; do
  # The driver's lines not handled yet (bash 3: no mapfile).
  new_lines="$(grep '^E2E_' "$LOG" 2>/dev/null | sed -n "$((handled + 1)),\$p" || true)"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    handled=$((handled + 1))
    echo "$line"
    case "$line" in
      "E2E_SNAP "*)
        xcrun simctl io "$DEV" screenshot "$OUT/${line#E2E_SNAP }.png" >/dev/null 2>&1
        touch "$WORK/ack/${line#E2E_SNAP }" ;;
      E2E_FACEID)
        for _ in 1 2 3; do
          xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit_Sim.pearl.match
          sleep 1
        done ;;
      "E2E_TEXT "*)
        xcrun simctl ui "$DEV" content_size "${line#E2E_TEXT }" >/dev/null 2>&1 || true ;;
      "E2E_APPEARANCE "*)
        xcrun simctl ui "$DEV" appearance "${line#E2E_APPEARANCE }" >/dev/null 2>&1 || true ;;
      "E2E_NET off") stop_relay ;;
      "E2E_NET on") start_relay ;;
      E2E_DONE) status=0; break ;;
      "E2E_FAIL "*) status=1; break ;;
    esac
  done <<< "$new_lines"
  if [[ $status == 2 ]] && ! kill -0 "$LAUNCH_PID" 2>/dev/null; then
    grep -q '^E2E_DONE' "$LOG" && status=0 || status=1
  fi
  sleep 0.3
done
xcrun simctl terminate "$DEV" app.verrou.ios >/dev/null 2>&1 || true
kill "$LAUNCH_PID" 2>/dev/null || true
if [[ $status != 0 ]]; then
  echo "--- app log ---" >&2
  tail -40 "$LOG" >&2
  echo "iPhone walk FAILED" >&2
  exit 1
fi
echo "screenshots: $OUT"
