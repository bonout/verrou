#!/usr/bin/env bash
# Mesures de l'app iPhone (build Debug) sur un coffre fictif de 2 000
# éléments, dans un simulateur sans fenêtre :
#
#   1. lancement à froid jusqu'à l'accueil du coffre ouvert, RUNS fois
#      (apple/VerrouiOS/Demo/PhoneBenchDriver.swift), puis ouverture de la
#      liste et chaque frappe d'une recherche jusqu'à l'image suivante ;
#   2. saccades du défilement de la liste (XCUITest,
#      XCTOSSignpostMetric.scrollingAndDecelerationMetric).
#
#   scripts/ios-bench.sh
#
# Variables : OUT (défaut target/ios-bench), SKIP_BUILD=1, RUNS (défaut 6),
# MOCK_SIZE (défaut 2000), SKIP_SCROLL=1, SIM_DEVICE_TYPE, SIM_RUNTIME.
# Les temps du simulateur dépendent du Mac : comparer deux builds sur la
# même machine, au même moment.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
OUT="${OUT:-$ROOT/target/ios-bench}"
DERIVED="$ROOT/target/xcode-ios.noindex"
APP="$DERIVED/Build/Products/Debug-iphonesimulator/Verrou.app"
RUNS="${RUNS:-6}"
MOCK_SIZE="${MOCK_SIZE:-2000}"
SIM_DEVICE_TYPE="${SIM_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro}"
SIM_RUNTIME="${SIM_RUNTIME:-$(xcrun simctl list runtimes -j | python3 -I -c '
import json, sys
runtimes = [r for r in json.load(sys.stdin)["runtimes"] if r["platform"] == "iOS" and r["isAvailable"]]
print(runtimes[-1]["identifier"])')}"
DEV=""

cleanup() {
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
  xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS -configuration Debug \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath "$DERIVED" \
    ARCHS="$(uname -m)" build-for-testing -quiet
fi

DEV="$(xcrun simctl create "Verrou Bench" "$SIM_DEVICE_TYPE" "$SIM_RUNTIME")"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl spawn "$DEV" defaults write -g AppleLanguages -array fr-FR
xcrun simctl spawn "$DEV" defaults write -g AppleLocale -string fr_FR
xcrun simctl shutdown "$DEV"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl install "$DEV" "$APP"
# Le simulateur finit de démarrer ses services avant les mesures.
sleep 20

rm -rf "$OUT" && mkdir -p "$OUT"
for run in $(seq "$RUNS"); do
  SIMCTL_CHILD_VERROU_MOCK=1 SIMCTL_CHILD_VERROU_MOCK_SIZE="$MOCK_SIZE" SIMCTL_CHILD_VERROU_BENCH=1 \
    xcrun simctl launch --console-pty --terminate-running-process "$DEV" app.verrou.ios \
    > "$OUT/run-$run.log" 2>&1 &
  launch_pid=$!
  # Le pilote quitte l'app après BENCH_DONE ; trois minutes au plus.
  for _ in $(seq 900); do kill -0 "$launch_pid" 2>/dev/null || break; sleep 0.2; done
  kill "$launch_pid" 2>/dev/null || true
  xcrun simctl terminate "$DEV" app.verrou.ios >/dev/null 2>&1 || true
  grep -q '^BENCH_DONE' "$OUT/run-$run.log" || { echo "mesure $run inachevée :" >&2; tail -20 "$OUT/run-$run.log" >&2; exit 1; }
  sleep 2
done

python3 -I - "$OUT" "$RUNS" <<'PY'
import re, statistics, sys, pathlib
out, runs = pathlib.Path(sys.argv[1]), int(sys.argv[2])
launch, launch_cpu, lists, list_cpu, keys, key_cpu, built = [], [], [], [], [], [], []
for run in range(1, runs + 1):
    text = (out / f"run-{run}.log").read_text(errors="replace")
    m = re.search(r"BENCH LAUNCH .*\+(\d+) ms du lancement, CPU du processus (\d+) ms", text)
    if m and run > 1:  # le premier lancement remplit les caches du système
        launch.append(int(m.group(1)))
        launch_cpu.append(int(m.group(2)))
    m = re.search(r"BENCH LIST ouverture .*CPU ([\d.]+) ms", text)
    if m:
        list_cpu.append(float(m.group(1)))
    m = re.search(r"BENCH LIST affichée en (\d+) ms", text)
    if m:
        lists.append(int(m.group(1)))
    for ms, cpu, rows in re.findall(r"BENCH KEY .*: ([\d.]+) ms \(CPU ([\d.]+) ms\), (\d+) lignes", text):
        keys.append(float(ms))
        key_cpu.append(float(cpu))
        built.append(int(rows))
keys.sort()
p95 = keys[min(len(keys) - 1, int(len(keys) * 0.95))]
print(f"lancement à froid → accueil ouvert : médiane {statistics.median(launch):.0f} ms (min {min(launch)}, max {max(launch)}, {len(launch)} lancements)")
print(f"  CPU du processus au même moment : médiane {statistics.median(launch_cpu):.0f} ms")
print(f"ouverture de « Tous les éléments » : médiane {statistics.median(lists):.0f} ms (CPU du fil principal : médiane {statistics.median(list_cpu):.0f} ms)")
print(f"frappe de recherche : médiane {statistics.median(keys):.2f} ms, p95 {p95:.2f} ms, max {keys[-1]:.2f} ms ({len(keys)} frappes), lignes construites par frappe : médiane {statistics.median(built):.0f}")
print(f"  CPU du fil principal par frappe : médiane {statistics.median(key_cpu):.2f} ms")
PY

if [[ "${SKIP_SCROLL:-0}" != 1 ]]; then
  xcodebuild test-without-building -project apple/Verrou.xcodeproj -scheme VerrouiOS \
    -destination "id=$DEV" -derivedDataPath "$DERIVED" \
    -only-testing:VerrouiOSUITests/ScrollPerformanceUITests > "$OUT/scroll.log" 2>&1 || {
      tail -30 "$OUT/scroll.log" >&2; echo "ÉCHEC de la mesure du défilement" >&2; exit 1; }
  grep -E "measured \[" "$OUT/scroll.log" | sed -E 's/.*measured \[([^]]*)\].*average: ([0-9.]+).*relative standard deviation: ([0-9.]+%).*/défilement : \1 = \2 (écart relatif \3)/' || true
fi
