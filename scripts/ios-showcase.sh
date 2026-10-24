#!/usr/bin/env bash
# Showcase of the iPhone app (Debug build) on the fake vault, in a
# windowless simulator: each screen in light and dark mode, captured by
# `simctl io screenshot` (apple/VerrouiOSUITests/ShowcaseUITests.swift).
#
#   scripts/ios-showcase.sh                 # screenshots in target/ios-showcase/{clair,sombre}
#   RECORD=docs/media/ios-app.mp4 scripts/ios-showcase.sh   # the video only
#
# Variables: OUT, SHOWCASE_LANG (simulator language, default en-US; fr-FR
# gives the French UI and demo vault), SKIP_BUILD=1, KEEP_SIMULATOR=1, SIM_DEVICE_TYPE,
# SIM_RUNTIME, APPEARANCES (default "light dark"), RECORD (video of
# testRecording, with pauses of RECORD_PAUSE seconds, default 1;
# RECORD_TEST picks another test, for example testMotionUnlock).
#
# Nothing shows on the Mac's screen: `simctl boot` doesn't open
# Simulator.app, and the screenshots aren't displayed anywhere.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
OUT="${OUT:-$ROOT/target/ios-showcase}"
DERIVED="$ROOT/target/xcode-ios.noindex"
APP="$DERIVED/Build/Products/Debug-iphonesimulator/Verrou.app"
SIM_DEVICE_TYPE="${SIM_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro}"
SIM_RUNTIME="${SIM_RUNTIME:-$(xcrun simctl list runtimes -j | python3 -I -c '
import json, sys
runtimes = [r for r in json.load(sys.stdin)["runtimes"] if r["platform"] == "iOS" and r["isAvailable"]]
print(runtimes[-1]["identifier"])')}"
RECORD="${RECORD:-}"
[[ -z "$RECORD" || "$RECORD" == /* ]] || RECORD="$PWD/$RECORD"
WORK="$(mktemp -d)"
DEV=""
SHOOTER_PID=""
RECORD_PID=""

cleanup() {
  [[ -n "$SHOOTER_PID" ]] && kill "$SHOOTER_PID" 2>/dev/null || true
  [[ -n "$RECORD_PID" ]] && kill -INT "$RECORD_PID" 2>/dev/null || true
  if [[ -n "$DEV" && "${KEEP_SIMULATOR:-0}" != 1 ]]; then
    xcrun simctl shutdown "$DEV" >/dev/null 2>&1 || true
    xcrun simctl delete "$DEV" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
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

# Windowless simulator, in SHOWCASE_LANG, fixed time and status bar.
DEV="$(xcrun simctl create "Verrou Showcase" "$SIM_DEVICE_TYPE" "$SIM_RUNTIME")"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
LANG_CODE="${SHOWCASE_LANG:-en-US}"
xcrun simctl spawn "$DEV" defaults write -g AppleLanguages -array "$LANG_CODE"
xcrun simctl spawn "$DEV" defaults write -g AppleLocale -string "${LANG_CODE/-/_}"
xcrun simctl spawn "$DEV" defaults write com.apple.Preferences DidShowContinuousPathIntroduction -bool true
xcrun simctl shutdown "$DEV"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl status_bar "$DEV" override --time "9:41" --dataNetwork wifi --wifiBars 3 \
  --cellularMode active --cellularBars 4 --batteryState charged --batteryLevel 100
xcrun simctl spawn "$DEV" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit.enrollmentChanged
xcrun simctl install "$DEV" "$APP"
sleep 5

# Answers the test's screenshot requests: req/<name> → <folder>/<name>.png.
start_shooter() {
  local dest="$1"
  mkdir -p "$dest" "$WORK/req" "$WORK/ack"
  (
    while true; do
      for request in "$WORK"/req/*; do
        [[ -e "$request" ]] || continue
        name="$(basename "$request")"
        xcrun simctl io "$DEV" screenshot "$dest/$name.png" >/dev/null 2>&1 || true
        rm -f "$request"
        touch "$WORK/ack/$name"
      done
      sleep 0.2
    done
  ) &
  SHOOTER_PID=$!
}
stop_shooter() {
  kill "$SHOOTER_PID" 2>/dev/null || true
  wait "$SHOOTER_PID" 2>/dev/null || true
  SHOOTER_PID=""
  rm -rf "$WORK/req" "$WORK/ack"
}

run_test() {
  local test="$1" log="$2"
  TEST_RUNNER_VERROU_SHOWCASE_DIR="$WORK" \
  TEST_RUNNER_VERROU_SHOWCASE_PAUSE="$( [[ -n "$RECORD" ]] && echo "${RECORD_PAUSE:-1}" || echo 0 )" \
    xcodebuild test-without-building -project apple/Verrou.xcodeproj -scheme VerrouiOS \
      -destination "id=$DEV" -derivedDataPath "$DERIVED" \
      -only-testing:"VerrouiOSUITests/ShowcaseUITests/$test" > "$log" 2>&1
}

mkdir -p "$OUT"
status=0
if [[ -n "$RECORD" ]]; then
  xcrun simctl ui "$DEV" appearance "${APPEARANCES:-light}"
  mkdir -p "$(dirname "$RECORD")"
  rm -f "$RECORD"
  xcrun simctl io "$DEV" recordVideo --codec=h264 --force "$RECORD" >"$WORK/record.log" 2>&1 &
  RECORD_PID=$!
  # Markers to cut the video: RECORD_START here, SHOWCASE_MARK in the test's log.
  echo "RECORD_START $(python3 -I -c 'import time; print(time.time())')"
  sleep 2
  run_test "${RECORD_TEST:-testRecording}" "$OUT/record.log" || status=$?
  sleep 1
  kill -INT "$RECORD_PID" 2>/dev/null || true
  wait "$RECORD_PID" 2>/dev/null || true
  RECORD_PID=""
  grep -E "Test Case .*(passed|failed)|error: |SHOWCASE_MARK" "$OUT/record.log" || true
  echo "video: $RECORD"
else
  for appearance in ${APPEARANCES:-light dark}; do
    label="$( [[ "$appearance" == dark ]] && echo sombre || echo clair )"
    xcrun simctl ui "$DEV" appearance "$appearance"
    rm -rf "${OUT:?}/$label"
    start_shooter "$OUT/$label"
    run_test testShowcase "$OUT/$label.log" || status=$?
    stop_shooter
    grep -E "Test Case .*(passed|failed)|error: " "$OUT/$label.log" || true
    echo "$label: $(ls "$OUT/$label" | wc -l | tr -d ' ') screenshots in $OUT/$label"
  done
fi
[[ $status == 0 ]] || { echo "showcase FAILED (logs in $OUT)" >&2; exit 1; }
