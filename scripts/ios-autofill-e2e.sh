#!/usr/bin/env bash
# Remplissage automatique d'iOS de bout en bout (extension VerrouAutoFill),
# dans un simulateur sans fenêtre, contre un Vaultwarden jetable.
#
#   scripts/ios-autofill-e2e.sh
#
# Ce que fait le script :
#   1. construit le cœur Rust (macOS de cette machine + simulateur), puis
#      l'app, l'extension et le test XCUITest pour le simulateur, signés ad
#      hoc (« - ») : sans signature, ni groupe d'apps ni droit de fournisseur
#      de remplissage (sauf SKIP_BUILD=1) ;
#   2. lance un Vaultwarden jetable (conteneur verrou-vw-autofill-ios, port
#      8122) et y crée le compte du parcours (seed_walkthrough_account) ;
#   3. sert la page de test (scripts/ios-autofill-page) sur
#      http://localhost:<port libre> : WebAuthn y est permis sans HTTPS ;
#   4. crée un simulateur « Verrou AutoFill E2E », le démarre sans ouvrir
#      Simulator.app, le passe en français, enrôle Face ID, installe l'app et
#      choisit Verrou comme fournisseur de remplissage (pluginkit, ce que
#      fait le bouton de Réglages → Général → Remplissage automatique) ;
#   5. lance les tests XCUITest (apple/VerrouAutoFillUITests) en acceptant
#      chaque demande Face ID ; ils pilotent l'app, puis Safari ;
#   6. relève le pic de mémoire de l'extension (journal AUTOFILL_MEMORY),
#      puis efface simulateur, serveur de page et conteneur.
#
# Variables : OUT (captures, défaut target/ios-autofill-e2e), SKIP_BUILD=1,
# KEEP_SIMULATOR=1, KEEP_SERVER=1, SIM_DEVICE_TYPE, SIM_RUNTIME, ONLY (un
# test, ex. test2_PasswordFillsFromTheKeyboardSuggestion), VW_CONTAINER et
# VW_PORT (autre conteneur, pour deux exécutions en parallèle),
# VERROU_RECORD=<fichier.mp4> (vidéo du simulateur, `simctl io recordVideo`,
# avec des pauses de RECORD_PAUSE secondes, défaut 2, aux étapes clés ; les
# repères AUTOFILL_E2E_MARK du journal, comparés à RECORD_START, permettent
# de la découper), APPEARANCE (light ou dark, défaut light). Les captures
# sont prises par `simctl io screenshot`, à la demande du test.
#
# Rien ne s'affiche sur l'écran du Mac : `simctl boot` n'ouvre pas
# Simulator.app, et les captures viennent de XCUIScreen (dans le simulateur).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
OUT="${OUT:-$ROOT/target/ios-autofill-e2e}"
DERIVED="$ROOT/target/xcode-ios.noindex"
APP="$DERIVED/Build/Products/Debug-iphonesimulator/Verrou.app"
SIM_DEVICE_TYPE="${SIM_DEVICE_TYPE:-com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro}"
SIM_RUNTIME="${SIM_RUNTIME:-$(xcrun simctl list runtimes -j | python3 -I -c '
import json, sys
runtimes = [r for r in json.load(sys.stdin)["runtimes"] if r["platform"] == "iOS" and r["isAvailable"]]
print(runtimes[-1]["identifier"])')}"
CONTAINER="${VW_CONTAINER:-verrou-vw-autofill-ios}"
VW_PORT="${VW_PORT:-8122}"
RECORD="${VERROU_RECORD:-}"
[[ -z "$RECORD" || "$RECORD" == /* ]] || RECORD="$PWD/$RECORD"
RECORD_PID=""
PAGE_PORT="$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
WORK="$(mktemp -d)"
DEV=""
PAGE_PID=""
FACE_PID=""
SHOOTER_PID=""
STARTED_SERVER=0

stop_recording() {
  if [[ -n "$RECORD_PID" ]]; then
    # SIGINT : recordVideo termine proprement le fichier.
    kill -INT "$RECORD_PID" 2>/dev/null || true
    wait "$RECORD_PID" 2>/dev/null || true
    RECORD_PID=""
  fi
}

cleanup() {
  stop_recording
  [[ -n "$FACE_PID" ]] && kill "$FACE_PID" 2>/dev/null || true
  [[ -n "$SHOOTER_PID" ]] && kill "$SHOOTER_PID" 2>/dev/null || true
  [[ -n "$PAGE_PID" ]] && kill "$PAGE_PID" 2>/dev/null || true
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

# 1. Construction
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  HOST="$(uname -m | sed 's/arm64/aarch64/')-apple-darwin"
  SIM="$( [[ "$(uname -m)" == arm64 ]] && echo aarch64-apple-ios-sim || echo x86_64-apple-ios )"
  PROFILE="${PROFILE:-release}" PLATFORMS=all TARGETS="$HOST" IOS_TARGETS="" SIM_TARGETS="$SIM" scripts/build-apple.sh
  (cd apple && xcodegen generate --quiet)
  xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS -configuration Debug \
    -destination 'generic/platform=iOS Simulator' -derivedDataPath "$DERIVED" \
    ARCHS="$(uname -m)" build-for-testing -quiet
fi

# 2. Serveur et compte
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
SEED="$(VERROU_TEST_SERVER="http://localhost:$VW_PORT" VERROU_SEED_EMAIL="autofill-$(date +%s)@verrou.test" \
  cargo test -q -p verrou-vaultwarden --test server -- --ignored --nocapture seed_walkthrough_account 2>/dev/null)"
EMAIL="$(sed -n 's/^SEED_EMAIL=//p' <<< "$SEED")"
PASSWORD="$(sed -n 's/^SEED_PASSWORD=//p' <<< "$SEED")"
TOTP="$(sed -n 's/^SEED_TOTP=//p' <<< "$SEED")"
[[ -n "$TOTP" ]] || { echo "compte du parcours impossible à créer" >&2; exit 1; }

# 3. Page de test
python3 -I -m http.server "$PAGE_PORT" --bind 127.0.0.1 --directory "$ROOT/scripts/ios-autofill-page" \
  >/dev/null 2>&1 &
PAGE_PID=$!
for _ in $(seq 20); do curl -fs "http://localhost:$PAGE_PORT/" >/dev/null && break; sleep 0.25; done
SITE="http://localhost:$PAGE_PORT"

# 4. Simulateur sans fenêtre, en français, avec Face ID enrôlé
DEV="$(xcrun simctl create "Verrou AutoFill E2E" "$SIM_DEVICE_TYPE" "$SIM_RUNTIME")"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl spawn "$DEV" defaults write -g AppleLanguages -array fr-FR
xcrun simctl spawn "$DEV" defaults write -g AppleLocale -string fr_FR
xcrun simctl spawn "$DEV" defaults write com.apple.Preferences DidShowContinuousPathIntroduction -bool true
xcrun simctl shutdown "$DEV"
xcrun simctl boot "$DEV"
xcrun simctl bootstatus "$DEV" -b >/dev/null
xcrun simctl status_bar "$DEV" override --time "9:41" --dataNetwork wifi --wifiBars 3 \
  --cellularMode active --cellularBars 4 --batteryState charged --batteryLevel 100
xcrun simctl ui "$DEV" appearance "${APPEARANCE:-light}"
if [[ -n "$RECORD" ]]; then
  mkdir -p "$(dirname "$RECORD")"
  rm -f "$RECORD"
  xcrun simctl io "$DEV" recordVideo --codec=h264 --force "$RECORD" >"$WORK/record.log" 2>&1 &
  RECORD_PID=$!
  echo "RECORD_START $(python3 -I -c 'import time; print(time.time())')"
fi
xcrun simctl spawn "$DEV" notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit.enrollmentChanged
xcrun simctl install "$DEV" "$APP"
# Verrou comme fournisseur de remplissage : l'élection de pluginkit est ce
# que règle l'interrupteur « Verrou » des Réglages. Refaite tant que le test
# réinstalle l'app.
enable_provider() {
  xcrun simctl spawn "$DEV" pluginkit -e use -i app.verrou.ios.autofill >/dev/null 2>&1 || true
}
enable_provider
xcrun simctl spawn "$DEV" pluginkit -m -v -p com.apple.authentication-services-credential-provider-ui
sleep 5

# 5. Tests, Face ID reconnu à chaque demande
(
  while true; do
    xcrun simctl spawn "$DEV" notifyutil -p com.apple.BiometricKit_Sim.pearl.match >/dev/null 2>&1 || true
    enable_provider
    sleep 1.5
  done
) &
FACE_PID=$!

rm -rf "$OUT" && mkdir -p "$OUT" "$WORK/ack" "$WORK/snap/req" "$WORK/snap/ack"
# Captures demandées par le test : req/<nom> → $OUT/<nom>.png.
(
  while true; do
    for request in "$WORK"/snap/req/*; do
      [[ -e "$request" ]] || continue
      name="$(basename "$request")"
      xcrun simctl io "$DEV" screenshot "$OUT/$name.png" >/dev/null 2>&1 || true
      rm -f "$request"
      touch "$WORK/snap/ack/$name"
    done
    sleep 0.2
  done
) &
SHOOTER_PID=$!
ONLY_ARG=(-only-testing:VerrouAutoFillUITests)
[[ -n "${ONLY:-}" ]] && ONLY_ARG=(-only-testing:"VerrouAutoFillUITests/AutoFillUITests/$ONLY")
status=0
TEST_RUNNER_VERROU_AUTOFILL_E2E_SERVER="http://localhost:$VW_PORT" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_EMAIL="$EMAIL" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_PASSWORD="$PASSWORD" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_TOTP="$TOTP" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_SITE="$SITE" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_PAGE="$SITE/" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_ACK="$WORK/ack" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_SHOTS="$OUT" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_SNAP_DIR="$WORK/snap" \
TEST_RUNNER_VERROU_AUTOFILL_E2E_PAUSE="$( [[ -n "$RECORD" ]] && echo "${RECORD_PAUSE:-2}" || echo 0 )" \
  xcodebuild test-without-building -project apple/Verrou.xcodeproj -scheme VerrouiOS \
    -destination "id=$DEV" -derivedDataPath "$DERIVED" "${ONLY_ARG[@]}" \
    > "$OUT/xcodebuild.log" 2>&1 || status=$?
grep -E "Test Case .*(passed|failed|skipped)|error: |AUTOFILL_E2E|Executed" "$OUT/xcodebuild.log" || true
stop_recording
[[ -n "$RECORD" ]] && echo "vidéo : $RECORD"

# 6. Mémoire de l'extension
xcrun simctl spawn "$DEV" log show --last 30m --style compact \
  --predicate 'subsystem == "app.verrou.autofill" AND category == "memory"' > "$OUT/memory.log" 2>/dev/null || true
PEAK="$(sed -n 's/.*peak=\([0-9.]*\)MB.*/\1/p' "$OUT/memory.log" | sort -n | tail -1)"
echo "pic de mémoire de l'extension : ${PEAK:-inconnu} Mo (limite d'iOS : environ 120 Mo)"
if [[ -n "$PEAK" ]] && python3 -I -c "import sys; sys.exit(0 if float(sys.argv[1]) < 120 else 1)" "$PEAK"; then
  :
elif [[ -n "$PEAK" ]]; then
  echo "ÉCHEC : l'extension dépasse 120 Mo" >&2
  status=1
fi

if [[ $status != 0 ]]; then
  echo "ÉCHEC du remplissage automatique (journal : $OUT/xcodebuild.log)" >&2
  exit 1
fi
echo "captures : $OUT"
