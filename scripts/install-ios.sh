#!/usr/bin/env bash
# Construit Verrou pour iPhone en Release, signé avec votre équipe Apple, et
# l'installe sur l'iPhone branché en USB (ou appairé en Wi-Fi).
#
#   VERROU_TEAM=ABCDE12345 scripts/install-ios.sh [identifiant de l'iPhone]
#
# Prérequis, une fois :
# - un compte Apple Developer (payant : le groupe d'apps et le remplissage
#   automatique ne sont pas ouverts aux comptes gratuits), connecté dans
#   Xcode → Réglages → Comptes, contrat de licence à jour ;
# - le mode développeur activé sur l'iPhone ;
# - le groupe d'apps créé sur developer.apple.com (Identifiers → App Groups) :
#   xcodebuild l'active mais ne le crée pas. Par défaut
#   group.app.verrou.<équipe en minuscules>, ou VERROU_APP_GROUP. Il doit être
#   coché dans les App IDs app.verrou.ios et app.verrou.ios.autofill (créés au
#   premier essai).
#
# Un profil de développement porte get-task-allow : c'est le prix d'une
# installation hors App Store et TestFlight.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TEAM="${VERROU_TEAM:?VERROU_TEAM=<identifiant de votre équipe Apple> est requis}"
GROUP="${VERROU_APP_GROUP:-group.app.verrou.$(tr '[:upper:]' '[:lower:]' <<<"$TEAM")}"

DEVICE="${1:-}"
if [[ -z "$DEVICE" ]]; then
  JSON="$(mktemp)"
  trap 'rm -f "$JSON"' EXIT
  xcrun devicectl list devices --json-output "$JSON" >/dev/null
  DEVICE="$(python3 -c '
import json, sys
for d in json.load(open(sys.argv[1]))["result"]["devices"]:
    hw = d.get("hardwareProperties", {})
    if hw.get("platform") == "iOS" and hw.get("deviceType") == "iPhone" and hw.get("udid"):
        print(hw["udid"]); break
' "$JSON")"
fi
[[ -n "$DEVICE" ]] || { echo "Aucun iPhone trouvé : branchez-le et déverrouillez-le." >&2; exit 1; }

PLATFORMS=all scripts/build-apple.sh
(cd apple && xcodegen generate --quiet)
xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS -configuration Release \
  -destination "id=$DEVICE" -derivedDataPath target/xcode-device.noindex \
  DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_STYLE=Automatic VERROU_APP_GROUP="$GROUP" \
  -allowProvisioningUpdates build -quiet

APP="target/xcode-device.noindex/Build/Products/Release-iphoneos/Verrou.app"
# Sans le groupe dans la signature, l'extension ne verrait pas le coffre.
if ! codesign -d --entitlements - --xml "$APP" 2>/dev/null | grep -q "$GROUP"; then
  echo "Le groupe $GROUP manque à la signature : voir les prérequis en tête du script." >&2
  exit 1
fi
xcrun devicectl device install app --device "$DEVICE" "$APP" >/dev/null
echo "Installé sur l'iPhone $DEVICE (équipe $TEAM, groupe $GROUP)"
