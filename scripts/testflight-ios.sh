#!/usr/bin/env bash
# Archive l'app iPhone en Release, signée pour la distribution avec votre
# équipe, et l'envoie sur App Store Connect pour TestFlight (tests internes).
#
#   VERROU_TEAM=ABCDE12345 scripts/testflight-ios.sh
#
# Prérequis, en plus de ceux de scripts/install-ios.sh (compte payant,
# groupe d'apps créé) :
# - la fiche de l'app dans App Store Connect (iOS, bundle app.verrou.ios) ;
# - l'envoi : le compte connecté dans Xcode suffit, ou une clé API App Store
#   Connect (rôle App Manager) passée par ASC_KEY_PATH (fichier .p8, gardé
#   hors du dépôt), ASC_KEY_ID et ASC_ISSUER_ID.
#
# Le numéro de build est l'horodatage (AAAAMMJJHHMM) : chaque envoi le
# dépasse, comme l'exige App Store Connect. VERROU_BUILD le remplace.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TEAM="${VERROU_TEAM:?VERROU_TEAM=<identifiant de votre équipe Apple> est requis}"
GROUP="${VERROU_APP_GROUP:-group.app.verrou.$(tr '[:upper:]' '[:lower:]' <<<"$TEAM")}"
BUILD="${VERROU_BUILD:-$(date -u +%Y%m%d%H%M)}"
OUT="target/testflight"
ARCHIVE="$OUT/Verrou.xcarchive"

AUTH=()
if [[ -n "${ASC_KEY_PATH:-}" ]]; then
  AUTH=(-authenticationKeyPath "$ASC_KEY_PATH" -authenticationKeyID "${ASC_KEY_ID:?}"
        -authenticationKeyIssuerID "${ASC_ISSUER_ID:?}")
fi

rm -rf "$OUT"
mkdir -p "$OUT"
PLATFORMS=all scripts/build-apple.sh
(cd apple && xcodegen generate --quiet)

xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS -configuration Release \
  -destination 'generic/platform=iOS' -derivedDataPath target/xcode-device.noindex \
  -archivePath "$ARCHIVE" \
  DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_STYLE=Automatic VERROU_APP_GROUP="$GROUP" \
  CURRENT_PROJECT_VERSION="$BUILD" \
  -allowProvisioningUpdates ${AUTH[@]+"${AUTH[@]}"} archive -quiet

cat > "$OUT/ExportOptions.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>teamID</key><string>$TEAM</string>
  <key>signingStyle</key><string>automatic</string>
  <key>testFlightInternalTestingOnly</key><true/>
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
EOF

xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$OUT/export" \
  -exportOptionsPlist "$OUT/ExportOptions.plist" -allowProvisioningUpdates ${AUTH[@]+"${AUTH[@]}"}

echo "Envoyé sur App Store Connect : version $(/usr/libexec/PlistBuddy -c 'Print :ApplicationProperties:CFBundleShortVersionString' "$ARCHIVE/Info.plist"), build $BUILD (équipe $TEAM)"
