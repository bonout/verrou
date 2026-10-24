#!/usr/bin/env bash
# Builds the Mac app for a release, in target/release-macos/.
#
#   scripts/release-macos.sh 0.1.0
#
# Without VERROU_TEAM: ad hoc signed Verrou-<version>-macos-arm64-adhoc.zip
# (scripts/install-macos.sh, without the system credential provider). macOS
# quarantines it: users clear it with
# `xattr -dr com.apple.quarantine /Applications/Verrou.app`.
#
# With VERROU_TEAM and an App Store Connect API key (ASC_KEY_PATH, ASC_KEY_ID,
# ASC_ISSUER_ID): archive signed by the team, exported for Developer ID (with
# the VerrouAutoFillMac credential provider and the app group
# <team>.app.verrou), notarized and stapled, in Verrou-<version>-macos.dmg.
# The Developer ID Application certificate must be in the keychain, and the
# two Developer ID profiles installed ("Verrou Developer ID" for the app,
# "Verrou AutoFill Developer ID" for its extension): the release workflow
# imports them. The export signs manually with them: an API key can't create
# Developer ID profiles.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:?usage: release-macos.sh <version>}"
OUT="target/release-macos"
rm -rf "$OUT"
mkdir -p "$OUT"

TEAM="${VERROU_TEAM:-}"
if [[ -z "$TEAM" ]]; then
  VERROU_INSTALL_DIR=none scripts/install-macos.sh
  APP="target/xcode.noindex/Build/Products/Release/Verrou.app"
  ditto -c -k --keepParent "$APP" "$OUT/Verrou-$VERSION-macos-arm64-adhoc.zip"
  echo "ad hoc: $OUT/Verrou-$VERSION-macos-arm64-adhoc.zip"
  exit 0
fi

[[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || { echo "VERROU_TEAM: 10-character team identifier expected" >&2; exit 2; }
AUTH=(-authenticationKeyPath "${ASC_KEY_PATH:?}" -authenticationKeyID "${ASC_KEY_ID:?}"
      -authenticationKeyIssuerID "${ASC_ISSUER_ID:?}")
ARCHIVE="$OUT/Verrou.xcarchive"

scripts/build-apple.sh
(cd apple && xcodegen generate --quiet)
xcodebuild -project apple/Verrou.xcodeproj -scheme Verrou -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath target/xcode-release.noindex \
  -archivePath "$ARCHIVE" \
  CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$TEAM" \
  VERROU_MAC_APP_GROUP="$TEAM.app.verrou" VERROU_MAC_ENTITLEMENTS=Verrou/Verrou-team.entitlements \
  VERROU_MAC_AUTOFILL_ENTITLEMENTS=VerrouAutoFillMac/VerrouAutoFillMac.entitlements \
  CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO MARKETING_VERSION="$VERSION" \
  -allowProvisioningUpdates "${AUTH[@]}" archive -quiet

cat > "$OUT/ExportOptions.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>developer-id</string>
  <key>teamID</key><string>$TEAM</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>Developer ID Application</string>
  <key>provisioningProfiles</key>
  <dict>
    <key>app.verrou.mac</key><string>Verrou Developer ID</string>
    <key>app.verrou.mac.autofill</key><string>Verrou AutoFill Developer ID</string>
  </dict>
</dict>
</plist>
EOF
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$OUT/export" \
  -exportOptionsPlist "$OUT/ExportOptions.plist" -allowProvisioningUpdates "${AUTH[@]}"

APP="$OUT/export/Verrou.app"
codesign --verify --strict --deep "$APP"
# No get-task-allow: no debugger must be able to read the vault's memory.
for code in "$APP" "$APP/Contents/PlugIns/VerrouAutoFillMac.appex"; do
  if codesign -d --entitlements - --xml "$code" 2>/dev/null | grep -q get-task-allow; then
    echo "get-task-allow present in the release build ($code): aborting" >&2
    exit 1
  fi
done

DMG="$OUT/Verrou-$VERSION-macos.dmg"
STAGE="$OUT/dmg"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/Verrou.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -quiet -volname "Verrou $VERSION" -srcfolder "$STAGE" -format UDZO "$DMG"
codesign --sign "Developer ID Application" --timestamp "$DMG"

xcrun notarytool submit "$DMG" --key "$ASC_KEY_PATH" --key-id "$ASC_KEY_ID" \
  --issuer "$ASC_ISSUER_ID" --wait
xcrun stapler staple "$DMG"
spctl --assess --type open --context context:primary-signature --verbose "$DMG"
echo "notarized: $DMG"
