#!/usr/bin/env bash
# Archives the iPhone app in Release, signed for distribution with your
# team, and uploads it to App Store Connect for TestFlight (internal testing).
#
#   VERROU_TEAM=ABCDE12345 scripts/testflight-ios.sh
#
# Prerequisites, in addition to those of scripts/install-ios.sh (paid
# account, app group created):
# - the app's record in App Store Connect (iOS, bundle app.verrou.ios);
# - the upload: the account signed in to Xcode is enough, or an App Store
#   Connect API key (App Manager role) passed through ASC_KEY_PATH (.p8 file,
#   kept out of the repository), ASC_KEY_ID and ASC_ISSUER_ID.
#
# The build number is the timestamp (YYYYMMDDHHMM): each upload exceeds the
# previous one, as App Store Connect requires. VERROU_BUILD overrides it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TEAM="${VERROU_TEAM:?VERROU_TEAM=<your Apple team identifier> is required}"
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

echo "Uploaded to App Store Connect: version $(/usr/libexec/PlistBuddy -c 'Print :ApplicationProperties:CFBundleShortVersionString' "$ARCHIVE/Info.plist"), build $BUILD (team $TEAM)"
