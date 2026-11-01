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
# ASC_ISSUER_ID, for notarization): archive signed directly with the
# Developer ID certificate and profiles, never a development certificate
# (a fresh CI machine would otherwise create one at every release, until
# Apple's cap), exported for Developer ID (with
# the VerrouAutoFillMac credential provider and the app group
# <team>.app.verrou), notarized and stapled, in Verrou-<version>-macos.dmg.
# The Developer ID Application certificate must be in the keychain, and the
# two Developer ID profiles installed ("Verrou Developer ID" for the app,
# "Verrou AutoFill Developer ID" for its extension): the release workflow
# imports them. The export signs manually with them: an API key can't create
# Developer ID profiles.
#
# Updates (Sparkle): the Developer ID build carries the public key below and
# a build number that grows with the version (0.3.1 → 301). With
# SPARKLE_ED_PRIVATE_KEY (exported by Sparkle's generate_keys -x), the disk
# image is signed and appcast.xml written next to it: attached to the
# release, it is what installed apps read
# (releases/latest/download/appcast.xml). VERROU_SPARKLE_FEED points a test
# build to another feed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:?usage: release-macos.sh <version>}"
[[ "$VERSION" =~ ^([0-9]+)\.([0-9]{1,2})\.([0-9]{1,2})$ ]] || { echo "version x.y.z expected: $VERSION" >&2; exit 2; }
BUILD=$(( BASH_REMATCH[1] * 10000 + 10#${BASH_REMATCH[2]} * 100 + 10#${BASH_REMATCH[3]} ))
# EdDSA public key of the updates; its private key is the SPARKLE_ED_PRIVATE_KEY
# secret of the release environment.
SPARKLE_PUBLIC_KEY="mxqF/wn5FR6ivEJcfAfAsLunKzAOp54UDg0E3yUZbVE="
REPOSITORY="${GITHUB_REPOSITORY:-bonout/verrou}"
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
xcodebuild -project apple/Verrou.xcodeproj -packageAuthorizationProvider netrc -scheme Verrou -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath target/xcode-release.noindex \
  -archivePath "$ARCHIVE" \
  CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_IDENTITY="Developer ID Application" \
  VERROU_MAC_PROFILE="Verrou Developer ID" VERROU_MAC_AUTOFILL_PROFILE="Verrou AutoFill Developer ID" \
  VERROU_MAC_APP_GROUP="$TEAM.app.verrou" VERROU_MAC_ENTITLEMENTS=Verrou/Verrou-team.entitlements \
  VERROU_MAC_AUTOFILL_ENTITLEMENTS=VerrouAutoFillMac/VerrouAutoFillMac.entitlements \
  CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO MARKETING_VERSION="$VERSION" \
  CURRENT_PROJECT_VERSION="$BUILD" VERROU_SPARKLE_PUBLIC_KEY="$SPARKLE_PUBLIC_KEY" \
  ${VERROU_SPARKLE_FEED:+VERROU_SPARKLE_FEED="$VERROU_SPARKLE_FEED"} \
  archive -quiet

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
for attempt in 1 2 3 4 5; do
  xcrun stapler staple "$DMG" && break
  (( attempt < 5 )) || exit 1
  sleep $((attempt * 20))
done
spctl --assess --type open --context context:primary-signature --verbose "$DMG"
echo "notarized: $DMG"

if [[ -z "${SPARKLE_ED_PRIVATE_KEY:-}" ]]; then
  echo "no SPARKLE_ED_PRIVATE_KEY: no appcast.xml, installed apps won't see this release"
  exit 0
fi
# Sparkle's tools come with the package Xcode resolved (checksum checked).
SIGN_UPDATE="$(find target/xcode-release.noindex/SourcePackages/artifacts -path '*/bin/sign_update' -type f | head -1)"
[[ -x "$SIGN_UPDATE" ]] || { echo "sign_update not found" >&2; exit 1; }
SIGNATURE="$(printf '%s' "$SPARKLE_ED_PRIVATE_KEY" | "$SIGN_UPDATE" --ed-key-file - "$DMG")"
[[ "$SIGNATURE" =~ ^sparkle:edSignature=\"[A-Za-z0-9+/=]+\"\ length=\"[0-9]+\"$ ]] || { echo "unexpected sign_update output" >&2; exit 1; }
cat > "$OUT/appcast.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Verrou</title>
    <item>
      <title>Verrou $VERSION</title>
      <pubDate>$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')</pubDate>
      <sparkle:version>$BUILD</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>15.0</sparkle:minimumSystemVersion>
      <sparkle:fullReleaseNotesLink>https://github.com/$REPOSITORY/releases/tag/v$VERSION</sparkle:fullReleaseNotesLink>
      <enclosure url="https://github.com/$REPOSITORY/releases/download/v$VERSION/Verrou-$VERSION-macos.dmg" type="application/octet-stream" $SIGNATURE/>
    </item>
  </channel>
</rss>
XML
# The feed is signed too (SURequireSignedFeed): nobody can serve an older
# release or other notes in its place.
printf '%s' "$SPARKLE_ED_PRIVATE_KEY" | "$SIGN_UPDATE" --ed-key-file - "$OUT/appcast.xml"
echo "appcast: $OUT/appcast.xml"
