#!/usr/bin/env bash
# Builds Verrou in Release and installs it in /Applications.
#
#   scripts/install-macos.sh
#   VERROU_MAC_TEAM=<team> scripts/install-macos.sh   # with the credential provider
#
# Ad hoc signing (default): no Apple developer team is needed, the app only
# runs on this Mac. The account and the cache live in the app's container
# (~/Library/Containers/app.verrou.mac): reinstalling doesn't erase them.
#
# VERROU_MAC_TEAM: signed "Apple Development" by this team (profiles created
# by Xcode, this Mac registered in the team), with the VerrouAutoFillMac
# extension (Safari and the Mac's apps) and the app group
# <team>.app.verrou. On first launch, the app copies its account into the
# group (see VerrouStorage.migrateMac and docs/GUIDE.md). macOS refuses both
# to an ad hoc signed app.
#
# VERROU_INSTALL_DIR: install folder (default /Applications);
# VERROU_INSTALL_DIR=none builds without installing (checks).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DEST="${VERROU_INSTALL_DIR:-/Applications}"

ARCH="$(uname -m)"
[[ "$ARCH" == arm64 ]] && TARGET=aarch64-apple-darwin || TARGET=x86_64-apple-darwin
TEAM="${VERROU_MAC_TEAM:-}"
if [[ -n "$TEAM" ]]; then
  [[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || { echo "VERROU_MAC_TEAM: 10-character team identifier expected" >&2; exit 2; }
  SIGNING=(CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_IDENTITY="Apple Development"
           VERROU_MAC_APP_GROUP="$TEAM.app.verrou" VERROU_MAC_ENTITLEMENTS=Verrou/Verrou-team.entitlements
           VERROU_MAC_AUTOFILL_ENTITLEMENTS=VerrouAutoFillMac/VerrouAutoFillMac.entitlements
           -allowProvisioningUpdates)
else
  SIGNING=(CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM=)
fi

[[ "${SKIP_RUST:-}" == 1 ]] || TARGETS="$TARGET" scripts/build-apple.sh
(cd apple && xcodegen generate --quiet)
xcodebuild -project apple/Verrou.xcodeproj -scheme Verrou -configuration Release \
  -destination "platform=macOS,arch=$ARCH" -derivedDataPath target/xcode.noindex \
  "${SIGNING[@]}" CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  build -quiet

APP="target/xcode.noindex/Build/Products/Release/Verrou.app"
codesign --verify --strict "$APP"
# No get-task-allow: no debugger must be able to read the vault's memory.
for code in "$APP" "$APP/Contents/PlugIns/VerrouAutoFillMac.appex"; do
  [[ -e "$code" ]] || continue
  if codesign -d --entitlements - --xml "$code" 2>/dev/null | grep -q get-task-allow; then
    echo "get-task-allow present in the Release build ($code): aborting" >&2
    exit 1
  fi
done
APPEX="$APP/Contents/PlugIns/VerrouAutoFillMac.appex"
if [[ -n "$TEAM" ]]; then
  [[ -d "$APPEX" ]] || { echo "VerrouAutoFillMac extension missing from the signed build" >&2; exit 1; }
  codesign --verify --strict "$APPEX"
  # Provider entitlements and app group, allowed by the profile.
  for code in "$APP" "$APPEX"; do
    codesign -d --entitlements - --xml "$code" 2>/dev/null | grep -q "$TEAM.app.verrou" \
      || { echo "app group missing from $code" >&2; exit 1; }
  done
elif [[ -d "$APPEX" ]]; then
  # Ad hoc: the extension is built without entitlements (macOS only launches
  # a credential provider signed by a team); we remove it and re-sign the
  # app with its own entitlements.
  ENTITLEMENTS="$(mktemp)"
  codesign -d --entitlements - --xml "$APP" > "$ENTITLEMENTS"
  rm -rf "$APPEX"
  codesign --force --sign - --options runtime --entitlements "$ENTITLEMENTS" "$APP"
  rm -f "$ENTITLEMENTS"
  codesign --verify --strict "$APP"
fi
if [[ "$DEST" == none ]]; then
  echo "Built (not installed): $APP"
  exit 0
fi
osascript -e 'tell application id "app.verrou.mac" to quit' >/dev/null 2>&1 || true
# The app sometimes refuses to quit ("User canceled"): the old version
# would stay open on top of the new bundle.
sleep 1
pkill -x Verrou 2>/dev/null || true
rm -rf "$DEST/Verrou.app"
ditto "$APP" "$DEST/Verrou.app"
echo "Installed: $DEST/Verrou.app"
