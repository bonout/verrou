#!/usr/bin/env bash
# Builds Verrou for iPhone in Release, signed with your Apple team, and
# installs it on the iPhone connected over USB (or paired over Wi-Fi).
#
#   VERROU_TEAM=ABCDE12345 scripts/install-ios.sh [iPhone identifier]
#
# Prerequisites, once:
# - an Apple Developer account (paid: the app group and AutoFill are not
#   open to free accounts), signed in under Xcode → Settings → Accounts,
#   license agreement up to date;
# - developer mode turned on on the iPhone;
# - the app group created on developer.apple.com (Identifiers → App Groups):
#   xcodebuild enables it but doesn't create it. By default
#   group.app.verrou.<team in lowercase>, or VERROU_APP_GROUP. It must be
#   checked in the App IDs app.verrou.ios and app.verrou.ios.autofill (created
#   on the first attempt).
#
# A development profile carries get-task-allow: that is the price of an
# install outside the App Store and TestFlight.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TEAM="${VERROU_TEAM:?VERROU_TEAM=<your Apple team identifier> is required}"
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
[[ -n "$DEVICE" ]] || { echo "No iPhone found: connect it and unlock it." >&2; exit 1; }

PLATFORMS=all scripts/build-apple.sh
(cd apple && xcodegen generate --quiet)
xcodebuild -project apple/Verrou.xcodeproj -packageAuthorizationProvider netrc -scheme VerrouiOS -configuration Release \
  -destination "id=$DEVICE" -derivedDataPath target/xcode-device.noindex \
  DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_STYLE=Automatic VERROU_APP_GROUP="$GROUP" \
  -allowProvisioningUpdates build -quiet

APP="target/xcode-device.noindex/Build/Products/Release-iphoneos/Verrou.app"
# Without the group in the signature, the extension wouldn't see the vault.
if ! codesign -d --entitlements - --xml "$APP" 2>/dev/null | grep -q "$GROUP"; then
  echo "The group $GROUP is missing from the signature: see the prerequisites at the top of the script." >&2
  exit 1
fi
xcrun devicectl device install app --device "$DEVICE" "$APP" >/dev/null
echo "Installed on the iPhone $DEVICE (team $TEAM, group $GROUP)"
