#!/usr/bin/env bash
# Construit Verrou en Release et l'installe dans /Applications.
#
#   scripts/install-macos.sh
#
# Signature ad hoc : aucune équipe de développeur Apple n'est nécessaire,
# l'app ne tourne que sur ce Mac. Le compte et le cache vivent dans le
# conteneur de l'app (~/Library/Containers/app.verrou.mac) : réinstaller ne
# les efface pas.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DEST="${VERROU_INSTALL_DIR:-/Applications}"

ARCH="$(uname -m)"
[[ "$ARCH" == arm64 ]] && TARGET=aarch64-apple-darwin || TARGET=x86_64-apple-darwin
TARGETS="$TARGET" scripts/build-apple.sh
(cd apple && xcodegen generate --quiet)
xcodebuild -project apple/Verrou.xcodeproj -scheme Verrou -configuration Release \
  -destination "platform=macOS,arch=$ARCH" -derivedDataPath target/xcode \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= \
  CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  build -quiet

APP="target/xcode/Build/Products/Release/Verrou.app"
codesign --verify --strict "$APP"
# Pas de get-task-allow : aucun débogueur ne doit pouvoir lire la mémoire du coffre.
if codesign -d --entitlements - --xml "$APP" 2>/dev/null | grep -q get-task-allow; then
  echo "get-task-allow présent dans le build Release : abandon" >&2
  exit 1
fi
osascript -e 'tell application id "app.verrou.mac" to quit' >/dev/null 2>&1 || true
rm -rf "$DEST/Verrou.app"
ditto "$APP" "$DEST/Verrou.app"
echo "Installé : $DEST/Verrou.app"
