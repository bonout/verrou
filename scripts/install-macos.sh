#!/usr/bin/env bash
# Construit Verrou en Release et l'installe dans /Applications.
#
#   scripts/install-macos.sh
#   VERROU_MAC_TEAM=<équipe> scripts/install-macos.sh   # avec le fournisseur d'identifiants
#
# Signature ad hoc (par défaut) : aucune équipe de développeur Apple n'est
# nécessaire, l'app ne tourne que sur ce Mac. Le compte et le cache vivent
# dans le conteneur de l'app (~/Library/Containers/app.verrou.mac) :
# réinstaller ne les efface pas.
#
# VERROU_MAC_TEAM : signé « Apple Development » par cette équipe (profils
# créés par Xcode, ce Mac enregistré dans l'équipe), avec l'extension
# VerrouAutoFillMac (Safari et les apps du Mac) et le groupe d'apps
# <équipe>.app.verrou. Au premier lancement, l'app copie son compte dans le
# groupe (voir VerrouStorage.migrateMac et docs/GUIDE.md). macOS refuse les
# deux à une app signée ad hoc.
#
# VERROU_INSTALL_DIR : dossier d'installation (défaut /Applications) ;
# VERROU_INSTALL_DIR=none construit sans installer (vérifications).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DEST="${VERROU_INSTALL_DIR:-/Applications}"

ARCH="$(uname -m)"
[[ "$ARCH" == arm64 ]] && TARGET=aarch64-apple-darwin || TARGET=x86_64-apple-darwin
TEAM="${VERROU_MAC_TEAM:-}"
if [[ -n "$TEAM" ]]; then
  [[ "$TEAM" =~ ^[A-Z0-9]{10}$ ]] || { echo "VERROU_MAC_TEAM : identifiant d'équipe à 10 caractères attendu" >&2; exit 2; }
  SIGNING=(CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_IDENTITY="Apple Development"
           VERROU_MAC_APP_GROUP="$TEAM.app.verrou" VERROU_MAC_ENTITLEMENTS=Verrou/Verrou-team.entitlements
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
# Pas de get-task-allow : aucun débogueur ne doit pouvoir lire la mémoire du coffre.
for code in "$APP" "$APP/Contents/PlugIns/VerrouAutoFillMac.appex"; do
  [[ -e "$code" ]] || continue
  if codesign -d --entitlements - --xml "$code" 2>/dev/null | grep -q get-task-allow; then
    echo "get-task-allow présent dans le build Release ($code) : abandon" >&2
    exit 1
  fi
done
APPEX="$APP/Contents/PlugIns/VerrouAutoFillMac.appex"
if [[ -n "$TEAM" ]]; then
  [[ -d "$APPEX" ]] || { echo "extension VerrouAutoFillMac absente du build signé" >&2; exit 1; }
  codesign --verify --strict "$APPEX"
  # Droits du fournisseur et groupe d'apps, autorisés par le profil.
  for code in "$APP" "$APPEX"; do
    codesign -d --entitlements - --xml "$code" 2>/dev/null | grep -q "$TEAM.app.verrou" \
      || { echo "groupe d'apps absent de $code" >&2; exit 1; }
  done
else
  [[ ! -d "$APPEX" ]] || { echo "extension VerrouAutoFillMac dans un build ad hoc : abandon" >&2; exit 1; }
fi
if [[ "$DEST" == none ]]; then
  echo "Construit (non installé) : $APP"
  exit 0
fi
osascript -e 'tell application id "app.verrou.mac" to quit' >/dev/null 2>&1 || true
# L'app refuse parfois de quitter (« User canceled ») : l'ancienne version
# resterait ouverte par-dessus le nouveau paquet.
sleep 1
pkill -x Verrou 2>/dev/null || true
rm -rf "$DEST/Verrou.app"
ditto "$APP" "$DEST/Verrou.app"
echo "Installé : $DEST/Verrou.app"
