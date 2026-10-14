#!/usr/bin/env bash
# Extension Firefox installable pour de bon : signée par Mozilla (distribution
# « unlisted », hors du catalogue addons.mozilla.org), ou non signée pour
# Firefox Developer Edition / Nightly.
#
#   AMO_JWT_ISSUER=user:… AMO_JWT_SECRET=… scripts/sign-firefox.sh
#   scripts/sign-firefox.sh --unsigned
#
# Le Firefox ordinaire n'installe durablement que des modules signés par
# Mozilla. Clés d'API : https://addons.mozilla.org/developers/addon/api/key/
# (compte Mozilla de l'utilisateur ; « Émetteur JWT » et « Secret JWT »).
# La signature « unlisted » est automatique (quelques minutes), le module
# n'est pas publié ; le fichier .xpi signé s'installe par about:addons ›
# ⚙ › « Installer un module depuis un fichier… ».
#
# Le dossier signé est produit comme dans Verrou.app (firefox-extension.sh,
# puis stamp-extension.sh sur les deux dossiers) : même contenu, même
# version que l'extension livrée par l'app compilée depuis ce dépôt. Mozilla
# refuse de signer deux fois la même version : modifier l'extension change
# la version.
#
# --unsigned : un .xpi non signé (pour Developer Edition ou Nightly, avec
# `xpinstall.signatures.required` à false dans about:config) ; sans clés.
#
# Rien n'est lancé automatiquement : ni la CI ni la compilation n'appellent
# ce script. `web-ext` (l'outil de Mozilla) est téléchargé par npx.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/target/firefox-sign"
OUT="$ROOT/target/firefox-xpi"

unsigned=false
case "${1:-}" in
  "") ;;
  --unsigned) unsigned=true ;;
  *) echo "usage : sign-firefox.sh [--unsigned]" >&2; exit 1 ;;
esac

if ! $unsigned; then
  [[ -n "${AMO_JWT_ISSUER:-}" && -n "${AMO_JWT_SECRET:-}" ]] || {
    echo "sign-firefox : AMO_JWT_ISSUER et AMO_JWT_SECRET sont nécessaires (clés d'API de addons.mozilla.org)" >&2
    exit 1
  }
fi
command -v npx >/dev/null || { echo "sign-firefox : npx (Node.js) introuvable" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK" "$OUT"
cp -R "$ROOT/extension" "$WORK/extension"
"$ROOT/scripts/firefox-extension.sh" "$WORK/extension" "$WORK/extension-firefox" >/dev/null
"$ROOT/scripts/stamp-extension.sh" "$WORK/extension" "$WORK/extension-firefox"
version="$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([0-9.]+)".*$/\1/p' "$WORK/extension-firefox/manifest.json")"

if $unsigned; then
  npx --yes web-ext@8 build --source-dir "$WORK/extension-firefox" --artifacts-dir "$WORK/build" --overwrite-dest
  zip="$(ls "$WORK"/build/*.zip | head -n 1)"
  cp "$zip" "$OUT/verrou-$version-unsigned.xpi"
  echo "non signé : $OUT/verrou-$version-unsigned.xpi"
  exit 0
fi

# Les clés passent par l'environnement de web-ext, pas par sa ligne de
# commande (visible dans la liste des processus).
WEB_EXT_API_KEY="$AMO_JWT_ISSUER" WEB_EXT_API_SECRET="$AMO_JWT_SECRET" \
  npx --yes web-ext@8 sign --channel=unlisted \
    --source-dir "$WORK/extension-firefox" --artifacts-dir "$OUT"
echo "signé : $(ls -t "$OUT"/*.xpi | head -n 1) (version $version)"
