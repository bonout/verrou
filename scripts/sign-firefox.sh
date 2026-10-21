#!/usr/bin/env bash
# Firefox extension installable for good: signed by Mozilla ("unlisted"
# distribution, outside the addons.mozilla.org catalog), or unsigned for
# Firefox Developer Edition / Nightly.
#
#   AMO_JWT_ISSUER=user:… AMO_JWT_SECRET=… scripts/sign-firefox.sh
#   scripts/sign-firefox.sh --unsigned
#
# Regular Firefox only installs add-ons signed by Mozilla for good. API keys:
# https://addons.mozilla.org/developers/addon/api/key/ (the user's Mozilla
# account; "JWT issuer" and "JWT secret").
# "Unlisted" signing is automatic (a few minutes), the add-on is not
# published; the signed .xpi file is installed through about:addons ›
# ⚙ › "Install Add-on From File…".
#
# The signed folder is produced as in Verrou.app (firefox-extension.sh, then
# stamp-extension.sh on both folders): same content, same version as the
# extension shipped by the app built from this repository. Mozilla refuses
# to sign the same version twice: changing the extension changes the
# version.
#
# --unsigned: an unsigned .xpi (for Developer Edition or Nightly, with
# `xpinstall.signatures.required` set to false in about:config); no keys.
#
# Nothing runs automatically: neither CI nor the build calls this script.
# `web-ext` (Mozilla's tool) is downloaded by npx.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/target/firefox-sign"
OUT="$ROOT/target/firefox-xpi"

unsigned=false
case "${1:-}" in
  "") ;;
  --unsigned) unsigned=true ;;
  *) echo "usage: sign-firefox.sh [--unsigned]" >&2; exit 1 ;;
esac

if ! $unsigned; then
  [[ -n "${AMO_JWT_ISSUER:-}" && -n "${AMO_JWT_SECRET:-}" ]] || {
    echo "sign-firefox: AMO_JWT_ISSUER and AMO_JWT_SECRET are required (addons.mozilla.org API keys)" >&2
    exit 1
  }
fi
command -v npx >/dev/null || { echo "sign-firefox: npx (Node.js) not found" >&2; exit 1; }

rm -rf "$WORK"
mkdir -p "$WORK" "$OUT"
cp -R "$ROOT/extension" "$WORK/extension"
"$ROOT/scripts/firefox-extension.sh" "$WORK/extension" "$WORK/extension-firefox" >/dev/null
"$ROOT/scripts/stamp-extension.sh" "$WORK/extension" "$WORK/extension-firefox"
version="$(sed -nE 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"([0-9.]+)".*$/\1/p' "$WORK/extension-firefox/manifest.json")"

if $unsigned; then
  npx --yes web-ext@8.10.0 build --source-dir "$WORK/extension-firefox" --artifacts-dir "$WORK/build" --overwrite-dest
  zip="$(ls "$WORK"/build/*.zip | head -n 1)"
  cp "$zip" "$OUT/verrou-$version-unsigned.xpi"
  echo "unsigned: $OUT/verrou-$version-unsigned.xpi"
  exit 0
fi

# The keys go through web-ext's environment, not its command line (visible
# in the process list).
WEB_EXT_API_KEY="$AMO_JWT_ISSUER" WEB_EXT_API_SECRET="$AMO_JWT_SECRET" \
  npx --yes web-ext@8.10.0 sign --channel=unlisted \
    --source-dir "$WORK/extension-firefox" --artifacts-dir "$OUT"
echo "signed: $(ls -t "$OUT"/*.xpi | head -n 1) (version $version)"
