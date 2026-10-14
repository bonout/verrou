#!/usr/bin/env bash
# Produit l'extension pour Firefox à partir de celle de Brave.
#
#   scripts/firefox-extension.sh [SOURCE [DESTINATION]]
#
# SOURCE : le dossier de l'extension (par défaut extension/ du dépôt).
# DESTINATION : le dossier à produire (par défaut target/extension-firefox),
# remplacé entièrement.
#
# Un seul code : les fichiers sont copiés tels quels (les scripts choisissent
# `browser` ou `chrome` d'eux-mêmes, voir extension/browser.js) ; seul le
# manifeste change :
#   - `background.scripts` (page d'arrière-plan) au lieu de `service_worker` ;
#   - `browser_specific_settings.gecko` : identifiant fixe (celui que Verrou
#     autorise dans la déclaration Native Messaging de Firefox, voir
#     BrowserBridge.swift) et Firefox 128 au moins (`world: "MAIN"` des
#     scripts de contenu, nécessaire aux passkeys) ;
#   - `host_permissions` : les sites des scripts de contenu, que
#     l'utilisateur peut accorder ou retirer (bouton de la fenêtre de
#     l'extension) ;
#   - sans `key` ni `minimum_chrome_version`, propres à Chrome.
#
# Appelé par la phase « Version de l'extension » d'apple/project.yml sur la
# copie du paquet, avant stamp-extension.sh ; à la main pour charger
# l'extension depuis le dépôt.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$ROOT/extension}"
DEST="${2:-$ROOT/target/extension-firefox}"
[[ -f "$SRC/manifest.json" ]] || { echo "firefox-extension : $SRC/manifest.json introuvable" >&2; exit 1; }

FIREFOX_ID="verrou@verrou.app"
FIREFOX_MIN="128.0"

rm -rf "$DEST"
mkdir -p "$DEST"
# Les fichiers livrés, sans les tests (comme stamp-extension.sh).
(
  cd "$SRC"
  find . -type f ! -name manifest.json ! -name .DS_Store ! -path './test/*' ! -path './e2e/*' -print0 \
    | while IFS= read -r -d '' file; do
        mkdir -p "$DEST/$(dirname "$file")"
        cp "$file" "$DEST/$file"
      done
)

/usr/bin/env python3 -I - "$SRC/manifest.json" "$DEST/manifest.json" "$FIREFOX_ID" "$FIREFOX_MIN" <<'PY'
import json
import sys

source, target, gecko_id, minimum = sys.argv[1:5]
with open(source, encoding="utf-8") as f:
    manifest = json.load(f)

for key in ("key", "minimum_chrome_version"):
    manifest.pop(key, None)

background = manifest.get("background", {})
worker = background.get("service_worker")
if not worker:
    sys.exit("firefox-extension : background.service_worker attendu dans le manifeste")
manifest["background"] = {"scripts": [worker], **({"type": background["type"]} if "type" in background else {})}

hosts = []
for script in manifest.get("content_scripts", []):
    for pattern in script.get("matches", []):
        if pattern not in hosts:
            hosts.append(pattern)

result = {}
for key, value in manifest.items():
    result[key] = value
    if key == "permissions":
        result["host_permissions"] = hosts
if "host_permissions" not in result:
    result["host_permissions"] = hosts
result["browser_specific_settings"] = {
    "gecko": {
        "id": gecko_id,
        "strict_min_version": minimum,
        # Rien ne quitte le Mac : l'extension ne parle qu'à l'app Verrou
        # (exigé par addons.mozilla.org pour la signature).
        "data_collection_permissions": {"required": ["none"]},
    }
}

with open(target, "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
chmod 644 "$DEST/manifest.json"
echo "extension Firefox : $DEST"
