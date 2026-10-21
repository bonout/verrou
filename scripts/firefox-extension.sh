#!/usr/bin/env bash
# Produces the extension for Firefox from Brave's.
#
#   scripts/firefox-extension.sh [SOURCE [DESTINATION]]
#
# SOURCE: the extension's folder (by default extension/ of the repository).
# DESTINATION: the folder to produce (by default target/extension-firefox),
# entirely replaced.
#
# A single code base: the files are copied as is (the scripts pick `browser`
# or `chrome` by themselves, see extension/browser.js); only the manifest
# changes:
#   - `background.scripts` (background page) instead of `service_worker`;
#   - `browser_specific_settings.gecko`: fixed ID (the one Verrou allows in
#     Firefox's Native Messaging declaration, see BrowserBridge.swift) and
#     Firefox 128 at least (`world: "MAIN"` of the content scripts, needed
#     for passkeys);
#   - `host_permissions`: the sites of the content scripts, which the user
#     can grant or withdraw (button in the extension's popup);
#   - without `key` or `minimum_chrome_version`, specific to Chrome.
#
# Called by the "Extension version" phase of apple/project.yml on the
# bundle's copy, before stamp-extension.sh; by hand to load the extension
# from the repository.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$ROOT/extension}"
DEST="${2:-$ROOT/target/extension-firefox}"
[[ -f "$SRC/manifest.json" ]] || { echo "firefox-extension: $SRC/manifest.json not found" >&2; exit 1; }

FIREFOX_ID="verrou@verrou.app"
FIREFOX_MIN="128.0"

rm -rf "$DEST"
mkdir -p "$DEST"
# The shipped files, without the tests (like stamp-extension.sh).
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
    sys.exit("firefox-extension: background.service_worker expected in the manifest")
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
        # Nothing leaves the Mac: the extension only talks to the Verrou app
        # (required by addons.mozilla.org for signing).
        "data_collection_permissions": {"required": ["none"]},
    }
}

with open(target, "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)
    f.write("\n")
PY
chmod 644 "$DEST/manifest.json"
echo "Firefox extension: $DEST"
