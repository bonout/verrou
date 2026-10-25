#!/usr/bin/env bash
# Gives the extension copied into Verrou.app a version specific to its content.
#
#   scripts/stamp-extension.sh <folder of the copied extension> [<other folder>…]
#
# Brave keeps in memory the code of an extension loaded "unpacked" until it
# is reloaded. So the extension compares its version with the one of
# manifest.json on disk (and with the one Verrou announces) and reloads by
# itself when they differ (see extension/update.js).
#
# The version becomes `a.b.c.n`: `a.b.c`, the one of extension/manifest.json
# (under version control, valid as is for development), and `n`, drawn from
# a SHA-256 digest of the extension's files (0 to 65535). Any change of a
# shipped file gives a new version; an app rebuilt without touching the
# extension keeps the same one, and the extension doesn't reload for
# nothing. Only equality matters: the order of versions is irrelevant.
#
# Several folders (Brave's extension, then Firefox's, produced by
# firefox-extension.sh) get the same version, drawn from the digest of all
# of them: the bridge announces only one version (the one of the "extension"
# folder), valid for both browsers.
#
# Called by the "Extension version" phase of apple/project.yml, on the
# bundle's copy; never on extension/ of the repository.
set -euo pipefail

(( $# >= 1 )) || { echo "usage: stamp-extension.sh FOLDER [FOLDER…]" >&2; exit 1; }

# The `"version": "…"` line (a single one, at the root of the manifest).
LINE='^([[:space:]]*"version"[[:space:]]*:[[:space:]]*")([0-9.]+)(".*)$'

# The a.b.c version of each folder's manifest: the same everywhere.
base=""
for DIR in "$@"; do
  MANIFEST="$DIR/manifest.json"
  [[ -f "$MANIFEST" ]] || { echo "stamp-extension: $MANIFEST not found" >&2; exit 1; }
  current="$(sed -nE "s/$LINE/\\2/p" "$MANIFEST")"
  [[ "$(printf '%s\n' "$current" | grep -c .)" == 1 ]] \
    || { echo "stamp-extension: version not found in $MANIFEST" >&2; exit 1; }
  # The first three numbers: running the script again changes nothing.
  this="$(printf '%s' "$current" | cut -d. -f1-3)"
  [[ "$this" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || { echo "stamp-extension: unexpected version \"$current\" (a.b.c expected)" >&2; exit 1; }
  [[ -z "$base" || "$this" == "$base" ]] \
    || { echo "stamp-extension: different versions ($base, $this)" >&2; exit 1; }
  base="$this"
done

# Digest: for each folder, in the given order, the manifest without its
# version (the one being written), then path and content of each shipped
# file, in a fixed order.
digest="$(
  for DIR in "$@"; do
    (
      cd "$DIR"
      sed -E "s/$LINE/\\1\\3/" manifest.json
      find . -type f ! -name manifest.json ! -name .DS_Store ! -path './test/*' ! -path './e2e/*' ! -path './safari/*' \
        | LC_ALL=C sort \
        | while IFS= read -r file; do
            printf '%s\n' "$file"
            shasum -a 256 < "$file"
          done
    )
  done | shasum -a 256 | cut -c1-4
)"
version="$base.$((16#$digest))"

for DIR in "$@"; do
  MANIFEST="$DIR/manifest.json"
  current="$(sed -nE "s/$LINE/\\2/p" "$MANIFEST")"
  if [[ "$version" != "$current" ]]; then
    tmp="$(mktemp "$MANIFEST.XXXXXX")"
    sed -E "s/$LINE/\\1$version\\3/" "$MANIFEST" > "$tmp"
    mv "$tmp" "$MANIFEST"
    chmod 644 "$MANIFEST"
  fi
done
echo "extension: version $version"
