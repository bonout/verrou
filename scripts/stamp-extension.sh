#!/usr/bin/env bash
# Donne à l'extension copiée dans Verrou.app une version propre à son contenu.
#
#   scripts/stamp-extension.sh <dossier de l'extension copiée>
#
# Brave garde en mémoire le code d'une extension chargée « non empaquetée »
# jusqu'à ce qu'on la recharge. L'extension compare donc sa version à celle du
# manifest.json sur le disque (et à celle qu'annonce Verrou) et se recharge
# d'elle-même quand elles diffèrent (voir extension/update.js).
#
# La version devient `a.b.c.n` : `a.b.c`, celle de extension/manifest.json
# (versionnée, valable telle quelle pour le développement), et `n`, tiré d'une
# empreinte SHA-256 des fichiers de l'extension (0 à 65535). Tout changement
# d'un fichier livré donne une nouvelle version ; une app reconstruite sans
# toucher à l'extension garde la même, et l'extension ne se recharge pas pour
# rien. Seule l'égalité compte : l'ordre des versions n'a pas d'importance.
#
# Appelé par la phase « Version de l'extension » d'apple/project.yml, sur la
# copie du paquet ; jamais sur extension/ du dépôt.
set -euo pipefail

DIR="${1:?usage : stamp-extension.sh DOSSIER}"
MANIFEST="$DIR/manifest.json"
[[ -f "$MANIFEST" ]] || { echo "stamp-extension : $MANIFEST introuvable" >&2; exit 1; }

# La ligne `"version": "…"` (une seule, à la racine du manifeste).
LINE='^([[:space:]]*"version"[[:space:]]*:[[:space:]]*")([0-9.]+)(".*)$'
current="$(sed -nE "s/$LINE/\\2/p" "$MANIFEST")"
[[ "$(printf '%s\n' "$current" | grep -c .)" == 1 ]] \
  || { echo "stamp-extension : version introuvable dans $MANIFEST" >&2; exit 1; }
# Les trois premiers nombres : relancer le script ne change rien.
base="$(printf '%s' "$current" | cut -d. -f1-3)"
[[ "$base" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || { echo "stamp-extension : version « $current » inattendue (a.b.c attendu)" >&2; exit 1; }

# Empreinte : chemin et contenu de chaque fichier livré, dans un ordre fixe ;
# le manifeste sans sa version (celle qu'on écrit).
digest="$(
  cd "$DIR"
  {
    sed -E "s/$LINE/\\1\\3/" manifest.json
    find . -type f ! -name manifest.json ! -name .DS_Store ! -path './test/*' ! -path './e2e/*' \
      | LC_ALL=C sort \
      | while IFS= read -r file; do
          printf '%s\n' "$file"
          shasum -a 256 < "$file"
        done
  } | shasum -a 256 | cut -c1-4
)"
version="$base.$((16#$digest))"

if [[ "$version" != "$current" ]]; then
  tmp="$(mktemp "$MANIFEST.XXXXXX")"
  sed -E "s/$LINE/\\1$version\\3/" "$MANIFEST" > "$tmp"
  mv "$tmp" "$MANIFEST"
  chmod 644 "$MANIFEST"
fi
echo "extension : version $version"
