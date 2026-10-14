#!/usr/bin/env bash
# Donne à l'extension copiée dans Verrou.app une version propre à son contenu.
#
#   scripts/stamp-extension.sh <dossier de l'extension copiée> [<autre dossier>…]
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
# Plusieurs dossiers (l'extension de Brave, puis celle de Firefox, produite
# par firefox-extension.sh) reçoivent la même version, tirée de l'empreinte
# de tous : le pont n'annonce qu'une version (celle du dossier « extension »),
# valable pour les deux navigateurs.
#
# Appelé par la phase « Version de l'extension » d'apple/project.yml, sur la
# copie du paquet ; jamais sur extension/ du dépôt.
set -euo pipefail

(( $# >= 1 )) || { echo "usage : stamp-extension.sh DOSSIER [DOSSIER…]" >&2; exit 1; }

# La ligne `"version": "…"` (une seule, à la racine du manifeste).
LINE='^([[:space:]]*"version"[[:space:]]*:[[:space:]]*")([0-9.]+)(".*)$'

# La version a.b.c du manifeste de chaque dossier : la même partout.
base=""
for DIR in "$@"; do
  MANIFEST="$DIR/manifest.json"
  [[ -f "$MANIFEST" ]] || { echo "stamp-extension : $MANIFEST introuvable" >&2; exit 1; }
  current="$(sed -nE "s/$LINE/\\2/p" "$MANIFEST")"
  [[ "$(printf '%s\n' "$current" | grep -c .)" == 1 ]] \
    || { echo "stamp-extension : version introuvable dans $MANIFEST" >&2; exit 1; }
  # Les trois premiers nombres : relancer le script ne change rien.
  this="$(printf '%s' "$current" | cut -d. -f1-3)"
  [[ "$this" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || { echo "stamp-extension : version « $current » inattendue (a.b.c attendu)" >&2; exit 1; }
  [[ -z "$base" || "$this" == "$base" ]] \
    || { echo "stamp-extension : versions différentes ($base, $this)" >&2; exit 1; }
  base="$this"
done

# Empreinte : pour chaque dossier, dans l'ordre donné, le manifeste sans sa
# version (celle qu'on écrit), puis chemin et contenu de chaque fichier livré,
# dans un ordre fixe.
digest="$(
  for DIR in "$@"; do
    (
      cd "$DIR"
      sed -E "s/$LINE/\\1\\3/" manifest.json
      find . -type f ! -name manifest.json ! -name .DS_Store ! -path './test/*' ! -path './e2e/*' \
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
echo "extension : version $version"
