#!/usr/bin/env bash
# Prints the release notes of a version: its section of CHANGELOG.md, then a
# link to the full list of changes. Fails if the version has no section.
#
#   scripts/release-notes.sh 0.3.1
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:?usage: release-notes.sh <version>}"
REPOSITORY="${GITHUB_REPOSITORY:-bonout/verrou}"

notes="$(awk -v heading="## $VERSION" '
  $0 == heading { inside = 1; next }
  inside && /^## / { exit }
  inside { print }
' "$ROOT/CHANGELOG.md" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"
[[ -n "$notes" ]] || { echo "CHANGELOG.md has no section \"## $VERSION\"" >&2; exit 1; }

# The release just before this one.
previous="$( { git -C "$ROOT" tag --list 'v*'; echo "v$VERSION"; } | sort -uV | grep -B1 -x "v$VERSION" | grep -vx "v$VERSION" || true)"
printf '%s\n' "$notes"
if [[ -n "$previous" ]]; then
  printf '\n**All changes**: https://github.com/%s/compare/%s...v%s\n' "$REPOSITORY" "$previous" "$VERSION"
fi
