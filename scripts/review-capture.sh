#!/usr/bin/env bash
# Revue visuelle hors écran de l'app Mac (build Debug) : chaque écran rendu
# sur le coffre fictif, en clair et en sombre, sans fenêtre à l'écran ni
# ScreenCaptureKit. Les PNG arrivent dans target/review/.
#
#   scripts/review-capture.sh [chemin/vers/Verrou.app]
#
# L'audit de mise en page de chaque écran (REVIEW_OK / REVIEW_FAIL) est
# affiché ; le script échoue si l'un d'eux échoue, après avoir copié les images.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/target/xcode.noindex/Build/Products/Debug/Verrou.app}"
DEST="$ROOT/target/review"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

status=0
VERROU_REVIEW=1 "$APP/Contents/MacOS/Verrou" > "$LOG" 2>/dev/null || status=$?
grep -E '^REVIEW_(OK|FAIL|DONE)' "$LOG" || true
OUT="$(sed -n 's/^REVIEW_OUT //p' "$LOG" | tail -1)"
if [[ -z "$OUT" ]] || ! grep -q '^REVIEW_DONE' "$LOG"; then
  echo "la revue ne s'est pas terminée :" >&2
  cat "$LOG" >&2
  exit 1
fi
rm -rf "$DEST" && mkdir -p "$DEST"
cp "$OUT"/*.png "$DEST/"
echo "$(ls "$DEST" | wc -l | tr -d ' ') images : $DEST"
exit "$status"
