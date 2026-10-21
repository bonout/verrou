#!/usr/bin/env bash
# Offscreen visual review of the Mac app (Debug build): each screen rendered
# on the fake vault, in light and dark mode, without a window on screen or
# ScreenCaptureKit. The PNGs land in target/review/.
#
#   scripts/review-capture.sh [path/to/Verrou.app]
#
# The layout audit of each screen (REVIEW_OK / REVIEW_FAIL) is shown; the
# script fails if one of them fails, after copying the images.
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
  echo "the review did not finish:" >&2
  cat "$LOG" >&2
  exit 1
fi
rm -rf "$DEST" && mkdir -p "$DEST"
cp "$OUT"/*.png "$DEST/"
echo "$(ls "$DEST" | wc -l | tr -d ' ') images : $DEST"
exit "$status"
