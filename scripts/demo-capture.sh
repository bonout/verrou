#!/usr/bin/env bash
# Replays the scripted demo of the Mac app and puts its screenshots and its
# video in docs/media/.
#
#   scripts/demo-capture.sh [path/to/Verrou.app]
#   DEMO_LANG=fr MEDIA=docs/media/fr scripts/demo-capture.sh   # the French demo
#
# The app captures its own windows with ScreenCaptureKit (see
# WindowRecorder.swift), and only them: the terminal running this script
# needs the "Screen Recording" permission.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/target/xcode.noindex/Build/Products/Debug/Verrou.app}"
MEDIA="${MEDIA:-$ROOT/docs/media}"
[[ "$MEDIA" == /* ]] || MEDIA="$ROOT/$MEDIA"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
mkdir -p "$MEDIA"

LANG_ARGS=()
[[ -n "${DEMO_LANG:-}" ]] && LANG_ARGS=(-AppleLanguages "($DEMO_LANG)" -AppleLocale "$DEMO_LANG")
VERROU_DEMO=1 "$APP/Contents/MacOS/Verrou" ${LANG_ARGS[@]+"${LANG_ARGS[@]}"} > "$LOG" 2>/dev/null || true

OUT="$(sed -n 's/^DEMO_OUT //p' "$LOG" | tail -1)"
grep -q '^DEMO_DONE' "$LOG" || { echo "the demo did not finish:" >&2; cat "$LOG" >&2; exit 1; }
cp "$OUT"/*.png "$MEDIA/"
if [[ -s "$OUT/demo.mov" ]]; then
  ffmpeg -y -loglevel error -i "$OUT/demo.mov" -c:v libx264 -preset slow -crf 22 -pix_fmt yuv420p -movflags +faststart -an "$MEDIA/demo.mp4"
  ffmpeg -y -loglevel error -i "$MEDIA/demo.mp4" -vf "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=192[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" "$MEDIA/demo.gif"
fi
ls -1 "$MEDIA"
