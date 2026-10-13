#!/usr/bin/env bash
# Rejoue la démonstration scriptée de l'app Mac et range ses captures et sa
# vidéo dans docs/media/.
#
#   scripts/demo-capture.sh [chemin/vers/Verrou.app]
#
# L'app capture ses propres fenêtres par ScreenCaptureKit (voir
# WindowRecorder.swift), et seulement elles : le terminal qui lance ce script
# doit avoir l'autorisation « Enregistrement de l'écran ».
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/target/xcode/Build/Products/Debug/Verrou.app}"
MEDIA="$ROOT/docs/media"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
mkdir -p "$MEDIA"

VERROU_DEMO=1 "$APP/Contents/MacOS/Verrou" > "$LOG" 2>/dev/null || true

OUT="$(sed -n 's/^DEMO_OUT //p' "$LOG" | tail -1)"
grep -q '^DEMO_DONE' "$LOG" || { echo "la démonstration ne s'est pas terminée :" >&2; cat "$LOG" >&2; exit 1; }
cp "$OUT"/*.png "$MEDIA/"
if [[ -s "$OUT/demo.mov" ]]; then
  ffmpeg -y -loglevel error -i "$OUT/demo.mov" -c:v libx264 -preset slow -crf 22 -pix_fmt yuv420p -movflags +faststart -an "$MEDIA/demo.mp4"
  ffmpeg -y -loglevel error -i "$MEDIA/demo.mp4" -vf "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=192[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" "$MEDIA/demo.gif"
fi
ls -1 "$MEDIA"
