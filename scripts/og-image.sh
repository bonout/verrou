#!/usr/bin/env bash
# The website's share image (site/img/og-<lang>.png, 1200×630): the icon,
# a headline, three strengths and the Mac app's screenshot
# (docs/media/<lang>/02-vault.png, from scripts/demo-capture.sh), rendered
# by headless Chrome.
#
#   CHROME=/path/to/chrome-headless-shell scripts/og-image.sh de es it
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHROME="${CHROME:?CHROME: path to Chrome or chrome-headless-shell}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Headline, its highlighted end, the strengths.
texts() {
  case "$1" in
    de) echo "Dein Vaultwarden-Tresor, nativ auf Mac|und iPhone.|Sofortige Suche · Freigabe per iPhone · Secrets fern von KI-Agenten" ;;
    es) echo "Tu bóveda Vaultwarden, nativa en Mac|y iPhone.|Búsqueda instantánea · aprobación desde el iPhone · secretos lejos de los agentes de IA" ;;
    it) echo "La tua cassaforte Vaultwarden, nativa su Mac|e iPhone.|Ricerca istantanea · approvazione da iPhone · segreti lontani dagli agenti IA" ;;
    fr) echo "Votre coffre Vaultwarden, natif|sur Mac et iPhone.|Recherche instantanée · validation sur iPhone · secrets loin des agents IA" ;;
    en) echo "Your Vaultwarden vault, native on Mac|and iPhone.|Instant search · iPhone approvals · secrets kept from AI agents" ;;
    *) echo "og-image: unknown language $1" >&2; exit 1 ;;
  esac
}

for lang in "$@"; do
  IFS='|' read -r headline accent strengths <<<"$(texts "$lang")"
  shot="$ROOT/docs/media/$lang/02-vault.png"
  [[ "$lang" == en ]] && shot="$ROOT/docs/media/02-vault.png"
  [[ -f "$shot" ]] || { echo "og-image: $shot missing (scripts/demo-capture.sh)" >&2; exit 1; }
  cat > "$WORK/card.html" <<HTML
<!doctype html><meta charset="utf-8">
<style>
  html, body { margin: 0; width: 1200px; height: 630px; overflow: hidden; }
  body {
    background: radial-gradient(60% 75% at 15% 0%, rgba(108, 116, 255, 0.42), transparent 70%), #07070b;
    font-family: -apple-system, "SF Pro Display", sans-serif; color: #fff;
  }
  .brand { position: absolute; left: 70px; top: 76px; display: flex; align-items: center; gap: 22px;
           font-size: 34px; font-weight: 700; }
  .brand img { width: 52px; height: 52px; border-radius: 12px; }
  h1 { position: absolute; left: 64px; top: 180px; width: 500px; margin: 0;
       font-size: 54px; line-height: 1.07; letter-spacing: -1.6px; font-weight: 800; }
  h1 span { color: #c9c7ff; }
  p { position: absolute; left: 64px; top: 372px; width: 500px; margin: 0;
      font-size: 24px; line-height: 1.4; color: #a3a3b6; }
  .shot { position: absolute; left: 622px; top: 90px; width: 760px; border-radius: 14px;
          box-shadow: 0 0 0 1.5px rgba(255, 255, 255, 0.14), 0 30px 80px rgba(0, 0, 0, 0.6); }
</style>
<div class="brand"><img src="file://$ROOT/docs/media/icon.png" alt="">Verrou</div>
<h1>$headline <span>$accent</span></h1>
<p>$strengths</p>
<img class="shot" src="file://$shot" alt="">
HTML
  "$CHROME" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size=1200,630 --allow-file-access-from-files \
    --screenshot="$ROOT/site/img/og-$lang.png" "file://$WORK/card.html" >/dev/null 2>&1
  echo "site/img/og-$lang.png"
done
