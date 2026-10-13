#!/usr/bin/env bash
# Parcours de bout en bout de l'app Mac (build Debug) contre un Vaultwarden
# jetable : connexion, second facteur TOTP, coffre, verrouillage, déconnexion.
#
#   scripts/e2e.sh [chemin/vers/Verrou.app]
#
# Variables : VERROU_E2E_SERVER, VERROU_E2E_EMAIL, VERROU_E2E_PASSWORD,
# VERROU_E2E_TOTP (graine du second facteur). Le compte doit exister et
# contenir le jeu d'essai des tests d'intégration (voir
# crates/verrou-vaultwarden/tests/server.rs). Le vrai compte de l'app n'est
# jamais touché : le parcours travaille dans un dossier temporaire.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/target/xcode.noindex/Build/Products/Debug/Verrou.app}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
# Le pont vers Brave s'essaie sur un port à part ; les déclarations Native
# Messaging qu'il écrit désignent ce build : on les retire ensuite.
VERROU_BRIDGE_PORT="${VERROU_BRIDGE_PORT:-41799}" "$APP/Contents/MacOS/Verrou" > "$LOG" 2>/dev/null || true
for dir in "BraveSoftware/Brave-Browser" "Google/Chrome"; do
  manifest="$HOME/Library/Application Support/$dir/NativeMessagingHosts/app.verrou.bridge.json"
  if grep -qs "$APP" "$manifest"; then rm -f "$manifest"; fi
done
grep '^E2E_' "$LOG"
grep -q '^E2E_DONE' "$LOG"
OUT="$(sed -n 's/^E2E_OUT //p' "$LOG" | tail -1)"
mkdir -p "$ROOT/target/e2e" && cp "$OUT"/*.png "$ROOT/target/e2e/" 2>/dev/null || true
echo "captures : $ROOT/target/e2e"
