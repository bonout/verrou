#!/usr/bin/env bash
# End-to-end walk through the Mac app (Debug build) against a throwaway
# Vaultwarden: sign-in, TOTP second factor, vault, lock, sign-out.
#
#   scripts/e2e.sh [path/to/Verrou.app]
#
# Variables: VERROU_E2E_SERVER, VERROU_E2E_EMAIL, VERROU_E2E_PASSWORD,
# VERROU_E2E_TOTP (second factor seed). The account must exist and contain
# the integration tests' fixture (see
# crates/verrou-vaultwarden/tests/server.rs). The app's real account is
# never touched: the walk works in a temporary folder.
#
# Each visited screen also goes through the layout audit (LayoutAudit):
# "E2E_OK layout: …" or "E2E_FAIL broken layout: …".
#
# Each visited screen also goes through the layout audit (LayoutAudit):
# "E2E_OK layout: …" or "E2E_FAIL broken layout: …".
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/target/xcode.noindex/Build/Products/Debug/Verrou.app}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
# The bridge to Brave is tried on a separate port; the Native Messaging
# declarations it writes point to this build: we remove them afterwards.
VERROU_BRIDGE_PORT="${VERROU_BRIDGE_PORT:-41799}" "$APP/Contents/MacOS/Verrou" > "$LOG" 2>/dev/null || true
for dir in "BraveSoftware/Brave-Browser" "Google/Chrome"; do
  manifest="$HOME/Library/Application Support/$dir/NativeMessagingHosts/app.verrou.bridge.json"
  if grep -qs "$APP" "$manifest"; then rm -f "$manifest"; fi
done
grep '^E2E_' "$LOG"
grep -q '^E2E_DONE' "$LOG"
OUT="$(sed -n 's/^E2E_OUT //p' "$LOG" | tail -1)"
mkdir -p "$ROOT/target/e2e" && cp "$OUT"/*.png "$ROOT/target/e2e/" 2>/dev/null || true
echo "screenshots: $ROOT/target/e2e"
