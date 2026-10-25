#!/usr/bin/env bash
# Generates apple/Verrou.xcodeproj from apple/project.yml (xcodegen).
#
#   scripts/generate-project.sh
#   VERROU_WATCH=0 scripts/generate-project.sh   # without the Apple Watch app
#
# VERROU_WATCH=0 leaves the Watch app out of the iPhone app, for a Mac whose
# Xcode lacks the watchOS platform (Xcode › Settings › Components): an
# iPhone app that embeds a Watch app can't build without it. CI and releases
# keep the Watch.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/apple"
if [[ "${VERROU_WATCH:-1}" == 0 ]]; then
  SPEC=".project-without-watch.yml"
  trap 'rm -f "$SPEC"' EXIT
  grep -v '^      - target: VerrouWatch$' project.yml > "$SPEC"
  xcodegen generate --quiet --spec "$SPEC"
else
  xcodegen generate --quiet
fi
