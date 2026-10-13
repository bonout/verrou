#!/usr/bin/env bash
# Construit le cœur Rust pour macOS et génère la liaison Swift.
#
#   scripts/build-apple.sh            # release, arm64 + x86_64 (binaire universel)
#   PROFILE=debug scripts/build-apple.sh
#
# Produit :
#   apple/Frameworks/VerrouFFI.xcframework   bibliothèque statique + en-têtes C
#   apple/Shared/Generated/verrou_ffi.swift  liaison Swift générée par UniFFI
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROFILE="${PROFILE:-release}"
# Même cible que l'app (apple/project.yml) : sans elle, le code assembleur
# des dépendances est compilé pour la version de macOS de la machine.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
read -r -a TARGETS <<< "${TARGETS:-aarch64-apple-darwin x86_64-apple-darwin}"
FLAG=$([[ "$PROFILE" == release ]] && echo "--release" || echo "")
OUT="$ROOT/apple/Frameworks"
GEN="$ROOT/apple/Shared/Generated"
TMP="$ROOT/target/apple"

for target in "${TARGETS[@]}"; do
  rustup target add "$target" >/dev/null 2>&1 || true
  cargo build -p verrou-ffi --lib $FLAG --target "$target"
done

rm -rf "$TMP" && mkdir -p "$TMP/include" "$GEN" "$OUT"
LIBS=()
for target in "${TARGETS[@]}"; do LIBS+=("target/$target/$PROFILE/libverrou_ffi.a"); done
lipo -create "${LIBS[@]}" -output "$TMP/libverrou_ffi.a"

# La liaison se génère depuis la bibliothèque dynamique de l'hôte, qui porte
# les métadonnées UniFFI.
cargo run -q -p verrou-ffi --bin uniffi-bindgen -- generate \
  --library "target/aarch64-apple-darwin/$PROFILE/libverrou_ffi.dylib" \
  --language swift --out-dir "$TMP/swift"
cp "$TMP/swift/verrou_ffi.swift" "$GEN/verrou_ffi.swift"
cp "$TMP/swift/verrou_ffiFFI.h" "$TMP/include/"
cp "$TMP/swift/verrou_ffiFFI.modulemap" "$TMP/include/module.modulemap"

rm -rf "$OUT/VerrouFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$TMP/libverrou_ffi.a" -headers "$TMP/include" \
  -output "$OUT/VerrouFFI.xcframework" >/dev/null
echo "OK : $OUT/VerrouFFI.xcframework, $GEN/verrou_ffi.swift"
