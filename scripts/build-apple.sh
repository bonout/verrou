#!/usr/bin/env bash
# Construit le cœur Rust pour les apps Apple et génère la liaison Swift.
#
#   scripts/build-apple.sh                    # macOS seulement, release, arm64 + x86_64
#   PROFILE=debug scripts/build-apple.sh
#   PLATFORMS=ios scripts/build-apple.sh      # iPhone (appareil + simulateur) seulement
#   PLATFORMS=all scripts/build-apple.sh      # macOS + iPhone, dans le même xcframework
#
# Variables :
#   PLATFORMS    macos (défaut, ce qu'attend install-macos.sh), ios ou all
#   TARGETS      cibles macOS (défaut : aarch64-apple-darwin x86_64-apple-darwin)
#   IOS_TARGETS  cibles iPhone (défaut : aarch64-apple-ios ; vide : pas de
#                tranche appareil, pour un build du simulateur plus rapide)
#   SIM_TARGETS  cibles du simulateur (défaut : aarch64-apple-ios-sim ; ajouter
#                x86_64-apple-ios pour un simulateur sur Mac Intel)
#
# Produit :
#   apple/Frameworks/VerrouFFI.xcframework   bibliothèque statique + en-têtes C,
#                                            une tranche par plateforme construite
#   apple/Shared/Generated/verrou_ffi.swift  liaison Swift générée par UniFFI
#   apple/Helpers/verrou-native-host         hôte Native Messaging (macOS seulement)
#
# Une construction `ios` seule remplace le xcframework sans tranche macOS :
# l'app Mac ne compile plus tant qu'on n'a pas relancé `macos` ou `all`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROFILE="${PROFILE:-release}"
PLATFORMS="${PLATFORMS:-macos}"
case "$PLATFORMS" in
  macos) BUILD_MAC=1; BUILD_IOS=0 ;;
  ios) BUILD_MAC=0; BUILD_IOS=1 ;;
  all) BUILD_MAC=1; BUILD_IOS=1 ;;
  *) echo "PLATFORMS inconnu : $PLATFORMS (macos, ios ou all)" >&2; exit 2 ;;
esac
# Mêmes cibles que les apps (apple/project.yml) : sans elles, le code
# assembleur des dépendances est compilé pour la version du système de la
# machine.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
read -r -a MAC_TARGETS <<< "${TARGETS:-aarch64-apple-darwin x86_64-apple-darwin}"
read -r -a IOS_DEVICE_TARGETS <<< "${IOS_TARGETS-aarch64-apple-ios}"
read -r -a IOS_SIM_TARGETS <<< "${SIM_TARGETS:-aarch64-apple-ios-sim}"
FLAG=$([[ "$PROFILE" == release ]] && echo "--release" || echo "")
OUT="$ROOT/apple/Frameworks"
GEN="$ROOT/apple/Shared/Generated"
TMP="$ROOT/target/apple"

build_lib() {
  rustup target add "$1" >/dev/null 2>&1 || true
  cargo build -p verrou-ffi --lib $FLAG --target "$1"
}

# Assemble les bibliothèques de plusieurs architectures d'une même
# plateforme (macOS, simulateur) en une seule.
fat_lib() {
  local dest="$1"; shift
  local libs=()
  for target in "$@"; do libs+=("target/$target/$PROFILE/libverrou_ffi.a"); done
  mkdir -p "$(dirname "$dest")"
  lipo -create "${libs[@]}" -output "$dest"
}

rm -rf "$TMP" && mkdir -p "$TMP/include" "$GEN" "$OUT"
XC_ARGS=()
BINDGEN_LIB=""

if [[ $BUILD_MAC == 1 ]]; then
  for target in "${MAC_TARGETS[@]}"; do
    build_lib "$target"
    cargo build -p verrou-bridge --bin verrou-native-host $FLAG --target "$target"
  done
  fat_lib "$TMP/macos/libverrou_ffi.a" "${MAC_TARGETS[@]}"
  XC_ARGS+=(-library "$TMP/macos/libverrou_ffi.a" -headers "$TMP/include")
  HOSTS=()
  for target in "${MAC_TARGETS[@]}"; do HOSTS+=("target/$target/$PROFILE/verrou-native-host"); done
  mkdir -p "$ROOT/apple/Helpers"
  lipo -create "${HOSTS[@]}" -output "$ROOT/apple/Helpers/verrou-native-host"
  BINDGEN_LIB="target/${MAC_TARGETS[0]}/$PROFILE/libverrou_ffi.dylib"
fi

if [[ $BUILD_IOS == 1 ]]; then
  for target in ${IOS_DEVICE_TARGETS[@]+"${IOS_DEVICE_TARGETS[@]}"} "${IOS_SIM_TARGETS[@]}"; do
    build_lib "$target"
  done
  if [[ ${#IOS_DEVICE_TARGETS[@]} -gt 0 ]]; then
    fat_lib "$TMP/ios/libverrou_ffi.a" "${IOS_DEVICE_TARGETS[@]}"
    XC_ARGS+=(-library "$TMP/ios/libverrou_ffi.a" -headers "$TMP/include")
  fi
  fat_lib "$TMP/ios-simulator/libverrou_ffi.a" "${IOS_SIM_TARGETS[@]}"
  XC_ARGS+=(-library "$TMP/ios-simulator/libverrou_ffi.a" -headers "$TMP/include")
  BINDGEN_LIB="${BINDGEN_LIB:-target/${IOS_SIM_TARGETS[0]}/$PROFILE/libverrou_ffi.dylib}"
fi

# La liaison se génère depuis une bibliothèque dynamique déjà construite,
# qui porte les métadonnées UniFFI (identiques sur toutes les plateformes).
cargo run -q -p verrou-ffi --bin uniffi-bindgen -- generate \
  --library "$BINDGEN_LIB" --language swift --out-dir "$TMP/swift"
cp "$TMP/swift/verrou_ffi.swift" "$GEN/verrou_ffi.swift"
cp "$TMP/swift/verrou_ffiFFI.h" "$TMP/include/"
cp "$TMP/swift/verrou_ffiFFI.modulemap" "$TMP/include/module.modulemap"

rm -rf "$OUT/VerrouFFI.xcframework"
xcodebuild -create-xcframework "${XC_ARGS[@]}" \
  -output "$OUT/VerrouFFI.xcframework" >/dev/null
echo "OK ($PLATFORMS) : $OUT/VerrouFFI.xcframework, $GEN/verrou_ffi.swift"
