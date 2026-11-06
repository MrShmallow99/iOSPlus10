#!/bin/bash
# Host/CI only. Never flashes or contacts a phone. Run local builds in tmux.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$REPO/out/preservation-ci
mkdir -p "$WORK/bin" "$WORK/kdk-empty"
git init -q "$WORK/dxb"
git -C "$WORK/dxb" fetch -q --depth 1 https://github.com/blacktop/darwin-xnu-build 663906528d1cd5ea8fde7de6f16de73db9511549
git -C "$WORK/dxb" checkout -q FETCH_HEAD
cp "$REPO"/external/slop/negroni-ios/xnu/patches/*.patch "$REPO"/external/slop/negroni-ios/xnu/patches/*.sh "$WORK/dxb/patches/"
rm -f "$WORK/dxb/patches/0127-negroni-gpu-show.patch"
cp "$REPO"/patches/xnu/*.patch "$WORK/dxb/patches/"
sed -i '' 's/ARCHS="x86_64 arm64e" VALID_ARCHS="x86_64 arm64e"/ARCHS="x86_64 arm64e arm64" VALID_ARCHS="x86_64 arm64e arm64"/' "$WORK/dxb/build.sh"
# Existing recipe's xcodes stub: the runner already has the selected Xcode.
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/xcodes"
chmod +x "$WORK/bin/xcodes"
export PATH="$WORK/bin:$PATH"
export MACOS_VERSION=13.5 KERNEL_CONFIG=DEVELOPMENT MACHINE_CONFIG=NEGRONI KDKROOT="$WORK/kdk-empty"
cd "$WORK/dxb"
bash build.sh 2>&1 | tee "$WORK/build.log"
# A successful linker is insufficient: fail closed if the protection was skipped.
python3 "$REPO/scripts/kernel/verify-preservation-source.py" "$WORK/dxb/xnu" "$WORK/verification.json"
mkdir -p "$WORK/artifact"
test -f fakeroot/System/Library/Kernels/kernel.development.negroni
cp fakeroot/System/Library/Kernels/kernel.development.negroni "$WORK/artifact/"
cp "$WORK/verification.json" "$WORK/artifact/"
printf 'EXPERIMENTAL KERNEL ONLY. UEFI/storage isolation is not yet verified. DO NOT BOOT OR FLASH.\n' > "$WORK/artifact/DO-NOT-BOOT.txt"
cd "$WORK/artifact"
shasum -a 256 kernel.development.negroni > SHA256SUMS
