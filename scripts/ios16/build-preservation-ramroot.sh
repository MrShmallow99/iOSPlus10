#!/bin/bash
# macOS CI only: produce a small HFS+ RAM root and an intermediate NEGRONIX payload.
# No mkbootimg, adb, fastboot, device mounts, or phone writes.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$REPO/out/preservation-ramroot
KERNEL=${1:?usage: build-preservation-ramroot.sh VERIFIED_KERNEL_ARTIFACT_DIRECTORY}
python3 "$REPO/scripts/kernel/verify-preservation-artifact.py" "$KERNEL"
mkdir -p "$OUT/root/sbin" "$OUT/root/dev" "$OUT/artifact"
xcrun --sdk iphoneos clang -arch arm64 -target arm64-apple-ios16.0 -nostdlib \
  -Wl,-static -Wl,-no_pie -Wl,-e,_start \
  "$REPO/userland/preservation-init/start.S" -o "$OUT/root/sbin/launchd"
codesign --force --sign - --timestamp=none "$OUT/root/sbin/launchd"
codesign --verify --strict "$OUT/root/sbin/launchd"
hdiutil create -size 32m -fs HFS+ -volname PRESERVE_RAM_ROOT -layout NONE \
  -format UDRW -srcfolder "$OUT/root" "$OUT/root.dmg"
hdiutil convert "$OUT/root.dmg" -format UDTO -o "$OUT/root.raw"
mv "$OUT/root.raw.cdr" "$OUT/artifact/root.hfs"
# macOS fsck_hfs needs a block device. Attach this host-created image read-only,
# without mounting its filesystem, and always detach it on a failed check.
hdiutil attach -nomount -readonly -plist "$OUT/root.dmg" > "$OUT/attachment.plist"
RAMROOT_DEVICE=$(python3 -c 'import plistlib,sys; p=plistlib.load(open(sys.argv[1],"rb")); print(p["system-entities"][0]["dev-entry"])' "$OUT/attachment.plist")
[[ "$RAMROOT_DEVICE" =~ ^/dev/disk[0-9]+$ ]] || { echo "unexpected RAM-root image device" >&2; exit 1; }
trap 'hdiutil detach "$RAMROOT_DEVICE" >/dev/null || true' EXIT
sudo /sbin/fsck_hfs -n -f "$RAMROOT_DEVICE"
hdiutil detach "$RAMROOT_DEVICE"
trap - EXIT
cp "$OUT/root/sbin/launchd" "$OUT/artifact/launchd"
python3 "$REPO/scripts/ios16/pack-preservation-ramroot.py" "$KERNEL/kernel.development.negroni" "$OUT/artifact"
printf 'INTERMEDIATE RAM-ROOT PAYLOAD ONLY. No device boot is approved. No iOS UI/apps included.\n' > "$OUT/artifact/DO-NOT-BOOT.txt"
cd "$OUT/artifact"
shasum -a 256 root.hfs launchd negroni.adt kernel-ramroot.negronix > SHA256SUMS
