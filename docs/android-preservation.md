# Preserve this owner's Android installation

Owner requirement, 2026-11-06: keep the existing Android boot and data. The owner reports an
unlocked, rooted OnePlus 10 Pro connected by USB. The owner ran the read-only inventory;
results were read from `out/android-inventory`. Do not inherit the previous owner's backups.

Verified inventory: NE2213 / OP516FL1 / taro, `NE2213_16.0.3.530(EX01)`, Android 16,
security patch 2026-06-01, unlocked (`ro.boot.flash.locked=0`), active slot `_a`, Magisk
`uid=0`, file-based encryption. `/data` is F2FS on dm-72 with inline encryption;
`userdata` maps to `/dev/block/sda14`. The report shows 224G total, 136G used, 88G available.
That is filesystem free space, not a spare partition. The inventory does not establish GPT
free extents, inactive-slot bootability, or total physical RAM.

## Verified from this checkout

- The normal installer replaces `userdata`, `boot_a`, `vendor_boot_a`, `vbmeta_a`, and `dtbo_a`.
  It changes the active slot. Restore formats userdata. Neither workflow meets this requirement.
- `scripts/flash/test-boot.sh` can flash its safe image to `boot_a` before RAM booting. It is not
  a read-only entry point for a stock Android phone.
- Config enables `ufsrw=1`; XNU's UFS root is selected by GPT name `userdata`.
- Firmware areas and persistent logs occupy raw offsets near the end of `userdata`.
  Free space reported by Android is not unallocated raw storage.
- Patch 0367 can write boot logs without `ufsrw=1`. It checks HFS+ and layout markers first;
  these checks are useful guards, but are not a substitute for isolating Android's storage.
  `negronilog=0` disables this logger. Older log paths also need review.
- Custom vendor_boot/DTBO handling is part of the documented boot chain. RAM-loading boot.img
  alone has not been shown to preserve the stock Android boot chain and boot iOS successfully.
- The three pinned kernel/loader submodules and the pinned DarwinBoot child submodule are
  initialized (both tmux download jobs exited 0). No iOS build or phone boot was performed.

## Preservation development completed on the host

`config/phone-storage-policy` is `preserve-android`. The shared host policy now blocks the
old full install, restore, root reflash, firmware-area write, test-boot, and individual
mutating flash steps before any phone tools run. Missing/invalid policy also blocks writes.
`CONFIRM=yes` and `--yes` do not override preservation. Read-only checks and dry-run steps
remain available. This is a script guard, not a system-wide fastboot interception.

Patch `0403-negroni-preserve-android.patch` gates this XNU driver's SCSI submission path,
forces its block device read-only, and disables persistent logging. See
`../patches/xnu/README-preserve-android.md` for scope and limitations. The full kernel is not
compiled. The change intentionally prevents the old writable internal-UFS iOS root setup.

Host tests passed (exit 0): all 12 mutation invocations blocked before mocked phone tools;
missing/invalid policy blocked; UFS reconstructed from 32 applicable patches; actual command
policy header compiled and executed with all data-out/unknown commands rejected. The gate
precedes descriptors and the UFS doorbell in the reconstructed source. No device was used.

The pinned DarwinBoot supports an `initrd` passed through UniXNU and a zero-initialized
`/chosen/memory-map/RAMDisk` ADT property. It rejects stale/nonzero RAMDisk addresses and
limits the input image to 256 MiB (`PackedRamdisk.h`). Dense RAM expansion must fit the
kernel allocation window. Existing slop patches include memory-disk root handling.
This gives a source-supported candidate for a small RAM-root milestone, not a full iOS UI.
The ordinary root image is far larger than the loader's input limit. Packed sparse images
omit zero ranges; that does not make arbitrary multi-gigabyte iOS content fit in 256 MiB.

The negroni UEFI build includes XHCI, USB bus, and USB mass-storage drivers. External storage
is therefore worth investigating at the UEFI stage, but XNU USB-root support is not proven.
UEFI uses runtime variables and includes binary Qualcomm drivers; its persistent writes and
the stock-compatible temporary boot path remain unaudited. Do not boot an image yet.

## Verified boot-chain backup

`out/android-backup/20261106T205035.212783Z/` contains 14 images (both slots' boot,
vendor_boot, dtbo, vbmeta, vbmeta_system, vbmeta_vendor, recovery), 1,065,746,432 bytes total.
`manifest.json` records the sizes and SHA-256 values. Every image matched device hashes
before and after its read; `COMPLETE.txt` records completion. boot and vendor_boot have
Android header version 4. This preserves the current Magisk-patched boot image as read.
No restore test has been performed. Apps, personal files, GPT, and device-specific partitions
are not backed up by this script. No phone writes, slot switches, or reboots occurred.

Two earlier incomplete directories contain 73-byte shell error messages, not images.
They have no completion marker and must not be used for restoration. The exec-out quoting
bug was reproduced with a read-only printf and fixed: `su -c` receives an unquoted command
argument for exec-out, unlike the adb shell helper. The size check rejected both bad files.

## Implementation decision pending device evidence

Start with a tethered experimental boot that leaves Android as the default. Do not change
either slot, GPT, or Android's userdata to obtain an initial boot.

There is no verified compatible root-storage backend in the checkout that meets this rule.
Investigate RAM-backed storage first for a limited kernel/loader milestone. A full iOS root
may exceed available RAM; do not promise SpringBoard from a RAM-only milestone.
External USB storage is a candidate only after proving UEFI/XNU host-controller and storage
support, Type-C role handling, power, and an alternative logging/control path. USB gadget
support does not establish USB mass-storage host support.

A disk image in encrypted Android `/data` is not directly readable by this XNU port. It needs
filesystem, encryption/key access, and block-image support. Do not map file extents and write
them after Android shuts down: filesystem relocation and encryption make that unsafe.
Shrinking userdata or repurposing another partition is not the chosen approach.

## Next checks and implementation gates

1. Obtain read-only device identity, firmware, active slot, root status, mounts, and partition
   layout with `scripts/backup/inspect-android.ps1` from a normal PowerShell session.
2. Back up this phone's boot-chain images and device-specific partitions to the host with
   hashes; separately back up user files and application data. An inventory is not a backup.
   An online raw copy of mounted encrypted userdata is not a verified restorable app backup.
   `python scripts/backup/backup-android-boot.py` makes boot-chain copies for both slots,
   verifies size and SHA-256 before/after reads, and saves a manifest under ignored `out/`.
   It reads the phone only. Device-specific partitions and user data are not included.
3. Initialize pinned sources in a working Linux/macOS build environment. Audit every UFS
   write path, including panic/reboot logging, firmware, raw device access, and UEFI writes.
4. Implement and test a preservation mode that denies internal-UFS writes at the common
   command submission layer. Disable all persistent logging. Validate the actual transport
   write commands, not just filesystem read-only flags. Reject incompatible options.
5. Prove a stock-compatible temporary loader path and isolated root backend. Test bounds,
   rejected internal writes, root selection, and fallback before testing hardware.
6. Only then RAM-boot a reviewed image. Verify Android boots afterward, compare boot-chain
   hashes, and check Android data. There is no reviewed test image at present.

## Host access

Development fork: `https://github.com/MrShmallow99/iOSPlus10`, branch `android-preservation`.
The root `Android preservation` workflow runs host tests first, then attempts an experimental
kernel build on macos-15/Xcode 16.4. Patch 0404 adds the IORPC field expected by the newer
interface generator; this is a build compatibility experiment, not a verified device ABI.
Packaging requires exact audited UFS source/header matches and marks artifacts DO-NOT-BOOT.
Phone backups and output folders are excluded from the published branch.

Sandboxed ADB fails at startup with `Cannot mkdir '\.android': Permission denied`; sandboxed
WSL enumeration fails with E_ACCESSDENIED. After the permission profile changed, reviewed
unsandboxed read-only ADB and WSL calls succeeded. The agent completed the backup directly.
Ubuntu WSL2 starts, has git and tmux, and can reach GitHub. Its initial PATH lacked clang
and cargo. Docker engine pipe was absent. The current local XNU kernel recipe requires
macOS/Xcode; Ubuntu access alone does not supply that compiler/SDK environment.

Windows checkout CRLF broke the tmux shell launcher. `.gitattributes` now requests LF for
shell scripts; the launcher and notification helper were normalized before retrying.
