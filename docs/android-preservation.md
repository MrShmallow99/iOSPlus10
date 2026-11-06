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

### Intermediate RAM-root artifact and direct-loader ABI

RAM-root run `42299679864` passed:
https://github.com/MrShmallow99/iOSPlus10/actions/runs/42299679864

It built a signed static ARM64 PID 1, a checked 32 MiB HFS+ filesystem, and a roughly 49 MiB
intermediate `NEGRONIX` payload containing the known preservation kernel. No phone boot
image is produced. The ADT has no UFS node; root is `md0`; disk logging and UFS writes are
disabled in the arguments as well as in the kernel. No proprietary iOS userland is included.
The generated tree warns that the donor `/product` node is absent; this minimal root does
not supply the identity/services expected by the full iOS userland.

Downloaded under `out/preservation-ramroot-run-42299679864/`; all four published artifact
hashes matched. Stronger local repacking checks passed against the same filesystem: its
catalog contains the exact generated PID 1, which has a Unix-thread entry, a signature, and
no dynamic-library/loader dependency. Payload memory bounds and no-UFS checks passed.
The stronger checks also passed on GitHub in run `42300296420`:
https://github.com/MrShmallow99/iOSPlus10/actions/runs/42300296420

The direct-loader audit found two incompatible upstream interfaces: the common shim accepts
`SWEETXNU`, while the negroni packer writes `NEGRONIX`; and the shim writes the 608-byte
boot-argument ABI while kernel patch 0363 expects 1024. The new shim patch fixes both for
BOARD_NEGRONI while retaining the old sweet layout. It keeps the payload header's 608-byte
command field separate, zero-filling the larger kernel field through the existing boot-args
allocation. Static assertions require 1152-byte boot_args and memSizeActual at 0x478.

Direct-loader run `42299680091` passed AArch64 object compilation for negroni and sweet:
https://github.com/MrShmallow99/iOSPlus10/actions/runs/42299680091

The patch is stored in the parent repo; pinned submodule sources remain unchanged. Next:
compile and audit the complete shim, validate how the stock bootloader presents the combined
ramdisk and DTB for a temporary boot, and plan a recoverable observation path. The existing
generic test-boot script remains blocked. No execution of this RAM root has been observed.

### Successful kernel build and downloaded artifact

GitHub run `42295405065` passed both host-tests and kernel jobs:
https://github.com/MrShmallow99/iOSPlus10/actions/runs/42295405065

Downloaded under `out/preservation-ci-run-42295405065/`. The ARM64 Mach-O kernel is
18,124,712 bytes, SHA-256
`46ab1bb7c625314d08a61bf28adcffc8b98445159fc8474374e6d0d0268ffe97`.
`scripts/kernel/verify-preservation-artifact.py` verified its digest, Mach-O command bounds,
compiled preservation log marker, source report, and experimental notice. The source report
matches the audited UFS implementation. These checks do not prove whole-boot safety.
Nothing was booted or flashed. The Xcode 16.4/0404 build compatibility experiment linked;
its runtime ABI remains untested.

### Candidate UEFI configuration (not compiled)

Patch `patches/mu/0003-negroni-preserve-android.patch` removes internal UFS/SD drivers,
USB mass-storage gadget, capsule runtime, Windows boot-order helper, and firmware-update /
mass-storage apps from the selected board configuration. External USB host storage remains.
It explicitly selects `PcdEmuVariableNvModeEnable=TRUE`; this setting was already true in
the shared platform configuration. The pinned basecore source uses that PCD to select
`InitEmuNonVolatileVariableStore` rather than the real-storage initialization path.

`scripts/uefi/audit-preservation.py` reconstructs the configuration in `out/` from the pinned
Mu commit. It accepts an existing patch only if the exact reverse check succeeds; the pinned
Mu already contains the 0002 memory change. It checks the storage/variable/app selections and
tests rejection after deliberately reintroducing UFSDxe. This passed on Windows and Ubuntu.
The independent `UEFI preservation audit` workflow checks the same candidate on GitHub.
This is a configuration audit, not an assertion that every binary Qualcomm driver is safe.
GitHub configuration audit run `42298071571` passed:
https://github.com/MrShmallow99/iOSPlus10/actions/runs/42298071571

### Actual device RAM and temporary boot blocker

A read-only `/proc/meminfo` and `/proc/iomem` capture from this phone is saved in ignored
`out/android-inventory/memory.txt`. MemTotal is 11,485,740 kB. The high System RAM range is
`0x840000000..0xA7FFFFFFF`, so this NE2213 is the approximately 12 GB variant, not the
8 GB NE2213 from the earlier port notes. No phone files or partitions were written.

The ordinary header-v4 UEFI path relies on a DTB installed in vendor_boot and an ABL splash
that remains visible. That path is still incompatible with our no-partition-write requirement.
Upstream slop documents acceptance of a temporary header-v2 shim using the stock base DTB,
but the panel went black and the initial test reset. Its direct NEGRONIX payload loader can
place the kernel and a small RAM root without UEFI. This is another source-supported candidate
for the first limited kernel milestone; it has not been built or tested here. A missing UFS
node in its ADT avoids initializing the UFS driver. It does not deliver a full iOS filesystem.

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

### Offline loader and emulator progress

The minimal preservation shim compiled successfully in CI run 42303381326. Its
runtime payload validator passed sanitizer checks with the actual stock vendor
ramdisk prefix and the minimal RAM-root payload. An offline Android v2 container
also passed component hash, round-trip and requested RAM-range checks. These checks
do not verify ABL's actual placement, DTB selection or phone display handoff.

Diskless QEMU execution reached kernel initialization. A 60-second run using CPU
`max` then panicked in `_nc_init+0x2d8` with a kernel data abort. Repeating with
`cortex-a76` produced the same panic. Disassembly and patch 0203 identify this as
the Negroni PMIC clock initializer, not the similarly named filesystem name-cache
code. The faulting instruction reads the Qualcomm SPMI arbiter, absent in QEMU.
The emulator now requests the existing `negronirtc=0` software-clock fallback.
That passed the first fault; the next abort was `_nr_open+0xa0`, accessing the same
absent arbiter during reboot preparation. Patch 0405 adds `negronireboot=0` before
any reboot-arbiter MMIO; it blocks SDAM reason and PS_HOLD access through that path.
The default remains enabled. A compiled test of the reconstructed initializer
verifies zero mappings/reads when disabled and normal initialization when absent.
The emulator also disables the existing PMIC battery driver (`negronibatt=0`).
PID 1 has not been observed. The emulator uses
its own virtual RAM profile, which the phone shim
rejects; this failure must be investigated before considering hardware execution.
No candidate has been flashed or booted, and the existing Android remains intact.

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
