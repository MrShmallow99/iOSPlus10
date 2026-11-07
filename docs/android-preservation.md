# Preserve this owner's Android installation

Owner requirement, 2026-11-06: keep the existing Android boot and data. The owner reports an
unlocked, rooted OnePlus 10 Pro connected by USB. The owner ran the read-only inventory;
results were read from `out/android-inventory`. Do not inherit the previous owner's backups.

Current milestone (2026-11-07): the physical NE2213 completed a temporary RAM boot
of the minimal XNU/HFS system. The owner reported its HFS mount line and confirmed
the exact `PRESERVE RAM ROOT: PID 1 reached.` marker. Android returned on slot A
after a hardware restart. All 14 saved boot-chain partition hashes and all saved
GPT regions still match; the owner confirmed a familiar app's saved data is intact.
No flash, erase or slot-change command was issued. This is minimal standalone init,
not full Apple userland or a persistent dual-boot installation.

Test record: `out/phone-ram-test/20261107T001203.585728Z/` (preflight,
bootloader-state.json, boot.log and observer-result.json). Read-only postcheck:
`out/phone-ram-test/20261107T002144.807217Z/preflight.json`. Exact image SHA:
`840a921a9ec94d4bab94b0f39498d503b911bd1e642d9323e894c50924ee060c`.
`scripts/shim/ramroot-phone-test.py` admits only that image, binds the handset and
separates preflight, bootloader entry, inspection and RAM boot. Old destructive
installer/restore scripts remain blocked by the preservation policy.

The bootloader reported hardware fastboot, unlocked, slot A successful/bootable
and max download 805,306,368 bytes. `fastboot boot` sent 52,492 KiB and returned
Booting OKAY. Readiness/mount observations came from the owner at the handset;
USB is disabled in this profile, so no physical register/console capture was made.
This validates one boot-and-return cycle on this exact phone/firmware/image. It
does not prove every bootloader path write-free or provide a full app-data backup.

Static inspection of this phone's copied ABL found a legacy v2 parser and a
conditional GPT attribute-update path inside the fastboot boot handler. A RAM
boot is therefore not established as wholly read-only. Evidence and remaining
checks: [stock ABL findings](abl-preservation.md). Both ABL copies are verified;
their extracted executables differ. Slot B is not a verified fallback.

Further review produced a static layout model consistent with the stock Android
measurements; header address requests are not the resulting load addresses on its
successful-query path. The modeled legacy path omits the vendor prefix. The
refreshed candidate uses the newer PMIC-disable kernel and a shared minimal
profile. It remains experimental; its first controlled hardware test is recorded
above. Captured slot attributes predict no changes for
the reviewed slot routines, but complete runtime write behavior remains unverified.
Exact inputs, addresses and Evidence IDs are in the linked ABL findings.

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

The patch is stored in the parent repo; pinned submodule sources remain unchanged.
Later work compiled the complete shim and reached PID 1 in emulation; see the offline
loader/emulator progress below. Physical temporary-boot handoff and a recoverable
observation path remain unverified. The generic test-boot script remains blocked.

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

Full shim integration passed in the 120-second capture
`out/preservation-qemu/20261106T231916.280563Z`: PID1 marker observed, zero unknown
glyphs, no visible panic, and all 1152 shim-produced boot-argument bytes match the
reference. This starts at the unchanged Image from shim CI 42303381326, not directly
at XNU. The source payload uses the required high 3 GiB bank, virtual GIC/timer ADT,
and emulator-only hardware disable switches. Real vendor prefix: 22,603,096 bytes.

Read-only live FDT capture `out/android-handoff/20261106T231318.768974Z` is 1,181,468
bytes, SHA-256 `689dd6856fd967c07e97276b5d3c269ad2ab1327451711af3de454dda64c0167`,
verified before/on-host/after. Stock initrd addresses are `0xb690d000..0xb7ffee10`;
the FDT reports bank `0x840000000 + 0xc0000000`. These are stock Android observations,
not temporary v2 boot placement. The integration test changes only initrd address
property values in a local FDT copy; phone/firmware files remain unchanged.

QEMU lacks the Gunyah watchdog SMC. Separate emulator-only EL3 firmware models that
return, rejects other SMCs, and initializes the virtual GIC security state. Without
that initialization, the kernel received no timer IRQs and stopped in early startup.
The phone Image is unchanged. This does not validate the real secure firmware or
physical display. No drives, USB devices or guest network interfaces are attached.

`tools/preservation-tests/test-handoff.py` compares the actual shim FDT parser with
the bounded host parser for synthetic and captured-stock fixtures under sanitizers.
The host parser rejects every truncated synthetic fixture and invalid header ranges.
This does not establish malformed-input safety for the older shim parser.

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
Kernel CI 42306974447 passed; its downloaded kernel SHA-256 is
`95a222bfc1282e57307f593a4bd2f20028daeb7909b8503cced05a80359600c9`.
Further QEMU runs passed those faults and mounted `PRESERVE_RAM_ROOT` on `md0`.
Absent display-engine and backlight accesses are skipped with existing display
switches. The charger default is a dry run that reads a physical key even with
`negronikeys=0`; the emulator uses `negronicharge=1`, which returns immediately
because this virtual board has neither a decoded PON log nor a charger boot arg.
This is an emulator-only profile, not a phone boot recommendation.
With periodic framebuffer statistics disabled, the 60-second run at
`out/preservation-qemu/20261106T230156.348210Z` reached `/sbin/launchd` and printed
`PRESERVE RAM ROOT: PID 1 reached.` Its decoded framebuffer had zero unknown glyphs
and no visible panic. The preceding run's exception trace also showed EL0 SVCs.
This validates the minimal init and RAM filesystem in emulation, not Apple userland
or physical-device safety. The emulator uses
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
