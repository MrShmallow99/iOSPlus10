# Stock ABL and Android preservation

This is static firmware evidence from this owner's NE2213, firmware
`NE2213_16.0.3.530(EX01)`, active slot A. No experimental phone boot, flash,
slot switch, firmware execution or partition write was performed.

## Identity and method

Both 1 MiB ABL partitions were copied read-only and verified by size and SHA-256
before/on-host/after in `out/android-backup/20261106T232451.856224Z`.

- ABL A SHA-256: `ef5fbd916f430ab81d70c47ad06eeb935db4f26feee8eddc35a424c95160ddb5`.
- ABL B SHA-256: `2afd8200ba5546f46a567ba7d462c412c58b41c93719ee3e679cac390203337e`.
- Active A's extracted ARM64 PE: 819,200 bytes, SHA-256
  `2ce7a5ee3cd35357e12b13041aea819fdce2c9feb333e83a400295cb182697db`.
- B's extracted PE differs: SHA-256
  `664be6f1a0febcb07276809711fdbf012c07ec6276584bd158b0c2a4f378a994`.

`scripts/uefi/inspect-abl.py` validates firmware-volume header bounds/checksum,
walks bounded FFS/section containers, decompresses the recognized LZMA GUID
section and extracts PE sections. It does not validate Qualcomm signatures or
execute firmware. The container and PE copies remain under ignored `out/`.

REA's firmware/Binwalk operation was unavailable on its Windows host. Local
format-aware extraction was followed by REA/Ghidra 12.1.4 static analysis of
the active A PE. No provider configuration changed. Full REA Evidence and the
snapshot are in `out/abl-analysis/20261106T232636.867171Z/rea-evidence.json` and
`rea-snapshot.json`; the native session was closed after export.

## Observed paths and inferences

The names below describe inferred roles; `FUN_...` are Ghidra's actual names.

1. **Observed:** `FUN_0001bdec` contains the locked-device rejection and fastboot
   boot errors. It calls `FUN_00007760`, whose callers/callees link to the image
   size/header parser `FUN_00025478`.
   Evidence: `ev_45f9a5e85f70ab0f4e37bd39b12923dfd09bcf792cbb6f4687d63bd8f43f386f`,
   `ev_8f8c6673f39be8be2e2f7209ef408f71f9d621ecfd6f37eab3268702b1e65278`.
2. **Observed:** `FUN_00025478` checks `ANDROID!` and includes legacy versions
   below 3, with a specific v2 DTB/header-size path requiring `0x67c` (1660).
   **Inference:** this ABL contains the v2 parsing needed by the offline candidate.
   This does not prove authentication, load placement, DTB selection or successful
   execution of that candidate.
   Evidence: `ev_5caf56718174b36165222f172e841df7275b4340503893e7f7133d029949a7d6`.
3. **Observed:** before loading the downloaded image, the boot handler detects
   multiple boot slots through `FUN_000435d0` and calls `FUN_00049810`.
   The latter uses `ClearUnbootable` error strings, gets the active boot entry,
   clears mask `0x00800000` in its attributes' upper 32 bits (overall bit 55),
   then calls `FUN_00044bb0(1)`.
   Evidence: `ev_62427a3b2da942bb96e0a4c9c3c2f61d2a014902caac28ba0b541c60f42b0594`,
   `ev_00a34bd7cc875af625666926f9fd36ce1a58d975893b70ac86a287deb8e83a1c`.
4. **Observed:** `FUN_00044bb0` compares in-memory partition attributes with
   GPT entries. On differences it updates entries and CRCs, then makes block-I/O
   calls through offset `0x20`, adjacent to GPT-write error messages.
   **Inference:** this is conditional persistence of GPT metadata. A call to
   `ClearUnbootable` does not itself establish that a write will occur if all
   compared attributes already match.
   Evidence: `ev_39ec80f43a99fcf2cd720a7cbbc432500e72e4add3fb94e5516869917768d5ed`.

Consequently, `fastboot boot` is not established as a wholly read-only operation
on this firmware. These are static observations, not a runtime trace. Other
bootloader write paths, secure-firmware effects and error/fallback paths remain
unreviewed. The existing no-phone-boot decision remains in effect.

## Current GPT metadata backup

Read-only capture `out/android-gpt/20261106T233309.678172Z` completed for all six
detected UFS LUNs (`sda` through `sdf`). It contains only the protective MBR,
primary/backup GPT headers and their entry arrays. Each region was size- and
SHA-verified before/on-host/after. Both GPT header and entry-array CRCs matched;
primary and backup entries matched. No restoration was attempted.

The `sde` boot entries currently contain:

| Entry | Attributes | Bit 55 (unbootable) |
|---|---|---|
| `boot_a` | `0x77000000000000` | clear |
| `boot_b` | `0xfb000000000000` | set |

Therefore, this particular active-entry bit already has the value ClearUnbootable
would select. That does **not** prove the whole command will avoid GPT writes:
the update routine compares more attributes, and other paths remain unreviewed.
The inactive B entry is marked unbootable; do not switch to it as a presumed fallback.

Offline re-verification:

```text
python scripts/backup/backup-android-gpt.py --verify out/android-gpt/20261106T233309.678172Z
```

That offline re-verification passed for all six LUNs. Synthetic host tests in
`tools/preservation-tests/test-gpt.py` also passed CRC, truncation, usable-range
and metadata-overlap rejection. These checks do not test restoration.

The first attempted capture correctly failed its exact-size check because ADB
merged dd's remote statistics into the binary stream. The script now suppresses
those statistics remotely and retains exact-size/hash checks. The failed folder
has no COMPLETE marker and is not a valid backup.

## Placement model and refreshed offline candidate

Further static inspection found that the successful firmware-query path computes
load addresses instead of copying the requested addresses from the v2 header:

- `FUN_00022bd0`: legacy versions use the generic ramdisk size; vendor ramdisk
  sizes are populated in the newer-header paths.
- `FUN_00023460`: reads `KernelBaseAddr`/`KernelSize`, adds the raw ARM64 Image's
  `text_offset` to the base when its runtime `image_size` is nonzero, allocates the
  ramdisk downward from the region end with page rounding plus one extra page,
  and reserves 2 MiB plus a page below it for DTB placement.
- `FUN_00024b80`: prepends vendor/recovery ramdisks only for versions above 2.
  It copies the legacy generic ramdisk and updates the FDT's initrd values.

Evidence respectively:
`ev_9537727306818f0e4926c3261fa3e5637988a128d280a741ca0c9c9f4daff09e`,
`ev_629c0bc8011cd9e6d9390212dc69243d9b80abf7871f02751dbd2a24bc962a36`,
`ev_9a87a7ca0d9952e5824229f9afc845b001cd76f478556fc7cd49ce8c031b7362`.
The variable-query helper is `FUN_00027288`, Evidence
`ev_a2dc1e61dea079a6b385da4033a625025c8a51d7d4ee0fa48ee4102bd1b24e88`.

`scripts/shim/abl_layout.py` transcribes only the raw ARM64/successful-query case.
It does not model gzip, 32-bit images, failed firmware queries or all overlays.
The stock Image has text_offset 0 and a nonzero runtime size. Its file length
exceeds that runtime size; the model checks the larger extent against overlap.

Stock `/proc/iomem` kernel code at `0xa8000000`, verified boot/vendor ramdisk
lengths, and live initrd start `0xb690d000` algebraically imply a firmware region
`0xa8000000 + 0x10000000` under that path. The firmware variables were **not read**.
This is an inference from the existing Android boot, not a temporary-boot trace.

Refreshed unapproved candidate:
`out/preservation-boot-candidate/20261106T235413.689908Z/UNAPPROVED-ramroot-boot-v2.img`.
SHA-256: `840a921a9ec94d4bab94b0f39498d503b911bd1e642d9323e894c50924ee060c`.
It uses the verified 0405 kernel from CI 42306974447 and the shared minimal profile
in `config/preservation-ramroot-cmdline`. Reused HFS/init bytes are unchanged.
Component hashes, Android-header round trip and runtime-validator sanitizer checks
passed. No phone command is part of its build. Under the inferred region:

| Component | Header request | Static model |
|---|---|---|
| Shim | `0xa8008000` | `0xa8000000` |
| Generic ramdisk | `0xa9000000` | `0xb4eb7000` |
| DTB | `0xb0000000` | `0xb4cb6000` |

Model report: `out/abl-layout/20261106T235651.414092Z/report.json`.
The candidate remains unapproved; ABL was not executed. DTB selection, real secure
firmware, display and physical recovery remain unverified.

The 120-second complete-shim QEMU capture
`out/preservation-qemu/20261107T000139.134514Z` reached the PID1 marker at these
exact modeled component addresses, with all 1152 boot-argument bytes matching,
zero unknown glyphs and no visible panic. Its virtual ADT is smaller than the
phone ADT, so 5,696 trailing zero bytes were added to match the candidate's generic
ramdisk length. No vendor prefix was used. The guest still uses virtual GIC/timer
data and emulator-only EL3 firmware; this is not execution of the Android boot
container by ABL or validation of the physical ADT. The HFS/init and kernel bytes
match the refreshed candidate's inputs.

Clean CI at 035749b passed direct-loader/layout/slot/GPT host tests in run
42315354371 and the updated RAM-root build in run 42315354271. The shared profile
requires the 0405 PMIC-disable feature; packer/emulator reject kernels lacking its
compiled marker. GPT/slot tests include changing and ambiguous-state cases.

## Review of the captured slot state

`FUN_00043848` selects already-active entries by priority and has a separate
default-initialization path. `FUN_000499e8` avoids retry decrement when the selected
slot is successful and not unbootable. `FUN_00048fd8` sets active bit 50 on names
ending with the selected suffix and clears it on the other entries.

Evidence:
`ev_f184d4acee55356998862df840d4a687b1749dd6669d941c9c5e97032b10871f`,
`ev_bab5ae8038a901fd549bbb79ef6e47340285a03f9e5a06ba4e537e8eb1a389cd`,
`ev_18541972a41010afa5849dffda24d251ee8648597ca4a38dce42aa35236fd330`.
The GUID-validation path calls `FUN_00020bf0` with argument 1, selecting its
`Get BootLun` branch rather than `SetBootLun` (Evidence
`ev_5d0a091137e89b70fd8961ea5c40c5268bceb338b31f6bf06ff9e5fbb4324a22`).

The offline assessment of all 125 captured GPT entries selected A, successful,
not unbootable; ClearUnbootable would not change its bit; active flags already
match A across all entries. Thus those particular attribute updates are predicted
to be no-ops **if that captured state is retained**. This does not prove the whole
temporary-boot command avoids writes. Authentication, secure-world protocols and
other failure paths are not completely audited. Static pseudocode also has
outlined-helper/decompiler limitations; it is not a runtime observation.

Assessment: `out/android-slot-assessment/20261106T235541.369323Z/report.json`.
Evidence export/snapshot:
`out/abl-analysis/20261106T232636.867171Z/placement-slot-final-evidence.json` and
`placement-slot-snapshot.json`. The analysis session was closed after export.

## Remaining checks

- GPT copies are verified, but restoration and fallback bootability remain untested.
- Validate actual temporary-boot placement and DTB selection beyond the static model.
- Audit remaining persistent side effects through authentication, handoff and
  failure paths. Keep the bootloader image unchanged.
- Establish a recoverable observation path and preserve app data. A boot-chain
  or GPT backup does not contain Android apps, encryption keys or user files.

The full-shim QEMU test already reaches minimal PID 1, with matching boot arguments,
the real vendor prefix and locally adjusted stock DTB. It models watchdog/GIC
firmware and does not model ABL. See [Android preservation](android-preservation.md).
