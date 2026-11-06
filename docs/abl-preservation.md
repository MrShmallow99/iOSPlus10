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

## Remaining checks

- GPT copies are verified, but restoration and fallback bootability remain untested.
- Resolve actual kernel, ramdisk and DTB placement and image-selection behavior.
- Audit remaining persistent side effects through authentication, handoff and
  failure paths. Keep the bootloader image unchanged.
- Establish a recoverable observation path and preserve app data. A boot-chain
  or GPT backup does not contain Android apps, encryption keys or user files.

The full-shim QEMU test already reaches minimal PID 1, with matching boot arguments,
the real vendor prefix and locally adjusted stock DTB. It models watchdog/GIC
firmware and does not model ABL. See [Android preservation](android-preservation.md).
