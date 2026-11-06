# Android preservation (0403)

This checkout is being developed for an owner who requires the existing Android installation
and app data to remain intact. Patch 0403 makes the negroni XNU UFS path read-only by default,
without a boot-argument override. It intentionally prevents the old writable-UFS iOS setup.

The command gate runs at the beginning of `ufs_scsi`, before descriptor access, cache work,
and the transfer doorbell. It permits only the existing TEST UNIT READY, power-active, and
bounded READ(10) requests. It denies all data-out requests, unknown commands, writes,
UNMAP, FORMAT, MODE SELECT, and SYNCHRONIZE CACHE. `su.writable` stays false even with
`ufsrw=1`. Persistent boot logging does not start, regardless of `negronilog`.

This protects only this XNU driver's command path. It does not protect UEFI, Qualcomm binary
drivers, bootloader variables, other future storage drivers, or direct fastboot commands.
It does not add a separate iOS root filesystem. No image may be booted based on this patch
alone. In particular, RAM-loading a kernel is not proof that the entire boot path is read-only.

## Host verification

Run in Linux/WSL from the repository:

```
python3 tools/preservation-tests/run.py
```

The test substitutes fake phone tools and checks 12 mutation invocations against the host
policy. It tests missing and invalid policies in a temporary fixture. It reconstructs the UFS
source from the pinned slop patches plus this repo's patches, normalizing Windows patch line
endings in private copies under `out/`. Every relevant patch must apply. It compiles and runs
the actual policy header extracted from 0403, tests all 256 opcode values and data-out
directions, and checks allowed reads, transfer lengths, power requests, and invalid inputs.
An integration assertion checks that the gate precedes descriptor access and the doorbell.

Verified 2026-11-06: tests passed under Ubuntu WSL, GCC 15.2, exit 0. All 32 patches touching
the UFS source applied. Resulting driver SHA-256:
`2ad3efd52829041ed4ddf9e8ae504d4c4ba989265cc58bba498dadb262b94f5f`.
Log: `logs/preservation-tests.log`. This is not a full XNU compile or a device boot test.
The real kernel build must fail if 0403 is skipped; the older build scripts' general
skip-on-conflict behavior is not acceptable evidence for a preservation image.
