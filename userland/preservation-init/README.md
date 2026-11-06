# Minimal RAM-root init

This is a standalone ARM64 PID 1 for a small Darwin/XNU RAM filesystem. It opens
`/dev/console`, writes a readiness line, and waits with `select`. It does not mount filesystems,
open block devices, reboot, or load dynamic libraries. It is not Apple's launchd and does not
start iOS services or an iOS interface. Kernel code-signing acceptance and runtime behavior
have not been tested on the phone. A diskless QEMU run with kernel CI 42306974447
mounted this HFS root, executed `/sbin/launchd` and displayed the readiness line
for a 60-second run. Evidence is under `out/preservation-qemu/20261106T230156.348210Z`.

The macOS `Experimental RAM root` workflow compiles and ad-hoc signs it, creates a 32 MiB
HFS+ image, checks the filesystem through a read-only host image attachment, and packs the
known successful preservation kernel with it. The packer reads `/sbin/launchd` from the actual
HFS+ catalog and requires an exact match. It checks the Mach-O entry/signature/no-library
properties, root signature/size, payload destination bounds, segment overlap and entry bounds,
and the absence of the UFS node in both the input and packaged device trees.

Output is an intermediate `NEGRONIX` payload, **not an Android boot image**. No phone command
is part of this build. The direct loader needs `patches/shim/0001-negroni-direct-loader-abi.patch`
to accept its magic and match the compiled kernel's 1024-byte boot-argument layout. The
`Direct loader ABI audit` compiles that loader object with static offset/size assertions;
the complete minimal shim is now also built and audited. The offline Android boot
container checks and QEMU run do not validate a physical boot.
