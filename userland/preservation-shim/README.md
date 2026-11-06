# Experimental RAM loader

This minimal loader links only startup, framebuffer console, FDT parsing, payload
loading and the preservation entry point. It excludes the original hardware probes,
UFS implementation and UEFI fallback. The runtime validator rejects malformed,
overlapping and ambiguous payloads, unsafe root arguments and a kernel destination
that overlaps the running shim. These checks do not establish whole-device safety.

`scripts/shim/audit-preservation.py` reconstructs pinned sources, applies the parent
patches and builds the Image with source and digest evidence. The host payload tests
exercise the same header with address/undefined-behavior sanitizers.

`build-boot-container.py` creates an **unapproved local candidate** using the verified
stock vendor DTB and an isolated HFS RAM root. It checks requested memory ranges,
round-trips the Android header and tests the real vendor-prefix/payload combination.
Requested addresses do not prove where ABL actually loads the components.

`emulate-ramroot.py` instead runs a QEMU-only RAM layout with no guest disks, USB or
network interfaces. It captures the framebuffer, registers and bounded exception
trace. Its payload deliberately fails the physical-phone memory profile. The
emulator is a development diagnostic, not proof of phone compatibility or dual boot.
All output, including extracted stock material, stays under ignored `out/`.

`--shim-artifact` enters the verified, unchanged complete shim rather than XNU
directly. It uses a demand-paged 40 GiB guest address space (`reserve=off`, no
preallocation) to cover the required high 3 GiB RAM bank. It does not allocate
40 GiB of physical host RAM. `qemu-monitor.S` is separate virtual EL3 firmware,
not linked into the phone shim: it models the watchdog-disable SMC and returns
unsupported for other services. This does not validate real Gunyah behavior.
It sets the virtual GIC's single-security-state mode before nonsecure entry; the
register semantics are described in [Arm's GIC security documentation](https://support.arm.com/documentation/100336/0106/operation/security).

`--vendor-prefix` prepends locally saved vendor-ramdisk bytes. `--handoff-fdt`
uses a saved stock FDT with only its initrd start/end values changed offline.
Without that option the test uses a minimal synthetic FDT. Reports distinguish
these cases, hash the inputs and compare all 1152 shim-generated boot-argument
bytes against the reference. No guest boot image, bootloader or storage is modeled.

The 120-second full-shim capture `out/preservation-qemu/20261106T231916.280563Z`
reached the PID1 marker with the real vendor prefix and captured stock DTB. All
1152 boot-argument bytes matched; no panic was visible. This leaves physical ABL
placement, secure firmware, display and recovery unverified.

The virtual profile disables Qualcomm hardware services through their existing
switches. It requires kernel patch 0405 for `negronireboot=0`, which prevents PMIC
reboot-channel mapping and persistent reason writes. Older kernels ignore that
switch and can abort at `_nr_open` on QEMU. `negronirtc=0` selects the software
clock; it does not fix this separate reboot path.

For repeatable CI-to-emulator runs, launch `scripts/shim/ci-emulate-ramroot.sh`
through `scripts/bg.sh`, passing a kernel CI run ID and the verified RAM-root
artifact directory. It waits for CI success, downloads only the experimental
kernel artifact, then performs one bounded emulator run. `GH_EXECUTABLE` selects
the GitHub CLI; Windows `.exe` downloads use a converted Windows destination.

No script here flashes, changes slots or boots the phone. Android app data has not
been backed up by these tools. Do not use a candidate on hardware until its remaining
handoff and recovery requirements have been resolved.
