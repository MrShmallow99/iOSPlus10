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

No script here flashes, changes slots or boots the phone. Android app data has not
been backed up by these tools. Do not use a candidate on hardware until its remaining
handoff and recovery requirements have been resolved.
