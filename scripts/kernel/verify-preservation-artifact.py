"""Verify downloaded kernel integrity/evidence. Does not approve it for booting."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    root = args.directory
    kernel = root / "kernel.development.negroni"
    blob = kernel.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    fields = (root / "SHA256SUMS").read_text().split()
    if len(fields) != 2 or fields[1] != kernel.name or fields[0] != digest:
        raise ValueError("Kernel digest/filename does not match SHA256SUMS")
    if len(blob) < 32:
        raise ValueError("Truncated Mach-O")
    magic, cpu, subtype, filetype, commands, command_bytes = struct.unpack_from("<6I", blob)
    if magic != 0xfeedfacf or cpu != 0x0100000c or filetype != 2:
        raise ValueError("Expected a little-endian ARM64 Mach-O executable")
    if commands == 0 or command_bytes > len(blob) - 32:
        raise ValueError("Invalid Mach-O command range")
    end = 32 + command_bytes
    offset = 32
    for _ in range(commands):
        if offset + 8 > end:
            raise ValueError("Truncated Mach-O command")
        command, size = struct.unpack_from("<2I", blob, offset)
        if size < 8 or size % 8 or size > end - offset:
            raise ValueError("Invalid Mach-O command length")
        offset += size
    if offset != end:
        raise ValueError("Mach-O command count/size mismatch")
    evidence = json.loads((root / "verification.json").read_text())
    if evidence != {"ufs_sha256": "2ad3efd52829041ed4ddf9e8ae504d4c4ba989265cc58bba498dadb262b94f5f",
                    "policy_matches_tested_header": True, "device_boot_approved": False}:
        raise ValueError("Unexpected preservation-source evidence")
    if b"NEGRONI BOOTLOG: off (Android preservation)" not in blob:
        raise ValueError("Missing compiled preservation log marker")
    if "DO NOT BOOT OR FLASH" not in (root / "DO-NOT-BOOT.txt").read_text():
        raise ValueError("Missing experimental-artifact notice")
    report = {"kernel_sha256": digest, "bytes": len(blob), "arm64_macho_structure_valid": True,
              "compiled_preservation_marker_present": True, "source_evidence_matches": True,
              "whole_boot_safety_verified": False, "device_boot_approved": False}
    (root / "local-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: kernel integrity, ARM64 Mach-O structure, marker and source report: {digest}")
    print("The report/marker do not prove all executable paths are safe. Do not boot or flash.")


if __name__ == "__main__":
    main()
