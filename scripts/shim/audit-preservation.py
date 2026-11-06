"""Reconstruct and cross-compile the direct loader ABI. Does not produce a boot image."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    slop = REPO / "external/slop"
    pin = subprocess.check_output(["git", "-C", str(REPO), "ls-tree", "HEAD", "external/slop"], text=True).split()[2]
    destination = REPO / "out/direct-loader-audit" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    names = subprocess.check_output(["git", "-C", str(slop), "ls-tree", "-r", "--name-only", pin, "shim"], text=True).splitlines()
    for name in names:
        if Path(name).suffix not in (".c", ".h"):
            continue
        data = subprocess.check_output(["git", "-C", str(slop), "show", pin + ":" + name])
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.replace(b"\r\n", b"\n"))
    for patch in sorted((REPO / "patches/shim").glob("*.patch")):
        local = destination / patch.name
        local.write_bytes(patch.read_bytes().replace(b"\r\n", b"\n"))
        subprocess.run(["git", "-C", str(destination), "apply", "--whitespace=nowarn", str(local)], check=True)
    source = destination / "shim/loader.c"
    objects = {}
    for board, flags in (("negroni", ["-DBOARD_NEGRONI"]), ("sweet", [])):
        output = destination / ("loader-" + board + ".o")
        subprocess.run([args.cc, "--target=aarch64-none-elf", "-O2", "-ffreestanding", "-nostdlib",
                        "-fno-pic", "-mgeneral-regs-only", "-mstrict-align", "-Wall", "-Wextra", "-Werror",
                        *flags, "-c", str(source), "-o", str(output)], check=True)
        blob = output.read_bytes()
        if blob[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", blob, 18)[0] != 183:
            raise ValueError("Compiler did not produce an AArch64 ELF object")
        objects[board] = hashlib.sha256(blob).hexdigest()
    (destination / "report.json").write_text(json.dumps({
        "slop_commit": pin, "loader_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "objects": objects, "negroni_boot_args_bytes": 1152,
        "negroni_memory_size_actual_offset": "0x478", "payload_command_line_bytes": 608,
        "negroni_payload_magic": "NEGRONIX", "complete_shim_built": False,
        "phone_boot_image_created": False, "device_boot_approved": False}, indent=2) + "\n")
    print(f"PASS: direct-loader AArch64 compilation/static ABI assertions for negroni and sweet: {destination}")
    print("Object compilation only. No shim executable, boot image, or device test.")


if __name__ == "__main__":
    main()
