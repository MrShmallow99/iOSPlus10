"""Reconstruct and cross-compile the direct loader ABI. Does not produce a boot image."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
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
        if Path(name).suffix not in (".c", ".h", ".S", ".ld"):
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
    for name in ("main.c", "preserve_payload.h"):
        shutil.copyfile(REPO / "userland/preservation-shim" / name, destination / "shim" / name)
    build = destination / "complete"
    build.mkdir()
    full_objects = []
    for name in ("start.S", "console.c", "fdt.c", "loader.c", "main.c"):
        output = build / (Path(name).stem + ".o")
        subprocess.run([args.cc, "--target=aarch64-none-elf", "-O2", "-ffreestanding", "-nostdlib",
                        "-fno-pic", "-fno-stack-protector", "-mgeneral-regs-only", "-mstrict-align",
                        "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections",
                        "-DBOARD_NEGRONI", "-DPRESERVE_ANDROID", "-c", str(destination / "shim" / name),
                        "-o", str(output)], check=True)
        if name.endswith(".c"):
            obj = output.read_bytes()
            table = struct.unpack_from("<Q", obj, 40)[0]
            entry_size, entries = struct.unpack_from("<HH", obj, 58)
            for i in range(entries):
                section = struct.unpack_from("<II4QII2Q", obj, table + i * entry_size)
                if section[1] == 4:
                    for at in range(section[4], section[4] + section[5], section[9]):
                        relocation = struct.unpack_from("<Q", obj, at + 8)[0] & 0xffffffff
                        if relocation in (257, 258, 259):
                            raise ValueError("Absolute C address relocation would break arbitrary Image placement: " + name)
        full_objects.append(output)
    elf = build / "shim.elf"
    subprocess.run([args.cc, "--target=aarch64-none-elf", "-fuse-ld=lld", "-nostdlib", "-static",
                    "-Wl,--gc-sections", "-Wl,--build-id=none", "-Wl,-T," + str(destination / "shim/shim.ld"),
                    *map(str, full_objects), "-o", str(elf)], check=True)
    blob = elf.read_bytes()
    if blob[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", blob, 18)[0] != 183:
        raise ValueError("Not an AArch64 ELF executable")
    if struct.unpack_from("<Q", blob, 24)[0] != 0:
        raise ValueError("Shim must be linked at zero for the position-independent Image entry")
    phoff = struct.unpack_from("<Q", blob, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", blob, 54)
    image = bytearray()
    for index in range(phnum):
        kind, flags, offset, address, physical, size, memory, alignment = struct.unpack_from("<II6Q", blob, phoff + index * phsize)
        if kind != 1 or size == 0:
            continue
        if address != physical or size > memory or offset + size > len(blob) or address + size > 4 * 1024**2:
            raise ValueError("Invalid loadable shim segment")
        if address + size > len(image):
            image.extend(bytes(address + size - len(image)))
        image[address:address + size] = blob[offset:offset + size]
    if len(image) < 64 or image[56:60] != b"ARM\x64":
        raise ValueError("Missing ARM64 Linux Image header")
    declared = struct.unpack_from("<Q", image, 16)[0]
    if declared < len(image) or declared > 4 * 1024**2 or declared % 16:
        raise ValueError("Invalid shim image/BSS/stack size")
    image.extend(bytes(declared - len(image)))
    (build / "Image").write_bytes(image)
    # Defined function symbols, rather than incidental strings, identify linked paths.
    shoff = struct.unpack_from("<Q", blob, 40)[0]
    shsize, shnum = struct.unpack_from("<HH", blob, 58)
    sections = [struct.unpack_from("<II4QII2Q", blob, shoff + i * shsize) for i in range(shnum)]
    symbols = set()
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        table = blob[strings[4]:strings[4] + strings[5]]
        for at in range(section[4], section[4] + section[5], section[9]):
            name, info, other, defined, value, size = struct.unpack_from("<IBBHQQ", blob, at)
            if defined and name:
                symbols.add(table[name:table.index(0, name)].decode())
    forbidden = {"test_ufs", "ufs_init", "ufs_scsi", "probe_board", "loader_uefi", "uefi_boot", "mmu_enable"}
    if symbols & forbidden:
        raise ValueError("Forbidden shim paths were linked: " + repr(symbols & forbidden))
    image_hash = hashlib.sha256(image).hexdigest()
    (destination / "report.json").write_text(json.dumps({
        "slop_commit": pin, "loader_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "objects": objects, "negroni_boot_args_bytes": 1152,
        "negroni_memory_size_actual_offset": "0x478", "payload_command_line_bytes": 608,
        "negroni_payload_magic": "NEGRONIX", "complete_shim_built": True,
        "shim_image_sha256": image_hash, "shim_image_bytes": len(image),
        "internal_storage_uefi_probe_paths_linked": False,
        "phone_boot_image_created": False, "device_boot_approved": False}, indent=2) + "\n")
    print(f"PASS: direct-loader AArch64 compilation/static ABI assertions for negroni and sweet: {destination}")
    print(f"Complete minimal shim ELF and padded Image built: {len(image)} bytes, SHA-256 {image_hash}")
    print("No Android boot container or device test. Firmware handoff/display/ramdisk remain unverified.")


if __name__ == "__main__":
    main()
