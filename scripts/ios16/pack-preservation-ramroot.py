"""Pack and bound-check an intermediate direct-shim RAM-root payload. No phone access."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "external/slop/negroni-ios/tools"
sys.path.insert(0, str(TOOLS))
import adt
import mkadt
import mkpayload


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def main():
    kernel, destination = Path(sys.argv[1]), Path(sys.argv[2])
    if b"NEGRONI REBOOT: PMIC access off (negronireboot=0)" not in kernel.read_bytes():
        raise ValueError("Minimal profile requires the PMIC-disable kernel feature (0405)")
    root = destination / "root.hfs"
    root_blob = root.read_bytes()
    if not 0 < len(root_blob) <= 64 * 1024**2 or root_blob[1024:1026] not in (b"H+", b"HX"):
        raise ValueError("Expected a small raw HFS+ volume without a partition map")
    executable = (destination / "launchd").read_bytes()
    if struct.unpack_from("<2I", executable) != (0xfeedfacf, 0x0100000c):
        raise ValueError("PID 1 must be an ARM64 Mach-O executable")
    command_count, command_bytes = struct.unpack_from("<2I", executable, 16)
    position = 32
    commands = set()
    for _ in range(command_count):
        if position + 8 > min(len(executable), 32 + command_bytes):
            raise ValueError("Truncated PID 1 load commands")
        command, size = struct.unpack_from("<2I", executable, position)
        if size < 8 or position + size > min(len(executable), 32 + command_bytes):
            raise ValueError("Invalid PID 1 load command")
        commands.add(command)
        position += size
    if 0x5 not in commands or 0x1d not in commands or commands & {0xc, 0xe, 0x80000018, 0x8000001f}:
        raise ValueError("PID 1 must have a Unix-thread entry, a signature and no dynamic libraries/loader")
    # Read the actual filesystem catalog, not just the source-folder copy.
    spec = importlib.util.spec_from_file_location("preserve_hfs", REPO / "scripts/audio/hfs-extract.py")
    hfs_reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hfs_reader)
    filesystem = hfs_reader.HFS(hfs_reader.Image(str(root)))
    record = filesystem.lookup("/sbin/launchd")
    if record is None or record[1] != 2:
        raise ValueError("RAM filesystem is missing /sbin/launchd")
    contents, _ = filesystem.file_data(record[0], record[2])
    if contents != executable:
        raise ValueError("RAM filesystem contains a different PID 1 executable")
    tree = mkadt.build(board="negroni", dram=(0x840000000, 0xC0000000), ufs=False)
    if any(node.name in ("negroni-ufs", "sweet-ufs") for node in walk(tree)):
        raise ValueError("RAM-root ADT must not expose UFS")
    tree_path = destination / "negroni.adt"
    tree_path.write_bytes(adt.serialize(tree))
    args = (REPO / "config/preservation-ramroot-cmdline").read_text().strip()
    if len(args.encode()) >= 608 or "\n" in args or "\0" in args:
        raise ValueError("Invalid minimal RAM-root command line")
    payload, info = mkpayload.build(str(kernel), str(tree_path), args, str(root))
    virt, entry, adt_offset, adt_size, kernel_end, physical, memory_size = struct.unpack_from("<7Q", payload, 0x10)
    count = struct.unpack_from("<I", payload, 12)[0]
    header_end = mkpayload.SEG_TABLE + count * 32
    intervals = []
    for i in range(count):
        address, size, offset, file_size = struct.unpack_from("<4Q", payload, mkpayload.SEG_TABLE + i * 32)
        if address < virt or size == 0 or file_size > size or offset < header_end or offset + file_size > adt_offset:
            raise ValueError("Invalid payload segment")
        start = physical + address - virt
        end = start + size
        if start < physical or end > physical + memory_size:
            raise ValueError("Payload segment is outside the selected RAM window")
        if any(start < old_end and old_start < end for old_start, old_end in intervals):
            raise ValueError("Overlapping physical payload segments")
        intervals.append((start, end))
    top = ((physical + kernel_end - virt + adt_size + 0x3fff) & ~0x3fff) + 0x4000
    if adt_offset + adt_size > len(payload) or top > physical + memory_size or entry < virt:
        raise ValueError("Invalid entry/tree/boot-args RAM bounds")
    physical_entry = physical + entry - virt
    if not any(start <= physical_entry < end for start, end in intervals):
        raise ValueError("Kernel entry is outside the loaded segments")
    packed_tree, _ = adt.parse(payload[adt_offset:adt_offset + adt_size])
    if any(node.name in ("negroni-ufs", "sweet-ufs") for node in walk(packed_tree)):
        raise ValueError("Packaged ADT exposes UFS")
    (destination / "kernel-ramroot.negronix").write_bytes(payload)
    (destination / "cmdline.txt").write_text(args + "\n")
    (destination / "report.json").write_text(json.dumps({
        "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
        "root_sha256": hashlib.sha256(root_blob).hexdigest(), "root_bytes": len(root_blob),
        "root_contains_matching_static_signed_pid1": True,
        "ufs_node_present": False, "physical_window": [hex(physical), hex(memory_size)],
        "top_of_kernel_data": hex(top), "payload": info,
        "phone_boot_image_created": False, "device_boot_approved": False,
        "ios_user_interface_included": False}, indent=2) + "\n")
    print("PASS: intermediate RAM-root payload bounds; no UFS node and no phone boot image")


if __name__ == "__main__":
    main()
