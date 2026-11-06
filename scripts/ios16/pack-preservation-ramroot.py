"""Pack and bound-check an intermediate direct-shim RAM-root payload. No phone access."""
import hashlib
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
    root = destination / "root.hfs"
    root_blob = root.read_bytes()
    if not 0 < len(root_blob) <= 64 * 1024**2 or root_blob[1024:1026] not in (b"H+", b"HX"):
        raise ValueError("Expected a small raw HFS+ volume without a partition map")
    executable = (destination / "launchd").read_bytes()
    if struct.unpack_from("<2I", executable) != (0xfeedfacf, 0x0100000c):
        raise ValueError("PID 1 must be an ARM64 Mach-O executable")
    tree = mkadt.build(board="negroni", dram=(0x840000000, 0xC0000000), ufs=False)
    if any(node.name in ("negroni-ufs", "sweet-ufs") for node in walk(tree)):
        raise ValueError("RAM-root ADT must not expose UFS")
    tree_path = destination / "negroni.adt"
    tree_path.write_bytes(adt.serialize(tree))
    args = ("debug=0xc serial=3 cpus=1 keepsyms=1 -noprogress rd=md0 "
            "ufsrw=0 negronilog=0 negroniram=0 negronimetal=0 negronignss=0 "
            "negroniadsp=0 negronibt=0 negroniwlan=0 negronislpi=0 wdt=-1 "
            "launchd_unsecure_cache=1 unentitled_ios_sim_launch=1 ignition_level=1")
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
        "ufs_node_present": False, "physical_window": [hex(physical), hex(memory_size)],
        "top_of_kernel_data": hex(top), "payload": info,
        "phone_boot_image_created": False, "device_boot_approved": False,
        "ios_user_interface_included": False}, indent=2) + "\n")
    print("PASS: intermediate RAM-root payload bounds; no UFS node and no phone boot image")


if __name__ == "__main__":
    main()
