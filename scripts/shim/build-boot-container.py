"""Assemble/round-trip-check an UNAPPROVED v2 RAM boot candidate offline. No phone commands."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
MKBOOTIMG_PIN = "808ecd09666ffe0ff5800f02af693abce56eb395"


def digest(path, normalize=False):
    data = path.read_bytes()
    return hashlib.sha256(data.replace(b"\r\n", b"\n") if normalize else data).hexdigest()


def run_tool(tool, *arguments):
    return subprocess.run([sys.executable, str(tool), *map(str, arguments)],
                          capture_output=True, text=True, check=True).stdout


def align(n, size=4096):
    return (n + size - 1) // size * size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--shim-artifact", type=Path, required=True)
    parser.add_argument("--ramroot-artifact", type=Path, required=True)
    parser.add_argument("--tools", type=Path, default=REPO / "out/tools/mkbootimg-preserve")
    parser.add_argument("--memory", type=Path, default=REPO / "out/android-inventory/memory.txt")
    args = parser.parse_args()
    pin = subprocess.check_output(["git", "-C", str(args.tools), "rev-parse", "HEAD"], text=True).strip()
    if pin != MKBOOTIMG_PIN:
        raise ValueError("Expected the inspected Android 16 mkbootimg release commit")
    subprocess.run(["git", "-C", str(args.tools), "diff", "--quiet", "HEAD", "--", "."], check=True)
    identity = (args.backup / "identity.txt").read_text(encoding="utf-8-sig").splitlines()
    if identity[:2] != ["NE2213", "NE2213_16.0.3.530(EX01)"]:
        raise ValueError("Backup identity differs from the inspected phone/firmware")
    manifest = json.loads((args.backup / "manifest.json").read_text())
    vendor = args.backup / "vendor_boot_a.img"
    record = next(r for r in manifest if r["partition"] == "vendor_boot_a")
    if vendor.stat().st_size != record["bytes"] or digest(vendor) != record["sha256"]:
        raise ValueError("Stock vendor_boot backup differs from its verified manifest")
    reports = list(args.shim_artifact.rglob("report.json"))
    if len(reports) != 1:
        raise ValueError("Select exactly one audited shim artifact")
    report = json.loads(reports[0].read_text())
    if (not report.get("complete_shim_built") or report.get("internal_storage_uefi_probe_paths_linked") is not False
            or report.get("device_boot_approved") is not False):
        raise ValueError("Expected a complete, unapproved preservation shim")
    for field, relative in (("runtime_policy_sha256", "userland/preservation-shim/preserve_payload.h"),
                            ("preservation_main_sha256", "userland/preservation-shim/main.c")):
        if report.get(field) != digest(REPO / relative, normalize=True):
            raise ValueError("Shim audit does not match current preservation sources: " + field)
    patches = {p.name: digest(p, normalize=True) for p in sorted((REPO / "patches/shim").glob("*.patch"))}
    if report.get("shim_patches") != patches:
        raise ValueError("Shim audit does not match current loader patches")
    image = reports[0].parent / "complete/Image"
    if digest(image) != report["shim_image_sha256"] or image.stat().st_size != report["shim_image_bytes"]:
        raise ValueError("Shim image does not match its audit report")
    root = args.ramroot_artifact
    expected_names = {"root.hfs", "launchd", "negroni.adt", "kernel-ramroot.negronix"}
    names = set()
    for line in (root / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split()
        if name not in expected_names or name in names or digest(root / name) != expected:
            raise ValueError("Invalid RAM-root artifact hash manifest")
        names.add(name)
    if names != expected_names:
        raise ValueError("Incomplete RAM-root artifact")
    payload = root / "kernel-ramroot.negronix"
    payload_report = json.loads((root / "report.json").read_text())
    if (payload_report.get("device_boot_approved") is not False or payload_report.get("ufs_node_present") is not False
            or payload_report.get("root_contains_matching_static_signed_pid1") is not True):
        raise ValueError("RAM-root source evidence is missing required checks")
    output = REPO / "out/preservation-boot-candidate" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    unpack = args.tools / "unpack_bootimg.py"
    stock = output / "stock-vendor"
    (output / "stock-unpack-info.txt").write_text(run_tool(unpack, "--boot_img", vendor, "--out", stock))
    dtb = stock / "dtb"
    with vendor.open("rb") as stream:
        header = stream.read(4096)
        if header[:8] != b"VNDRBOOT" or struct.unpack_from("<I", header, 8)[0] != 4:
            raise ValueError("Expected the inspected v4 vendor boot header")
        page = struct.unpack_from("<I", header, 12)[0]
        vendor_bytes = struct.unpack_from("<I", header, 24)[0]
        header_bytes, dtb_bytes = struct.unpack_from("<II", header, 2096)
        config_bytes = struct.unpack_from("<I", header, 2124)[0]
        if page != 4096 or dtb.stat().st_size != dtb_bytes:
            raise ValueError("Unexpected vendor boot layout")
        stream.seek(align(header_bytes, page))
        prefix = stream.read(vendor_bytes)
        if len(prefix) != vendor_bytes:
            raise ValueError("Truncated vendor ramdisk")
    # Requests only: ABL's actual placement and treatment of a v2 boot must be observed.
    # These ranges fit the recorded System RAM and the firmware's low Kernel workspace.
    base, kernel_offset, ramdisk_offset, dtb_offset = 0xa8000000, 0x8000, 0x1000000, 0x8000000
    combined_max = align(vendor_bytes) + align(payload.stat().st_size) + align(config_bytes + 20) + 4096
    requested = {"shim": (base + kernel_offset, image.stat().st_size),
                 "combined_ramdisk_max": (base + ramdisk_offset, combined_max),
                 "dtb": (base + dtb_offset, dtb_bytes), "legacy_tags": (base + 0x100, 4096)}
    memory = args.memory.read_text()
    banks = [(int(a, 16), int(b, 16) + 1) for a, b in re.findall(r"(?m)^([0-9a-f]+)-([0-9a-f]+) : System RAM$", memory)]
    for name, (address, size) in requested.items():
        if not any(start <= address and address + size <= end for start, end in banks):
            raise ValueError("Requested address is outside recorded System RAM: " + name)
        if not 0xa8000000 <= address < address + size <= 0xb8000000:
            raise ValueError("Requested address leaves the low Kernel workspace: " + name)
    ranges = list(requested.values())
    for i, (address, size) in enumerate(ranges):
        if any(address < other + length and other < address + size for other, length in ranges[:i]):
            raise ValueError("Overlapping requested boot-component addresses")
    boot = output / "UNAPPROVED-ramroot-boot-v2.img"
    run_tool(args.tools / "mkbootimg.py", "--header_version", 2, "--kernel", image,
             "--ramdisk", payload, "--dtb", dtb, "--base", hex(base),
             "--kernel_offset", hex(kernel_offset), "--ramdisk_offset", hex(ramdisk_offset),
             "--dtb_offset", hex(dtb_offset), "--tags_offset", "0x100", "--pagesize", 4096,
             "--os_version", "16.0.0", "--os_patch_level", "2026-06", "--cmdline", "console=null", "-o", boot)
    roundtrip = output / "roundtrip"
    (output / "roundtrip-info.txt").write_text(run_tool(unpack, "--boot_img", boot, "--out", roundtrip))
    for name, original in (("kernel", image), ("ramdisk", payload), ("dtb", dtb)):
        if digest(roundtrip / name) != digest(original):
            raise ValueError("Boot container round-trip mismatch: " + name)
    with boot.open("rb") as stream:
        h = stream.read(1660)
    fields = struct.unpack_from("<10I", h, 8)
    if h[:8] != b"ANDROID!" or fields[8] != 2 or fields[7] != 4096 or fields[1] != requested["shim"][0] or fields[3] != requested["combined_ramdisk_max"][0] or fields[6] != requested["legacy_tags"][0]:
        raise ValueError("Unexpected independent v2 header check")
    if struct.unpack_from("<Q", h, 1652)[0] != requested["dtb"][0]:
        raise ValueError("Unexpected v2 DTB load address")
    # A local-only fixture exercises the runtime locator with the actual vendor prefix.
    fixture = output / "stock-prefix-plus-ramroot.bin"
    fixture.write_bytes(prefix + payload.read_bytes() + bytes(4096))
    result = {"backup_identity": identity, "vendor_backup_sha256": record["sha256"],
              "mkbootimg_commit": pin, "stock_dtb_sha256": digest(dtb), "shim_sha256": digest(image),
              "payload_sha256": digest(payload), "boot_image_sha256": digest(boot),
              "roundtrip_component_hashes_match": True, "requested_ranges": requested,
              "requested_ranges_in_recorded_system_ram": True, "actual_abl_placement_verified": False,
              "runtime_stock_prefix_test_passed": False, "device_boot_approved": False}
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "DO-NOT-BOOT.txt").write_text("Offline candidate only. ABL placement, DTB/ramdisk handoff, display and recovery are unverified. No phone boot is approved.\n")
    print(f"PASS: offline v2 container component hashes, round-trip and requested-range checks: {output}")
    print("No phone was contacted. Candidate is not approved for boot; actual ABL placement is unverified.")


if __name__ == "__main__":
    main()
