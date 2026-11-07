"""Static transcription of this phone's ABL raw ARM64 placement calculation.

This is a model, not execution of ABL or verification of temporary-boot placement.
Source: active A PE SHA256 2ce7a5ee3cd35357e12b13041aea819fdce2c9feb333e83a400295cb182697db,
FUN_00023460 (allocation), FUN_00022bd0 (sizes), FUN_00024b80 (legacy ramdisk).
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct

REPO = Path(__file__).resolve().parents[2]
ABL_SHA = "2ce7a5ee3cd35357e12b13041aea819fdce2c9feb333e83a400295cb182697db"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def raw_arm64_layout(image_header, image_bytes, ramdisk_bytes, page, region_base, region_size):
    if len(image_header) < 64 or image_header[56:60] != b"ARM\x64":
        raise ValueError("Model admits only raw ARM64 Linux Images")
    text_offset, runtime_bytes = struct.unpack_from("<QQ", image_header, 8)
    if (page != 4096 or runtime_bytes == 0 or text_offset % 4096
            or not 0 < image_bytes < 256 * 1024**2 or not 0 < ramdisk_bytes < 512 * 1024**2
            or not 0x80000000 <= region_base < region_base + region_size <= 0xb8000000):
        raise ValueError("Unsupported or invalid placement-model inputs")
    kernel = region_base + text_offset
    ramdisk = region_base + region_size - (((ramdisk_bytes + page - 1) & -page) + page)
    dtb = ramdisk - (0x200000 + page)
    if not region_base <= kernel < kernel + max(runtime_bytes, image_bytes) <= dtb < ramdisk < region_base + region_size:
        raise ValueError("ABL model leaves insufficient nonoverlapping load space")
    return {"shim": kernel, "ramdisk": ramdisk, "dtb": dtb,
            "successful_firmware_query_path_only": True,
            "ramdisk_end": ramdisk + ramdisk_bytes, "dtb_reserved_bytes": 0x200000,
            "ramdisk_file_bytes": ramdisk_bytes,
            "image_runtime_bytes": runtime_bytes, "image_file_bytes": image_bytes, "image_text_offset": text_offset,
            "header_requested_addresses_used": False, "legacy_vendor_prefix_used": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-backup", type=Path, required=True)
    parser.add_argument("--live-fdt", type=Path, required=True)
    parser.add_argument("--abl-pe", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--memory", type=Path, default=REPO / "out/android-inventory/memory.txt")
    args = parser.parse_args()
    if digest(args.abl_pe) != ABL_SHA:
        raise ValueError("Model is tied to the inspected active-A bootloader PE")
    if not (args.stock_backup / "COMPLETE.txt").is_file():
        raise ValueError("Stock boot-chain backup is incomplete")
    manifest = json.loads((args.stock_backup / "manifest.json").read_text())
    provenance = {}
    for name in ("boot_a", "vendor_boot_a"):
        path = args.stock_backup / (name + ".img")
        record = next(r for r in manifest if r["partition"] == name)
        if path.stat().st_size != record["bytes"] or digest(path) != record["sha256"]:
            raise ValueError("Stock backup digest mismatch")
        provenance[name] = record["sha256"]
    with (args.stock_backup / "boot_a.img").open("rb") as stream:
        boot = stream.read(4096)
        stream.seek(4096)
        image = stream.read(64)
    with (args.stock_backup / "vendor_boot_a.img").open("rb") as stream:
        vendor = stream.read(4096)
    if (boot[:8] != b"ANDROID!" or struct.unpack_from("<I", boot, 40)[0] != 4
            or vendor[:8] != b"VNDRBOOT" or struct.unpack_from("<I", vendor, 8)[0] != 4
            or image[56:60] != b"ARM\x64" or struct.unpack_from("<Q", image, 16)[0] == 0):
        raise ValueError("Expected the inspected raw ARM64 stock v4 boot profile")
    page = struct.unpack_from("<I", vendor, 12)[0]
    if page != 4096:
        raise ValueError("Unexpected stock page size")
    raw_ramdisk = struct.unpack_from("<I", boot, 12)[0] + struct.unpack_from("<I", vendor, 24)[0]
    spec = importlib.util.spec_from_file_location("handoff", REPO / "scripts/backup/inspect-android-handoff.py")
    handoff = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(handoff)
    live = handoff.summary(args.live_fdt.read_bytes())
    rd_start = int(live["chosen_addresses"]["linux,initrd-start"], 16)
    rd_end = int(live["chosen_addresses"]["linux,initrd-end"], 16)
    code = re.findall(r"(?m)^\s*([0-9a-f]+)-[0-9a-f]+ : Kernel code$", args.memory.read_text())
    if len(code) != 1:
        raise ValueError("Expected one measured stock kernel code range")
    # Inferred from observed Android placement and the inspected raw ARM64 path.
    # The firmware variables themselves have not been read, and ABL is not run.
    base = int(code[0], 16) - struct.unpack_from("<Q", image, 8)[0]
    end = rd_start + ((raw_ramdisk + page - 1) & -page) + page
    if not rd_start + raw_ramdisk <= rd_end <= end:
        raise ValueError("Live initrd does not fit the stock allocation model")
    stock = raw_arm64_layout(image, struct.unpack_from("<I", boot, 8)[0], raw_ramdisk, page, base, end - base)
    if stock["ramdisk"] != rd_start or stock["shim"] != int(code[0], 16):
        raise ValueError("Stock observations do not match the inferred region")
    with args.candidate.open("rb") as stream:
        header = stream.read(1660)
        if header[:8] != b"ANDROID!" or struct.unpack_from("<I", header, 40)[0] != 2:
            raise ValueError("Select the offline legacy v2 candidate")
        cp = struct.unpack_from("<I", header, 36)[0]
        stream.seek(cp)
        ci = stream.read(64)
    kernel_size, ramdisk_size = struct.unpack_from("<I", header, 8)[0], struct.unpack_from("<I", header, 16)[0]
    candidate = raw_arm64_layout(ci, kernel_size, ramdisk_size, cp, base, end - base)
    report = {"abl_pe_sha256": ABL_SHA, "stock_backup_sha256": provenance,
              "live_fdt_sha256": live["fdt_sha256"], "memory_capture_sha256": digest(args.memory),
              "candidate_sha256": digest(args.candidate), "firmware_region_base_inferred": base,
              "firmware_region_size_inferred": end - base, "stock_layout": stock,
              "stock_live_ramdisk_end": rd_end, "candidate_layout": candidate,
              "candidate_requested_addresses": {"shim": struct.unpack_from("<I", header, 12)[0],
                                                "ramdisk": struct.unpack_from("<I", header, 20)[0],
                                                "dtb": struct.unpack_from("<Q", header, 1652)[0]},
              "firmware_variables_read": False, "abl_executed": False,
              "fallback_placement_modeled": False,
              "actual_temporary_boot_placement_verified": False, "device_boot_approved": False}
    output = REPO / "out/abl-layout" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Static ABL layout model: {output}")
    print("Inferred stock firmware region:", hex(base), hex(end - base))
    print("Candidate modeled addresses:", {k: hex(candidate[k]) for k in ("shim", "ramdisk", "dtb")})
    print("No ABL execution or phone contact; temporary-boot placement remains unverified.")


if __name__ == "__main__":
    main()
