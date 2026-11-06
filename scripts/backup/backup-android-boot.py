"""Read boot-chain partitions to the host; never writes or reboots the phone."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

BOOT_PARTITIONS = tuple(f"{name}_{slot}" for slot in "ab" for name in (
    "boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor", "recovery"
))
ABL_PARTITIONS = ("abl_a", "abl_b")
PARTITIONS = BOOT_PARTITIONS + ABL_PARTITIONS


def text(adb, *args):
    return subprocess.run([adb, *args], check=True, capture_output=True, text=True).stdout.strip()


def root(adb, command):
    # Commands contain only fixed partition names and literals from this file.
    return text(adb, "shell", "su", "-c", "'" + command + "'")


def copy_partition(adb, name, destination):
    if name not in PARTITIONS:
        raise ValueError("Partition is outside the boot-chain allowlist")
    device_path = "/dev/block/by-name/" + name
    expected_size = int(root(adb, "blockdev --getsize64 " + device_path))
    if not 0 < expected_size <= 512 * 1024 * 1024:
        raise ValueError(f"Unexpected partition size for {name}: {expected_size}")
    before = root(adb, "sha256sum " + device_path).split()[0].lower()
    if len(before) != 64 or any(c not in "0123456789abcdef" for c in before):
        raise ValueError("Invalid device SHA-256")
    image = destination / (name + ".img")
    # Stream raw bytes directly to a file: no Windows PowerShell text pipeline.
    with image.open("xb") as stream, (destination / (name + ".stderr.txt")).open("xb") as errors:
        # exec-out preserves this argument; shell's extra literal quotes would
        # make su try to execute a program named "cat /dev/block/...".
        subprocess.run([adb, "exec-out", "su", "-c", "cat " + device_path],
                       stdout=stream, stderr=errors, check=True)
    if image.stat().st_size != expected_size:
        raise ValueError(f"Incomplete image: {name}: expected {expected_size} bytes, got {image.stat().st_size}; saved in {image}")
    with image.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    after = root(adb, "sha256sum " + device_path).split()[0].lower()
    if actual != before or actual != after:
        raise ValueError(f"Hash mismatch or changing partition: {name}")
    return {"partition": name, "bytes": expected_size, "sha256": actual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=r"C:\platform-tools\adb.exe")
    parser.add_argument("--abl-only", action="store_true", help="Read only both ABL images for offline firmware analysis")
    args = parser.parse_args()
    adb = args.adb
    if text(adb, "get-state") != "device":
        raise RuntimeError("One authorized Android device is required")
    if "uid=0(" not in root(adb, "id"):
        raise RuntimeError("Approve Magisk root access for shell and retry")
    repo = Path(__file__).resolve().parents[2]
    destination = repo / "out" / "android-backup" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    if shutil.disk_usage(destination).free < 3 * 1024**3:
        raise RuntimeError("At least 3 GiB of host free space is required")
    identity = text(adb, "shell", "getprop ro.product.model; getprop ro.build.display.id; getprop ro.boot.slot_suffix")
    if args.abl_only and identity.splitlines()[:2] != ["NE2213", "NE2213_16.0.3.530(EX01)"]:
        raise ValueError("ABL capture identity differs from the inspected owner device")
    (destination / "identity.txt").write_text(identity + "\n", encoding="utf-8")
    records = []
    for name in (ABL_PARTITIONS if args.abl_only else BOOT_PARTITIONS):
        print(f"Reading and verifying {name}...", flush=True)
        records.append(copy_partition(adb, name, destination))
        # Only verified images enter the manifest. A failed run has no COMPLETE marker.
        (destination / "manifest.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (destination / "COMPLETE.txt").write_text(
        "Boot-chain copies verified against device hashes before and after each read.\n"
        "Not a backup of apps, user files, unique partitions, GPT, or the full firmware.\n"
        "Restoration has not been tested. No device writes were performed.\n", encoding="utf-8")
    print(f"Verified boot-chain backup: {destination}")
    print("Android apps and user files are NOT included. No phone writes or reboots performed.")


if __name__ == "__main__":
    main()
