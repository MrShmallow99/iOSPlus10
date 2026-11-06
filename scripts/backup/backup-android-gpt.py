"""Copy primary/backup GPT metadata from fixed Android UFS LUNs. Read-only; no reboot."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zlib

REPO = Path(__file__).resolve().parents[2]


def header(blob, sector, sectors, expected_lba):
    if len(blob) != sector or blob[:8] != b"EFI PART":
        raise ValueError("Missing GPT header")
    revision, size, crc = struct.unpack_from("<III", blob, 8)
    if revision != 0x10000 or not 92 <= size <= sector:
        raise ValueError("Unsupported GPT revision/header size")
    checked = bytearray(blob[:size])
    checked[16:20] = bytes(4)
    if zlib.crc32(checked) != crc:
        raise ValueError("GPT header CRC mismatch")
    current, alternate, first, last = struct.unpack_from("<4Q", blob, 24)
    table, count, stride, entries_crc = struct.unpack_from("<QIII", blob, 72)
    length = count * stride
    blocks = (length + sector - 1) // sector
    if (current != expected_lba or alternate != (sectors - 1 if current == 1 else 1)
            or not 2 <= first <= last < sectors - 1
            or not 0 < count <= 4096 or not 128 <= stride <= 1024 or stride % 8
            or length > 1024**2 or table < 2 or table + blocks > sectors - 1):
        raise ValueError("Invalid GPT geometry")
    if current == 1 and table + blocks > first:
        raise ValueError("Primary GPT table overlaps usable storage")
    if current != 1 and table <= last:
        raise ValueError("Backup GPT table overlaps usable storage")
    return {"current_lba": current, "alternate_lba": alternate, "first_usable": first,
            "last_usable": last, "entry_lba": table, "entry_count": count,
            "entry_size": stride, "entry_bytes": length, "entry_blocks": blocks,
            "entries_crc32": entries_crc}


def entries(blob, h):
    table = blob[:h["entry_bytes"]]
    if zlib.crc32(table) != h["entries_crc32"]:
        raise ValueError("GPT entry-array CRC mismatch")
    result = []
    for index in range(h["entry_count"]):
        entry = table[index * h["entry_size"]:(index + 1) * h["entry_size"]]
        if entry[:16] == bytes(16):
            continue
        first, last, attributes = struct.unpack_from("<3Q", entry, 32)
        if not h["first_usable"] <= first <= last <= h["last_usable"]:
            raise ValueError("GPT partition leaves usable range")
        name = entry[56:128].decode("utf-16-le").split("\0", 1)[0]
        result.append({"index": index, "name": name, "first_lba": first, "last_lba": last,
                       "attributes": hex(attributes), "unbootable_bit55": bool(attributes & (1 << 55))})
    return result


def verify(folder):
    if not (folder / "COMPLETE.txt").is_file():
        raise ValueError("GPT capture has no completion marker")
    units = json.loads((folder / "manifest.json").read_text())
    allowed = {"primary-header.bin", "backup-header.bin", "primary-entries.bin", "backup-entries.bin", "protective-mbr.bin"}
    for unit in units:
        name = unit["lun"]
        if name not in {"sd" + letter for letter in "abcdefgh"}:
            raise ValueError("Invalid captured LUN name")
        sector, size = unit["sector_size"], unit["bytes"]
        if sector not in (512, 4096) or size % sector:
            raise ValueError("Invalid captured LUN geometry")
        names = []
        for record in unit["reads"]:
            filename = record["file"]
            if filename not in allowed or filename in names:
                raise ValueError("Unexpected/duplicate GPT metadata file")
            names.append(filename)
            blob = (folder / name / filename).read_bytes()
            if len(blob) != record["blocks"] * sector or hashlib.sha256(blob).hexdigest() != record["sha256"]:
                raise ValueError("Saved GPT metadata differs from manifest")
        if unit["gpt_present"]:
            if set(names) != allowed:
                raise ValueError("Incomplete GPT metadata file set")
            base = folder / name
            p = header((base / "primary-header.bin").read_bytes(), sector, size // sector, 1)
            b = header((base / "backup-header.bin").read_bytes(), sector, size // sector, size // sector - 1)
            if p != unit["primary"] or b != unit["backup"]:
                raise ValueError("Saved GPT header differs from manifest")
            if (entries((base / "primary-entries.bin").read_bytes(), p) != unit["partitions"]
                    or entries((base / "backup-entries.bin").read_bytes(), b) != unit["partitions"]):
                raise ValueError("Saved GPT entries differ from manifest")
    print(f"PASS: saved GPT hashes, geometry, header CRCs and entry CRCs for {len(units)} LUNs; no phone access")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=r"C:\platform-tools\adb.exe")
    parser.add_argument("--verify", type=Path, help="Verify an existing capture offline; no ADB use")
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
        return
    def text(*arguments):
        return subprocess.check_output([args.adb, *arguments], text=True, timeout=30).strip()
    def root(command):
        return text("shell", "su", "-c", "'" + command + "'")
    if text("get-state") != "device" or "uid=0(" not in root("id"):
        raise ValueError("One authorized rooted Android device is required")
    identity = text("shell", "getprop ro.product.model; getprop ro.build.display.id; getprop ro.boot.slot_suffix")
    if identity.splitlines()[:2] != ["NE2213", "NE2213_16.0.3.530(EX01)"]:
        raise ValueError("Connected device differs from this owner's inspected phone")
    output = REPO / "out/android-gpt" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    (output / "identity.txt").write_text(identity + "\n")
    units = []
    for letter in "abcdefgh":
        device, name = "/dev/block/sd" + letter, "sd" + letter
        if root(f"if [ -b {device} ]; then echo present; fi") != "present":
            continue
        sector, size = int(root("blockdev --getss " + device)), int(root("blockdev --getsize64 " + device))
        if sector not in (512, 4096) or size % sector or size // sector < 34:
            raise ValueError("Unexpected UFS LUN geometry")
        sectors = size // sector
        folder = output / name
        folder.mkdir()
        reads = []
        def copy(label, lba, blocks):
            if not 0 <= lba < sectors or not 0 < blocks <= 2048 or lba + blocks > sectors:
                raise ValueError("Read leaves LUN bounds")
            # adb exec-out can merge remote stderr into stdout. Suppress dd's
            # statistics in the remote shell, then verify exact bytes and hashes.
            command = f"dd if={device} bs={sector} skip={lba} count={blocks} 2>/dev/null"
            before = root(command + " | sha256sum").split()[0]
            path = folder / (label + ".bin")
            with path.open("xb") as stream, (folder / (label + ".stderr.txt")).open("xb") as errors:
                subprocess.run([args.adb, "exec-out", "su", "-c", command], stdout=stream,
                               stderr=errors, check=True, timeout=30)
            data = path.read_bytes()
            after = root(command + " | sha256sum").split()[0]
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != blocks * sector or digest != before or digest != after:
                raise ValueError("Incomplete or changing GPT read: " + label)
            reads.append({"file": path.name, "lba": lba, "blocks": blocks, "sha256": digest})
            return data
        print(f"Reading GPT metadata from {name}...", flush=True)
        primary = copy("primary-header", 1, 1)
        if primary[:8] != b"EFI PART":
            units.append({"lun": name, "bytes": size, "sector_size": sector,
                          "gpt_present": False, "reads": reads})
            continue
        p = header(primary, sector, sectors, 1)
        backup = copy("backup-header", sectors - 1, 1)
        b = header(backup, sector, sectors, sectors - 1)
        if (primary[56:72] != backup[56:72] or p["first_usable"] != b["first_usable"]
                or p["last_usable"] != b["last_usable"] or p["entry_count"] != b["entry_count"]
                or p["entry_size"] != b["entry_size"]):
            raise ValueError("Primary and backup GPT geometry differ")
        pt = copy("primary-entries", p["entry_lba"], p["entry_blocks"])
        bt = copy("backup-entries", b["entry_lba"], b["entry_blocks"])
        partitions = entries(pt, p)
        if entries(bt, b) != partitions or pt[:p["entry_bytes"]] != bt[:b["entry_bytes"]]:
            raise ValueError("Primary and backup GPT entries differ")
        copy("protective-mbr", 0, 1)
        units.append({"lun": name, "bytes": size, "sector_size": sector,
                      "gpt_present": True, "primary": p, "backup": b,
                      "partitions": partitions, "reads": reads})
        (output / "manifest.json").write_text(json.dumps(units, indent=2) + "\n")
    if not any(unit["gpt_present"] for unit in units):
        raise ValueError("No GPT-bearing LUNs found")
    (output / "manifest.json").write_text(json.dumps(units, indent=2) + "\n")
    (output / "COMPLETE.txt").write_text("GPT metadata copied with size, before/after SHA and CRC checks. No phone writes/reboots. Not an app-data backup or restoration test.\n")
    print(f"Verified read-only GPT metadata copies: {output}")
    for unit in units:
        for partition in unit.get("partitions", []):
            if partition["name"] in ("boot_a", "boot_b"):
                print(unit["lun"], partition["name"], partition["attributes"], "unbootable", partition["unbootable_bit55"])


if __name__ == "__main__":
    main()
