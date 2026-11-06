"""Capture Android's live FDT read-only, or inspect a saved FDT. Never reboots/writes the phone."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess

REPO = Path(__file__).resolve().parents[2]


def properties(blob, locations=False):
    if len(blob) < 40:
        raise ValueError("Truncated FDT header")
    magic, total, structure, strings, reserve, version, compatible, cpu, ns, nt = struct.unpack_from(">10I", blob)
    if (magic != 0xd00dfeed or not 40 <= total <= len(blob) <= 8 * 1024**2
            or version < 17 or compatible > 17 or structure % 4
            or not 40 <= structure <= structure + nt <= total
            or not 40 <= strings <= strings + ns <= total):
        raise ValueError("Invalid FDT header/ranges")
    names, end = blob[strings:strings + ns], structure + nt
    at, stack, found, ranges = structure, [], {}, {}
    def string(data, position, limit):
        stop = data.find(b"\0", position, limit)
        if stop < 0:
            raise ValueError("Unterminated FDT string")
        return data[position:stop].decode("ascii"), stop + 1
    while at + 4 <= end:
        token = struct.unpack_from(">I", blob, at)[0]
        at += 4
        if token == 1:
            name, at = string(blob, at, end)
            if len(stack) >= 64 or (not stack and name):
                raise ValueError("Invalid FDT root/depth")
            stack.append(name)
            at = (at + 3) & ~3
        elif token == 2:
            if not stack:
                raise ValueError("Unbalanced FDT nodes")
            stack.pop()
        elif token == 3:
            if not stack or at + 8 > end:
                raise ValueError("Invalid FDT property header")
            size, name = struct.unpack_from(">II", blob, at)
            at += 8
            if at + size > end or name >= len(names):
                raise ValueError("Out-of-bounds FDT property")
            name, _ = string(names, name, len(names))
            key = ("/" + "/".join(stack[1:]), name)
            if key in found:
                raise ValueError("Duplicate FDT property")
            found[key] = blob[at:at + size]
            ranges[key] = (at, size)
            at = (at + size + 3) & ~3
        elif token == 9:
            if stack:
                raise ValueError("FDT ended with open nodes")
            return ranges if locations else found
        elif token != 4:
            raise ValueError("Unknown FDT token")
    raise ValueError("Missing FDT end token")


def summary(blob):
    props = properties(blob)
    chosen = {}
    for name in ("linux,initrd-start", "linux,initrd-end"):
        value = props.get(("/chosen", name))
        if value is not None:
            if len(value) not in (4, 8):
                raise ValueError("Unexpected chosen address width")
            chosen[name] = hex(int.from_bytes(value, "big"))
    ac = int.from_bytes(props.get(("/", "#address-cells"), b"\0\0\0\2"), "big")
    sc = int.from_bytes(props.get(("/", "#size-cells"), b"\0\0\0\1"), "big")
    if ac not in (1, 2) or sc not in (1, 2):
        raise ValueError("Unexpected root cell counts")
    memory = []
    for (path, name), value in props.items():
        if path.count("/") == 1 and path.split("/")[-1].split("@")[0] == "memory" and name == "reg":
            width = 4 * (ac + sc)
            if len(value) % width:
                raise ValueError("Truncated memory bank")
            for at in range(0, len(value), width):
                memory.append({"base": hex(int.from_bytes(value[at:at + 4 * ac], "big")),
                               "size": hex(int.from_bytes(value[at + 4 * ac:at + width], "big"))})
    return {"fdt_sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob),
            "chosen_addresses": chosen, "memory_banks": memory,
            "bootargs_contents_omitted": True, "actual_temporary_boot_placement_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=r"C:\platform-tools\adb.exe")
    parser.add_argument("--input", type=Path, help="Inspect a saved single FDT without contacting a phone")
    args = parser.parse_args()
    output = REPO / "out/android-handoff" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    if args.input:
        blob = args.input.read_bytes()
    else:
        def text(*arguments):
            return subprocess.check_output([args.adb, *arguments], text=True, timeout=20).strip()
        if text("get-state") != "device":
            raise ValueError("One authorized Android device is required")
        identity = text("shell", "getprop ro.product.model; getprop ro.build.display.id; getprop ro.boot.slot_suffix")
        if identity.splitlines()[:2] != ["NE2213", "NE2213_16.0.3.530(EX01)"]:
            raise ValueError("Connected phone differs from the inspected owner device")
        def root(command):
            return text("shell", "su", "-c", "'" + command + "'")
        if "uid=0(" not in root("id"):
            raise ValueError("Root access is unavailable")
        before = root("sha256sum /sys/firmware/fdt").split()[0]
        target = output / "live-fdt.dtb"
        with target.open("xb") as stream, (output / "capture.stderr.txt").open("xb") as errors:
            subprocess.run([args.adb, "exec-out", "su", "-c", "cat /sys/firmware/fdt"],
                           stdout=stream, stderr=errors, check=True, timeout=20)
        blob = target.read_bytes()
        after = root("sha256sum /sys/firmware/fdt").split()[0]
        if before != after or hashlib.sha256(blob).hexdigest() != before:
            raise ValueError("FDT capture digest mismatch")
        (output / "identity.txt").write_text(identity + "\n")
    report = summary(blob)
    report.update(phone_contacted=not bool(args.input), phone_writes_or_reboots=False)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Read-only handoff evidence: {output}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
