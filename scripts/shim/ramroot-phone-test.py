"""Controlled experimental RAM test for one reviewed candidate. No flash/erase/slot commands.

Preflight only reads Android. Separate enter/boot stages require a recent
successful preflight. Bootloader firmware may have persistent side effects; this
does not claim whole-device read-only execution or production boot approval.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]
CANDIDATE_SHA = "840a921a9ec94d4bab94b0f39498d503b911bd1e642d9323e894c50924ee060c"
MODEL = "NE2213"
FIRMWARE = "NE2213_16.0.3.530(EX01)"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("preflight", "enter", "inspect", "boot", "return-android"))
    parser.add_argument("--adb", default=r"C:\platform-tools\adb.exe")
    parser.add_argument("--fastboot", default=r"C:\platform-tools\fastboot.exe")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--boot-backup", type=Path)
    parser.add_argument("--gpt-backup", type=Path)
    parser.add_argument("--preflight-report", type=Path)
    args = parser.parse_args()
    if (REPO / "config/phone-storage-policy").read_text().strip() != "preserve-android":
        raise ValueError("This controlled test requires the Android-preservation policy")
    target_serial = None
    def adb(*arguments, timeout=30):
        return subprocess.check_output([args.adb, *(["-s", target_serial] if target_serial else []), *arguments], text=True, timeout=timeout).strip()
    def root(command, timeout=30):
        return adb("shell", "su", "-c", "'" + command + "'", timeout=timeout)
    def identity():
        value = adb("shell", "getprop ro.product.model; getprop ro.build.display.id; getprop ro.boot.slot_suffix; getprop ro.boot.flash.locked")
        if value.splitlines() != [MODEL, FIRMWARE, "_a", "0"]:
            raise ValueError("Phone identity/firmware/slot/unlock state changed")
        return value
    def fastboot(*arguments, timeout=30):
        result = subprocess.run([args.fastboot, *(["-s", target_serial] if target_serial else []), *arguments],
                                capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result
    def getvar(name):
        result = fastboot("getvar", name)
        output = result.stdout + result.stderr
        match = re.search(r"(?m)^(?:\(bootloader\)\s*)?" + re.escape(name) + r":\s*(\S+)", output)
        if not match:
            raise ValueError("Bootloader did not report " + name)
        return match[1].lower()
    if args.stage == "preflight":
        if not args.candidate or not args.boot_backup or not args.gpt_backup:
            raise ValueError("Preflight requires candidate, boot backup and GPT backup")
        candidate = args.candidate.resolve()
        if digest(candidate) != CANDIDATE_SHA:
            raise ValueError("This test admits only the reviewed refreshed candidate")
        report = json.loads((candidate.parent / "report.json").read_text())
        if (report.get("boot_image_sha256") != CANDIDATE_SHA
                or report.get("roundtrip_component_hashes_match") is not True
                or report.get("runtime_stock_prefix_test_passed") is not True):
            raise ValueError("Missing candidate host-test evidence")
        if adb("get-state") != "device" or "uid=0(" not in root("id"):
            raise ValueError("One authorized rooted Android device is required")
        target_serial = adb("get-serialno")
        if not target_serial or target_serial in ("unknown", "error"):
            raise ValueError("Cannot bind the temporary test to one physical phone")
        observed_identity = identity()
        if not (args.boot_backup / "COMPLETE.txt").is_file():
            raise ValueError("Boot backup lacks completion marker")
        records = json.loads((args.boot_backup / "manifest.json").read_text())
        expected_names = {f"{name}_{slot}" for slot in "ab" for name in
                          ("boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor", "recovery")}
        if {r["partition"] for r in records} != expected_names or len(records) != len(expected_names):
            raise ValueError("Expected both complete original boot-chain backups")
        for r in records:
            path = args.boot_backup / (r["partition"] + ".img")
            if path.stat().st_size != r["bytes"] or digest(path) != r["sha256"]:
                raise ValueError("Saved boot backup failed verification")
        expected_hashes = {r["partition"]: r["sha256"] for r in records}
        result = root("sha256sum " + " ".join("/dev/block/by-name/" + n for n in sorted(expected_names)), timeout=120)
        current = {}
        for line in result.splitlines():
            sha, path = line.split()
            current[path.rsplit("/", 1)[-1]] = sha
        if current != expected_hashes:
            raise ValueError("Current phone boot-chain hashes differ from saved backups")
        spec = importlib.util.spec_from_file_location("gpt", REPO / "scripts/backup/backup-android-gpt.py")
        gpt = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gpt)
        gpt.verify(args.gpt_backup)
        units = json.loads((args.gpt_backup / "manifest.json").read_text())
        commands, hashes = [], []
        for unit in units:
            name, sector = unit["lun"], unit["sector_size"]
            if name not in {"sd" + c for c in "abcdefgh"} or sector not in (512, 4096):
                raise ValueError("Invalid fixed UFS LUN read")
            for r in unit["reads"]:
                lba, count = r["lba"], r["blocks"]
                if not isinstance(lba, int) or not isinstance(count, int) or lba < 0 or not 0 < count <= 2048:
                    raise ValueError("Invalid GPT read bounds")
                commands.append(f"dd if=/dev/block/{name} bs={sector} skip={lba} count={count} 2>/dev/null | sha256sum")
                hashes.append(r["sha256"])
        current_gpt = [line.split()[0] for line in root("\n".join(commands), timeout=120).splitlines()]
        if current_gpt != hashes:
            raise ValueError("Current GPT differs from verified saved metadata")
        identity()
        output = REPO / "out/phone-ram-test" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        output.mkdir(parents=True, exist_ok=False)
        state = {"timestamp": time.time(), "identity": observed_identity.splitlines(),
                 "transport_serial": target_serial,
                 "candidate": str(candidate), "candidate_sha256": CANDIDATE_SHA,
                 "boot_backup": str(args.boot_backup.resolve()), "gpt_backup": str(args.gpt_backup.resolve()),
                 "boot_chain_hashes_match": True, "all_gpt_region_hashes_match": True,
                 "phone_rebooted": False, "partition_flash_or_slot_change_performed": False}
        (output / "preflight.json").write_text(json.dumps(state, indent=2) + "\n")
        print(f"PASS: current identity, both boot chains and all saved GPT regions match: {output / 'preflight.json'}")
        return
    if not args.preflight_report:
        raise ValueError("A recent successful preflight report is required")
    path = args.preflight_report.resolve()
    state = json.loads(path.read_text())
    target_serial = state["transport_serial"]
    if (not 0 <= time.time() - state["timestamp"] <= 900 or not state["boot_chain_hashes_match"]
            or not state["all_gpt_region_hashes_match"] or state["candidate_sha256"] != CANDIDATE_SHA):
        raise ValueError("Preflight is stale or failed")
    candidate = Path(state["candidate"])
    if digest(candidate) != CANDIDATE_SHA:
        raise ValueError("Candidate changed after preflight")
    if args.stage == "enter":
        identity()
        adb("reboot", "bootloader")
        (path.parent / "entered-bootloader.json").write_text(json.dumps({"timestamp": time.time()}) + "\n")
        print("Requested bootloader entry. No flash/erase/slot command was issued.")
        return
    observed = {name: getvar(name) for name in ("current-slot", "is-userspace")}
    if observed["current-slot"] != "a" or observed["is-userspace"] not in ("no", "false"):
        raise ValueError("Expected hardware bootloader on slot A")
    if args.stage == "return-android":
        r = fastboot("reboot")
    else:
        observed.update({name: getvar(name) for name in ("unlocked", "slot-successful:a", "slot-unbootable:a", "max-download-size")})
        if observed["unlocked"] not in ("yes", "true"):
            raise ValueError("Bootloader is not unlocked")
        if observed["slot-successful:a"] not in ("yes", "true") or observed["slot-unbootable:a"] not in ("no", "false"):
            raise ValueError("Active slot state differs from the reviewed successful state")
        if int(observed["max-download-size"], 0) < candidate.stat().st_size:
            raise ValueError("Candidate exceeds the bootloader download buffer")
        (path.parent / "bootloader-state.json").write_text(json.dumps(observed, indent=2) + "\n")
        if args.stage == "inspect":
            print(json.dumps(observed, indent=2))
            return
        # Windows fastboot needs a Windows path when invoked from WSL.
        image_path = str(candidate)
        if args.fastboot.endswith(".exe") and image_path.startswith("/mnt/"):
            image_path = subprocess.check_output(["wslpath", "-w", image_path], text=True).strip()
        r = fastboot("boot", image_path, timeout=90)
    (path.parent / (args.stage + ".log")).write_text(r.stdout + r.stderr)
    print(r.stdout + r.stderr)
    print("Only the selected RAM-boot/reboot command was issued; no flash/erase/slot command.")


if __name__ == "__main__":
    main()
