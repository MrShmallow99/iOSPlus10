"""Compare a verified GPT capture with observed ABL slot-update conditions. Offline only."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def assess(partitions):
    boots = [p for p in partitions if p["name"] in ("boot_a", "boot_b")]
    if sorted(p["name"] for p in boots) != ["boot_a", "boot_b"]:
        raise ValueError("Expected exactly both boot entries")
    eligible = [p for p in boots if int(p["attributes"], 16) & (1 << 50)
                and ((int(p["attributes"], 16) >> 48) & 3)]
    if not eligible:
        raise ValueError("No unambiguous already-active slot; initialization/fallback requires separate review")
    priority = max((int(p["attributes"], 16) >> 48) & 3 for p in eligible)
    selected = [p for p in eligible if ((int(p["attributes"], 16) >> 48) & 3) == priority]
    if len(selected) != 1:
        raise ValueError("Tied active slot priorities require separate review")
    selected = selected[0]
    suffix = selected["name"][-2:]
    a = int(selected["attributes"], 16)
    changes = []
    for partition in partitions:
        old = int(partition["attributes"], 16)
        new = old | (1 << 50) if partition["name"].endswith(suffix) else old & ~(1 << 50)
        if old != new:
            changes.append(partition["name"])
    unbootable, successful = bool(a & (1 << 55)), bool(a & (1 << 54))
    return {"selected_slot": suffix, "selected_boot_attributes": hex(a),
            "selected_boot_successful": successful, "selected_boot_unbootable": unbootable,
            "clear_unbootable_would_change_boot_attribute": unbootable,
            "active_flag_update_would_change_entries": changes,
            "successful_boot_branch_avoids_retry_decrement": successful and not unbootable,
            "get_active_slot_default_initialization_needed": False,
            "all_bootloader_persistent_effects_audited": False,
            "runtime_write_behavior_verified": False, "device_boot_approved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("gpt", REPO / "scripts/backup/backup-android-gpt.py")
    gpt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gpt)
    gpt.verify(args.capture)
    blob = (args.capture / "manifest.json").read_bytes()
    units = json.loads(blob)
    partitions = [p for unit in units for p in unit.get("partitions", [])]
    report = assess(partitions)
    report.update(gpt_manifest_sha256=hashlib.sha256(blob).hexdigest(), partition_count=len(partitions),
                  phone_contacted=False, source_abl_pe_sha256="2ce7a5ee3cd35357e12b13041aea819fdce2c9feb333e83a400295cb182697db")
    identity = (args.capture / "identity.txt").read_text().splitlines()
    if not identity or report["selected_slot"] != identity[-1]:
        raise ValueError("Selected slot differs from recorded Android slot")
    output = REPO / "out/android-slot-assessment" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Static slot-state assessment: {output}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
