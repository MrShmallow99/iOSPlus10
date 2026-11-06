"""Check static slot assessment against matching and changing metadata states."""
import copy
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def main():
    spec = importlib.util.spec_from_file_location("slot", REPO / "scripts/backup/assess-android-slot-state.py")
    slot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(slot)
    base = [{"name": "boot_a", "attributes": "0x77000000000000"},
            {"name": "boot_b", "attributes": "0xfb000000000000"},
            {"name": "persist", "attributes": "0x0"}]
    ok = slot.assess(base)
    assert ok["selected_slot"] == "_a" and ok["successful_boot_branch_avoids_retry_decrement"]
    assert not ok["clear_unbootable_would_change_boot_attribute"]
    assert ok["active_flag_update_would_change_entries"] == []
    assert not ok["device_boot_approved"] and not ok["runtime_write_behavior_verified"]
    def change(items, index, bit, enabled):
        old = int(items[index]["attributes"], 16)
        items[index]["attributes"] = hex(old | (1 << bit) if enabled else old & ~(1 << bit))
    changed = copy.deepcopy(base)
    change(changed, 0, 55, True)
    r = slot.assess(changed)
    assert r["clear_unbootable_would_change_boot_attribute"] and not r["successful_boot_branch_avoids_retry_decrement"]
    changed = copy.deepcopy(base)
    change(changed, 2, 50, True)
    assert slot.assess(changed)["active_flag_update_would_change_entries"] == ["persist"]
    changed = copy.deepcopy(base)
    change(changed, 0, 54, False)
    assert not slot.assess(changed)["successful_boot_branch_avoids_retry_decrement"]
    def rejects(items):
        try:
            slot.assess(items)
        except ValueError:
            return
        raise AssertionError("Accepted missing/ambiguous active slot")
    rejects(base[:1])
    changed = copy.deepcopy(base)
    change(changed, 0, 50, False)
    rejects(changed)
    changed = copy.deepcopy(base)
    change(changed, 1, 50, True)
    rejects(changed)
    print("PASS: static slot model distinguishes no-op, attribute changes and ambiguous state; no phone access")


if __name__ == "__main__":
    main()
