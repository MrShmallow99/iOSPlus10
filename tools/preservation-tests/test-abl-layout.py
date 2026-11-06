"""Check static layout arithmetic against stock observations and failure bounds."""
import importlib.util
from pathlib import Path
import struct

REPO = Path(__file__).resolve().parents[2]


def main():
    spec = importlib.util.spec_from_file_location("abl_layout", REPO / "scripts/shim/abl_layout.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    h = bytearray(64)
    h[56:60] = b"ARM\x64"
    struct.pack_into("<QQ", h, 8, 0, 0x2bc0000)
    stock = model.raw_arm64_layout(h, 0x2de2b3c, 0x16f1a45, 4096, 0xa8000000, 0x10000000)
    assert stock["shim"] == 0xa8000000
    assert stock["ramdisk"] == 0xb690d000  # Observed in the running stock Android FDT.
    assert stock["image_file_bytes"] > stock["image_runtime_bytes"]  # Stock GKI trailer admitted.
    struct.pack_into("<Q", h, 16, 81920)
    legacy = model.raw_arm64_layout(h, 81920, 51673856, 4096, 0xa8000000, 0x10000000)
    assert legacy["ramdisk"] == 0xb4eb7000 and legacy["dtb"] == 0xb4cb6000
    assert not legacy["header_requested_addresses_used"] and not legacy["legacy_vendor_prefix_used"]
    def rejects(header, image=81920, ramdisk=51673856, page=4096, base=0xa8000000, size=0x10000000):
        try:
            model.raw_arm64_layout(header, image, ramdisk, page, base, size)
        except ValueError:
            return
        raise AssertionError("Accepted an unsafe/unsupported model input")
    rejects(h[:63])
    bad = bytearray(h)
    bad[56] = 0
    rejects(bad)
    rejects(h, page=8192)
    rejects(h, ramdisk=0x10000000)
    rejects(h, size=0x1000)
    rejects(h, base=0xb8000000)
    struct.pack_into("<Q", h, 8, 1)
    rejects(h)
    struct.pack_into("<QQ", h, 8, 0, 0)
    rejects(h)
    print("PASS: model reproduces observed stock placement, legacy layout and bounds rejection")
    print("Static model only; ABL was not executed and no phone was contacted")


if __name__ == "__main__":
    main()
