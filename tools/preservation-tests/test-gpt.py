"""Test GPT metadata bounds/CRCs with synthetic sectors. No phone or private data."""
import importlib.util
from pathlib import Path
import struct
import zlib

REPO = Path(__file__).resolve().parents[2]


def main():
    spec = importlib.util.spec_from_file_location("gpt", REPO / "scripts/backup/backup-android-gpt.py")
    gpt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gpt)
    entry = bytearray(128)
    entry[:16], entry[16:32] = bytes(range(16)), bytes(range(16, 32))
    struct.pack_into("<3Q", entry, 32, 34, 100, 0x77000000000000)
    entry[56:68] = "boot_a".encode("utf-16-le")
    table = entry + bytes(512 - len(entry))
    h = bytearray(512)
    h[:8] = b"EFI PART"
    struct.pack_into("<III", h, 8, 0x10000, 92, 0)
    struct.pack_into("<4Q", h, 24, 1, 4095, 34, 4093)
    struct.pack_into("<QIII", h, 72, 2, 1, 128, zlib.crc32(entry))
    def checksum(blob):
        struct.pack_into("<I", blob, 16, 0)
        struct.pack_into("<I", blob, 16, zlib.crc32(blob[:92]))
    checksum(h)
    parsed = gpt.header(h, 512, 4096, 1)
    assert gpt.entries(table, parsed)[0]["name"] == "boot_a"
    assert not gpt.entries(table, parsed)[0]["unbootable_bit55"]
    def rejects(operation):
        try:
            operation()
        except ValueError:
            return
        raise AssertionError("Accepted invalid GPT metadata")
    rejects(lambda: gpt.header(h[:-1], 512, 4096, 1))
    damaged = bytearray(h)
    damaged[20] ^= 1
    rejects(lambda: gpt.header(damaged, 512, 4096, 1))
    bad_table = bytearray(table)
    bad_table[48] ^= 1
    rejects(lambda: gpt.entries(bad_table, parsed))
    for offset, value in ((40, 4094), (72, 34)):
        damaged = bytearray(h)
        struct.pack_into("<Q", damaged, offset, value)
        checksum(damaged)
        rejects(lambda: gpt.header(damaged, 512, 4096, 1))
    bad_table = bytearray(table)
    struct.pack_into("<Q", bad_table, 32, 20)
    changed = dict(parsed, entries_crc32=zlib.crc32(bad_table[:128]))
    rejects(lambda: gpt.entries(bad_table, changed))
    print("PASS: GPT CRC, truncation, usable-range and metadata-overlap rejection; no phone access")


if __name__ == "__main__":
    main()
