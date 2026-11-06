"""Resolve and disassemble an address in the experimental ARM64 Mach-O. Host only."""
import argparse
from pathlib import Path
import struct
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("address", type=lambda value: int(value, 0))
    args = parser.parse_args()
    blob = args.kernel.read_bytes()
    if blob[:4] != bytes.fromhex("cffaedfe"):
        raise ValueError("Expected little-endian 64-bit Mach-O")
    segments, symbols = [], []
    at = 32
    for _ in range(struct.unpack_from("<I", blob, 16)[0]):
        command, length = struct.unpack_from("<II", blob, at)
        if command == 0x19:
            segments.append(struct.unpack_from("<4Q", blob, at + 24))
        elif command == 2:
            offset, number, strings, size = struct.unpack_from("<4I", blob, at + 8)
            names = blob[strings:strings + size]
            for i in range(number):
                name, kind, section, desc, value = struct.unpack_from("<IBBHQ", blob, offset + i * 16)
                if name < len(names) and value:
                    symbols.append((value, names[name:names.index(0, name)].decode(errors="replace")))
        at += length
    start, name = max(item for item in symbols if item[0] <= args.address)
    print(f"{args.address:#x}: {name}+{args.address - start:#x}", flush=True)
    end = min(start + 4096, min((v for v, n in symbols if v > start), default=start + 4096))
    for address, size, offset, file_size in segments:
        if address <= start < end <= address + file_size:
            output = Path(__file__).resolve().parents[2] / "out/startup-analysis"
            output.mkdir(parents=True, exist_ok=True)
            binary = output / "function.bin"
            binary.write_bytes(blob[offset + start - address:offset + end - address])
            subprocess.run(["aarch64-linux-gnu-objdump", "-D", "-b", "binary", "-m", "aarch64",
                            f"--adjust-vma={start}", str(binary)], check=True)
            return
    raise ValueError("Symbol does not map into file-backed kernel bytes")


if __name__ == "__main__":
    main()
