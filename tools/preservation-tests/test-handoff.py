"""Validate FDT bounds and compare the real shim parser on valid handoff fixtures."""
import argparse
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Optional local live FDT; remains outside git")
    args = parser.parse_args()
    handoff = load("handoff", REPO / "scripts/backup/inspect-android-handoff.py")
    emulator = load("emulator", REPO / "scripts/shim/emulate-ramroot.py")
    fixture = emulator.shim_fdt(0xa9000000, 0xad000000)
    assert handoff.summary(fixture)["chosen_addresses"]["linux,initrd-end"] == "0xad000000"
    for length in range(len(fixture)):
        try:
            handoff.properties(fixture[:length])
        except (ValueError, UnicodeError):
            continue
        raise AssertionError("Accepted a truncated FDT")
    for offset, value in ((8, 0xfffffff0), (12, 0xfffffff0), (32, 0xffffffff), (36, 0xffffffff)):
        bad = bytearray(fixture)
        struct.pack_into(">I", bad, offset, value)
        try:
            handoff.properties(bad)
        except ValueError:
            continue
        raise AssertionError("Accepted an invalid FDT range")
    harness = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "fdt.h"
int main(int argc, char **argv) {
    assert(argc == 4);
    FILE *file = fopen(argv[1], "rb"); assert(file);
    assert(!fseek(file, 0, SEEK_END)); long size = ftell(file); assert(size > 0);
    rewind(file); void *data = malloc((size_t)size); assert(data);
    assert(fread(data, 1, (size_t)size, file) == (size_t)size); fclose(file);
    uint64_t start = 0, end = 0;
    assert(fdt_chosen_u64((uintptr_t)data, "linux,initrd-start", &start));
    assert(fdt_chosen_u64((uintptr_t)data, "linux,initrd-end", &end));
    assert(start == strtoull(argv[2], NULL, 0) && end == strtoull(argv[3], NULL, 0));
    free(data); puts("PASS: real shim FDT parser matches bounded host parser");
}
'''
    (REPO / "out").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=REPO / "out", prefix="handoff-test-") as temp:
        work = Path(temp)
        (work / "test.c").write_text(harness)
        binary = work / "test"
        shim = REPO / "external/slop/shim"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                        "-I" + str(shim), str(work / "test.c"), str(shim / "fdt.c"), "-o", str(binary)], check=True)
        blobs = [fixture]
        if args.input:
            blobs.append(args.input.read_bytes())
        for i, blob in enumerate(blobs):
            addresses = handoff.summary(blob)["chosen_addresses"]
            path = work / f"fixture-{i}.dtb"
            path.write_bytes(blob)
            subprocess.run([str(binary), str(path), addresses["linux,initrd-start"], addresses["linux,initrd-end"]], check=True)
    print("PASS: host parser rejects every truncated fixture and invalid header ranges; no phone access")


if __name__ == "__main__":
    main()
