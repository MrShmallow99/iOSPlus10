"""Exercise the real reboot-arbiter initializer with mocked MMIO on the host."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
EXPECTED = "7b3f6ff11d4e8acfb4c3c26fde8231f46199d89cc59fd1b76d78e51d6e9d607f"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-tree", type=Path)
    args = parser.parse_args()
    if args.source_tree:
        tree = args.source_tree
    else:
        subprocess.run([sys.executable, str(REPO / "scripts/kernel/audit-preservation.py"),
                        "--target", "bsd/dev/negroni_reboot.c"], check=True)
        reports = sorted((REPO / "out/preservation-audit").glob("*/report.json"))
        tree = next(p.parent for p in reversed(reports)
                    if json.loads(p.read_text())["driver"] == "bsd/dev/negroni_reboot.c")
    source = (tree / "bsd/dev/negroni_reboot.c").read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(source).hexdigest() != EXPECTED:
        raise ValueError("Reboot driver differs from audited source")
    text = source.decode()
    function = text.split("static bool\nnr_arb_open(void)\n", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
    defines = "\n".join(re.findall(r"^#define NR_(?:CORE_PA|CORE_SIZE|CNFG_PA|FEATURES|VERSION_V7_MIN|VERSION_V8_MIN|MAX_APIDS)\s+[^\n]+", text, re.M))
    harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uintptr_t vm_offset_t;
static vm_offset_t nr_core, nr_cnfg;
static uint32_t nr_arb, nr_apids;
static bool nr_arb_attempted, nr_arb_ready;
static int mode, maps, reads, parses;
static int PE_parse_boot_argn(const char *name, void *out, int size) {
    assert(!strcmp(name, "negronireboot") && size == sizeof(int));
    parses++; if (mode != -1) *(int *)out = mode; return mode != -1;
}
static vm_offset_t ml_io_map(vm_offset_t base, unsigned size) {
    (void)size; maps++; return base;
}
static uint32_t nr_rd(vm_offset_t base, unsigned offset) {
    (void)base; reads++; return offset ? 64 : 0x70000000u;
}
'''
    checks = r'''
int main(void) {
    mode = 0;
    assert(!nr_arb_open() && !nr_arb_open());
    assert(maps == 0 && reads == 0 && parses == 1);
    nr_arb_attempted = false; mode = -1;
    assert(nr_arb_open() && nr_arb_open());
    assert(maps == 2 && reads == 2 && parses == 2);
    puts("PASS: disabled PMIC has zero MMIO; absent switch retains normal initialization; both cache results");
}
'''
    with tempfile.TemporaryDirectory(dir=REPO / "out", prefix="reboot-policy-") as temp:
        unit, binary = Path(temp) / "test.c", Path(temp) / "test"
        unit.write_text(harness + defines + "\nstatic bool nr_arb_open(void)\n" + function + checks)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(unit), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
