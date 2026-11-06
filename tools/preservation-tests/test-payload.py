"""Compile and exercise the runtime payload policy on the host, with sanitizers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    (REPO / "out").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=REPO / "out", prefix="payload-policy-") as temp:
        executable = Path(temp) / "test"
        subprocess.run(["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I" + str(REPO / "userland/preservation-shim"),
                        str(REPO / "tools/preservation-tests/payload-policy.c"), "-o", str(executable)], check=True)
        subprocess.run([str(executable), *([str(args.payload)] if args.payload else [])], check=True)
        if args.report:
            args.report.write_text(json.dumps({
                "runtime_policy_sha256": hashlib.sha256((REPO / "userland/preservation-shim/preserve_payload.h").read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
                "payload_sha256": hashlib.sha256(args.payload.read_bytes()).hexdigest() if args.payload else None,
                "sanitizers": ["address", "undefined"], "tests_passed": True,
                "device_boot_approved": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
