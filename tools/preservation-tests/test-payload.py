"""Compile and exercise the runtime payload policy on the host, with sanitizers."""
import argparse
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path)
    args = parser.parse_args()
    (REPO / "out").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=REPO / "out", prefix="payload-policy-") as temp:
        executable = Path(temp) / "test"
        subprocess.run(["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I" + str(REPO / "userland/preservation-shim"),
                        str(REPO / "tools/preservation-tests/payload-policy.c"), "-o", str(executable)], check=True)
        subprocess.run([str(executable), *([str(args.payload)] if args.payload else [])], check=True)


if __name__ == "__main__":
    main()
