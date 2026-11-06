"""Reject kernel packaging unless its UFS source matches the audited implementation."""
import hashlib
import json
from pathlib import Path
import sys

EXPECTED_UFS = "2ad3efd52829041ed4ddf9e8ae504d4c4ba989265cc58bba498dadb262b94f5f"


def main():
    root = Path(sys.argv[1])
    report = Path(sys.argv[2])
    source = root / "bsd/dev/negroni_ufs.c"
    actual = hashlib.sha256(source.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if actual != EXPECTED_UFS:
        raise RuntimeError(f"UFS source differs from audited driver: {actual}")
    patch = Path(__file__).resolve().parents[2] / "patches/xnu/0403-negroni-preserve-android.patch"
    lines = patch.read_text().split("+++ b/bsd/dev/negroni_ufs_preserve.h\n", 1)[1].splitlines()
    expected_header = "\n".join(line[1:] for line in lines if line.startswith("+")) + "\n"
    header = (root / "bsd/dev/negroni_ufs_preserve.h").read_text()
    if header != expected_header:
        raise RuntimeError("Preservation header differs from tested policy")
    report.write_text(json.dumps({"ufs_sha256": actual, "policy_matches_tested_header": True,
                                 "device_boot_approved": False}, indent=2) + "\n")
    print("Audited UFS source and policy verified. Device boot is not approved.")


if __name__ == "__main__":
    main()
