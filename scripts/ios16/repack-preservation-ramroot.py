"""Repack verified existing HFS/init artifacts with a verified newer kernel. Host only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-artifact", type=Path, required=True)
    parser.add_argument("--ramroot-artifact", type=Path, required=True)
    args = parser.parse_args()
    subprocess.run([sys.executable, str(REPO / "scripts/kernel/verify-preservation-artifact.py"),
                    str(args.kernel_artifact)], check=True)
    source = args.ramroot_artifact
    manifest = {}
    expected = {"root.hfs", "launchd", "negroni.adt", "kernel-ramroot.negronix"}
    for line in (source / "SHA256SUMS").read_text().splitlines():
        sha, name = line.split()
        if name not in expected or name in manifest or digest(source / name) != sha:
            raise ValueError("RAM-root input manifest mismatch")
        manifest[name] = sha
    if set(manifest) != expected:
        raise ValueError("Incomplete RAM-root input manifest")
    output = REPO / "out/preservation-ramroot-local" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    for name in ("root.hfs", "launchd"):
        shutil.copyfile(source / name, output / name)
    subprocess.run([sys.executable, str(REPO / "scripts/ios16/pack-preservation-ramroot.py"),
                    str(args.kernel_artifact / "kernel.development.negroni"), str(output)], check=True)
    (output / "SHA256SUMS").write_text("".join(f"{digest(output / name)}  {name}\n" for name in sorted(expected)))
    provenance = {"input_ramroot_manifest": manifest,
                  "kernel_sha256": digest(args.kernel_artifact / "kernel.development.negroni"),
                  "command_line_sha256": digest(REPO / "config/preservation-ramroot-cmdline"),
                  "root_filesystem_reused_unchanged": digest(output / "root.hfs") == manifest["root.hfs"],
                  "device_boot_approved": False, "phone_contacted": False}
    (output / "repack-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (output / "DO-NOT-BOOT.txt").write_text("Offline intermediate. ABL placement/side effects/recovery remain unverified. No phone boot approved.\n")
    print(f"Verified offline RAM-root repack: {output}")


if __name__ == "__main__":
    main()
