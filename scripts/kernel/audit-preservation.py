"""Reconstruct the UFS driver from pinned patches for a host-only storage audit."""
import hashlib
import json
from pathlib import Path
import subprocess
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[2]
TARGET = "bsd/dev/negroni_ufs.c"


def main():
    destination = REPO / "out" / "preservation-audit" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    normalized = destination / "patch-inputs"
    normalized.mkdir()
    base = REPO / "external/slop/negroni-ios/xnu/patches"
    if not (base / "0028-negroni-ufs-root-device.patch").is_file():
        raise RuntimeError("Initialize the pinned slop submodule first")
    patches = dict((p.name, p) for p in base.glob("*.patch"))
    patches.update((p.name, p) for p in (REPO / "patches/xnu").glob("*.patch"))
    applied = []
    for name, patch in sorted(patches.items()):
        if ("+++ b/" + TARGET).encode() not in patch.read_bytes():
            continue
        # The parent checkout was made by Windows Git; compare the same LF
        # patch bytes on both hosts without changing the pinned submodules.
        local_patch = normalized / name
        local_patch.write_bytes(patch.read_bytes().replace(b'\r\n', b'\n'))
        # Apply only this file. Dependencies on kernel headers are deliberately
        # absent: this is a source reconstruction, not a kernel compile check.
        result = subprocess.run(["git", "-C", str(destination), "apply", "--whitespace=nowarn",
                                 "--include=" + TARGET,
                                 "--include=bsd/dev/negroni_ufs_preserve.h", str(local_patch)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"UFS reconstruction stopped at {name}:\n{result.stderr}")
        applied.append(name)
    source = destination / TARGET
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    report = {"driver": TARGET, "sha256": digest, "applied": applied,
              "kernel_compiled": False, "phone_booted": False}
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Reconstructed UFS driver from {len(applied)} patches: {source}")
    print(f"SHA-256: {digest}")
    print("Source reconstruction only. No kernel compilation or phone access.")


if __name__ == "__main__":
    main()
