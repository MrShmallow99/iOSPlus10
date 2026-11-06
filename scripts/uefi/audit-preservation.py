"""Reconstruct and check the candidate Mu preservation configuration; no phone access."""
import hashlib
import json
from pathlib import Path
import subprocess
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[2]
BOARD = Path("Platforms/OnePlus/negroniPkg")


def validate(root):
    includes = [root / BOARD / "Include" / name for name in ("APRIORI.inc", "DXE.inc")]
    banned = ("Drivers/UFSDxe/", "Drivers/SdccDxe/", "Drivers/UsbMsdDxe/", "Universal/CapsuleRuntimeDxe/")
    for path in includes:
        content = path.read_text()
        if any(name in content for name in banned):
            raise ValueError(f"Internal storage/update driver in {path}")
    dsc = (root / BOARD / "negroni.dsc").read_text()
    fdf = (root / BOARD / "negroni.fdf").read_text()
    if "/NegroniWindowsFirstDxe/" in dsc + fdf:
        raise ValueError("Windows boot-order helper is still selected")
    pcd = "gEfiMdeModulePkgTokenSpaceGuid.PcdEmuVariableNvModeEnable|TRUE"
    if pcd not in dsc or "PcdEmuVariableNvModeEnable|FALSE" in dsc:
        raise ValueError("Board must explicitly select emulated variable storage")
    if "!include Include/PreservationExtras.fdf.inc" not in fdf or "!include QcomPkg/Extra.fdf.inc" in fdf:
        raise ValueError("Board must select preservation extras")
    extras = (root / BOARD / "Include/PreservationExtras.fdf.inc").read_text()
    if any(name in extras for name in ("Applications/MassStorage/", "Applications/UFP/", "Applications/UFPLoader/")):
        raise ValueError("Firmware-update/mass-storage application is still selected")
    if "UsbMassStorageDxe/UsbMassStorageDxe.inf" not in includes[1].read_text():
        raise ValueError("External USB host storage was unexpectedly removed")


def main():
    mu = REPO / "external/Mu-Silicium-negroni"
    pinned = subprocess.check_output(["git", "-C", str(REPO), "ls-tree", "HEAD", "external/Mu-Silicium-negroni"], text=True).split()[2]
    destination = REPO / "out/mu-preservation-audit" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
    patches = sorted((REPO / "patches/mu").glob("*.patch"))
    inputs = set()
    for patch in patches:
        for line in patch.read_text().splitlines():
            if line.startswith("--- a/"):
                inputs.add(line[6:].split("\t", 1)[0])
    for name in inputs:
        content = subprocess.check_output(["git", "-C", str(mu), "show", pinned + ":" + name])
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.replace(b"\r\n", b"\n"))
    patch_states = {}
    for patch in patches:
        local = destination / patch.name
        local.write_bytes(patch.read_bytes().replace(b"\r\n", b"\n"))
        reverse = subprocess.run(["git", "-C", str(destination), "apply", "--reverse", "--check", str(local)],
                                 capture_output=True)
        if reverse.returncode == 0:
            patch_states[patch.name] = "already present in pinned source"
        else:
            subprocess.run(["git", "-C", str(destination), "apply", "--whitespace=nowarn", str(local)], check=True)
            patch_states[patch.name] = "applied"
    validate(destination)
    # Check the rejection path in an isolated copy of the rendered configuration.
    dxe = destination / BOARD / "Include/DXE.inc"
    original = dxe.read_text()
    try:
        dxe.write_text(original + "\n  INF Binaries/negroni/QcomPkg/Drivers/UFSDxe/UFSDxe.inf\n")
        try:
            validate(destination)
        except ValueError:
            pass
        else:
            raise AssertionError("Audit accepted a reintroduced internal UFS driver")
    finally:
        dxe.write_text(original)
    files = {str(p.relative_to(destination)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (destination / BOARD).rglob("*") if p.is_file()}
    report = {"mu_commit": pinned, "patches": patch_states, "files": files,
              "configuration_audit_passed": True, "firmware_compiled": False, "device_boot_approved": False}
    (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"PASS: candidate Mu configuration and UFS reintroduction rejection: {destination}")
    print("Configuration audit only. Binary Qualcomm drivers and final firmware are not verified. Do not boot.")


if __name__ == "__main__":
    main()
