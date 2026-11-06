"""Host-only integration checks. Run in Linux/WSL; no phone access."""
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[2]


def main():
    (REPO / "out").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=REPO / "out", prefix="policy-test-") as temp:
        work = Path(temp)
        spy = work / "spy"
        spy.mkdir()
        marker = work / "PHONE_TOOL_WAS_CALLED"
        for tool in ("adb", "fastboot", "ssh", "scp"):
            fake = spy / tool
            fake.write_text('#!/bin/sh\ntouch "$PHONE_TEST_MARKER"\nexit 99\n')
            fake.chmod(0o755)
        env = dict(os.environ, PATH=str(spy) + os.pathsep + os.environ["PATH"],
                   CONFIRM="yes", PHONE_TEST_MARKER=str(marker))
        calls = [("flash/all.sh", []), ("flash/restore.sh", ["--keep-userdata"]),
                 ("flash/test-boot.sh", ["missing-image"]), ("flash/reflash-root.sh", []),
                 ("fw/write-areas.sh", [])]
        calls += [("flash/ios16.sh", [step, "--yes"]) for step in
                  ("recovery", "vendor_boot", "vbmeta", "dtbo", "boot", "userdata", "active")]
        for script, args in calls:
            result = subprocess.run(["sh", str(REPO / "scripts" / script), *args], env=env,
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode == 78, (script, args, result.stdout, result.stderr)
            assert "preserves Android" in result.stderr
            assert not marker.exists(), "A phone tool was invoked before the policy check"
        # Unknown and missing policy must also fail closed; do not alter the real policy.
        (work / "scripts/flash").mkdir(parents=True)
        (work / "config").mkdir()
        harness = work / "scripts/flash/check.sh"
        harness.write_text('. "' + str(REPO / "scripts/lib/phone-policy.sh") + '"\nphone_require_destructive_policy\n')
        policy = work / "config/phone-storage-policy"
        for value in (None, "", "typo", "preserve-android"):
            if value is not None:
                policy.write_text(value + "\n")
            result = subprocess.run(["sh", str(harness)], capture_output=True, text=True)
            assert result.returncode == 78, (value, result.stderr)
        print("PASS: 12 mutation entry points blocked before phone tools; missing/invalid policy fails closed")
    subprocess.run(["python3", str(REPO / "scripts/kernel/audit-preservation.py")], check=True)
    reports = sorted((REPO / "out/preservation-audit").glob("*/report.json"))
    destination = reports[-1].parent
    source = (destination / "bsd/dev/negroni_ufs.c").read_text()
    start = source.index("ufs_scsi(const uint8_t *cdb,")
    guard = source.index("if (!negroni_ufs_preserve_allows", start)
    descriptor = source.index("struct utrd *utrd", start)
    doorbell = source.index("ufs_wr(REG_UTRLDBR, 1)", start)
    assert start < guard < descriptor < doorbell
    executable = destination / "ufs-policy-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I" + str(destination / "bsd/dev"), str(REPO / "tools/preservation-tests/ufs-policy.c"),
                    "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
    verifier = REPO / "scripts/kernel/verify-preservation-source.py"
    subprocess.run(["python3", str(verifier), str(destination), str(destination / "verified.json")], check=True)
    # Packaging must reject a driver that lacks or differs from the audited guard.
    with tempfile.TemporaryDirectory(dir=REPO / "out", prefix="verify-test-") as temp:
        altered = Path(temp)
        (altered / "bsd/dev").mkdir(parents=True)
        (altered / "bsd/dev/negroni_ufs.c").write_text(source + "\n/* unaudited edit */\n")
        result = subprocess.run(["python3", str(verifier), str(altered), str(altered / "verified.json")],
                                capture_output=True, text=True)
        assert result.returncode != 0 and not (altered / "verified.json").exists()
    print("PASS: packaging accepts audited source and rejects modified/missing protection")
    print("No kernel compilation, phone boot, or phone access was performed.")


if __name__ == "__main__":
    main()
