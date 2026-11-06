"""Attempt XNU/RAM-root execution in a headless, diskless ARM emulator. No phone access."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import struct
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "external/slop/negroni-ios/tools"
sys.path.insert(0, str(TOOLS))
import adt
import mkadt
import mkpayload


def shim_fdt(start, end):
    """Minimal standard FDT; tests the shim's actual /chosen parser."""
    strings = b"linux,initrd-start\0linux,initrd-end\0"
    def padded(value):
        return value + bytes((-len(value)) % 4)
    def node(name):
        return struct.pack(">I", 1) + padded(name.encode() + b"\0")
    def prop(name_offset, value):
        return struct.pack(">IIIQ", 3, 8, name_offset, value)
    tree = (node("") + node("chosen") + prop(0, start) + prop(19, end)
            + struct.pack(">III", 2, 2, 9))
    header = struct.pack(">10I", 0xd00dfeed, 56 + len(tree) + len(strings),
                         56, 56 + len(tree), 40, 17, 16, 0, len(strings), len(tree))
    return header + bytes(16) + tree + strings


def checked_shim(directory):
    reports = list(directory.rglob("report.json"))
    if len(reports) != 1:
        raise ValueError("Select one complete shim audit artifact")
    report = json.loads(reports[0].read_text())
    def digest(path):
        return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if (report.get("complete_shim_built") is not True
            or report.get("internal_storage_uefi_probe_paths_linked") is not False):
        raise ValueError("Expected the complete minimal preservation shim")
    for field, relative in (("runtime_policy_sha256", "userland/preservation-shim/preserve_payload.h"),
                            ("preservation_main_sha256", "userland/preservation-shim/main.c")):
        if report.get(field) != digest(REPO / relative):
            raise ValueError("Shim artifact differs from current source")
    if report.get("shim_patches") != {p.name: digest(p) for p in (REPO / "patches/shim").glob("*.patch")}:
        raise ValueError("Shim patch provenance mismatch")
    image = reports[0].parent / "complete/Image"
    if hashlib.sha256(image.read_bytes()).hexdigest() != report.get("shim_image_sha256"):
        raise ValueError("Shim image digest mismatch")
    return image, report


def font_address(blob):
    count = struct.unpack_from("<I", blob, 16)[0]
    at = 32
    for _ in range(count):
        command, length = struct.unpack_from("<II", blob, at)
        if command == 2:
            offset, number, strings, size = struct.unpack_from("<4I", blob, at + 8)
            names = blob[strings:strings + size]
            found = []
            for i in range(number):
                name, kind, section, desc, value = struct.unpack_from("<IBBHQ", blob, offset + i * 16)
                if name < len(names) and names[name:names.index(0, name)] == b"_iso_font":
                    found.append(value)
            if len(found) == 1:
                return found[0]
            raise ValueError("Expected exactly one kernel console font symbol")
        at += length
    raise ValueError("Kernel has no symbol table")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-artifact", type=Path, required=True)
    parser.add_argument("--ramroot-artifact", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--cpu", choices=("cortex-a76", "max"), default="cortex-a76")
    parser.add_argument("--shim-artifact", type=Path, help="Execute the real shim instead of entering XNU directly")
    parser.add_argument("--vendor-prefix", type=Path, help="Local vendor ramdisk bytes to prepend in shim mode")
    parser.add_argument("--handoff-fdt", type=Path, help="Local stock FDT; replace only its initrd addresses for emulation")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 180:
        raise ValueError("Choose a bounded 1..180 second emulator run")
    if (args.vendor_prefix or args.handoff_fdt) and not args.shim_artifact:
        raise ValueError("A vendor prefix or handoff FDT requires complete-shim mode")
    subprocess.run([sys.executable, str(REPO / "scripts/kernel/verify-preservation-artifact.py"),
                    str(args.kernel_artifact)], check=True)
    kernel = args.kernel_artifact / "kernel.development.negroni"
    root = args.ramroot_artifact / "root.hfs"
    manifest = json.loads((args.ramroot_artifact / "report.json").read_text())
    if hashlib.sha256(root.read_bytes()).hexdigest() != manifest["root_sha256"]:
        raise ValueError("RAM-root digest mismatch")
    output = REPO / "out/preservation-qemu" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    # Direct mode uses a lower RAM window rejected by the phone shim. Full-shim
    # mode retains its required high bank, but both use QEMU's virtual GIC/timer.
    physical, memory_size = (0x840000000, 0xc0000000) if args.shim_artifact else (0x50000000, 0x40000000)
    tree = mkadt.build(board="negroni", qemu=True, dram=(physical, memory_size), ufs=False)
    tree_path = output / "qemu-only.adt"
    tree_path.write_bytes(adt.serialize(tree))
    line = (args.ramroot_artifact / "cmdline.txt").read_text().strip()
    # QEMU has no Qualcomm PMIC/SPMI arbiter. Use the port's existing soft-clock
    # fallback rather than touching a physical MMIO address on this virtual board.
    line += (" negronirtc=0 negronireboot=0 negronibatt=0 negronithermal=0"
             " negronicpuperf=0 negronikeys=0 negronitouch=0 negroniusb=0 negronihap=0"
             " negronifb_dpuprobe=0 negronifb_zerocopy=0 negronibl=0 negronifb_esd=0"
             " negronicharge=1 negronifb_stats=0 negronitop=0")
    # Charge mode 0 is a diagnostic dry run that unconditionally samples the
    # physical key. Mode 1 returns before sampling when no charger boot trigger
    # exists. This virtual ADT has no PON log or androidboot.mode=charger.
    if len(line.encode()) >= 608:
        raise ValueError("Emulator arguments exceed the payload command-line field")
    payload, info = mkpayload.build(str(kernel), str(tree_path), line, str(root))
    (output / "QEMU-ONLY.negronix").write_bytes(payload)
    virt, entry, tree_offset, tree_size, kernel_end, physical, memory_size = struct.unpack_from("<7Q", payload, 0x10)
    delta = physical - virt
    tree_pa = kernel_end + delta
    ba_pa = (tree_pa + tree_size + 0x3fff) & ~0x3fff
    top = ba_pa + 0x4000
    flat = bytearray(top - physical)
    for i in range(struct.unpack_from("<I", payload, 12)[0]):
        address, size, offset, file_size = struct.unpack_from("<4Q", payload, 0x2a8 + i * 32)
        target = address - virt
        if target < 0 or target + size > len(flat) or offset + file_size > len(payload):
            raise ValueError("Invalid emulator image bounds")
        flat[target:target + file_size] = payload[offset:offset + file_size]
    flat[tree_pa - physical:tree_pa - physical + tree_size] = payload[tree_offset:tree_offset + tree_size]
    video = (0xb8000000, 1, 1080 * 4, 1080, 2412, 32)
    boot_args = struct.pack("<HH4x4Q6QI4xQI", 2, 2, virt, physical, memory_size, top,
                            *video, 0, tree_pa - delta, tree_size)
    boot_args += line.encode().ljust(1024, b"\0") + bytes(4) + struct.pack("<QQ", 0, memory_size)
    if len(boot_args) != 1152:
        raise ValueError("Wrong emulator boot-argument ABI")
    flat[ba_pa - physical:ba_pa - physical + len(boot_args)] = boot_args
    (output / "ram.bin").write_bytes(flat)
    stub_pa = 0x40200000
    (output / "stub.bin").write_bytes(struct.pack("<4I2Q", 0x58000080, 0x580000a1,
        0xd61f0020, 0xd503201f, ba_pa, entry + delta))
    shim_info = None
    if args.shim_artifact:
        shim, shim_info = checked_shim(args.shim_artifact)
        shim_pa, initrd_pa, fdt_pa = 0xa8008000, 0xa9000000, 0xb0000000
        prefix = args.vendor_prefix.read_bytes() if args.vendor_prefix else b""
        if len(prefix) % 8 or len(prefix) > 64 * 1024**2:
            raise ValueError("Vendor prefix must be aligned and bounded")
        combined = prefix + payload + bytes(4096)
        if initrd_pa + len(combined) > fdt_pa:
            raise ValueError("Combined ramdisk overlaps the synthetic FDT")
        (output / "combined-initrd.bin").write_bytes(combined)
        fdt_blob = shim_fdt(initrd_pa, initrd_pa + len(combined))
        if args.handoff_fdt:
            spec = importlib.util.spec_from_file_location("handoff", REPO / "scripts/backup/inspect-android-handoff.py")
            handoff = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(handoff)
            fdt_blob = bytearray(args.handoff_fdt.read_bytes())
            ranges = handoff.properties(fdt_blob, locations=True)
            for name, value in (("linux,initrd-start", initrd_pa), ("linux,initrd-end", initrd_pa + len(combined))):
                offset, width = ranges[("/chosen", name)]
                if width not in (4, 8):
                    raise ValueError("Unsupported live FDT initrd width")
                fdt_blob[offset:offset + width] = value.to_bytes(width, "big")
            handoff.summary(fdt_blob)
        (output / "shim-handoff.dtb").write_bytes(fdt_blob)
        (output / "stub.bin").write_bytes(struct.pack("<4I2Q", 0x58000080, 0x580000a1,
            0xd61f0020, 0xd503201f, fdt_pa, shim_pa))
        monitor = REPO / "userland/preservation-shim/qemu-monitor.S"
        subprocess.run(["aarch64-linux-gnu-as", str(monitor), "-o", str(output / "monitor.o")], check=True)
        subprocess.run(["aarch64-linux-gnu-ld", "-Ttext=0x40200000", "-e", "_start",
                        str(output / "monitor.o"), "-o", str(output / "monitor.elf")], check=True)
        subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary", str(output / "monitor.elf"),
                        str(output / "stub.bin")], check=True)
    spec = importlib.util.spec_from_file_location("qemu_screen", REPO / "external/slop/tools/qemu-sweet.py")
    screen_tools = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(screen_tools)
    screen_tools.FB_BASE, screen_tools.FB_W, screen_tools.FB_H, screen_tools.FB_STRIDE = video[0], 1080, 2412, 4320
    font = screen_tools.payload_data(payload, font_address(kernel.read_bytes()), 256 * 16)
    command = ["qemu-system-aarch64", "-M", "virt,gic-version=3", "-cpu", args.cpu, "-smp", "1", "-m", "4G",
               "-accel", "tcg,thread=single", "-nodefaults", "-nic", "none", "-display", "none",
               "-serial", "file:" + str(output / "serial.txt"), "-monitor", "none", "-qmp", "stdio",
               "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
               "-d", "int,guest_errors,unimp", "-D", str(output / "qemu.log"), "-no-reboot",
               "-device", f"loader,file={output / 'ram.bin'},addr={physical:#x},force-raw=on",
               "-device", f"loader,file={output / 'stub.bin'},addr={stub_pa:#x},force-raw=on",
               "-device", f"loader,addr={stub_pa:#x},cpu-num=0"]
    if args.shim_artifact:
        # Large sparse guest address space, demand-paged; no preallocation. The
        # kernel manages only its 3 GiB high bank. No host disk is a guest drive.
        command[command.index("4G")] = "40G"
        command[command.index("virt,gic-version=3")] = "virt,gic-version=3,secure=on,memory-backend=guest-ram"
        command += ["-object", "memory-backend-ram,id=guest-ram,size=40G,reserve=off,prealloc=off"]
        index = command.index(f"loader,file={output / 'ram.bin'},addr={physical:#x},force-raw=on")
        command[index] = f"loader,file={shim},addr={shim_pa:#x},force-raw=on"
        command += ["-device", f"loader,file={output / 'combined-initrd.bin'},addr={initrd_pa:#x},force-raw=on",
                    "-device", f"loader,file={output / 'shim-handoff.dtb'},addr={fdt_pa:#x},force-raw=on"]
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    report = {"phone_contacted": False, "host_disks_or_usb_attached_to_guest": False,
              "kernel_sha256": hashlib.sha256(kernel.read_bytes()).hexdigest(),
              "root_sha256": hashlib.sha256(root.read_bytes()).hexdigest(),
              "emulator_cpu": args.cpu, "emulator_boot_arguments": line,
              "emulation_only_ram_window": [hex(physical), hex(memory_size)],
              "physical_phone_boot_profile_compatible": False, "pid1_observed": False,
              "device_boot_approved": False, "payload": info}
    report["complete_shim_entry_selected"] = bool(args.shim_artifact)
    if shim_info:
        report.update(shim_image_sha256=shim_info["shim_image_sha256"],
                      gunyah_watchdog_service_emulated=True,
                      virtual_monitor_sha256=hashlib.sha256(monitor.read_bytes()).hexdigest(),
                      vendor_prefix_sha256=hashlib.sha256(prefix).hexdigest(),
                      vendor_prefix_bytes=len(prefix), synthetic_fdt=not bool(args.handoff_fdt),
                      handoff_fdt_sha256=hashlib.sha256(fdt_blob).hexdigest(),
                      source_fdt_sha256=hashlib.sha256(args.handoff_fdt.read_bytes()).hexdigest() if args.handoff_fdt else None,
                      actual_abl_placement_verified=False)
    process = None
    try:
        with (output / "stderr.txt").open("w") as errors:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=errors, bufsize=0)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            buffered = bytearray()
            def read_message(timeout=10):
                deadline = time.monotonic() + timeout
                while b"\n" not in buffered:
                    if not selector.select(max(0, deadline - time.monotonic())):
                        raise TimeoutError("No QMP response")
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        raise RuntimeError("Emulator stopped before QMP capture")
                    buffered.extend(chunk)
                    if len(buffered) > 1024**2:
                        raise RuntimeError("Unexpectedly large QMP response")
                line, _, rest = buffered.partition(b"\n")
                buffered[:] = rest
                return json.loads(line)
            def qmp(name, **arguments):
                process.stdin.write((json.dumps({"execute": name, "arguments": arguments}) + "\n").encode())
                process.stdin.flush()
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    response = read_message()
                    if "error" in response:
                        raise RuntimeError(str(response["error"]))
                    if "return" in response:
                        return response["return"]
                raise TimeoutError("QMP command timed out")
            greeting = read_message()
            report["qmp_version"] = greeting.get("QMP", {}).get("version")
            qmp("qmp_capabilities")
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline and process.poll() is None:
                trace = output / "qemu.log"
                if trace.exists() and trace.stat().st_size > 16 * 1024**2:
                    report["trace_limit_reached"] = True
                    break
                time.sleep(0.1)
            qmp("stop")
            if args.shim_artifact:
                captured = output / "shim-bootargs.bin"
                qmp("pmemsave", val=ba_pa, size=len(boot_args), filename=str(captured))
                report["shim_boot_arguments_match_reference"] = captured.read_bytes() == boot_args
            (output / "registers.txt").write_text(qmp("human-monitor-command", **{"command-line": "info registers"}))
            qmp("pmemsave", val=video[0], size=1080 * 2412 * 4, filename=str(output / "fb.raw"))
            raw = (output / "fb.raw").read_bytes()
            screen_tools.write_png(str(output / "fb.png"), raw)
            text, unknown = screen_tools.decode_screen(raw, font)
            (output / "fb.txt").write_text(text)
            report["unknown_glyphs"] = unknown
            report["pid1_observed"] = "PRESERVE RAM ROOT: PID 1 reached." in text
            report["screen_has_panic"] = "panic(cpu" in text or "EARLY PANIC" in text
            report["screen_snapshot_only"] = True
            qmp("quit")
            process.wait(timeout=5)
    except Exception as error:
        report["capture_error"] = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Emulator evidence: {output}")
    print(json.dumps({k: report[k] for k in ("pid1_observed", "device_boot_approved")}))
    if "capture_error" in report:
        print("Capture error:", report["capture_error"])
    if (not report["pid1_observed"] or "capture_error" in report
            or report.get("screen_has_panic")
            or (args.shim_artifact and not report.get("shim_boot_arguments_match_reference"))):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
