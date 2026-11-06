"""Extract bounded UEFI PE sections from a copied ABL image. Offline; never executes firmware."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import lzma
from pathlib import Path
import struct
import uuid

REPO = Path(__file__).resolve().parents[2]
LZMA_GUID = "ee4e5898-3914-4259-9d6e-dc7bd79403cf"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    blob = args.image.read_bytes()
    if not 0 < len(blob) <= 8 * 1024**2 or blob[:4] != b"\x7fELF":
        raise ValueError("Expected the bounded copied ABL ELF container")
    output = REPO / "out/abl-analysis" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output.mkdir(parents=True, exist_ok=False)
    records, executables = [], []
    def sections(data, owner, depth):
        if depth > 8:
            raise ValueError("Excessive firmware nesting")
        at = 0
        while at + 4 <= len(data):
            if data[at:] == b"\xff" * (len(data) - at):
                return
            size, kind, header = int.from_bytes(data[at:at + 3], "little"), data[at + 3], 4
            if size == 0xffffff:
                if at + 8 > len(data):
                    raise ValueError("Truncated extended section")
                size, header = struct.unpack_from("<I", data, at + 4)[0], 8
            if size < header or at + size > len(data):
                raise ValueError("Invalid section size")
            body = data[at + header:at + size]
            record = {"owner": owner, "type": kind, "offset_in_parent": at, "bytes": size}
            records.append(record)
            if len(records) > 512:
                raise ValueError("Excessive section count")
            if kind == 2:
                if len(body) < 20:
                    raise ValueError("Truncated GUID section")
                guid = str(uuid.UUID(bytes_le=body[:16]))
                offset, attributes = struct.unpack_from("<HH", body, 16)
                record.update(guid=guid, attributes=attributes)
                if not header + 20 <= offset <= size:
                    raise ValueError("Invalid GUID data offset")
                if guid == LZMA_GUID:
                    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 * 1024**2)
                    decoded = decoder.decompress(data[at + offset:at + size], max_length=16 * 1024**2 + 1)
                    if not decoder.eof or len(decoded) > 16 * 1024**2:
                        raise ValueError("Incomplete or oversized LZMA section")
                    record["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
                    sections(decoded, owner + "/lzma", depth + 1)
                else:
                    record["unsupported_guid_payload"] = True
            elif kind == 0x17:
                volume(body, owner + "/fv", depth + 1)
            elif kind == 0x10:
                if len(body) < 64 or body[:2] != b"MZ":
                    raise ValueError("PE section lacks DOS header")
                pe = struct.unpack_from("<I", body, 60)[0]
                if pe + 26 > len(body) or body[pe:pe + 4] != b"PE\0\0":
                    raise ValueError("Invalid PE signature")
                machine = struct.unpack_from("<H", body, pe + 4)[0]
                path = output / f"section-{len(executables):02d}.efi"
                path.write_bytes(body)
                executables.append({"file": path.name, "owner": owner, "machine": hex(machine),
                                    "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
            at = (at + size + 3) & ~3

    def volume(data, owner, depth):
        if len(data) < 56 or data[40:44] != b"_FVH":
            raise ValueError("Missing firmware volume header")
        length = struct.unpack_from("<Q", data, 32)[0]
        header = struct.unpack_from("<H", data, 48)[0]
        if not 56 <= header <= length <= len(data) or header % 2:
            raise ValueError("Invalid firmware volume bounds")
        if sum(struct.unpack_from("<" + "H" * (header // 2), data)) & 0xffff:
            raise ValueError("Firmware volume header checksum mismatch")
        at = (header + 7) & ~7
        while at + 24 <= length:
            h = data[at:at + 24]
            if h == bytes([255]) * 24:
                break
            guid, kind = str(uuid.UUID(bytes_le=h[:16])), h[18]
            size = int.from_bytes(h[20:23], "little")
            if not 24 <= size < 0xffffff or at + size > length:
                raise ValueError("Invalid or unsupported FFS bounds")
            if kind != 0xf0:
                sections(data[at + 24:at + size], owner + "/" + guid, depth + 1)
            at = (at + size + 7) & ~7

    starts = [at - 40 for at in range(40, len(blob) - 4) if blob[at:at + 4] == b"_FVH"]
    if len(starts) != 1:
        raise ValueError("Expected one outer ABL firmware volume")
    volume(blob[starts[0]:], "abl", 0)
    report = {"source_sha256": hashlib.sha256(blob).hexdigest(), "source_bytes": len(blob),
              "outer_fv_offset": starts[0], "sections": records, "executables": executables,
              "firmware_executed": False, "boot_header_support_established": False}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Offline ABL extraction: {output}")
    print(json.dumps(executables, indent=2))


if __name__ == "__main__":
    main()
