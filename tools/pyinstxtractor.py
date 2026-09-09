"""Minimal PyInstaller CArchive extractor (supports PyInstaller 4/5/6 layout)."""
import os
import struct
import sys
import zlib

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def read_cookie(data: bytes):
    # Cookie: magic(8) + lengthofPackage(4) + toc(4) + tocLen(4) + pyver(4) + pylibname(64)
    cookie_size = 8 + 4 + 4 + 4 + 4 + 64
    pos = data.rfind(MAGIC)
    if pos == -1:
        raise SystemExit("No PyInstaller cookie found")
    cookie = data[pos:pos + cookie_size]
    magic, lengthofPackage, toc, tocLen, pyver = struct.unpack(
        "!8sIIII", cookie[:24]
    )
    pylibname = cookie[24:cookie_size].rstrip(b"\x00").decode("utf-8", "replace")
    return lengthofPackage, toc, tocLen, pyver, pylibname


def main(exe_path: str, out_dir: str):
    data = open(exe_path, "rb").read()
    lengthofPackage, toc_off, tocLen, pyver, pylibname = read_cookie(data)
    tail = len(data)
    overlay_start = tail - lengthofPackage
    toc_pos = overlay_start + toc_off
    pyc_ver = f"{pyver}"

    entries = []
    p = toc_pos
    end = toc_pos + tocLen
    while p < end:
        (entry_size,) = struct.unpack("!i", data[p:p + 4])
        name_len = entry_size - 4 - 4 - 4 - 4 - 1 - 1
        entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name = struct.unpack(
            f"!IIIBc{name_len}s", data[p + 4:p + entry_size]
        )
        name = name.rstrip(b"\x00").decode("utf-8", "replace")
        entries.append((entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name))
        p += entry_size

    os.makedirs(out_dir, exist_ok=True)
    for entryPos, csize, usize, flag, typ, name in entries:
        raw = data[overlay_start + entryPos: overlay_start + entryPos + csize]
        if flag:
            try:
                raw = zlib.decompress(raw)
            except Exception as e:
                print(f"  [!] decompress failed for {name}: {e}")
        safe = name.replace("\\", "/").replace("..", "__")
        outp = os.path.join(out_dir, safe)
        os.makedirs(os.path.dirname(outp) or out_dir, exist_ok=True)
        if typ in (b"s", b"m", b"M"):
            # python script: add pyc header so it can be unmarshalled
            outp += ".pyc"
            # build header: magic(4)+flags(4)+timestamp(4)+size(4) for 3.7+
            import importlib.util
            magic = importlib.util.MAGIC_NUMBER
            hdr = magic + b"\x00" * 12
            raw = hdr + raw
        with open(outp, "wb") as f:
            f.write(raw)
        print(f"  {typ.decode()} {name} ({len(raw)} bytes)")

    print(f"\nPython version tag from cookie: {pyver} (pylib: {pylibname})")
    print(f"Extracted {len(entries)} entries to {out_dir}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
