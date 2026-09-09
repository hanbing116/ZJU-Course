"""Extract PyInstaller PYZ (ZlibArchive) contents."""
import marshal
import os
import struct
import sys
import zlib
import importlib.util


def main(pyz_path: str, out_dir: str):
    data = open(pyz_path, "rb").read()
    assert data[:4] == b"PYZ\0", "not a PYZ archive"
    toc_pos = struct.unpack("!i", data[8:12])[0]
    toc = marshal.loads(data[toc_pos:])
    if isinstance(toc, list):
        toc = dict(toc)
    os.makedirs(out_dir, exist_ok=True)
    for name, (typ, pos, length) in toc.items():
        raw = data[pos:pos + length]
        try:
            raw = zlib.decompress(raw)
        except Exception as e:
            print(f"[!] {name}: {e}")
            continue
        safe = name.replace(".", "/")
        if typ == 1:  # package
            safe = os.path.join(safe, "__init__")
        outp = os.path.join(out_dir, safe + ".pyc")
        os.makedirs(os.path.dirname(outp), exist_ok=True)
        with open(outp, "wb") as f:
            f.write(importlib.util.MAGIC_NUMBER + b"\x00" * 12 + raw)
    print(f"Extracted {len(toc)} modules")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
