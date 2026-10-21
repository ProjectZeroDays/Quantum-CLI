#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_all_kernel.py — generate and compile every kernel C exploit; report
which build cleanly. A compile-gate so a broken C stub never ships silently.

  python3 build_all_kernel.py              # generate + compile, report
  python3 build_all_kernel.py --strict     # exit 1 if any fail
  python3 build_all_kernel.py --no-generate  # only compile existing exploits/*.c
"""
import argparse, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXPLOITS = ROOT / "exploits"

GENERATOR_MARKERS = ("C_STUB", "C = r'''", 'C = r"""')


def generate_all(workdir: Path) -> list:
    """Run every generator that emits C, collecting the produced .c files."""
    produced = []
    for py in sorted(EXPLOITS.glob("*.py")):
        text = py.read_text(errors="ignore")
        if not any(m in text for m in GENERATOR_MARKERS):
            continue
        base = workdir / py.stem
        try:
            r = subprocess.run([sys.executable, str(py), str(base)],
                               capture_output=True, text=True, timeout=25)
        except subprocess.TimeoutExpired:
            print(f"  [!] {py.name}: generator timeout"); continue
        if r.returncode != 0:
            print(f"  [!] {py.name}: generator failed ({r.stderr.strip()[:60]})")
            continue
        for c in sorted(workdir.glob(f"{py.stem}*.c")):
            produced.append(c)
    # any pre-existing .c in exploits/ too
    produced += sorted(EXPLOITS.glob("*.c"))
    return sorted(set(produced))


def compile_one(cpath: Path, outdir: Path, timeout=90):
    exe = outdir / cpath.stem
    cmd = ["cc", "-O2", "-Wall", "-pthread", str(cpath), "-o", str(exe)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    return r.returncode, (r.stderr or "")


def main() -> int:
    ap = argparse.ArgumentParser(prog="build_all_kernel")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any failure")
    ap.add_argument("--no-generate", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep the build dir")
    ap.add_argument("--outdir", default=None,
                    help="copy the compiled binaries into this directory "
                         "(CI uses it to upload build artifacts)")
    a = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="tvkernel_"))
    out = work / "bin"; out.mkdir()

    try:
        sources = (sorted(EXPLOITS.glob("*.c")) if a.no_generate
                   else generate_all(work))
        sources = [s for s in sources if s.exists()]
        if not sources:
            print("[!] no C sources found"); return 1

        print(f"[*] compiling {len(sources)} kernel source(s)")
        ok = fail = 0
        for c in sources:
            rc, err = compile_one(c, out)
            if rc == 0:
                print(f"  [+] {c.name}"); ok += 1
            else:
                # Show enough of the compiler output to diagnose the
                # failure — a single line ("In function 'main':") is not
                # enough to tell what actually went wrong.
                lines = (err or "").strip().splitlines() or ["?"]
                detail = " | ".join(l.strip() for l in lines[:3])[:240]
                print(f"  [-] {c.name}: {detail}"); fail += 1

        print(f"[{'PASS' if not fail else 'FAIL'}] {ok} compiled, {fail} failed")
        if a.outdir:
            dest = Path(a.outdir)
            dest.mkdir(parents=True, exist_ok=True)
            for binary in sorted(out.iterdir()):
                if binary.is_file():
                    shutil.copy2(binary, dest / binary.name)
            print(f"[*] artifacts copied to {dest}")
        if a.keep:
            print(f"[*] artifacts in {out}")
        else:
            shutil.rmtree(work, ignore_errors=True)
        return 1 if (fail and a.strict) else 0
    finally:
        if a.keep:
            print(f"[*] workdir: {work}")


if __name__ == "__main__":
    sys.exit(main())
