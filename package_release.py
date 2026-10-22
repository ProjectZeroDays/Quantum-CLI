#!/usr/bin/env python3
"""package_release.py — build the per-version release archives.

Two archives per version, matching the v4.6.0 / v4.6.1 layout:

  quantum-exploits-v<ver>.zip   the exploit modules + the operator harness
                                 (run_all.py, build_all_kernel.py, tv_sweep.py,
                                 callback_server.py, watch.py, beacon.js, the
                                 Makefile, the committed payload lock, ...)
  quantum-payloads-v<ver>.zip   the built payload artifacts (the contents of
                                 dist/ after run_all.py)

Both archives are deterministic: every ZIP entry is stamped with a fixed
epoch and stored uncompressed, so the same tree always produces the same
bytes. Rebuilding a release must not churn the archive hashes.

  python package_release.py --version 4.6.2
  python package_release.py --version 4.6.2 --outdir release

Authorized engagements / lab work only.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

#: Fixed ZIP entry timestamp (the DOS epoch) — writestr() would stamp the
#: current time and every rebuild would produce different bytes.
_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Harness files shipped next to the exploit modules.
HARNESS_FILES = [
    "run_all.py",
    "build_all_kernel.py",
    "build_platform_index.py",
    "resolve_offsets.py",
    "tv_sweep.py",
    "callback_server.py",
    "watch.py",
    "beacon.js",
    "tier1_gate.py",
    "Makefile",
    "payloads.lock.json",
    "requirements-dev.txt",
    "requirements.txt",
]

#: Extra files that only exist in some versions.
OPTIONAL_HARNESS_FILES = ["PLATFORM_INDEX.json"]


def _add(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    """Add one deterministic (stored, epoch-stamped) entry."""
    info = zipfile.ZipInfo(arcname, date_time=_EPOCH)
    info.compress_type = zipfile.ZIP_STORED
    # Pin the "version made by" host field: ZipInfo defaults it to 0 on
    # Windows and 3 on Unix, so the archive would differ per OS.
    info.create_system = 0
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def _write_zip(target: Path, entries: list) -> None:
    """Write a deterministic zip from [(arcname, bytes), ...]."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for arcname, data in entries:
            _add(zf, arcname, data)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(buf.getvalue())


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_payloads(dist: Path) -> Path:
    """Build the payload artifacts into ``dist`` and return the directory."""
    print("[*] building payloads ->", dist)
    r = subprocess.run([sys.executable, "run_all.py", "--outdir", str(dist)],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout or "")
        sys.stderr.write(r.stderr or "")
        raise SystemExit("[!] payload build failed")
    return dist


def collect_exploits() -> list:
    """[(arcname, bytes)] for every exploit module."""
    entries = []
    src = ROOT / "exploits"
    for py in sorted(src.glob("*.py")):
        if py.stem == "__init__":
            continue
        entries.append(("exploits/" + py.name, py.read_bytes()))
    return entries


def collect_harness() -> list:
    """[(arcname, bytes)] for the operator harness files."""
    entries = []
    for name in HARNESS_FILES:
        p = ROOT / name
        if p.is_file():
            entries.append((name, p.read_bytes()))
    for name in OPTIONAL_HARNESS_FILES:
        p = ROOT / name
        if p.is_file():
            entries.append((name, p.read_bytes()))
    return entries


def collect_payload_artifacts(dist: Path) -> list:
    """[(arcname, bytes)] for the built payload artifacts (flat).

    The artifact list comes from the manifest, not from a directory
    scan: dist/ also holds the archived single-file spec and whatever
    else a build left behind, and none of that belongs in the release
    archive.

    manifest.json carries a "generated" build timestamp, which would
    make every rebuild produce a different archive. The timestamp is
    build metadata, not artifact metadata (each artifact is covered by
    its own sha256 inside the manifest), so it is stripped for a
    reproducible archive.
    """
    entries = []
    manifest = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest.get("artifacts", []):
        name = artifact.get("file")
        if not name or not artifact.get("sha256"):
            continue
        path = dist / name
        if not path.is_file():
            raise SystemExit("[!] manifest lists %s but it is not in %s"
                             % (name, dist))
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
            raise SystemExit("[!] %s does not match the manifest hash" % name)
        entries.append((name, data))

    # the manifest itself, with the volatile build timestamp removed
    data = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    data.pop("generated", None)
    entries.append(("manifest.json",
                    (json.dumps(data, indent=2) + "\n").encode("utf-8")))
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(prog="package_release")
    ap.add_argument("--version", required=True,
                    help="release version, e.g. 4.6.2")
    ap.add_argument("--outdir", default="release",
                    help="release root (default: release)")
    ap.add_argument("--skip-build", action="store_true",
                    help="reuse the existing dist/ instead of rebuilding")
    a = ap.parse_args()

    outroot = ROOT / a.outdir
    dest = outroot / f"v{a.version}"
    dest.mkdir(parents=True, exist_ok=True)

    dist = (ROOT / "dist") if a.skip_build else build_payloads(ROOT / "dist")

    exploits_zip = dest / f"quantum-exploits-v{a.version}.zip"
    payloads_zip = dest / f"quantum-payloads-v{a.version}.zip"

    print("[*] exploits archive")
    _write_zip(exploits_zip, collect_exploits() + collect_harness())
    print(f"    {exploits_zip.relative_to(ROOT)}  "
          f"{exploits_zip.stat().st_size} bytes  "
          f"sha256={_sha256(exploits_zip)[:16]}")

    print("[*] payloads archive")
    _write_zip(payloads_zip, collect_payload_artifacts(dist))
    print(f"    {payloads_zip.relative_to(ROOT)}  "
          f"{payloads_zip.stat().st_size} bytes  "
          f"sha256={_sha256(payloads_zip)[:16]}")

    # The payload lock has to describe the shipped artifacts.
    r = subprocess.run([sys.executable, "run_all.py", "--outdir", str(dist),
                        "--diff", "payloads.lock.json"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout or "")
        sys.stderr.write(r.stderr or "")
        raise SystemExit("[!] payload manifest does not match payloads.lock.json")
    print("[+] payload manifest matches payloads.lock.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
