#!/usr/bin/env python3
"""
run_all.py — generate every exploit payload into dist/ and emit a hashed manifest.

  python3 run_all.py                  # build all + manifest.json + manifest.md
  python3 run_all.py --verify         # re-hash dist/ against manifest.json
  python3 run_all.py --no-manifest    # payloads only

Modules without a build() are recorded as 'driver' (need hardware).
"""
import argparse, hashlib, importlib.util, json, re, sys, time
from pathlib import Path

EXT = {
    "cve_2023_41064_blastpass_webp": "webp",
    "cve_2021_30860_forcedentry_jbig2": "pdf",
    "cve_2023_41991_imessage_blastdoor": "gif",
    "cve_2023_2569_whatsapp_mp4": "mp4",
    "cve_2023_21268_mediacodec": "mp4",
    "cve_2023_47081_imessage_mp4": "mp4",
    "cve_2019_11931_whatsapp_mp4": "mp4",
    "cve_2015_6602_stagefright": "mp4",
    "cve_2025_20878_roku_mediaplayer": "mp4",
    "cve_2017_13077_krack": "bin",
    "cve_2023_31864_kdtree": "bin",
    "cve_2023_35964_schema": "bin",
    "cve_2023_32780_rt_table": "bin",
    "cve_2022_0847_dirtypipe": "bin",
    "cve_2020_0022_bluefrag": None,        # live driver
    "cve_2026_0073_adb_tls_bypass": None,  # live driver
    # ---- browser / HTML drive-by pages ----
    "cve_2020_6418_chrome_v8": "html",
    "cve_2020_16040_chrome_v8": "html",
    "cve_2021_21224_chrome_v8": "html",
    "cve_2020_0674_ie_jscript": "html",
    "cve_2023_42793_tizen_browser": "html",
    "cve_2026_87588_chromecast_uaf": "html",
    "cve_2026_95372_chromecast_uaf": "html",
    "cve_2026_106382_chromecast_uaf": "html",
    # ---- images / fonts ----
    "cve_2020_15999_freetype": "png",
    "cve_2025_27610_tizen_imageviewer": "jpg",
    # ---- structured payloads ----
    "cve_2019_8641_imessage_nskeyed": "plist",
    "cve_2019_3568_whatsapp_voip": "sip",
    "cve_2024_25065_webos_lunabus": "json",
    "cve_2025_22450_vizio_smartcastagent": "json",
    "cve_2023_42791_webos_mrcjson": "json",
    "cve_2025_25066_webos_webappmgr": "json",
    "cve_2023_42787_roku_ecp": "xml",
    "cve_2023_28412_tizen_privmgr": "xml",
    "cve_2024_36210_roku_devmode": "zip",
    "cve_2023_42790_webos_aresinstall": "ipk",
    "cve_2024_42794_tizen_wasm": "wasm",
    "cve_2024_36212_hisense_mediafw": "mkv",
    "cve_2024_23339_tizen_service": "tsvc",
    "cve_2023_26084_androidtv_binder": "parcel",
    "cve_2025_20879_hisense_settings": "txt",
    # ---- radio frames ----
    "cve_2020_24588_fragattacks_amsdu": "frame",
    "cve_2020_24586_fragattacks_cache": "frame",
    "cve_2020_24587_fragattacks_mixedkey": "frame",
    "cve_2023_42794_chromecast_companion": "mdns",
    # ---- kernel / config triggers ----
    "cve_2024_1086_nftables": "nft",
    "cve_2023_0179_nftables": "nft",
    "cve_2022_2588_cls_route": "sh",
}

def _cve_id(stem: str) -> str:
    m = re.match(r"cve_(\d{4})_(\d{4,6})", stem)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else stem.upper()

def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def build_all(exploits_dir: Path, outdir: Path) -> list:
    outdir.mkdir(parents=True, exist_ok=True)
    entries = []
    for py in sorted(p for p in exploits_dir.glob("*.py") if p.stem != "__init__"):
        cve = _cve_id(py.stem)
        try:
            mod = _load(py)
        except Exception as e:
            entries.append({"cve": cve, "module": py.name, "status": "load-error",
                            "error": f"{type(e).__name__}: {e}"})
            print(f"  [-] {cve}: load error ({e})")
            continue

        if not hasattr(mod, "build"):
            entries.append({"cve": cve, "module": py.name, "status": "driver"})
            print(f"  [~] {cve}: driver (no payload)")
            continue

        try:
            data = mod.build()
        except Exception as e:
            entries.append({"cve": cve, "module": py.name, "status": "build-error",
                            "error": f"{type(e).__name__}: {e}"})
            print(f"  [-] {cve}: build error ({e})")
            continue

        ext = EXT.get(py.stem, "bin")
        fname = f"{cve}.{ext}"
        (outdir / fname).write_bytes(data)
        entries.append({"cve": cve, "module": py.name, "status": "ok",
                        "file": fname, "bytes": len(data), "sha256": _sha(data)})
        print(f"  [+] {cve}: {fname} ({len(data)} bytes)")

        # side artifacts (bytes-exact: no text-mode newline translation)
        if hasattr(mod, "C_STUB"):
            stub_bytes = mod.C_STUB.encode()
            (outdir / f"{cve}.c").write_bytes(stub_bytes)
            entries.append({"cve": cve, "module": py.name, "status": "ok",
                            "file": f"{cve}.c", "bytes": len(stub_bytes),
                            "sha256": _sha(stub_bytes)})
        if hasattr(mod, "radiotap_wrap"):
            frame = mod.radiotap_wrap(data)
            (outdir / f"{cve}.frame").write_bytes(frame)
            entries.append({"cve": cve, "module": py.name, "status": "ok",
                            "file": f"{cve}.frame", "bytes": len(frame),
                            "sha256": _sha(frame)})
    return entries

def write_manifest(outdir: Path, entries: list) -> Path:
    ok = [e for e in entries if e["status"] == "ok"]
    manifest = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "count": len(ok),
        "total_bytes": sum(e.get("bytes", 0) for e in ok),
        "artifacts": ok,
        "non_payload": [e for e in entries if e["status"] != "ok"],
    }
    mj = outdir / "manifest.json"
    # newline="\n" so the manifest is byte-identical on every platform:
    # the default text mode writes CRLF on Windows, which would make the
    # payload lock and the release archives differ between a Windows
    # checkout and a CI one.
    with open(mj, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(manifest, indent=2))

    lines = [f"# Payload manifest", "",
             f"Generated: {manifest['generated']}",
             f"Artifacts: {manifest['count']}  |  Total: {manifest['total_bytes']} bytes", "",
             "| CVE | file | bytes | sha256 |", "|-----|------|------:|--------|"]
    for e in ok:
        lines.append(f"| {e['cve']} | `{e['file']}` | {e['bytes']} | `{e['sha256'][:16]}...` |")
    if manifest["non_payload"]:
        lines += ["", "## Non-payload", ""]
        for e in manifest["non_payload"]:
            lines.append(f"- {e['cve']} — {e['status']}" + (f" ({e['error']})" if e.get("error") else ""))
    with open(outdir / "manifest.md", "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return mj

def verify(outdir: Path) -> int:
    mj = outdir / "manifest.json"
    if not mj.exists():
        print("[!] no manifest.json — run without --verify first"); return 1
    manifest = json.loads(mj.read_text())
    bad = 0
    for e in manifest["artifacts"]:
        p = outdir / e["file"]
        if not p.exists():
            print(f"  [-] MISSING {e['file']}"); bad += 1; continue
        got = _sha(p.read_bytes())
        if got != e["sha256"]:
            print(f"  [-] TAMPERED {e['file']}"); bad += 1
        else:
            print(f"  [+] ok {e['file']}")
    print(f"[{'FAIL' if bad else 'PASS'}] {len(manifest['artifacts']) - bad}/"
          f"{len(manifest['artifacts'])} verified")
    return 1 if bad else 0

def diff_manifest(lock: Path, outdir: Path) -> int:
    """Compare freshly-built artifacts against a committed lock. 1 = drift."""
    if not lock.exists():
        print(f"[!] lock file {lock} missing"); return 1
    mj = outdir / "manifest.json"
    if not mj.exists():
        print("[!] no dist/manifest.json — run the build first"); return 1
    lock_m = json.loads(lock.read_text())
    cur = json.loads(mj.read_text())
    a = {e["file"]: e for e in lock_m.get("artifacts", [])}
    b = {e["file"]: e for e in cur.get("artifacts", [])}
    drift = []
    for f in sorted(set(a) | set(b)):
        if f not in a:
            drift.append(f"+ {f} (new)")
        elif f not in b:
            drift.append(f"- {f} (removed)")
        elif a[f]["sha256"] != b[f]["sha256"]:
            drift.append(f"~ {f}  {a[f]['sha256'][:12]} -> {b[f]['sha256'][:12]}")
    if drift:
        print("[!] payload manifest drift:")
        for d in drift:
            print(f"    {d}")
        print("    -> run 'make lock' and commit payloads.lock.json")
        return 1
    print(f"[+] manifest matches lock ({len(a)} artifacts)")
    return 0

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exploits", default="exploits")
    ap.add_argument("--outdir", default="dist")
    ap.add_argument("--no-manifest", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--diff", metavar="LOCK",
                    help="compare built manifest against a committed lock")
    a = ap.parse_args()

    ed, out = Path(a.exploits), Path(a.outdir)
    if not ed.exists():
        print(f"[!] exploits dir '{ed}' not found"); return 1

    if a.verify:
        return verify(out)

    if a.diff:
        return diff_manifest(Path(a.diff), out)

    print(f"[*] generating payloads from {ed}/ -> {out}/")
    entries = build_all(ed, out)
    ok = sum(1 for e in entries if e["status"] == "ok")
    if not a.no_manifest:
        mj = write_manifest(out, entries)
        print(f"[+] manifest -> {mj} and {out}/manifest.md")
    print(f"[+] {ok} artifacts written to {out}/")
    return 0

if __name__ == "__main__":
    sys.exit(main())
