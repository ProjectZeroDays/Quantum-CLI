#!/usr/bin/env python3
"""Smoke + structural regression tests. No hardware required."""
import hashlib, importlib.util, json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
EXPLOITS = ROOT / "exploits"

PAYLOADS = {
    "cve_2023_41064_blastpass_webp":    dict(magic=b"RIFF", contains=[b"WEBP"]),
    "cve_2021_30860_forcedentry_jbig2": dict(magic=b"%PDF", contains=[b"/JBIG2Decode"], tail=b"%%EOF"),
    "cve_2023_41991_imessage_blastdoor":dict(magic=b"GIF89a"),
    "cve_2023_2569_whatsapp_mp4":       dict(magic=None, contains=[b"ftyp", b"stsc"]),
    "cve_2023_21268_mediacodec":        dict(magic=None, contains=[b"ftyp", b"stsc"]),
    "cve_2023_47081_imessage_mp4":      dict(magic=None, contains=[b"ftyp", b"stsc", b"mvhd"]),
    "cve_2017_13077_krack":             dict(magic=b"\x02\x03"),
    "cve_2023_31864_kdtree":            dict(exact_len=22),  # BB(2)+ii(8)+d(8)+I(4)
    "cve_2023_35964_schema":            dict(magic=b"SCHM"),
    "cve_2023_32780_rt_table":          dict(exact_len=18),  # 3xIPv4(12)+IH(6)
    "cve_2022_0847_dirtypipe":          dict(tail=b"\x0f\x05"),
}
DRIVERS = ["cve_2020_0022_bluefrag", "cve_2026_0073_adb_tls_bypass"]

def _load(stem):
    p = EXPLOITS / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

@pytest.mark.parametrize("stem", sorted(PAYLOADS) + DRIVERS)
def test_module_loads(stem):
    assert (EXPLOITS / f"{stem}.py").exists()
    _load(stem)

@pytest.mark.parametrize("stem", sorted(PAYLOADS))
def test_build_returns_bytes(stem):
    data = _load(stem).build()
    assert isinstance(data, bytes) and len(data) > 0

@pytest.mark.parametrize("stem", sorted(PAYLOADS))
def test_build_is_deterministic(stem):
    mod = _load(stem)
    assert mod.build() == mod.build()

@pytest.mark.parametrize("stem", sorted(PAYLOADS))
def test_structural_invariants(stem):
    spec, data = PAYLOADS[stem], _load(stem).build()
    if spec.get("magic"):
        assert data.startswith(spec["magic"])
    for needle in spec.get("contains", []):
        assert needle in data, f"{stem}: missing {needle!r}"
    if spec.get("tail"):
        assert data.endswith(spec["tail"])
    if spec.get("exact_len"):
        assert len(data) == spec["exact_len"]

def test_drivers_have_no_build_or_are_importable():
    for stem in DRIVERS:
        mod = _load(stem)
        assert hasattr(mod, "main")

def test_manifest_matches_dist_if_present():
    mj = ROOT / "dist" / "manifest.json"
    if not mj.exists():
        pytest.skip("no dist/manifest.json")
    manifest = json.loads(mj.read_text())
    for e in manifest["artifacts"]:
        p = ROOT / "dist" / e["file"]
        assert p.exists(), f"missing {e['file']}"
        assert hashlib.sha256(p.read_bytes()).hexdigest() == e["sha256"], f"hash drift {e['file']}"

def test_manifest_has_no_error_entries():
    mj = ROOT / "dist" / "manifest.json"
    if not mj.exists():
        pytest.skip("no dist/manifest.json")
    manifest = json.loads(mj.read_text())
    errors = [e for e in manifest["non_payload"] if e["status"].endswith("error")]
    assert not errors, f"build/load errors: {errors}"

ZIP_MODULES = ["cve_2023_42790_webos_aresinstall", "cve_2024_36210_roku_devmode"]

@pytest.mark.parametrize("stem", ZIP_MODULES)
def test_zip_entries_pinned_epoch(stem):
    """ZIP builds must not embed wall-clock mtimes (manifest drift)."""
    import io, zipfile
    data = _load(stem).build()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert z.namelist(), f"{stem}: empty zip"
        for info in z.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0), \
                f"{stem}:{info.filename} has wall-clock mtime {info.date_time}"


@pytest.mark.parametrize("stem", ZIP_MODULES)
def test_zip_bytes_are_platform_and_zlib_independent(stem):
    """The built archive must be byte-identical everywhere.

    Two sources of drift are pinned here:
      * ZipInfo.create_system defaults to 0 on Windows and 3 on Unix;
      * DEFLATE output depends on the zlib build (classic zlib vs
        zlib-ng disagree byte-for-byte on the same input).
    So the archive is stored (no compressor) and the host field is pinned.
    """
    import io, zipfile
    data = _load(stem).build()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            assert info.compress_type == zipfile.ZIP_STORED, \
                f"{stem}:{info.filename} is compressed — deflate output " \
                f"varies with the zlib build and drifts the manifest"
            assert info.create_system == 0, \
                f"{stem}:{info.filename} host field is {info.create_system} — " \
                f"ZipInfo defaults to 0 on Windows and 3 on Unix"


C_STUB_MODULES = ["cve_2019_2215_bad_binder", "cve_2022_0847_dirtypipe",
                  "cve_2024_1086_nftables"]


@pytest.mark.parametrize("stem", C_STUB_MODULES)
def test_manifest_byte_count_is_the_encoded_size(stem, tmp_path):
    """The manifest must record the BYTE size of a C stub, not its
    character count.

    These stubs contain U+2014 (em dash): one character, three bytes.
    Recording len(str) made the manifest's "bytes" field disagree with
    the file actually written, so the release archive did not match
    payloads.lock.json.
    """
    mod = _load(stem)
    stub = mod.C_STUB
    assert len(stub) != len(stub.encode()), \
        f"{stem}: expected the stub to contain a non-ASCII character — " \
        f"this test would not catch the char/byte mix-up"

    import run_all
    entries = run_all.build_all(EXPLOITS, tmp_path)
    run_all.write_manifest(tmp_path, entries)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    arts = {a["file"]: a for a in manifest["artifacts"] if a.get("file")}

    stub_files = [f for f in arts if f.endswith(".c")]
    assert stub_files, "no C stub artifacts were produced"
    for name in stub_files:
        on_disk = (tmp_path / name).read_bytes()
        assert arts[name]["bytes"] == len(on_disk), \
            f"{name}: manifest says {arts[name]['bytes']} bytes, " \
            f"file is {len(on_disk)}"
        assert arts[name]["sha256"] == hashlib.sha256(on_disk).hexdigest()
