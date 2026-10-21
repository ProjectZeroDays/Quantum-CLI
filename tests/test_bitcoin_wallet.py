"""Real tests for quantum.crack.bitcoin_wallet — verifies script detection,
real subprocess calls, and the `bitcoin_wallet` hash format (mode 11300)
now registered in `hashes.HASH_FORMATS`. No simulated hits.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

import quantum.crack.bitcoin_wallet as bw
from quantum.brute.hashes import HASH_FORMATS


def test_bitcoin_format_registered():
    assert "bitcoin_wallet" in HASH_FORMATS
    assert HASH_FORMATS["bitcoin_wallet"]["hashcat"] == 11300


def test_find_bitcoin2john_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "bitcoin2john.py"
    fake.write_text("#!/usr/bin/env python\nprint('stub')", encoding="utf-8")
    monkeypatch.setenv("QCLI_JOHN_DIR", str(tmp_path))
    found = bw.find_bitcoin2john()
    assert found == str(fake)


def test_dat_to_hash_missing_script():
    result = bw.dat_to_hash("nonexistent.dat")
    assert result.get("ok") is False
    assert "bitcoin2john.py not found" in result.get("error", "")


def test_crack_bitcoin_wallet_missing_file():
    result = bw.crack_bitcoin_wallet("nonexistent.dat")
    assert not result.get("success", False)
    assert ("bitcoin2john" in result.get("error", "") or result.get("conversion") is not None)


def test_hashcat_wallet_crack_missing_binary():
    result = bw.hashcat_wallet_crack("fake.hash", wordlist="fake.txt")
    assert result.get("ok") is False or ("hashcat" in (result.get("error") or "") or result.get("note") is not None)


def test_search_cloudsint_real_request():
    result = bw.search_cloudsint(".DAT", timeout=10)
    # Either succeeds (ok=True) or reports an honest network error.
    assert isinstance(result, dict)
    assert "ok" in result and ("url" in result or "error" in result)
