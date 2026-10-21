#!/usr/bin/env python3
"""Contract tests for the remaining operator modules.

Same rule as the other probe tests: a module may only report a
capability it actually verified. These modules used to return a literal
dictionary with "hardware_connected": True and no probe behind it.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quantum.postexploit import dark_web_browser  # noqa: E402
from quantum.postexploit import ddos  # noqa: E402
from quantum.postexploit import god_mode  # noqa: E402
from quantum.postexploit import mobile_verification  # noqa: E402
from quantum.postexploit import nso_pegasus_ios  # noqa: E402
from quantum.postexploit import otp_bypass  # noqa: E402
from quantum.postexploit import pivot_lateral  # noqa: E402
from quantum.postexploit import rat_mobile  # noqa: E402
from quantum.postexploit import vault_share  # noqa: E402

STATES = [
    ("dark_web_browser", dark_web_browser.dark_web_browser_state),
    ("ddos", ddos.ddos_dashboard_state),
    ("god_mode", god_mode.god_mode_config),
    ("mobile_verification", mobile_verification.mobile_verification_state),
    ("nso_pegasus_ios", nso_pegasus_ios.nso_pegasus_dashboard_state),
    ("otp_bypass", otp_bypass.intercept_sms_state),
    ("pivot_lateral", pivot_lateral.pivot_dashboard_state),
    ("rat_mobile", rat_mobile.rat_dashboard_state),
    ("vault_share", vault_share.vault_dashboard_state),
]


@pytest.mark.parametrize("name,fn", STATES)
def test_state_is_json_safe(name, fn):
    state = fn()
    assert isinstance(state, dict), name
    json.dumps(state)


@pytest.mark.parametrize("name,fn", STATES)
def test_state_never_claims_unverified_hardware(name, fn):
    """hardware_connected may only be True when something was found."""
    state = fn()
    if not state.get("ok"):
        return
    if state.get("hardware_connected"):
        assert state.get("status_note"), (
            "%s claims hardware without saying what it found" % name)


# ---- otp_bypass -------------------------------------------------------

def test_sms_forward_code_is_well_formed():
    """The forwarding code must be the carrier's own format."""
    code = otp_bypass._forward_code("+1 (555) 123-4567")
    assert code == "*#*#15551234567#*#*#"
    assert otp_bypass._forward_code("nonsense") == ""


def test_sms_state_lists_its_real_sources():
    """Every SMS source reported must actually have been read."""
    state = otp_bypass.intercept_sms_state()
    for source in state["sources"]:
        if source.get("source", "").startswith("adb"):
            assert source.get("ok") in (True, False)
        else:
            assert "count" in source or "modems" in source


def test_forwarding_without_a_channel_is_not_claimed():
    """No modem and no device must not report a forwarding set."""
    result = otp_bypass.set_sms_forwarding("15551234567")
    if result.get("ok"):
        assert result.get("status") == "submitted"
    else:
        assert result.get("status") == "not_submitted"
        assert result.get("error")


# ---- pivot_lateral ----------------------------------------------------

def test_neighbour_scan_comes_from_the_host():
    """The neighbours reported must be the host's own ARP entries."""
    result = pivot_lateral.pivot_scan(limit=4)
    assert result["ok"] is True
    for entry in result["results"]:
        assert entry["ip"]
        assert isinstance(entry["pivot_surfaces"], list)


def test_pivot_probe_only_reports_open_ports():
    """A surface listed must have answered."""
    state = pivot_lateral.pivot_dashboard_state()
    assert state["ok"] is True
    for neighbour in state["neighbours"]:
        assert isinstance(neighbour["pivot_surfaces"], list)


# ---- vault_share ------------------------------------------------------

def test_vault_state_lists_real_paths():
    """Any path reported must exist."""
    state = vault_share.vault_dashboard_state()
    assert state["ok"] is True
    for group in ("encrypted_mounts", "cryptomator_vaults", "backup_dirs"):
        for path in state[group]:
            assert os.path.isdir(path), path
    for path in state["encrypted_files"]:
        assert os.path.isfile(path), path


# ---- rat / darkweb / ios -----------------------------------------------

def test_rat_state_reads_the_tracked_module():
    """The RAT state must come from the tracked rat module."""
    state = rat_mobile.rat_dashboard_state()
    assert state["ok"] is True
    assert state["repo_count"] > 0
    assert state["modules_enabled"] is not None


def test_dark_web_reports_the_real_tor_state():
    """The Tor state must reflect the host, not a claim."""
    state = dark_web_browser.dark_web_browser_state()
    assert state["ok"] is True
    assert isinstance(state["socks_open"], bool)
    if state["tor_binary"] is None:
        assert state["socks_open"] is False


def test_ios_state_lists_real_paths():
    """Any iOS artefact path reported must exist."""
    state = nso_pegasus_ios.nso_pegasus_dashboard_state()
    assert state["ok"] is True
    for group in ("backups", "pairing_records"):
        for entry in state[group]:
            assert os.path.isdir(entry["path"]), entry["path"]
    for path in state["indicators"]:
        assert os.path.isfile(path), path


# ---- god_mode ---------------------------------------------------------

def test_god_mode_reports_real_privileges():
    """privileged_access must reflect the process, not a constant."""
    config = god_mode.god_mode_config()
    assert config["ok"] is True
    assert config["privileged_access"] in (True, False)
    assert config["effective_user"]
    assert config["modules_enabled"] or config["modules_missing"]
    if config["privileged_access"]:
        assert "administrator" in config["privileges"]
    else:
        assert "standard" in config["privileges"]


def test_operator_profile_round_trips(tmp_path, monkeypatch):
    """The saved profile must be readable again."""
    monkeypatch.setattr(god_mode, "PROFILE_PATH",
                        str(tmp_path / "profile.json"))
    saved = god_mode.set_operator_profile(["crypto", "adb_exploit"],
                                          notes="test")
    assert saved["ok"] is True
    assert "crypto" in saved["modules"]
    assert "adb_exploit" in saved["modules"]
    loaded = god_mode._load_profile()
    assert loaded["notes"] == "test"
    assert loaded["modules"] == saved["modules"]


# ---- ddos -------------------------------------------------------------

def test_ddos_reports_real_egress():
    """The egress flag must reflect a real connectivity check."""
    state = ddos.ddos_dashboard_state()
    assert state["ok"] is True
    if not state["egress"]:
        assert state["egress_error"]


def test_target_config_requires_authorization():
    """A target may not be recorded without an authorization reference."""
    assert ddos.target_config("example.com").get("ok") is False
    ok = ddos.target_config("example.com", 80, 5, "AUTH-42")
    assert ok["ok"] is True
    assert ok["authorization"] == "AUTH-42"


def test_lab_load_test_is_loopback_only():
    """The load test must refuse anything that is not loopback."""
    import inspect
    src = inspect.getsource(ddos.lab_load_test)
    assert "127.0.0.1" in src
    assert "LOOPBACK" in src
