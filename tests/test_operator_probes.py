#!/usr/bin/env python3
"""Contract tests for the operator probe modules.

Same rule as the other probe tests: a module may only report a
capability it actually verified. These modules used to return a literal
dictionary with "hardware_connected": True and no probe behind it.
"""
import json
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quantum.postexploit import advanced_config_aggregator as agg  # noqa: E402
from quantum.postexploit import c2_proxy  # noqa: E402
from quantum.postexploit import cookie_manager  # noqa: E402
from quantum.postexploit import cve_update  # noqa: E402
from quantum.postexploit import mitm_dashboard  # noqa: E402
from quantum.postexploit import persistence_checker  # noqa: E402
from quantum.postexploit import traffic_analysis  # noqa: E402

STATES = [
    ("advanced_config", agg.advanced_config_state),
    ("c2_proxy", c2_proxy.c2_proxy_dashboard_state),
    ("cookie", cookie_manager.cookie_manager_state),
    ("cve_update", cve_update.cve_update_state),
    ("mitm", mitm_dashboard.mitm_dashboard_state),
    ("persistence", persistence_checker.persistence_dashboard_state),
    ("traffic", traffic_analysis.traffic_dashboard_state),
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


# ---- cve_update -------------------------------------------------------

def test_cve_state_reports_the_registry_size():
    """The state must know how many CVEs this build ships."""
    state = cve_update.cve_update_state()
    assert state["registry_cves"] > 0
    assert state["update_method"] == "live_kev_feed_cross_check"


def test_cve_feed_result_matches_the_cached_catalogue():
    """A cached catalogue must be cross-checked against the registry."""
    state = cve_update.cve_update_state()
    if not state.get("feed_cached"):
        return
    assert state["kev_total"] > 0
    known = state["kev_known_to_registry"]
    assert isinstance(known, list)
    for cve in known:
        assert cve.startswith("CVE-")


# ---- persistence ------------------------------------------------------

def test_persistence_scan_reports_real_mechanisms():
    """The scan must find the mechanisms it knows about."""
    result = persistence_checker.check_persistence()
    assert result["ok"] is True
    assert result["platform"]
    for finding in result["findings"]:
        assert finding["mechanism"]
        assert "name" in finding


def test_persistence_dashboard_is_self_consistent():
    """The dashboard's own counts must agree with the findings it lists.

    The scan is not compared against a second scan: the host's services
    change between calls, so only the dashboard's internal consistency
    is asserted.
    """
    state = persistence_checker.persistence_dashboard_state()
    assert state["ok"] is True
    counted = state["checks"]
    listed = state["findings"]
    assert sum(counted.values()) == state["total"]
    for finding in listed:
        assert finding["mechanism"] in counted
    if listed:
        assert len(listed) == min(state["total"], len(listed))


# ---- cookie manager ---------------------------------------------------

def _make_cookie_db(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cookies (name TEXT, host_key TEXT, path TEXT, "
                 "expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, "
                 "value TEXT)")
    conn.executemany("INSERT INTO cookies VALUES (?,?,?,?,?,?,?)", [
        ("session", ".example.com", "/", 13400000000000000, 1, 1, "abc"),
        ("csrf", "app.example.com", "/app", 0, 0, 0, "tok"),
    ])
    conn.commit()
    conn.close()


def test_cookie_store_is_read_and_exported(tmp_path):
    """A real SQLite cookie store must be read and exported correctly."""
    db = str(tmp_path / "Cookies")
    _make_cookie_db(db)
    result = cookie_manager.read_cookie_store(db)
    assert result["ok"] is True
    assert result["count"] == 2
    names = {c["name"] for c in result["cookies"]}
    assert names == {"session", "csrf"}

    out = str(tmp_path / "cookies.txt")
    export = cookie_manager.export_netscape(result["cookies"], out)
    assert export["ok"] is True
    body = open(out, encoding="utf-8").read()
    assert "#HttpOnly_session" in body
    assert "app.example.com" in body


def test_cookie_store_failures_are_reported(tmp_path):
    """A locked / encrypted / missing store must say so, not look empty."""
    junk = str(tmp_path / "junk.db")
    with open(junk, "wb") as fh:
        fh.write(b"NOTSQLITE" * 8)
    result = cookie_manager.read_cookie_store(junk)
    assert result["ok"] is False
    assert result["error"]

    missing = cookie_manager.read_cookie_store(str(tmp_path / "nope.db"))
    assert missing["ok"] is False
    assert missing["error"]


def test_cookie_string_builder_and_injection(tmp_path):
    """The builder formats a string; the injector appends a real line."""
    built = cookie_manager.create_malicious_cookie("sid", "abc", ".example.com")
    assert built["cookie_string"].startswith("sid=abc")
    assert "HttpOnly" in built["flags"]

    target = str(tmp_path / "cookies.txt")
    result = cookie_manager.inject_cookie_session(built["cookie_string"], target)
    assert result["ok"] is True
    assert "sid" in open(target, encoding="utf-8").read()


# ---- mitm / traffic / c2 proxy ----------------------------------------

def test_mitm_reports_the_real_proxy_environment():
    """The proxy env it reports must be the environment's own."""
    state = mitm_dashboard.mitm_dashboard_state()
    assert state["ok"] is True
    for key, value in state["proxy_env"].items():
        assert os.environ.get(key) == value


def test_mitm_config_reports_whether_the_port_is_free():
    """A configuration must say whether the port could be bound."""
    config = mitm_dashboard.mitm_config(proxy_port=0)
    assert config["ok"] is True
    assert isinstance(config["port_free"], bool)
    assert config["available_tools"] is not None


def test_traffic_reports_real_interface_counters():
    """The interface list must come from the host, with real counters."""
    state = traffic_analysis.traffic_dashboard_state()
    assert state["ok"] is True
    for iface in state["interfaces"]:
        assert iface["name"]
        assert iface["rx_bytes"] >= 0
        assert iface["tx_bytes"] >= 0
    assert state["total_rx_bytes"] == sum(i["rx_bytes"]
                                          for i in state["interfaces"])


def test_c2_proxy_checks_its_endpoints():
    """A proxy chain must be probed, not just declared."""
    result = c2_proxy.configure_proxy_chain(["http://127.0.0.1:1"], [])
    assert result["ok"] is True
    assert result["checks"]
    check = result["checks"][0]
    assert check["host"] == "127.0.0.1"
    assert check["tcp_open"] in (True, False)


def test_c2_proxy_reverse_dns_is_verified():
    """reverse_dns_c2 must report whether the name resolves."""
    result = c2_proxy.reverse_dns_c2("localhost")
    assert result["ok"] is True
    assert result["resolves"] is True


# ---- aggregator --------------------------------------------------------

def test_aggregator_lists_every_module():
    """The aggregator must cover its declared sources."""
    result = agg.aggregate_all()
    assert result["ok"] is True
    assert result["modules"] == len(agg.SOURCES)
    for entry in result["detail"]:
        assert entry["module"]
        assert isinstance(entry["active"], bool)


def test_aggregator_does_not_count_unavailable_modules_as_active():
    """A module that failed to load must not be reported as active."""
    result = agg.aggregate_all()
    for entry in result["unavailable_modules"]:
        assert entry["module"] not in result["active_modules"]
        assert entry["error"]
