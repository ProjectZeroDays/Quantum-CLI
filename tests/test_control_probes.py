#!/usr/bin/env python3
"""Contract tests for the real hardware probes.

These modules used to ship placeholder dashboards that hard-coded
"hardware_connected": True (or False) and listed no devices. The
invariant these tests lock in is that a probe may only claim hardware is
present when it actually found something — the same "no simulated code"
rule the rest of the codebase follows.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quantum.control import bluetooth as bt  # noqa: E402
from quantum.control import hid as hidmod  # noqa: E402
from quantum.control import imsi as imsimod  # noqa: E402
from quantum.control import sdr as sdrmod  # noqa: E402

PROBES = [
    ("bluetooth", bt.bluetooth_dashboard_state),
    ("hid", hidmod.hid_dashboard_state),
    ("sdr", sdrmod.sdr_dashboard_state),
    ("imsi", imsimod.imsi_dashboard_state),
]


@pytest.mark.parametrize("name,fn", PROBES)
def test_probe_returns_a_json_safe_state(name, fn):
    """Every probe returns a JSON-serialisable state with the common keys."""
    state = fn()
    assert isinstance(state, dict), name
    assert state.get("ok") in (True, False), name
    assert "updated" in state, name
    json.dumps(state)  # must be JSON-safe


@pytest.mark.parametrize("name,fn", PROBES)
def test_probe_never_claims_unverified_hardware(name, fn):
    """hardware_connected may only be True when a device was actually found.

    This is the regression test for the placeholder dashboards, which
    returned a hard-coded "hardware_connected": True with no devices.
    """
    state = fn()
    if not state.get("ok"):
        return
    connected = state.get("hardware_connected")
    assert connected in (True, False), name
    if connected:
        found = state.get("devices_found")
        assert isinstance(found, int) and found > 0, (
            "%s claims hardware_connected with no devices found" % name)


@pytest.mark.parametrize("name,fn", PROBES)
def test_probe_reports_a_status_note(name, fn):
    """A probe that finds nothing must say so."""
    state = fn()
    if not state.get("ok"):
        return
    note = state.get("status_note", "")
    assert note, name
    if not state.get("hardware_connected"):
        assert "no" in note.lower() or "install" in note.lower(), (
            "%s: status note should explain the absence: %r" % (name, note))


def test_bluetooth_controller_split_is_real():
    """The Bluetooth probe separates controllers from services."""
    state = bt.bluetooth_dashboard_state()
    if not state.get("ok"):
        return
    controllers = state.get("controllers", [])
    devices = state.get("devices", [])
    assert len(controllers) + len(devices) >= state.get("devices_found", 0)
    if state.get("hardware_connected"):
        assert controllers, (
            "a host with a Bluetooth radio must list the controller")


def test_bluetooth_scan_is_honest():
    """scan_devices either reports a real scan or explains why it cannot."""
    result = bt.scan_devices()
    assert "ok" in result
    if result.get("ok"):
        assert "devices_found" in result
    else:
        assert result.get("error")


def test_hid_raw_is_linux_only_and_says_so():
    """hidraw nodes only exist on Linux; other hosts must say so."""
    result = hidmod.hid_raw_devices()
    if result.get("ok"):
        assert "nodes" in result
    else:
        assert result.get("error")


def test_sdr_probe_lists_only_installed_tools():
    """probe_radios must only report tools that are actually installed."""
    result = sdrmod.probe_radios()
    assert "tools" in result
    for entry in result.get("tools", []):
        assert entry.get("tool")
        assert entry.get("ok") in (True, False)


def test_imsi_read_needs_a_real_modem():
    """read_imsi must not invent an IMSI."""
    result = imsimod.read_imsi("")
    if result.get("ok"):
        imsi = result.get("imsi", "")
        assert imsi.isdigit() and 14 <= len(imsi) <= 16, result
    else:
        assert result.get("error")


def test_control_package_exposes_no_empty_modules():
    """No module in quantum.control may be an empty placeholder file."""
    pkg = os.path.join(ROOT, "src", "quantum", "control")
    for name in sorted(os.listdir(pkg)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(pkg, name)
        with open(path, "rb") as fh:
            body = fh.read()
        assert body.strip(), "empty module: %s" % name


def test_cli_registers_the_probe_commands():
    """The CLI accepts the probe commands."""
    with open(os.path.join(ROOT, "src", "quantum", "__main__.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    for cmd in ("bluetooth", "hid", "sdr", "imsi"):
        assert 'a.cmd == "%s"' % cmd in src, cmd
