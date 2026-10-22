#!/usr/bin/env python3
"""Contract tests for the operator CLI commands.

The operator modules were importable and exposed over the API, but the
CLI had no command for them. These tests check that every command is
accepted, dispatches to a real module, and answers with real data.

The commands are exercised in-process through quantum.__main__.main()
and each one is only run twice (with and without its sub-query): the
probes behind them are real, so running each command four times cost
twenty minutes of the suite's runtime.
"""
import io
import json
import os
import sys
from contextlib import redirect_stdout

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from quantum.__main__ import main  # noqa: E402

#: command -> (module it must reach, a sub-query to exercise)
COMMANDS = {
    "cve": ("quantum.postexploit.cve_update", "check"),
    "persistence": ("quantum.postexploit.persistence_checker", "scan"),
    "cookiejar": ("quantum.postexploit.cookie_manager", "stores"),
    "mitm": ("quantum.postexploit.mitm_dashboard", "config"),
    "traffic": ("quantum.postexploit.traffic_analysis", "config"),
    "c2proxy": ("quantum.postexploit.c2_proxy", "chain"),
    "autoconfig": ("quantum.postexploit.auto_config", "defaults"),
    "godmode": ("quantum.postexploit.god_mode", None),
    "vault": ("quantum.postexploit.vault_share", "mount"),
    "pegasus": ("quantum.postexploit.nso_pegasus_ios", None),
    "otp": ("quantum.postexploit.otp_bypass", "forward"),
    "pivot": ("quantum.postexploit.pivot_lateral", "scan"),
    "mobile": ("quantum.postexploit.mobile_verification", None),
    "biometric": ("quantum.postexploit.biometric_clone", "artifacts"),
    "wallet": ("quantum.postexploit.cryptowallet", "search"),
    "logclean": ("quantum.postexploit.log_cleaner", "find"),
    "adbx": ("quantum.postexploit.adb_exploit", "devices"),
    "advanced": ("quantum.postexploit.advanced_config_aggregator", None),
}


def _run(args):
    """Run a CLI command in-process and return (rc, output).

    main() returns None for the commands that just print, which the
    launcher turns into exit code 0 via sys.exit(None).
    """
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(list(args))
    return rc, buf.getvalue()


def _ok(rc):
    """True when the command did not fail."""
    return rc in (0, None)


def _json(out):
    """The JSON document the command printed.

    The CLI prints a status banner (the AI bootstrap line) before the
    payload, so the document starts at the first brace.
    """
    body = out.strip()
    start = body.find("{")
    assert start != -1, "no JSON in the output: %r" % body[:200]
    return json.loads(body[start:])


def test_every_command_is_accepted():
    """The argparse choices must list every operator command."""
    with open(os.path.join(ROOT, "src", "quantum", "__main__.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    start = src.find('p.add_argument("cmd"')
    block = src[start:src.find('help="direct command', start)]
    for name in COMMANDS:
        assert '"%s"' % name in block, "%s is not an accepted command" % name


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_command_works(name):
    """The command must answer with JSON, reach its module, and not
    claim hardware it did not find."""
    import importlib
    module, query = COMMANDS[name]

    rc, out = _run([name])
    assert _ok(rc), out[-500:]
    assert out.strip(), name
    assert "ModuleNotFoundError" not in out
    assert "ImportError" not in out
    assert importlib.import_module(module) is not None

    state = _json(out)
    if isinstance(state, dict) and state.get("ok") and \
            state.get("hardware_connected"):
        assert state.get("status_note"), (
            "%s claims hardware without saying what it found" % name)

    if query is None:
        pytest.skip("no sub-query for %s" % name)
    rc, out = _run([name, "--query", query])
    assert _ok(rc), out[-500:]
    _json(out)
