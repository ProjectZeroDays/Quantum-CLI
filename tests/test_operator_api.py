#!/usr/bin/env python3
"""Contract tests for the operator API surface.

Two invariants are locked in here:

1. Every route the operator modules expose must work — the modules were
   rewritten, and the routes that call them must still find the
   functions they import.

2. A state-changing operation must not be reachable with a GET. A GET
   can be triggered by a browser prefetch, a link preview or a crawler,
   so routes that clean logs, inject cookies, deploy an APK or set SMS
   forwarding are POST-only.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from quantum.c2.app import make_c2  # noqa: E402

#: Routes that read state — safe to call.
READ_ROUTES = [
    "/api/crypto/dashboard", "/api/biometric/dashboard",
    "/api/biometric/search", "/api/biometric/style", "/api/otp/dashboard",
    "/api/otp/intercept", "/api/logclean/find", "/api/logclean/dashboard",
    "/api/adb/dashboard", "/api/adb/usb", "/api/pivot/dashboard",
    "/api/ddos/dashboard", "/api/c2proxy/dashboard",
    "/api/autoconfig/dashboard", "/api/autoconfig/defaults",
    "/api/god_mode/config", "/api/darkweb/dashboard", "/api/darkweb/search",
    "/api/darkweb/services", "/api/darkweb/state", "/api/vault/dashboard",
    "/api/nso_pegasus/dashboard", "/api/mitm/dashboard",
    "/api/rat/dashboard", "/api/rat/ios", "/api/rat/android",
    "/api/rat/mobile_spy", "/api/rat/features", "/api/mobile/verify",
    "/api/cookie/manager", "/api/traffic/analysis",
    "/api/persistence/check", "/api/advanced/config",
    "/api/bluetooth/state", "/api/bluetooth/scan", "/api/hid/state",
    "/api/hid/raw", "/api/sdr/state", "/api/sdr/probe", "/api/imsi/state",
]

#: Routes that change state — POST only.
STATE_CHANGING_ROUTES = [
    "/api/otp/forward", "/api/otp/reset", "/api/logclean/clean",
    "/api/cookie/inject", "/api/adb/deploy",
    "/api/nso_pegasus/forced_entry", "/api/imsi/read",
]


@pytest.fixture(scope="module")
def client():
    return make_c2({"default": "# agent"}).test_client()


@pytest.mark.parametrize("path", READ_ROUTES)
def test_read_route_works(client, path):
    """Every read route must answer, and must not 5xx."""
    r = client.get(path)
    assert r.status_code < 500, "%s -> %d" % (path, r.status_code)
    assert r.status_code in (200, 404, 405), path


@pytest.mark.parametrize("path", STATE_CHANGING_ROUTES)
def test_state_changing_route_refuses_get(client, path):
    """A state-changing route must not be reachable with a GET."""
    r = client.get(path, json={})
    assert r.status_code == 405, (
        "%s answered GET with %d — state-changing operations must be "
        "POST-only" % (path, r.status_code))


def test_no_route_imports_a_missing_symbol():
    """Every symbol the routes import must exist in its module."""
    import importlib
    import re
    with open(os.path.join(ROOT, "src", "quantum", "c2", "routes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    pattern = re.compile(
        r"from\s+(quantum\.postexploit\.[a-z_]+)\s+import\s+\(([^)]*)\)|"
        r"from\s+(quantum\.postexploit\.[a-z_]+)\s+import\s+([^\n(]+)")
    missing = []
    checked = 0
    for m in pattern.finditer(src):
        module = m.group(1) or m.group(3)
        names = m.group(2) or m.group(4)
        for name in [n.strip() for n in names.replace("\n", " ").split(",")
                     if n.strip()]:
            checked += 1
            mod = importlib.import_module(module)
            if not hasattr(mod, name):
                missing.append("%s.%s" % (module, name))
    assert checked > 40
    assert not missing, "routes import missing symbols: %s" % missing


def test_log_cleaner_does_not_search_the_working_directory():
    """The cleaner must not default to the source tree.

    A cleaner that can rewrite the operator's own repository is a
    foot-gun: the endpoint is reachable from the dashboard.
    """
    from quantum.postexploit import log_cleaner
    import inspect
    src = inspect.getsource(log_cleaner.find_target_logs)
    body = src.split("paths = [", 1)[-1].split("]", 1)[0]
    assert '"."' not in body and "'.'" not in body, (
        "the default search roots must not include the working directory")
    # and the default must not return files from the repo
    for path in log_cleaner.find_target_logs():
        assert not os.path.abspath(path).startswith(
            os.path.abspath(ROOT) + os.sep), path
