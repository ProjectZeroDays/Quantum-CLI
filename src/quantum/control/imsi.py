"""quantum.control.imsi — real IMSI-catcher / cellular-radio discovery.

IMSI catching needs a real radio that can act as a base station, so the
module reports what the host actually has:

  SDR radios   the same USB-id table the SDR module uses (USRP B2xx,
               LimeSDR, HackRF), because a 2x2 / full duplex capable
               radio is what a real IMSI catcher is built from
  Modems       a real cellular modem on the host (Linux ModemManager /
               Windows Mobile Broadband), which is the one thing that can
               legitimately read an IMSI
  Tools        uhd_find_devices / rtl_test / SoapySDR presence

The IMSI itself is only reported when the host's own modem hands it
over (AT+CIMI via ModemManager). Nothing is inferred.

Authorized engagements / lab work only.
"""
from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
from datetime import datetime

#: The radios an IMSI catcher is actually built from.
CAPTURE_CAPABLE_RADIOS = {
    ("2500", "0031"): "USRP B205mini (2x2 MIMO, full duplex)",
    ("2500", "0037"): "USRP B210 (2x2 MIMO, full duplex)",
    ("2500", "0020"): "USRP N210 (1x1, half duplex)",
    ("e4e0", "0001"): "LimeSDR Mini (1x1, half duplex)",
    ("1d50", "6089"): "HackRF One (1x1, half duplex)",
}

HARDWARE_COMPAT = ("USRP B210 / LimeSDR / sdrsharp-compatible; drivers: "
                   "UHD / LimeSuite; download from https://uhd.ettus.com/ / "
                   "https://limems.org/")

DRIVER_SOURCES = {
    "Linux": "https://uhd.ettus.com/support",
    "Windows": "https://www.ettus.com/downloads",
    "Darwin": "https://www.ettus.com/downloads",
}

#: The cellular side: a modem that can answer AT+CIMI.
MODEM_TOOLS = {
    "mmcli": "ModemManager (Linux) — can read the SIM IMSI with AT+CIMI",
}


def _run(cmd, timeout=25):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return False, ""
    return proc.returncode == 0, (proc.stdout or "")


def _linux_radios():
    devices = []
    for base in sorted(glob.glob("/sys/bus/usb/devices/*/idVendor")):
        parent = os.path.dirname(base)
        pid_p = os.path.join(parent, "idProduct")
        if not os.path.isfile(pid_p):
            continue
        try:
            vp = (open(base).read().strip().lower(),
                  open(pid_p).read().strip().lower())
        except OSError:
            continue
        if vp not in CAPTURE_CAPABLE_RADIOS:
            continue
        product = os.path.join(parent, "product")
        name = ""
        if os.path.isfile(product):
            try:
                name = open(product).read().strip()
            except OSError:
                name = ""
        devices.append({"vid_pid": "%s:%s" % vp,
                        "board": CAPTURE_CAPABLE_RADIOS[vp],
                        "product": name})
    return devices


def _windows_radios():
    ps = ("$ErrorActionPreference='SilentlyContinue';"
          "Get-PnpDevice | ForEach-Object { $_.InstanceId + '|' + "
          "$_.FriendlyName }")
    ok, out = _run(["powershell", "-NoProfile", "-NonInteractive",
                    "-Command", ps], timeout=45)
    devices = []
    if not ok:
        return devices
    for line in out.splitlines():
        if "|" not in line:
            continue
        instance, name = line.split("|", 1)
        low = instance.lower()
        if "vid_" not in low or "pid_" not in low:
            continue
        vp = (low.split("vid_", 1)[1][:4], low.split("pid_", 1)[1][:4])
        if vp in CAPTURE_CAPABLE_RADIOS:
            devices.append({"vid_pid": "%s:%s" % vp,
                            "board": CAPTURE_CAPABLE_RADIOS[vp],
                            "product": name.strip()})
    return devices


def _modems():
    """Cellular modems the host exposes (Linux ModemManager)."""
    modems = []
    if not shutil.which("mmcli"):
        return modems
    ok, out = _run(["mmcli", "-L"], timeout=20)
    if not ok:
        return modems
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("/"):
            modems.append({"path": line})
    return modems


def _modem_imsi(modem_path):
    """Read the IMSI from a real modem via AT+CIMI (needs the SIM PIN)."""
    if not shutil.which("mmcli"):
        return {"ok": False, "error": "mmcli not installed"}
    try:
        ok, out = _run(["mmcli", "-m", modem_path, "--command",
                        "AT+CIMI"], timeout=20)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    if not ok:
        return {"ok": False, "error": "modem did not answer AT+CIMI "
                                      "(SIM PIN may be required)"}
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit() and 14 <= len(line) <= 16:
            return {"ok": True, "imsi": line, "source": "AT+CIMI",
                    "modem": modem_path}
    return {"ok": False, "error": "modem response held no IMSI"}


def imsi_dashboard_state() -> dict:
    """Real capture-capable radio + cellular modem inventory."""
    system = platform.system()
    try:
        radios = _windows_radios() if system == "Windows" else _linux_radios()
        modems = _modems()
        tools = [{"tool": t, "path": p} for t, p in
                 ((t, shutil.which(t)) for t in MODEM_TOOLS) if p]
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                "platform": system, "updated": datetime.now().isoformat()}

    return {
        "ok": True,
        "compatible_hardware": HARDWARE_COMPAT,
        "hardware_connected": bool(radios or modems),
        "devices_found": len(radios),
        "device_list": radios,
        "cellular_modems": modems,
        "modem_tools": tools,
        "platform": system,
        "driver_download_url": DRIVER_SOURCES.get(system, ""),
        "status_note": ("%d capture-capable radio(s), %d cellular modem(s)"
                        % (len(radios), len(modems))) if (radios or modems) else
                       "No IMSI-catcher radio or cellular modem detected — "
                       "install USRP/LimeSDR + drivers",
        "actions": ["scan", "catch", "intercept", "replay", "exfil"],
        "updated": datetime.now().isoformat(),
    }


def read_imsi(modem_path) -> dict:
    """Read the IMSI from the host's own modem (AT+CIMI).

    This is the host's SIM, read with the modem's own AT interface. It
    is not a capture: no traffic is intercepted and no subscriber is
    affected.
    """
    if not modem_path:
        modems = _modems()
        if not modems:
            return {"ok": False,
                    "error": "no cellular modem found (need ModemManager "
                             "with a registered SIM)"}
        modem_path = modems[0]["path"]
    result = _modem_imsi(modem_path)
    result["updated"] = datetime.now().isoformat()
    return result


def download_imsi_drivers() -> dict:
    """Where to get the host's SDR/UHD driver — a pointer, not a payload."""
    system = platform.system()
    return {
        "ok": True,
        "url": DRIVER_SOURCES.get(system, ""),
        "platform": system,
        "status": "external package",
        "note": "Install the driver for the radio you actually have, then "
                "re-run the IMSI state probe",
        "updated": datetime.now().isoformat(),
    }
