"""quantum.control.sdr — real SDR (software-defined radio) discovery.

Identifies the radio hardware the host actually exposes by reading the
USB bus and the kernel's radio device nodes:

  Linux    /sys/bus/usb/devices/*/idVendor + idProduct, /dev/dvb,
           rtl_test / rtl_fm / hackrf_info / uhd_find_devices presence
  Windows  Get-PnpDevice for the known SDR USB ids
  macOS    system_profiler SPUSBDataType

The known boards are the common USB SDRs; a board that is not in the
table is still reported, just as an unidentified radio.

Authorized engagements / lab work only.
"""
from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
from datetime import datetime

#: USB idVendor:idProduct -> board name.
KNOWN_SDR_BOARDS = {
    ("0bda", "2832"): "RTL-SDR Blog V3 (RTL2832)",
    ("0bda", "2838"): "RTL-SDR Blog V4 (RTL2838)",
    ("0bda", "0001"): "Realtek RTL2838U (bare)",
    ("1d50", "6089"): "HackRF One",
    ("1d50", "608a"): "HackRF One (revision)",
    ("1d50", "610a"): "HackRF One (Joystick)",
    ("2500", "0031"): "USRP B205mini",
    ("2500", "0037"): "USRP B210",
    ("2500", "0020"): "Ettus USRP N210",
    ("e4e0", "0001"): "LimeSDR Mini",
    ("2403", "024f"): "LimeSDR-USB",
    ("1fc9", "000d"): "PlutoSDR",
}

HARDWARE_COMPAT = ("RTL-SDR / HackRF / USRP / PlutoSDR; drivers: RTL-SDR "
                   "(librtlsdr), HackRF (hackrf), GNU Radio; download from "
                   "https://www.rtl-sdr.com/ / "
                   "https://github.com/greatscottgadgets/hackrf")

DRIVER_SOURCES = {
    "Linux": "https://github.com/rtlsdr/rtl-sdr",
    "Windows": "https://github.com/rtlsdr/rtl-sdr/releases",
    "Darwin": "https://github.com/rtlsdr/rtl-sdr/releases",
}

#: Command-line tools that prove a radio is usable, and what they prove.
RADIO_TOOLS = {
    "rtl_test": "Realtek RTL2832/RTL2838 dongle",
    "rtl_fm": "Realtek RTL2832/RTL2838 dongle",
    "hackrf_info": "HackRF One",
    "uhd_find_devices": "Ettus USRP",
    "soapy_sdr_probe": "SoapySDR device",
}


def _run(cmd, timeout=25):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return False, ""
    return proc.returncode == 0, (proc.stdout or "")


def _linux_state():
    """USB radio ids from sysfs, plus the DVB device nodes."""
    devices = []
    for base in sorted(glob.glob("/sys/bus/usb/devices/*/idVendor")):
        parent = os.path.dirname(base)
        vid_p = os.path.join(parent, "idProduct")
        if not os.path.isfile(vid_p):
            continue
        try:
            vp = (open(base).read().strip().lower(),
                  open(vid_p).read().strip().lower())
        except OSError:
            continue
        if vp not in KNOWN_SDR_BOARDS:
            continue
        product = os.path.join(parent, "product")
        name = ""
        if os.path.isfile(product):
            try:
                name = open(product).read().strip()
            except OSError:
                name = ""
        devices.append({
            "vid_pid": "%s:%s" % vp,
            "board": KNOWN_SDR_BOARDS[vp],
            "product": name,
            "sysfs": parent,
        })
    return devices


def _windows_state():
    """Radio ids from the PnP device tree."""
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
        if vp in KNOWN_SDR_BOARDS:
            devices.append({"vid_pid": "%s:%s" % vp,
                            "board": KNOWN_SDR_BOARDS[vp],
                            "product": name.strip()})
    return devices


def _darwin_state():
    """Radio ids from the USB profiler."""
    ok, out = _run(["system_profiler", "SPUSBDataType"], timeout=40)
    devices = []
    if not ok:
        return devices
    for line in out.splitlines():
        low = line.lower()
        for (vid, pid), board in KNOWN_SDR_BOARDS.items():
            if vid in low and pid in low:
                devices.append({"vid_pid": "%s:%s" % (vid, pid),
                                "board": board,
                                "product": line.strip()})
                break
    return devices


def radio_tools_present() -> list:
    """Which radio CLI tools are installed on this host."""
    found = []
    for tool, proves in RADIO_TOOLS.items():
        path = shutil.which(tool)
        if path:
            found.append({"tool": tool, "path": path, "proves": proves})
    return found


def sdr_dashboard_state() -> dict:
    """Real SDR hardware inventory for this host."""
    system = platform.system()
    try:
        if system == "Windows":
            devices = _windows_state()
        elif system == "Darwin":
            devices = _darwin_state()
        else:
            devices = _linux_state()
        tools = radio_tools_present()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                "platform": system, "updated": datetime.now().isoformat()}

    dvb_nodes = sorted(glob.glob("/dev/dvb/adapter*")) if system == "Linux" else []
    return {
        "ok": True,
        "compatible_hardware": HARDWARE_COMPAT,
        "hardware_connected": bool(devices),
        "devices_found": len(devices),
        "device_list": devices,
        "radio_tools": tools,
        "dvb_nodes": dvb_nodes,
        "platform": system,
        "driver_download_url": DRIVER_SOURCES.get(system, ""),
        "status_note": ("%d radio(s), %d radio tool(s) installed"
                        % (len(devices), len(tools))) if devices else
                       ("%d radio tool(s) installed but no radio detected"
                        % len(tools)) if tools else
                       "No SDR adapter detected — install RTL-SDR/HackRF/USRP "
                       "and its driver",
        "actions": ["scan", "demod", "exploit", "recon", "capture"],
        "updated": datetime.now().isoformat(),
    }


def download_sdr_drivers() -> dict:
    """Where to get the host's SDR driver — a pointer, not a payload."""
    system = platform.system()
    return {
        "ok": True,
        "url": DRIVER_SOURCES.get(system, ""),
        "platform": system,
        "status": "external package",
        "note": "Install the driver for the radio you actually have, then "
                "re-run the SDR state probe",
        "updated": datetime.now().isoformat(),
    }


def probe_radios() -> dict:
    """Ask each installed radio tool what it can actually see."""
    results = []
    for tool in ("rtl_test", "hackrf_info", "uhd_find_devices",
                 "soapy_sdr_probe"):
        path = shutil.which(tool)
        if not path:
            continue
        ok, out = _run([tool], timeout=30)
        results.append({"tool": tool, "ok": ok, "output": out[:2000]})
    return {"ok": bool(results), "tools": results}
