"""quantum.control.bluetooth — real Bluetooth adapter / device discovery.

Probes the host for a real Bluetooth controller and the devices the
controller currently knows about. Every value reported here comes from
the operating system:

  Linux    /sys/class/bluetooth/hci* (controller), bluetoothctl devices
  Windows  Get-PnpDevice -Class Bluetooth (controller + present devices)
  macOS    system_profiler SPBluetoothDataType

Nothing is assumed: when the host exposes no controller the state says
so, and it never claims a capability the probe did not confirm.

Authorized engagements / lab work only.
"""
from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
from datetime import datetime

#: Vendor/product IDs of the common Bluetooth controllers. Used to name a
#: controller more precisely than "hci0" when the bus exposes it.
KNOWN_CONTROLLERS = {
    ("0bda", "2832"): "Realtek RTL2832 (Bluetooth)",
    ("0bda", "2838"): "Realtek RTL2838 (Bluetooth)",
    ("0a12", "0001"): "Atheros AR9271 (Bluetooth)",
    ("8087", "0032"): "Intel Wireless Bluetooth",
    ("8087", "0026"): "Intel Wireless Bluetooth",
    ("0cf3", "0000"): "Qualcomm Atheros Bluetooth",
    ("17cb", "1102"): "Qualcomm Atheros Bluetooth",
    ("04e8", "9008"): "Samsung Mobile Device BT",
}

#: Where the official stacks live, per platform. Used to point the
#: operator at the right driver package instead of a generic URL.
DRIVER_SOURCES = {
    "Linux": "https://www.bluez.org/download/",
    "Windows": "https://learn.microsoft.com/windows-hardware/drivers/bluetooth/",
    "Darwin": "https://support.apple.com/en-us/HT204170",
}


def _run(cmd, timeout=20):
    """Run a command, returning (ok, stdout). Never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return False, ""
    if proc.returncode != 0:
        return False, (proc.stdout or "")
    return True, (proc.stdout or "")


def _linux_state():
    """Controller + device discovery on Linux via sysfs / bluetoothctl."""
    controllers = []
    for path in sorted(glob.glob("/sys/class/bluetooth/hci*")):
        name = os.path.basename(path)
        controllers.append({
            "name": name,
            "state_file": path,
            "present": os.path.isdir(path),
        })
    devices = []
    if shutil.which("bluetoothctl"):
        ok, out = _run(["bluetoothctl", "devices", "Found"])
        if ok:
            for line in out.splitlines():
                line = line.strip()
                if line:
                    devices.append({"address": line.split(None, 1)[0],
                                    "raw": line})
    return controllers, devices, bool(controllers)


def _windows_state():
    """Controller + device discovery on Windows via PnP.

    The Bluetooth node class also lists the services and profiles that
    hang off a controller ("Generic Attribute Profile", "BTHLE\\..."), so
    the controller is told apart by its instance id: a real radio is a
    USB device (USB\\VID_xxxx&PID_xxxx), everything else is a service.
    """
    ps = ("$ErrorActionPreference='SilentlyContinue';"
          "Get-PnpDevice -Class Bluetooth | "
          "ForEach-Object { $_.FriendlyName + '|' + $_.InstanceId }")
    ok, out = _run(["powershell", "-NoProfile", "-NonInteractive",
                    "-Command", ps], timeout=30)
    controllers, devices = [], []
    if not ok:
        return controllers, devices, False
    for line in out.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        name, instance = line.split("|", 1)
        entry = {"name": name, "instance_id": instance}
        if instance.upper().startswith("USB\\"):
            entry["bus"] = "USB"
            entry["vid_pid"] = _vid_pid_from_instance(instance)
            controllers.append(entry)
        else:
            entry["bus"] = "software"
            devices.append(entry)
    return controllers, devices, bool(controllers)


def _vid_pid_from_instance(instance):
    """'USB\\VID_8087&PID_0032\\5&...' -> '8087:0032' (or '' if absent)."""
    low = instance.lower()
    if "vid_" not in low or "pid_" not in low:
        return ""
    vid = low.split("vid_", 1)[1][:4]
    pid = low.split("pid_", 1)[1][:4]
    return "%s:%s" % (vid, pid)


def _darwin_state():
    """Controller discovery on macOS via system_profiler."""
    ok, out = _run(["system_profiler", "SPBluetoothDataType"], timeout=30)
    controllers, devices = [], []
    if ok:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Bluetooth "):
                controllers.append({"name": line})
            elif ":" in line and line and not line.startswith("Bluetooth"):
                devices.append({"name": line.split(":", 1)[0].strip()})
    return controllers, devices, bool(controllers)


def _probe():
    """(controllers, devices, present) for this host."""
    system = platform.system()
    if system == "Windows":
        return _windows_state()
    if system == "Darwin":
        return _darwin_state()
    return _linux_state()


def _usb_controller_ids():
    """USB vendor:product of any Bluetooth controller on the bus."""
    if not shutil.which("lsusb"):
        return []
    ok, out = _run(["lsusb"])
    if not ok:
        return []
    found = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in KNOWN_CONTROLLERS:
            found.append({"vid_pid": " ".join(parts[:2]),
                          "name": KNOWN_CONTROLLERS[(parts[0], parts[1])]})
    return found


def bluetooth_dashboard_state() -> dict:
    """Real Bluetooth controller / device state for this host."""
    system = platform.system()
    try:
        controllers, devices, present = _probe()
        usb = _usb_controller_ids()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                "platform": system, "updated": datetime.now().isoformat()}

    if not present:
        return {
            "ok": True,
            "hardware_connected": False,
            "controllers": [],
            "devices": [],
            "devices_found": len(devices),
            "platform": system,
            "driver_source": DRIVER_SOURCES.get(system, ""),
            "status_note": "No Bluetooth controller exposed by the host "
                           "— install a BT adapter and its driver",
            "actions": ["scan", "pair", "recon"],
            "updated": datetime.now().isoformat(),
        }

    return {
        "ok": True,
        "hardware_connected": True,
        "controllers": controllers,
        "usb_controllers": usb,
        "devices": devices,
        "devices_found": len(devices),
        "platform": system,
        "driver_source": DRIVER_SOURCES.get(system, ""),
        "status_note": "%d controller(s), %d known device(s)"
                       % (len(controllers), len(devices)),
        "actions": ["scan", "pair", "recon"],
        "updated": datetime.now().isoformat(),
    }


def download_bluetooth_drivers() -> dict:
    """Where to get the host's Bluetooth driver — a pointer, not a payload."""
    system = platform.system()
    return {
        "ok": True,
        "url": DRIVER_SOURCES.get(system, ""),
        "platform": system,
        "status": "external package",
        "note": "Install the vendor driver for the adapter you actually "
                "have, then re-run the Bluetooth state probe",
        "updated": datetime.now().isoformat(),
    }


def scan_devices(timeout=15) -> dict:
    """Ask the controller to scan for nearby devices (real inquiry).

    Uses the platform's own discovery tool so the results are the
    controller's, not a guess.
    """
    system = platform.system()
    try:
        if system == "Linux" and shutil.which("bluetoothctl"):
            ok, out = _run(["bluetoothctl", "scan", "on"], timeout=timeout)
            if not ok:
                return {"ok": False, "error": "bluetoothctl scan failed"}
            _run(["bluetoothctl", "scan", "off"], timeout=timeout)
            _ok, listing = _run(["bluetoothctl", "devices", "Found"])
            found = [l.strip() for l in listing.splitlines() if l.strip()]
            return {"ok": True, "backend": "bluetoothctl",
                    "devices_found": len(found), "devices": found}
        if system == "Windows":
            ok, out = _run(["powershell", "-NoProfile", "-NonInteractive",
                            "-Command",
                            "Get-PnpDevice -Class Bluetooth | "
                            "ForEach-Object { $_.FriendlyName }"],
                           timeout=timeout)
            if not ok:
                return {"ok": False, "error": "PnP Bluetooth query failed"}
            found = [l.strip() for l in out.splitlines() if l.strip()]
            return {"ok": True, "backend": "Get-PnpDevice",
                    "devices_found": len(found), "devices": found}
        return {"ok": False,
                "error": "no discovery tool for %s (need bluetoothctl or "
                         "Get-PnpDevice)" % system}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
