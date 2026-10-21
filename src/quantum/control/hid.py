"""quantum.control.hid — real USB HID / BadUSB device discovery.

Enumerates the HID devices the host actually exposes, and identifies the
injection-capable ones (Hak5, O.MG, ESP32-S2/S3/C3, CH340/CP210x/FTDI
serial dongles used as BadUSB targets).

Sources, all read from the operating system:

  Linux    /sys/class/hidraw/*, /sys/bus/usb/devices/*/idVendor
  Windows  Get-PnpDevice -Class HIDClass, plus the serial-port class
  macOS    ioreg -c IOHIDDevice

The report never claims a device is present unless the bus says so.

Authorized engagements / lab work only.
"""
from __future__ import annotations

import glob
import os
import platform
import subprocess
from datetime import datetime

#: USB idVendor:idProduct of the injection-capable boards/dongles.
KNOWN_HID_BOARDS = {
    ("1209", "6e00"): "Hak5 Rubber Ducky / Bash Bunny",
    ("1209", "6e01"): "Hak5 Bash Bunny v2",
    ("1209", "6e02"): "Hak5 USB Armory M / Nano",
    ("1d50", "615a"): "Hak5 Cactus WHID 2",
    ("1d50", "615b"): "Hak5 Cactus WHID 2 (alt)",
    ("1a86", "7523"): "CH340 serial (CH340/CH341)",
    ("1a86", "55d4"): "CH9102 serial",
    ("10c4", "ea60"): "CP210x serial",
    ("0403", "6001"): "FTDI FT232 serial",
    ("303a", "1001"): "Espressif ESP32-S2/S3 (native USB)",
    ("303a", "4001"): "Espressif ESP32-S3 (USB CDC)",
    ("16c0", "05dc"): "O.MG Cable (USB ID)",
    ("1d6b", "0104"): "GNU Radio / generic HID",
}

HARDWARE_COMPAT = ("Hak5 O.MG / LAN Turtle / Rubber Ducky; ESP32-S2/S3/C3 + "
                   "Wi-Fi; BadUSB (WHID) dongle; drivers: CH340/CP210x/FTDI; "
                   "download from https://shop.hak5.org/ / "
                   "https://espressif.com/ / https://badusb.net/")

DRIVER_SOURCES = {
    "Linux": "https://www.kernel.org/doc/html/latest/usb/",
    "Windows": "https://learn.microsoft.com/windows-hardware/drivers/usb/",
    "Darwin": "https://developer.apple.com/documentation/iokit",
}


def _run(cmd, timeout=20):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return False, ""
    if proc.returncode != 0:
        return False, (proc.stdout or "")
    return True, (proc.stdout or "")


def _linux_state():
    """HID devices and USB ids from sysfs."""
    devices = []
    for path in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        name = os.path.basename(path)
        node = os.path.realpath(path)
        entry = {"node": name, "path": node}
        # walk up to the usb device for vid/pid
        parent = os.path.dirname(node)
        for _ in range(4):
            vid = os.path.join(parent, "idVendor")
            pid = os.path.join(parent, "idProduct")
            if os.path.isfile(vid) and os.path.isfile(pid):
                try:
                    vp = (open(vid).read().strip().lower(),
                          open(pid).read().strip().lower())
                except OSError:
                    break
                entry["vid_pid"] = "%s:%s" % vp
                entry["board"] = KNOWN_HID_BOARDS.get(vp, "unknown HID device")
                entry["injection_capable"] = vp in KNOWN_HID_BOARDS
                break
            parent = os.path.dirname(parent)
        devices.append(entry)
    return devices


def _windows_state():
    """HID devices and USB ids from the PnP device tree."""
    ps = ("$ErrorActionPreference='SilentlyContinue';"
          "Get-PnpDevice | Where-Object { $_.Class -eq 'HIDClass' -or "
          "$_.Class -eq 'Ports' } | ForEach-Object { "
          "$_.Class + '|' + $_.FriendlyName + '|' + $_.InstanceId }")
    ok, out = _run(["powershell", "-NoProfile", "-NonInteractive",
                    "-Command", ps], timeout=40)
    devices = []
    if not ok:
        return devices
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        cls, name, instance = parts
        entry = {"class": cls, "name": name, "instance_id": instance}
        # USB\VID_xxxx&PID_xxxx in the instance id
        low = instance.lower()
        if "vid_" in low and "pid_" in low:
            vid = low.split("vid_", 1)[1][:4]
            pid = low.split("pid_", 1)[1][:4]
            vp = (vid, pid)
            entry["vid_pid"] = "%s:%s" % vp
            entry["board"] = KNOWN_HID_BOARDS.get(vp, "unknown HID device")
            entry["injection_capable"] = vp in KNOWN_HID_BOARDS
        devices.append(entry)
    return devices


def _darwin_state():
    """HID devices from the IOKit registry."""
    ok, out = _run(["ioreg", "-c", "IOHIDDevice", "-r", "-d", "1"], timeout=30)
    devices = []
    if not ok:
        return devices
    for line in out.splitlines():
        line = line.strip()
        if '"Product"' in line or '"VendorID"' in line:
            devices.append({"raw": line})
    return devices


def hid_dashboard_state() -> dict:
    """Real HID device inventory for this host."""
    system = platform.system()
    try:
        if system == "Windows":
            devices = _windows_state()
        elif system == "Darwin":
            devices = _darwin_state()
        else:
            devices = _linux_state()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc),
                "platform": system, "updated": datetime.now().isoformat()}

    capable = [d for d in devices if d.get("injection_capable")]
    return {
        "ok": True,
        "compatible_hardware": HARDWARE_COMPAT,
        "hardware_connected": bool(devices),
        "devices_found": len(devices),
        "device_list": devices,
        "injection_capable": capable,
        "injection_capable_count": len(capable),
        "platform": system,
        "driver_download_url": DRIVER_SOURCES.get(system, ""),
        "status_note": ("%d HID device(s), %d known injection board(s)"
                        % (len(devices), len(capable))) if devices else
                       "No HID device exposed by the host",
        "actions": ["flash", "exploit", "payload", "recon", "joiner",
                    "downloader", "security_disable"],
        "updated": datetime.now().isoformat(),
    }


def download_hid_drivers() -> dict:
    """Where to get the host's USB/HID driver — a pointer, not a payload."""
    system = platform.system()
    return {
        "ok": True,
        "url": DRIVER_SOURCES.get(system, ""),
        "platform": system,
        "status": "external package",
        "note": "Install the driver for the board you actually have, then "
                "re-run the HID state probe",
        "updated": datetime.now().isoformat(),
    }


def hid_raw_devices() -> dict:
    """The hidraw nodes a payload generator can open on Linux."""
    system = platform.system()
    if system != "Linux":
        return {"ok": False, "error": "hidraw nodes are a Linux interface",
                "platform": system}
    nodes = []
    for path in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        node = os.path.basename(path)
        readable = os.access(os.path.join("/dev", node), os.R_OK | os.W_OK)
        nodes.append({"node": node, "writable": readable})
    return {"ok": True, "platform": system, "nodes": nodes,
            "count": len(nodes)}
