"""quantum.skills.openrouter_config — the real provider / skill configuration.

Reads the tracked provider registry so the skill configuration reflects
what this build can actually reach: which provider is resolved, which
API key is present, how many free models the provider offers, and which
operator skills are importable here.

The previous version of this module returned a hard-coded
"god_mode_enabled": True and a static skill list with nothing behind
it. Nothing is enabled by this module — it only reports.

The OpenRouter free tier may answer 403; that is reported honestly
rather than papered over.

Authorized engagements / lab work only.
"""
from __future__ import annotations

import importlib
from datetime import datetime

#: The operator skills this build carries. The list is a catalogue; the
#: state below reports which of them actually import on this host.
SKILL_CATALOGUE = [
    "god_mode", "security_scanner", "vuln_scanner", "brute_force",
    "exploitation", "payload_engine", "cookie_harvester",
    "memory_corruption", "deserialization", "file_parse_exploit",
    "messaging_rce", "bluetooth_exploit", "iot_exploit", "android_exploit",
    "ios_exploit", "linux_exploit", "windows_exploit", "ssrf_exploit",
    "automobile_exploit", "nfc_exploit", "media_exploit",
]

#: Where a skill module is looked for, per name.
SKILL_MODULES = {
    "god_mode": "quantum.postexploit.god_mode",
    "security_scanner": "agents.specialized.SecurityScanner.security_scanneragent",
    "vuln_scanner": "agents.specialized.VulnScanner.vulnscanneragent",
    "brute_force": "agents.specialized.BruteForce.bruteforceagent",
    "exploitation": "agents.specialized.Exploitation.exploitationagent",
    "payload_engine": "agents.specialized.PayloadEngine.payloadengineagent",
    "cookie_harvester": "agents.specialized.CookieHarvester.cookieharvesteragent",
    "memory_corruption": "agents.specialized.MemoryCorruption.memorycorruptionagent",
    "deserialization": "agents.specialized.Deserialization.deserializationagent",
    "file_parse_exploit": "agents.specialized.FileParseExploit.fileparseexploitagent",
    "messaging_rce": "agents.specialized.MessagingRCE.messagingrceagent",
    "bluetooth_exploit": "agents.specialized.BluetoothExploit.bluetoothexploitagent",
    "iot_exploit": "agents.specialized.IOTExploit.iotexploitagent",
    "android_exploit": "agents.specialized.AndroidExploit.androidexploitagent",
    "ios_exploit": "agents.specialized.IOSExploit.iosexploitagent",
    "linux_exploit": "agents.specialized.LinuxExploit.linexploitagent",
    "windows_exploit": "agents.specialized.WindowsExploit.windowsexploitagent",
    "ssrf_exploit": "agents.specialized.SSRFExploit.ssrfexploitagent",
    "automobile_exploit": "agents.specialized.AutomobileExploit.automobileexploitagent",
    "nfc_exploit": "agents.specialized.NFCExploit.nfcexploitagent",
    "media_exploit": "agents.specialized.MediaExploit.mediaexploitagent",
}


def _openrouter_state():
    """The tracked provider registry's view of OpenRouter."""
    try:
        from quantum.ai.providers import provider_status
    except Exception as exc:  # noqa: BLE001
        return None, "%s: %s" % (type(exc).__name__, exc)
    for entry in provider_status() or []:
        if entry.get("id") == "openrouter":
            return entry, None
    return None, "openrouter is not in the provider registry"


def _available_skills():
    """Which of the catalogued skills actually import on this host."""
    available, missing = [], []
    for name in SKILL_CATALOGUE:
        module = SKILL_MODULES.get(name)
        if not module:
            missing.append(name)
            continue
        try:
            importlib.import_module(module)
            available.append(name)
        except Exception:
            missing.append(name)
    return available, missing


def openrouter_skills_config():
    """Real state: the provider, the key, the models and the skills."""
    entry, error = _openrouter_state()
    available, missing = _available_skills()

    if entry is None:
        return {
            "ok": False,
            "provider": "openrouter",
            "error": error,
            "skills_available": available,
            "skills_missing": missing,
            "note": "The provider registry could not be read.",
            "updated": datetime.now().isoformat(),
        }

    return {
        "ok": True,
        "provider": "openrouter",
        "label": entry.get("label"),
        "url": entry.get("url"),
        "model": entry.get("model"),
        "key_env": entry.get("key_env"),
        # the key is never echoed — only whether one was found
        "key_found": bool(entry.get("key_found")),
        "keyless": bool(entry.get("keyless")),
        "free": bool(entry.get("free")),
        "free_models": entry.get("free_models", 0),
        "tier": "free" if entry.get("free") else "keyed",
        "skills_available": available,
        "skills_missing": missing,
        "skills_count": len(available),
        "god_mode_enabled": False,
        "note": "Nothing is enabled by this module — it reports what the "
                "provider registry and this host actually offer. The "
                "OpenRouter free tier may answer 403; that is reported "
                "as-is.",
        "updated": datetime.now().isoformat(),
    }
