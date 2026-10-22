"""Build PLATFORM_INDEX.json — taxonomy of every verified exploit.

Maps CVE -> home (zero-click/zero-day), platform, registry weapon,
Desktop source path, and repo payload path. Regenerate after reorg:
    python build_platform_index.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# (cve, home, platform, weapon)
ROWS = [
    ("CVE-2017-0144", "zero-click", "windows", "check_ms17010"),
    ("CVE-2017-13077", "zero-click", "wifi", "check_krack"),
    ("CVE-2020-0022", "zero-click", "bluetooth", "check_bluefrag"),
    ("CVE-2023-45866", "zero-click", "bluetooth", "check_bt_hid"),
    ("CVE-2019-3568", "zero-click", "messaging", "check_whatsapp_voip"),
    ("CVE-2021-30860", "zero-click", "messaging", "check_forcedentry"),
    ("CVE-2022-27492", "zero-click", "messaging", "v3_whatsapp_libmultiple"),
    ("CVE-2023-41061", "zero-click", "messaging", "check_blastpass_wallet"),
    ("CVE-2023-41064", "zero-click", "messaging", "check_apple_imageio"),
    ("CVE-2023-23397", "zero-click", "messaging", "check_outlook_ntlm"),
    ("CVE-2025-32711", "zero-click", "messaging", "check_echoleak"),
    ("CVE-2021-30858", "zero-click", "browser", "check_webkit_escape"),
    ("CVE-2023-32409", "zero-click", "browser", "check_webkit_typeconf"),
    ("CVE-2023-32435", "zero-click", "browser", "check_triangulation_webkit"),
    ("CVE-2023-42924", "zero-click", "browser", "check_webkit_itw_2023"),
    ("CVE-2023-4863", "zero-click", "browser", "check_libwebp"),
    ("CVE-2024-4438", "zero-click", "browser", "check_webkit_intellexa"),
    ("CVE-2025-24085", "zero-click", "browser", "check_webkit_itw_2025"),
    ("CVE-2025-41300", "zero-click", "browser", "check_pegasus_webkit"),
    ("CVE-2023-32434", "zero-click", "ios", "check_triangulation_kernel"),
    ("CVE-2024-23225", "zero-click", "ios", "check_ios_kernel"),
    ("CVE-2022-44319", "zero-click", "android", "check_samsung_baseband"),
    ("CVE-2023-24033", "zero-click", "android", "check_exynos_baseband"),
    ("CVE-2026-0073", "zero-click", "android", "v3_adb_tls"),
    ("CVE-2020-1472", "zero-click", "network", "check_zerologon"),
    ("CVE-2021-1675", "zero-click", "network", "check_printnightmare"),
    ("CVE-2021-26855", "zero-click", "network", "check_proxylogon"),
    ("CVE-2021-34473", "zero-click", "network", "v3_proxyshell"),
    ("CVE-2021-36942", "zero-click", "network", "check_petitpotam"),
    ("CVE-2021-44228", "zero-click", "network", "v3_log4shell"),
    ("CVE-2022-22965", "zero-click", "network", "v3_spring4shell"),
    ("CVE-2022-41040", "zero-click", "network", "v3_proxynotshell"),
    ("CVE-2023-4966", "zero-click", "network", "v3_citrixbleed"),
    ("CVE-2024-6387", "zero-click", "network", "v3_regresshion"),
    ("CVE-2025-5777", "zero-click", "network", "v3_citrixbleed2"),
    ("CVE-2019-19781", "zero-click", "webapp", "v3_citrix_path"),
    ("CVE-2020-14882", "zero-click", "webapp", "v3_weblogic_console"),
    ("CVE-2021-21972", "zero-click", "webapp", "v3_vcenter_upload"),
    ("CVE-2021-35464", "zero-click", "webapp", "v3_forgerock"),
    ("CVE-2022-26134", "zero-click", "webapp", "v3_confluence_ognl"),
    ("CVE-2023-0669", "zero-click", "webapp", "v3_goanywhere"),
    ("CVE-2023-27350", "zero-click", "webapp", "v3_papercut"),
    ("CVE-2023-34362", "zero-click", "webapp", "v3_moveit_probe"),
    ("CVE-2023-35078", "zero-click", "webapp", "v3_ivanti_epmm"),
    ("CVE-2024-1709", "zero-click", "webapp", "v3_screenconnect"),
    ("CVE-2024-3400", "zero-click", "webapp", "v3_panos_cmd"),
    ("CVE-2024-47575", "zero-click", "webapp", "v3_fortimanager"),
    ("CVE-2025-0282", "zero-click", "webapp", "v3_ivanti_connect"),
    ("CVE-2025-31324", "zero-click", "webapp", "v3_sap_netweaver"),
    ("CVE-2021-3156", "zero-day", "linux", "check_baron_samedit"),
    ("CVE-2021-4034", "zero-day", "linux", "check_pwnkit"),
    ("CVE-2022-0847", "zero-day", "linux", "v3_dirtypipe"),
    ("CVE-2023-2640", "zero-day", "linux", "check_overlayfs"),
    ("CVE-2023-32233", "zero-day", "linux", "check_nftables_uaf"),
    ("CVE-2024-1086", "zero-day", "linux", "check_nftables_dblfree"),
    ("CVE-2017-7494", "zero-day", "linux", "v3_sambacry"),
    ("CVE-2021-40444", "zero-day", "windows", "v3_mshtml_maldoc"),
    ("CVE-2022-21894", "zero-day", "windows", "check_boothole"),
    ("CVE-2022-30190", "zero-day", "windows", "check_follina"),
    ("CVE-2023-36884", "zero-day", "windows", "check_office_html"),
    ("CVE-2023-20198", "zero-day", "network-device", "v3_ios_admin"),
]

DESK = r"C:\Users\Project Zero\Desktop\Exploits"


def slug(cve):
    table = {
        "CVE-2017-0144": "CVE-2017-0144-eternalblue",
        "CVE-2017-13077": "CVE-2017-13077-krack",
        "CVE-2017-7494": "CVE-2017-7494-sambacry",
        "CVE-2019-19781": "CVE-2019-19781-citrix-path-traversal",
        "CVE-2019-3568": "CVE-2019-3568-whatsapp-voip",
        "CVE-2020-0022": "CVE-2020-0022-bluefrag",
        "CVE-2020-1472": "CVE-2020-1472-zerologon",
        "CVE-2020-14882": "CVE-2020-14882-weblogic-console",
        "CVE-2021-1675": "CVE-2021-1675-printnightmare",
        "CVE-2021-21972": "CVE-2021-21972-vcenter-upload",
        "CVE-2021-26855": "CVE-2021-26855-proxylogon",
        "CVE-2021-30858": "CVE-2021-30858-webkit-escape",
        "CVE-2021-30860": "CVE-2021-30860-forcedentry",
        "CVE-2021-3156": "CVE-2021-3156-baron-samedit",
        "CVE-2021-34473": "CVE-2021-34473-proxyshell",
        "CVE-2021-35464": "CVE-2021-35464-forgerock",
        "CVE-2021-36942": "CVE-2021-36942-petitpotam",
        "CVE-2021-4034": "CVE-2021-4034-pwnkit",
        "CVE-2021-40444": "CVE-2021-40444-mshtml-maldoc",
        "CVE-2021-44228": "CVE-2021-44228-log4shell",
        "CVE-2022-0847": "CVE-2022-0847-dirtypipe",
        "CVE-2022-21894": "CVE-2022-21894-boothole",
        "CVE-2022-22965": "CVE-2022-22965-spring4shell",
        "CVE-2022-26134": "CVE-2022-26134-confluence-ognl",
        "CVE-2022-27492": "CVE-2022-27492-whatsapp-libmultiple",
        "CVE-2022-30190": "CVE-2022-30190-follina",
        "CVE-2022-41040": "CVE-2022-41040-proxynotshell",
        "CVE-2022-44319": "CVE-2022-44319-samsung-baseband",
        "CVE-2023-0669": "CVE-2023-0669-goanywhere",
        "CVE-2023-20198": "CVE-2023-20198-iosxe-webui",
        "CVE-2023-23397": "CVE-2023-23397-outlook-ntlm-leak",
        "CVE-2023-24033": "CVE-2023-24033-exynos-baseband",
        "CVE-2023-2640": "CVE-2023-2640-overlayfs",
        "CVE-2023-27350": "CVE-2023-27350-papercut",
        "CVE-2023-32233": "CVE-2023-32233-nftables-uaf",
        "CVE-2023-32409": "CVE-2023-32409-webkit-type-confusion",
        "CVE-2023-32434": "CVE-2023-32434-triangulation-kernel",
        "CVE-2023-32435": "CVE-2023-32435-triangulation-webkit",
        "CVE-2023-34362": "CVE-2023-34362-moveit-sqli",
        "CVE-2023-35078": "CVE-2023-35078-ivanti-epmm",
        "CVE-2023-36884": "CVE-2023-36884-office-html",
        "CVE-2023-41061": "CVE-2023-41061-blastpass-wallet",
        "CVE-2023-41064": "CVE-2023-41064-apple-imageio",
        "CVE-2023-42924": "CVE-2023-42924-webkit-itw",
        "CVE-2023-45866": "CVE-2023-45866-bt-hid-injection",
        "CVE-2023-4863": "CVE-2023-4863-libwebp",
        "CVE-2023-4966": "CVE-2023-4966-citrix-bleed",
        "CVE-2024-1086": "CVE-2024-1086-nftables-dblfree",
        "CVE-2024-1709": "CVE-2024-1709-screenconnect",
        "CVE-2024-23225": "CVE-2024-23225-ios-kernel",
        "CVE-2024-3400": "CVE-2024-3400-panos-globalprotect",
        "CVE-2024-4438": "CVE-2024-4438-webkit-intellexa",
        "CVE-2024-47575": "CVE-2024-47575-fortimanager",
        "CVE-2024-6387": "CVE-2024-6387-regresssion",
        "CVE-2025-0282": "CVE-2025-0282-ivanti-connect-secure",
        "CVE-2025-24085": "CVE-2025-24085-webkit-itw",
        "CVE-2025-31324": "CVE-2025-31324-sap-netweaver",
        "CVE-2025-32711": "CVE-2025-32711-echoleak",
        "CVE-2025-41300": "CVE-2025-41300-pegasus-webkit",
        "CVE-2025-5777": "CVE-2025-5777-citrix-bleed2",
        "CVE-2026-0073": "CVE-2026-0073-adb-tls-bypass",
    }
    return table[cve]


def main():
    entries = []
    for cve, home, platform, weapon in ROWS:
        home_dir = "zero-click_exploits" if home == "zero-click" else "zero-day_exploits"
        entries.append({
            "cve": cve,
            "home": home,
            "platform": platform,
            "weapon": weapon,
            "desktop": DESK + "\\" + home_dir + "\\_cve\\" + platform + "\\" + slug(cve),
            "repo": "exploit_payloads/" + slug(cve) + "/deploy.py",
        })
    out = ROOT / "PLATFORM_INDEX.json"
    # newline="\n" so the index is byte-identical on every platform: the
    # default text mode writes CRLF on Windows, which would make the
    # release archives differ between a Windows checkout and a CI one.
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"count": len(entries), "exploits": entries},
                            indent=2))
    print("wrote", out, len(entries), "entries")


if __name__ == "__main__":
    main()
