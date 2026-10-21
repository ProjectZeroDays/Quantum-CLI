# Quantum CLI v4.6.2

Release notes for the v4.6.2 line.

## Highlights

- **Android v4.6.2 APKs** — `full` (root-capable) and `limited` (non-root) release
  variants, both V2-signed and verified with `apksigner`.
- **ADB / FRP controller** — real device control over `adb`: QR pairing, shell
  execution, FRP removal, contacts/SMS/call-log/keychain exfiltration, media
  capture, APK install, backup.
- **HID payload generator** — DuckyScript output for Hak5 Ducky, Bash Bunny v2,
  O.MG cable, Cactus WHID 2 and BADUSB, with 12 pre-built attack vectors.
- **IoT dashboard** — NRSuite-style device discovery (ESP32, Tenda, Wavlink,
  D-Link, Belkin), MQTT/CoAP/Modbus protocol scanning, exploit payload generation.
- **Bash Bunny v2 generator** — GUI workflow to DuckyScript conversion plus
  natural-language prompt parsing.
- **VM/QEMU integration** — launch Kali Linux in QEMU with HID device passthrough.
- **Security tool catalog** — one interface for Metasploit, Shodan, sn1per,
  wifite3, Nmap, Burp Suite, AirCrack-ng, John and Hashcat.
- **Router exploits** — completed `Session` (cookie absorption + auth header) and
  `login()` for password-based router auth.

## Fixes

- `UiState` sealed class no longer generic — resolves the Kotlin→Java `CAP#1`
  wildcard-capture interop error that blocked `compileFullReleaseJavaWithJavac`.
- Stale generated `NativeGuiPattern.java` removed from the source tree.
- `Widget.Quantum` theme added; Material button styles corrected in
  `activity_quantum_native.xml`; `quantum_divider.xml` and
  `quantum_bottom_nav.xml` created.
- Registry folder-payload harness restored (`PAYLOADS_DIR`, `folder` on 61
  entries, `needs_target` on 29, `_fire_folder` runner) after v4.6.0 dropped it
  while the operator suite still required it.
- Bluetooth tier registered (CVE-2017-0781 / 0785, CVE-2018-5383, BLACKBED-BLE)
  and resolved by `resolve_weapon()`.
- `MALWARE-APK-WRAPPER-NECRO` registry entry plus `quantum.weapons.malware` probe.
- `brute/hashes`: the `bitcoin_wallet` format was missing the `salt` key that
  `cracking_dashboard_state()` reads.
- `brute/vaults`: `veracrypt_header_password_check()` now reports an honest
  `error` when the header invariants fail instead of returning a silent
  `ok=False`.
- Unused imports removed across `ops/`, `catalog/`, `crack/`, `weapons/`,
  `agents/specialized/` and `router_exploits.py`.

## Verification

| Check | Result |
|---|---|
| `pytest tests/` | 505 passed, 5 skipped, 0 failed |
| ruff gate (`E9,F63,F7,F82,F401,F811`) | clean on the committed tree |
| `gradlew assembleFullRelease assembleLimitedRelease` | BUILD SUCCESSFUL |
| `apksigner verify` | V2 signature scheme on both APKs |
| `aapt2 dump badging` | correct package names and version codes |

## Assets

| File | Size | Signature |
|---|---|---|
| `quantum-cli-full-4.6.2.apk` | 15.9 MB | V2 signed |
| `quantum-cli-limited-4.6.2.apk` | 15.9 MB | V2 signed |

## Authorized use only

All tooling and documentation in this release assume penetration-test, lab or
contracted-authorization contexts. Use only against systems you own or have
written authorization to test.
