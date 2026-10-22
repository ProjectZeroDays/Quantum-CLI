# Quantum CLI — Operator Surface Status

The 29 runtime modules that were sitting in the working tree as
placeholder dashboards are now real probes, committed, and reachable
from both the CLI and the dashboard API.

## Rule that governs all of it

A module may only report a capability it actually verified. The
placeholder dashboards returned a literal `hardware_connected: True`
with no probe behind it — a simulated capability, which the repo's
"no simulated code" rule forbids. Every module now reports what the
host actually has, and says so when it has nothing.

That rule is locked in by tests: `hardware_connected` may only be
`True` when a device was actually found.

## Modules

### Hardware probes (`quantum.control`)

| Module | What it probes | Result on this host |
|---|---|---|
| `bluetooth.py` | BT controller + known devices (sysfs / PnP / system_profiler / lsusb) | 1 controller, 65 services |
| `hid.py` | HID devices + USB ids; injection boards by vid:pid | 38 devices |
| `sdr.py` | RTL-SDR / HackRF / USRP / LimeSDR / PlutoSDR + radio tooling | 0 radios |
| `imsi.py` | Capture-capable radios + the host's own modem (`AT+CIMI`) | 0 radios |

### Operator modules (`quantum.postexploit`)

| Module | What it probes | Result on this host |
|---|---|---|
| `cve_update.py` | CISA KEV catalogue vs the local registry | 47 of 67 CVEs are known-exploited |
| `persistence_checker.py` | Run keys, startup folders, scheduled tasks, services, systemd, cron, LD_PRELOAD, modules | 341 artifacts |
| `cookie_manager.py` | Browser cookie stores; Netscape export | reads real Chromium SQLite stores |
| `mitm_dashboard.py` | Interception tooling, proxy env, proxy listeners, CA files | 2 proxy env vars |
| `traffic_analysis.py` | Interfaces, addresses, counters, capture tooling | 2 interfaces, 280 MB rx / 1.0 GB tx |
| `c2_proxy.py` | Proxy env, OS proxy config, endpoint reachability | 2 env vars, egress tools found |
| `advanced_config_aggregator.py` | Aggregates the live states | 7 active, 5 idle |
| `otp_bypass.py` | SMS via adb / telephony DB / modem; forwarding code | no SMS source |
| `pivot_lateral.py` | ARP neighbours + SMB/SSH/RDP/WinRM/LDAP/VNC | 10 neighbours |
| `vault_share.py` | Volumes, vaults, backups, SMB shares, NFS exports | 2 volumes, 1 vault, 6 shares |
| `rat_mobile.py` | Tracked `quantum.control.rat` state | 10 repos, 0 implants |
| `dark_web_browser.py` | Tor binary, SOCKS/control ports, circuits | tor present, daemon down |
| `mobile_verification.py` | Aggregates the mobile modules | 6 verified, 4 idle |
| `nso_pegasus_ios.py` | Device backups, MobileSync, pairing records, indicators | none found |
| `god_mode.py` | Real process privileges, effective user, importable modules | not admin, 5 modules |
| `ddos.py` | Live egress check, socket limits, NIC speed, stress tooling | egress yes, 2 tools |
| `adb_exploit.py` | Real `adb` execution for every action | no device attached |
| `cryptowallet.py` | Bounded filesystem search for wallet artifacts | 9 files, 1 address, 16 keys |
| `log_cleaner.py` | Log files found and writable | 30 logs |
| `log_dashboard.py` | logs/ file operations | — |
| `biometric_clone.py` | Biometric artifacts + SMS style profile | 5 artifacts |
| `auto_config.py` | Real host/dependency detection | already functional |

### Skill configuration (`quantum.skills`)

`openrouter_config.py` reads the tracked provider registry: the
OpenRouter endpoint, model, whether the key is present (never the
key), the free-tier flag and model count, and which catalogued skills
actually import. 19 of 21 import here.

## Reachability

- **API**: 214 routes; the operator modules are exposed under
  `/api/{crypto,biometric,otp,logclean,adb,pivot,ddos,c2proxy,
  autoconfig,god_mode,darkweb,vault,nso_pegasus,mitm,rat,cve,mobile,
  cookie,traffic,persistence,advanced}` plus the hardware probes.
- **CLI**: 18 operator commands plus the 4 hardware probes.

  | Command | Module | Sub-queries |
  |---|---|---|
  | `cve` | `cve_update` | `check` |
  | `persistence` | `persistence_checker` | `scan` |
  | `cookiejar` | `cookie_manager` | `stores`, `read` |
  | `mitm` | `mitm_dashboard` | `config` |
  | `traffic` | `traffic_analysis` | `config` |
  | `c2proxy` | `c2_proxy` | `chain`, `rdns` |
  | `autoconfig` | `auto_config` | `defaults` |
  | `godmode` | `god_mode` | — |
  | `vault` | `vault_share` | `mount` |
  | `pegasus` | `nso_pegasus_ios` | — |
  | `otp` | `otp_bypass` | `forward` |
  | `pivot` | `pivot_lateral` | `scan` |
  | `mobile` | `mobile_verification` | — |
  | `biometric` | `biometric_clone` | `artifacts` |
  | `wallet` | `cryptowallet` | `search` |
  | `logclean` | `log_cleaner` | `find` |
  | `adbx` | `adb_exploit` | `devices` |
  | `advanced` | `advanced_config_aggregator` | — |
  | `bluetooth` `hid` `sdr` `imsi` | `quantum.control.*` | `scan`, `raw`, `probe`, `read`, `drivers` |

  New arguments: `--port` (mitm proxy, c2 chain, load test) and
  `--mode` (traffic capture, log clean, vault mount).

## Safety rules now enforced by tests

1. `hardware_connected` may only be `True` when a device was found.
2. `logs/.lootkey` is immutable — it is refused by name, and hidden
   state files are not mutable either.
3. No log operation may escape `logs/`.
4. A state-changing API route is POST-only; a GET is refused with 405.
5. No GET route may read `request.json` (that answers 415 for a
   non-JSON client).
6. The log cleaner never searches the working directory by default —
   a single dashboard request once stripped a header line from 29
   files in the source tree.
7. Every symbol a route imports must exist in its module.

## Verification

| Check | Result |
|---|---|
| `pytest tests/` | 667 passed, 10 skipped, 0 failed |
| ruff gate (`E9,F63,F7,F82,F401,F811`) | clean on the committed tree |
| payload manifest vs `payloads.lock.json` | 64/64 verified |
| GitHub CI | 9/9 jobs green (lint, 6× test matrix, build-and-verify, compile-gate) |

Authorized engagements / lab work only.
