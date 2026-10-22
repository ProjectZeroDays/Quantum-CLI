# QUANTUM-CLI v4.6.3

The operator-surface release. The runtime modules that were placeholder
dashboards are now real probes, committed, and reachable from both the
CLI and the dashboard API.

## The rule that governs all of it

**A module may only report a capability it actually verified.**

The placeholder dashboards returned a literal `hardware_connected: True`
with no probe behind it — a simulated capability, which this project's
"no simulated code" rule forbids. Every module now reports what the
host actually has, and says so when it has nothing. The rule is
enforced by tests: `hardware_connected` may only be `True` when a
device was actually found.

## What the modules report now

| Module | Probe | Result on the reference host |
|---|---|---|
| `cve_update` | CISA KEV catalogue vs the local registry | **47 of 67** registered CVEs are known-exploited |
| `persistence_checker` | Run keys, startup folders, scheduled tasks, services, systemd, cron, LD_PRELOAD, modules | **731** artifacts (390 tasks, 323 services) |
| `traffic_analysis` | Interfaces, addresses, counters, capture tooling | 2 interfaces, 513 MB rx / 1.9 GB tx |
| `wallet` (cryptowallet) | Bounded filesystem search for wallet artifacts | 9 wallet files, 1 address, 16 keys |
| `pivot_lateral` | ARP/neighbour table + SMB, SSH, RDP, WinRM, LDAP, VNC | 15 neighbours |
| `vault_share` | Volumes, Cryptomator vaults, backups, SMB shares, NFS exports | 2 volumes, 1 vault, 6 shares |
| `cookie_manager` | Browser cookie stores, read from a copy, Netscape export | reads real Chromium SQLite stores |
| `mitm_dashboard` | Interception tooling, proxy env, proxy listeners, CA files | 2 proxy env vars |
| `c2_proxy` | Proxy env, OS proxy config, endpoint reachability | 2 env vars, egress tools found |
| `adb_exploit` | Real `adb` execution for every action | no device attached (reported honestly) |
| `bluetooth` / `hid` / `sdr` / `imsi` | BT controller, HID devices, radios, capture-capable radios + modem | 1 controller, 38 HID devices, 0 radios |
| `dark_web_browser` | Tor binary, SOCKS/control ports, circuits | tor present, daemon down |
| `nso_pegasus_ios` | Device backups, MobileSync, pairing records, indicators | none found |
| `god_mode` | Real process privileges, effective user, importable modules | not admin, 5 modules |
| `ddos` | Live egress check, socket limits, NIC speed, stress tooling | egress yes, 2 tools |
| `mobile_verification` | Aggregates the mobile modules | 5 verified, 5 idle |
| `advanced_config_aggregator` | Aggregates the live states | 6 active, 6 idle |
| `openrouter_config` | Provider registry: endpoint, model, key present, free models, importable skills | 17 free models, 19/21 skills |

## Reachability

**CLI** — 18 new operator commands, each with a `--query` sub-dispatch:

```
cve  persistence  cookiejar  mitm  traffic  c2proxy  autoconfig  godmode
vault  pegasus  otp  pivot  mobile  biometric  wallet  logclean  adbx
advanced
```

plus the hardware probes `bluetooth`, `hid`, `sdr`, `imsi`. Two new
arguments: `--port` and `--mode`.

**API** — the operator modules are exposed under `/api/{crypto, biometric,
otp, logclean, adb, pivot, ddos, c2proxy, autoconfig, god_mode, darkweb,
vault, nso_pegasus, mitm, rat, cve, mobile, cookie, traffic, persistence,
advanced}` (214 routes in total).

## Safety fixes

- **`logs/.lootkey` is now immutable by construction.** Deleting or
  editing it breaks every sealed `.gfy` in `loot/`. The key is refused
  by name and hidden state files are not mutable either.
- **No log operation can escape `logs/`.** The old guard used
  `os.path.isabs`, which does not mean the same thing on Windows —
  `/etc/passwd` was accepted and written outside the repository.
- **State-changing API routes are POST-only.** Cleaning logs, injecting
  cookies, deploying an APK and setting SMS forwarding were reachable
  with a GET, which a browser prefetch, a link preview or a crawler can
  trigger.
- **No GET route reads `request.json`.** That answers 415 for any
  client that does not send a JSON body.
- **The log cleaner no longer searches the working directory by
  default.** A single dashboard request once stripped a header line
  from 29 files in the source tree.
- **The payload manifest records byte counts, not character counts.**
  Three kernel stubs contain U+2014 — one character, three bytes — so
  the manifest disagreed with the files it described.

## Other fixes

- The `UiState` sealed class is no longer generic, which resolves the
  Kotlin→Java `CAP#1` wildcard-capture error that blocked
  `compileFullReleaseJavaWithJavac`.
- `@JavascriptInterface` methods bridge the suspend repository calls
  with `runBlocking` — they run on the WebView JS thread, not a
  coroutine.
- ZIP payload archives are byte-reproducible: stored rather than
  deflated (classic zlib and zlib-ng disagree byte-for-byte), a pinned
  host field, and the manifest's volatile timestamp stripped.
- `build_all_kernel.py` gained the `--outdir` the kernel-exploits
  workflow was already passing; the job had been failing on every run.
- The dirtypipe PoC defines `_GNU_SOURCE` and includes `<stdlib.h>`
  and `<sys/types.h>` (`splice`, `F_GETPIPE_SZ` and `loff_t` are GNU
  extensions).

## Assets

| File | Size | Notes |
|---|---|---|
| `quantum-cli-full-4.6.3.apk` | 15.9 MB | V2 signed, root-capable |
| `quantum-cli-limited-4.6.3.apk` | 15.9 MB | V2 signed, no-root |
| `quantum-exploits-v4.6.3.zip` | 213 KB | exploit modules + operator harness |
| `quantum-payloads-v4.6.3.zip` | 88 KB | 64 built payload artifacts |
| `payloads.lock.json` | 18 KB | sha256 manifest for every payload |
| `PLATFORM_INDEX.json` | 21 KB | platform/exploit index |

Both archives are byte-reproducible: every entry is stored, stamped
with a fixed epoch and a pinned host field, so rebuilding the same tree
yields identical archives. Every artifact in
`quantum-payloads-v4.6.3.zip` matches `payloads.lock.json` by size and
sha256.

Rebuild with:

```bash
python package_release.py --version 4.6.3
```

## Verification

| Check | Result |
|---|---|
| `pytest tests/` | 667 passed, 10 skipped, 0 failed |
| ruff gate (`E9,F63,F7,F82,F401,F811`) | clean on the committed tree |
| payload manifest vs `payloads.lock.json` | 64/64 verified |
| `apksigner verify` | V2 signature scheme on both APKs |
| GitHub CI | 9/9 jobs green |

## Authorized use only

All tooling in this release assumes penetration-test, lab or
contracted-authorization contexts. Use it only against systems you own
or have written authorization to test.
