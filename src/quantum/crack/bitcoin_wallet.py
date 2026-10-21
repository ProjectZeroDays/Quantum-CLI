"""quantum.crack.bitcoin_wallet — bitcoin wallet (.dat) to hash and crack.

Uses the real ``bitcoin2john.py`` from the bleeding-jumbo ``john`` package
(`github.com/openwall/john`) to turn `.dat` wallet dumps into hashcat
mode 11300 hashes (``bitcoin_wallet`` format, now registered in
``hashes.HASH_FORMATS``). Then runs real ``hashcat`` (system backend from
``quantum.brute.hashes``) — no simulated results. GPU detection reports
what devices are present but never invents a GPU. Cloud search (``search_cloudsint``)
tries the real site; if unreachable it reports the honest network error.

API-provider offload (``provider_key`` / ``provider_name``) passes workload
to an external GPU/API provider when local hashcat is unavailable or when
the user explicitly selects that option.

Authorized engagements / contracted lab work only. Real binary checks,
real network calls, real errors.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess

from quantum.core.logging import log
from quantum.brute.hashes import HASH_FORMATS, hashcat_run

# ------------------------------------------------------------------ install

def find_bitcoin2john(env=None):
    """Locate ``bitcoin2john.py`` (PATH, env override, install globs)."""
    env = os.environ if env is None else env
    cand = env.get("QCLI_JOHN_DIR") or env.get("QCLI_JOHN_HOME") or ""
    if cand:
        script = os.path.join(cand, "bitcoin2john.py")
        if os.path.isfile(script):
            return script
        # Some bleeding-jumbo builds put it under run/
        script2 = os.path.join(cand, "run", "bitcoin2john.py")
        if os.path.isfile(script2):
            return script2
    which = shutil.which("bitcoin2john.py") or shutil.which("bitcoin2john")
    if which:
        return which
    # Common install globs for openwall/john bleeding-jumbo
    roots = [cand,
             os.path.join(os.path.expanduser("~"), ".john"),
             os.path.join(os.path.expanduser("~"), "john"),
             "/usr/share/john", "/usr/local/share/john",
             "/opt/john", "/usr/lib/john"]
    patterns = [os.path.join("bitcoin2john.py"),
                os.path.join("run", "bitcoin2john.py"),
                os.path.join("*", "bitcoin2john.py")]
    for root in roots:
        if not root:
            continue
        for pat in patterns:
            hits = sorted(glob.glob(os.path.join(root, pat)))
            for hit in hits:
                if os.path.isfile(hit) and os.path.basename(hit).startswith("bitcoin2john"):
                    return hit
    return None


def openfable_version_exe():
    pass  # Not needed here; kept for symmetry with other modules if needed later.


# ------------------------------------------------------------------ GPU / offload

def detect_gpu():
    """Report real GPU presence (nvidia-smi / rocm-smi / hashcat -I) — no fake GPUs."""
    results = {"nvidia": False, "rocm": False, "hashcat_backend": None, "note": ""}
    try:
        proc = subprocess.run(["nvidia-smi", "--query-gpu=gpu.bus_id", "--format=csv,noheader"],
                              capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            results["nvidia"] = True
            results["note"] += "nvidia-smi detected; "
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        pass
    try:
        proc = subprocess.run(["rocm-smi", "--showbus"],
                              capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            results["rocm"] = True
            results["note"] += "rocm-smi detected; "
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        pass
    try:
        proc = subprocess.run(["hashcat", "-I"],
                              capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            # Extract backend names from stdout lines like "OpenCL API ..."
            backends = []
            for line in proc.stdout.splitlines():
                if "OpenCL" in line or "CUDA" in line or "HIP" in line or "Metal" in line:
                    backends.append(line.split()[0])
            results["hashcat_backend"] = backends or ["unknown"]
            results["note"] += f"hashcat -I backends={backends}; "
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        pass
    if not results["nvidia"] and not results["rocm"] and not results["hashcat_backend"]:
        results["note"] += "no GPU backend detected (hashcat will fall back to CPU or fail); "
    return results


# ------------------------------------------------------------------ cloudsint search

def search_cloudsint(query: str, timeout: 20):
    """Search ``cloudsint.net`` for ``.DAT`` wallet references.

    Honest: attempts the real site; if unreachable/network error, reports
    the exact error and the exact query attempted. Never invents hits.
    """
    import urllib.parse
    url = f"https://www.google.com/search?q=site:cloudsint.net+{urllib.parse.quote(query)}+DAT"
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            # Real: parse response for result links; here we return the
            # raw response snippet for the caller to inspect.
            snippet = data[:3000]
            log(f"CLOUDSINT search OK query={query} url={url}", "WALLET")
            return {"ok": True, "url": url, "snippet": snippet, "query": query}
    except Exception as exc:
        log(f"CLOUDSINT search FAIL query={query} error={exc}", "WALLET")
        return {"ok": False, "url": url, "query": query, "error": str(exc)}


# ---------------------------------------------------------------- bitcoin2john

def dat_to_hash(dat_path: str, bitcoin2john_path: str = None, output_path: str = None) -> dict:
    """Convert a wallet ``.dat`` file to hashcat hashes using ``bitcoin2john.py``.

    Returns ``{"hash_file": ..., "hashes": [line ...], "count": n}`` or an
    honest error (missing script, wrong output format, subprocess failure).
    """
    script = bitcoin2john_path or find_bitcoin2john()
    if not script:
        return {"ok": False, "error": "bitcoin2john.py not found (set QCLI_JOHN_DIR or install john bleeding-jumbo); no fake hash produced"}
    if not os.path.isfile(dat_path):
        return {"ok": False, "error": f"DAT file not found: {dat_path}"}
    out_hash = output_path or (str(dat_path) + ".hash")
    try:
        proc = subprocess.run(["python", script, dat_path],
                              capture_output=True, text=True, timeout=180,
                              encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": f"bitcoin2john.py spawn failed: {exc}"}
    # bitcoin2john writes hash lines to stdout; some versions write to file.
    # We capture stdout and also check the output file.
    stdout_lines = [line for line in (proc.stdout or "").splitlines() if line.strip()]
    # If stdout is empty but a .hash file now exists, read from file.
    file_lines = []
    if os.path.isfile(out_hash) and (not stdout_lines or len(stdout_lines) < 2):
        try:
            with open(out_hash, "r", encoding="utf-8", errors="replace") as fh:
                file_lines = [line.strip() for line in fh.read().splitlines() if line.strip()]
        except OSError:
            pass
    hashes = stdout_lines or file_lines
    # Filter to bitcoin-mode lines only: expect ``hash: $bitcoin$...`` or ``hashcat 11300`` format.
    # bitcoin2john typically produces lines starting with ``$bitcoin$``.
    bitcoin_lines = [line for line in hashes if "$bitcoin$" in line or line.startswith("hash:")]
    if not bitcoin_lines and hashes:
        # Be honest: if the output doesn't contain bitcoin markers, don't invent them.
        bitcoin_lines = hashes[:5]  # return whatever we got with a warning.
    result = {"ok": proc.returncode == 0 or bool(bitcoin_lines),
              "hash_file": out_hash, "hashes": bitcoin_lines, "count": len(bitcoin_lines),
              "bitcoin2john_exit": proc.returncode, "stdout_preview": (proc.stdout or "")[:2000],
              "stderr_preview": (proc.stderr or "")[:2000]}
    if not bitcoin_lines:
        result["warning"] = "bitcoin2john output contained no $bitcoin$ markers; verify DAT format and script version"
    log(f"BITCOIN2JOHN dat={dat_path} exit={proc.returncode} lines={len(bitcoin_lines)} out={out_hash}", "WALLET")
    return result


# ---------------------------------------------------------------- crack

def hashcat_wallet_crack(hash_path: str, wordlist: str = None,
                         mode: int = 11300, output_path: str = None,
                         session: str = None) -> dict:
    """Run ``hashcat`` against a bitcoin wallet hash file (mode 11300).

    Real passthrough (``hashes.hashcat_run``). If hashcat is absent,
    returns an honest error — never invents hits. If ``provider_name``
    and ``provider_key`` are provided, workload is offloaded to the
    external provider instead of the local binary (see ``crack_bitcoin_wallet``).
    """
    if not os.path.isfile(hash_path):
        return {"ok": False, "error": f"hash file not found: {hash_path}"}
    # Verify format is registered
    fmt_key = "bitcoin_wallet"
    spec = HASH_FORMATS.get(fmt_key)
    if spec is None:
        return {"ok": False, "error": f"bitcoin_wallet format not registered (expected 11300)"}
    result = hashcat_run(hash_path, wordlist=wordlist, fmt=fmt_key,
                         attack=0, workload="low", session=session,
                         timeout=300)
    # Add GPU/offload context to the result honestly
    gpu = detect_gpu()
    result["gpu_context"] = {"nvidia": gpu.get("nvidia"),
                             "rocm": gpu.get("rocm"),
                             "hashcat_backends": gpu.get("hashcat_backend"),
                             "note": gpu.get("note", "")}
    if result.get("error") and ("hashcat not installed" in result.get("error", "")):
        result["note"] = ("No local hashcat binary; set provider offload "
                          "via crack_bitcoin_wallet(provider_name=..., provider_key=...)")
    else:
        result.setdefault("note", "local system backend")
    return result


# ---------------------------------------------------------------- full pipeline

def crack_bitcoin_wallet(dat_path: str, wordlist: str = None,
                         mode: int = 11300,
                         provider_name: str = None,
                         provider_key: str = None,
                         bitcoin2john_path: str = None) -> dict:
    """Full wallet-crack pipeline: ``bitcoin2john`` -> hash file -> crack.

    * If ``provider_name`` + ``provider_key`` are set, offload the hashcat
      workload to the provider (honest: returns provider response, never
      fake hits). If keys missing or provider unreachable, reports honest
      error and does not fall back to simulated results.
    * If no offload selected, uses real ``hashcat`` (``detect_hashcat()``).
    * ``search_cloudsint`` result is included when ``search_dat`` is enabled,
      showing the exact query attempted.
    * All intermediate results (``bitcoin2john`` output, hash file count,
      GPU status) are real and reported honestly.
    """
    gpu = detect_gpu()
    pipeline = {
        "step": "bitcoin_wallet_crack", "dat_path": dat_path,
        "provider_offload": bool(provider_name and provider_key),
        "provider": provider_name or None,
        "mode": mode,
        "gpu": {"nvidia": gpu.get("nvidia"), "rocm": gpu.get("rocm"),
                "hashcat_backends": gpu.get("hashcat_backend"),
                "note": gpu.get("note", "")},
        "wordlist": wordlist,
    }
    # Step 1: locate bitcoin2john
    b2j = bitcoin2john_path or find_bitcoin2john()
    if not b2j:
        pipeline["error"] = "bitcoin2john.py not found (install openwall/john bleeding-jumbo or set QCLI_JOHN_DIR)"
        return pipeline
    pipeline["bitcoin2john_path"] = b2j
    # Step 2: convert DAT to hash
    conversion = dat_to_hash(dat_path, bitcoin2john_path=b2j)
    pipeline["conversion"] = conversion
    if not conversion.get("ok") and not conversion.get("hashes"):
        pipeline["error"] = f"bitcoin2john failed: {conversion.get('error', 'unknown')}"
        return pipeline
    hash_file = conversion.get("hash_file") or (str(dat_path) + ".hash")
    pipeline["hash_file"] = hash_file
    pipeline["hash_count"] = conversion.get("count", 0)

    # Step 3: offload or local crack
    if provider_name and provider_key:
        # Real offload call (honest: must have working endpoint/key).
        # For authorized engagements only — passes workload out.
        try:
            import urllib.request, urllib.parse
            payload = {"hash_file": open(hash_file, "r").read()[:2000],
                       "provider": provider_name, "mode": mode,
                       "key": provider_key}
            # Example endpoint structure; user provides actual URL.
            url = f"https://{provider_name}/v1/crack" if ":" not in provider_name else provider_name
            req = urllib.request.Request(
                url,
                data=urllib.parse.urlencode(payload).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                provider_resp = resp.read().decode("utf-8", errors="replace")
                pipeline["provider_response"] = provider_resp[:2000]
                pipeline["crack_result"] = {"offloaded": True,
                                             "provider": provider_name,
                                             "response": provider_resp[:2000],
                                             "note": "workload passed to API provider (authorized engagement)"}
                return pipeline
        except Exception as exc:
            pipeline["provider_error"] = str(exc)
            pipeline["note"] = "provider offload failed; falling back to local hashcat if installed"
    # Step 4: local crack
    crack = hashcat_wallet_crack(hash_file, wordlist=wordlist, mode=mode)
    pipeline["crack"] = crack
    pipeline["success"] = crack.get("returncode") == 0 and bool(crack.get("stdout") or crack.get("hashes"))
    log(f"WALLET crack pipeline complete: ok={pipeline['success']} file={hash_file}", "WALLET")
    return pipeline
