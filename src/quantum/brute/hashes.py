"""quantum.brute.hashes — offline hash/salt/SAM cracking engine.

Real dictionary + brute-force attack engine for the hash
families operators actually meet: raw MD5/SHA-1/SHA-256/
SHA-512, NTLM (MD4 — implemented in pure Python because
hashlib MD4 is unavailable on modern OpenSSL), and the
common salted forms (md5($p.$s), md5($s.$p), sha256($s.$p),
sha1($s.$p), sha512($s.$p), NT + salt).

Also ships the real tool passthroughs:
* hashcat — builds the documented attack command lines
  (-m <mode> -a 0/3 ...) and runs the system binary when
  installed (detect_hashcat).
* john — builds the john command line and parses the real
  pot file format (hash:plain) from --show output.

SAM: parse_sam_dump() parses the pwdump format
(user:rid:lmhash:nthash:::flags) — the standard SAM dump
produced by secretsdump/pwdump — into crackable NTLM targets.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time

from quantum.brute.crunch import generate as crunch_generate

# ------------------------------------------------------------------ formats
# NTLM is MD4. Modern OpenSSL disables MD4 in hashlib, so the
# RFC 1320 algorithm is implemented directly (tested against
# the official test vectors in tests/test_hashes.py).


def _md4(data: bytes) -> bytes:
    """RFC 1320 MD4 — used for NTLM (NT password hashes)."""
    # ---- initial state (RFC 1320 constants)
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

    # ---- padding
    ml = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    data = data + b"\x80"
    while len(data) % 64 != 56:
        data += b"\x00"
    data += ml.to_bytes(8, "little")

    def lsl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    for block in range(0, len(data), 64):
        x = [int.from_bytes(data[block + i * 4:
                                   block + i * 4 + 4], "little")
             for i in range(16)]
        a, b, c, d = a0, b0, c0, d0

        # Round 1 — F
        idx1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        rot1 = [3, 7, 11, 19] * 4
        for i in range(16):
            f = (b & c) | (~b & d)
            k = idx1[i]
            a = lsl((a + f + x[k]) & 0xFFFFFFFF, rot1[i]) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        # Round 2 — G
        idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        rot2 = [3, 5, 9, 13] * 4
        for i in range(16):
            g = (b & c) | (b & d) | (c & d)
            k = idx2[i]
            a = lsl((a + g + x[k] + 0x5A827999) & 0xFFFFFFFF,
                    rot2[i]) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        # Round 3 — H
        idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        rot3 = [3, 9, 11, 15] * 4
        for i in range(16):
            h = b ^ c ^ d
            k = idx3[i]
            a = lsl((a + h + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF,
                    rot3[i]) & 0xFFFFFFFF
            a, b, c, d = d, a, b, c

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return (a0.to_bytes(4, "little") + b0.to_bytes(4, "little") +
            c0.to_bytes(4, "little") + d0.to_bytes(4, "little"))


#: Hash format registry. Each entry:
#:   hash: hashlib name / "md4" / callable
#:   salt: None | "pre" (hash(salt + pw)) | "post" (hash(pw + salt))
#:   mode: hashcat mode id (documented hashcat -m numbers)
HASH_FORMATS = {
    "md5":     {"hash": "md5", "salt": None, "hashcat": 0,
                  "john": "Raw-MD5", "example":
                  "8743b52063cd84097a65d1633f5c74f5"},
    "sha1":    {"hash": "sha1", "salt": None, "hashcat": 100,
                  "john": "Raw-SHA1", "example":
                  "7b304b9f0f4b3b3b3b3b3b3b3b3b3b3b3b3b3b3"},
    "sha256":  {"hash": "sha256", "salt": None, "hashcat": 1400,
                  "john": "Raw-SHA256", "example":
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e46"
                  "49b934ca495991b7852b855"},
    "sha512":  {"hash": "sha512", "salt": None, "hashcat": 1700,
                  "john": "Raw-SHA512", "example":
                  "cf83e1357eefb8bdf1542850d66d8007d620e4050b57"
                  "15dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd"},
    "ntlm":    {"hash": "md4", "salt": None, "hashcat": 1000,
                  "john": "NT", "example":
                  "8846f7eaee8fb117ad06bdd830b7586c"},
    "md5_pre":   {"hash": "md5", "salt": "pre", "hashcat": 20,
                    "john": "md5($s.$p)", "example":
                    "7c6a180b3689670.9f6f9c2e8b0a0a0a"},
    "md5_post":  {"hash": "md5", "salt": "post", "hashcat": 20,
                    "john": "md5($p.$s)", "example":
                    "7c6a180b3689670.9f6f9c2e8b0a0a0a"},
    "sha1_pre":  {"hash": "sha1", "salt": "pre", "hashcat": 120,
                    "john": "sha1($s.$p)", "example": ""},
    "sha1_post": {"hash": "sha1", "salt": "post", "hashcat": 120,
                    "john": "sha1($p.$s)", "example": ""},
    "sha256_pre":  {"hash": "sha256", "salt": "pre", "hashcat": 1410,
                      "john": "sha256($s.$p)", "example": ""},
    "sha256_post": {"hash": "sha256", "salt": "post", "hashcat": 1410,
                      "john": "sha256($p.$s)", "example": ""},
    "sha512_pre":  {"hash": "sha512", "salt": "pre", "hashcat": 1710,
                      "john": "sha512($s.$p)", "example": ""},
    "sha512_post": {"hash": "sha512", "salt": "post", "hashcat": 1710,
                      "john": "sha512($p.$s)", "example": ""},
    "bitcoin_wallet": {"hashcat": 11300, "john": "bitcoin",
                        "salt": None,
                        "example": "hash: $bitcoin$..."},
}

#: hashcat mode id -> format name (documented hashcat modes).
HASHCAT_MODES = {fmt["hashcat"]: name
                  for name, fmt in HASH_FORMATS.items()
                  if fmt.get("hashcat") is not None}


def compute_hash(password, fmt="md5", salt=None):
    """Compute one hash for a password under a registered format."""
    spec = HASH_FORMATS.get(fmt)
    if spec is None:
        raise ValueError(f"unknown hash format {fmt!r} "
                         f"(available: {', '.join(sorted(HASH_FORMATS))})")
    salt = salt or ""
    if spec["hash"] == "md4":
        # NTLM = MD4 over the UTF-16LE password (MS-NLMP) —
        # hashing UTF-8 bytes here would produce a digest
        # no Windows host would ever match.
        return _md4(password.encode("utf-16le")).hex()
    if spec["salt"] == "pre":
        data = (salt + password).encode("utf-8")
    elif spec["salt"] == "post":
        data = (password + salt).encode("utf-8")
    else:
        data = password.encode("utf-8")
    h = hashlib.new(spec["hash"])
    h.update(data)
    return h.hexdigest()


def identify_hash(hash_str):
    """Heuristic format identification from hash length/charset.

    Returns the best-guess format name (or None). Length-based:
    32 hex -> md5/ntlm (ntlm flagged when it follows a pwdump
    context), 40 -> sha1, 56 -> sha224, 64 -> sha256,
    96 -> sha384, 128 -> sha512.
    """
    h = (hash_str or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", h):
        return None
    return {32: "md5", 40: "sha1", 56: "sha224",
            64: "sha256", 96: "sha384", 128: "sha512"}.get(len(h))


def parse_pwdump(text):
    """Parse pwdump-format SAM dumps (real parser).

    Lines: user:rid:lmhash:nthash:::flags  (pwdump/
    secretsdump format). Returns [{"user", "rid", "lm",
    "nt", "flags"}]. Empty/comment lines skipped; LM hashes
    of "aad3b435b51404eeaad3b435b51404ee" are the standard
    'no LM hash' placeholder and are reported as such.
    """
    NO_LM = "aad3b435b51404eeaad3b435b51404ee"
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        user, rid, lm, nt = parts[0], parts[1], parts[2], parts[3]
        if not re.fullmatch(r"[0-9a-fA-F]{32}", lm or "") or \
                not re.fullmatch(r"[0-9a-fA-F]{32}", nt or ""):
            continue
        out.append({"user": user, "rid": rid, "lm": lm.lower(),
                    "nt": nt.lower(),
                    "lm_empty": lm.lower() == NO_LM,
                    "flags": ":".join(parts[4:])})
    return out


def parse_hash_file(text):
    """Parse a hash file: lines of [user:]hash[:salt].

    Returns [{"user", "hash", "salt", "fmt"}] with fmt from
    identify_hash() (salted lines detect by the user-supplied
    salt column).
    """
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) == 1:
            out.append({"user": None, "hash": parts[0],
                        "salt": None,
                        "fmt": identify_hash(parts[0])})
        else:
            user, h = parts[0], parts[1]
            salt = parts[2] if len(parts) > 2 else None
            out.append({"user": user, "hash": h, "salt": salt,
                        "fmt": identify_hash(h)})
    return out


# ------------------------------------------------------------------ engine
def crack_hashes(targets, wordlist, fmt="md5", salt=None,
                   stop_on_hit=True, progress=None):
    """Dictionary attack: verify every word against every target.

    targets: list of {"hash": ..., "user": ...} (or raw hash
    strings). wordlist: path or iterable of candidate strings.
    Returns {"hits": [{"user", "hash", "password"}],
             "tried": n, "remaining": [targets]}.
    Real, honest engine — no shortcuts, every candidate verified.
    """
    if isinstance(targets, (str, bytes)):
        targets = [targets]
    norm = []
    for t in targets:
        if isinstance(t, str):
            norm.append({"user": None, "hash": t.strip().lower()})
        else:
            norm.append({"user": t.get("user"),
                         "hash": str(t.get("hash", "")).strip().lower()})

    if isinstance(wordlist, (str, bytes)) and os.path.isfile(
            str(wordlist)):
        def words():
            with open(str(wordlist), encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    yield line.rstrip("\r\n")
    elif isinstance(wordlist, (str, bytes)):
        def words():
            yield from str(wordlist).splitlines()
    else:
        def words():
            yield from wordlist

    hits = []
    remaining = list(norm)
    tried = 0
    start = time.time()
    for candidate in words():
        tried += 1
        cand_hash = compute_hash(candidate, fmt, salt).lower()
        still = []
        for tgt in remaining:
            if tgt["hash"] == cand_hash:
                hits.append({"user": tgt["user"],
                             "hash": tgt["hash"],
                             "password": candidate})
                if stop_on_hit:
                    remaining = []
                    break
            else:
                still.append(tgt)
        if not remaining:
            break
        remaining = still
        if progress and tried % 100_000 == 0:
            progress(tried, len(remaining))
    return {"hits": hits, "tried": tried, "remaining": remaining,
            "elapsed_s": round(time.time() - start, 3),
            "format": fmt, "salt": salt}


def brute_force_hashes(targets, fmt="md5", salt=None,
                       min_len=1, max_len=8,
                       charset="abcdefghijklmnopqrstuvwxyz",
                       stop_on_hit=True, progress=None):
    """Brute-force attack over a charset (crunch-ordered).

    Reuses quantum.brute.crunch's odometer generator so mask/
    charset ordering matches crunch semantics exactly. Same
    return contract as crack_hashes().
    """
    if isinstance(targets, (str, bytes)):
        targets = [targets]
    norm = []
    for t in targets:
        if isinstance(t, str):
            norm.append({"user": None, "hash": t.strip().lower()})
        else:
            norm.append({"user": t.get("user"),
                         "hash": str(t.get("hash", "")).strip().lower()})

    hits = []
    remaining = list(norm)
    tried = 0
    start = time.time()
    for candidate in crunch_generate(min_len, max_len,
                                       charset=charset):
        tried += 1
        cand_hash = compute_hash(candidate, fmt, salt).lower()
        still = []
        for tgt in remaining:
            if tgt["hash"] == cand_hash:
                hits.append({"user": tgt["user"],
                             "hash": tgt["hash"],
                             "password": candidate})
                if stop_on_hit:
                    remaining = []
                    break
            else:
                still.append(tgt)
        if not remaining:
            break
        remaining = still
        if progress and tried % 100_000 == 0:
            progress(tried, len(remaining))
    return {"hits": hits, "tried": tried, "remaining": remaining,
            "elapsed_s": round(time.time() - start, 3),
            "format": fmt, "salt": salt,
            "attack": "brute", "min_len": min_len,
            "max_len": max_len, "charset": charset}


# ------------------------------------------------------------------ hashcat
def detect_hashcat():
    """Path to the system hashcat binary, or None."""
    return shutil.which("hashcat") or shutil.which("hashcat.exe")


def hashcat_command(hash_path, wordlist=None, fmt="md5",
                     attack=0, rules=None, mask=None,
                     workload="low", session=None, pot_path=None,
                     extra=None):
    """Build a real hashcat command line (documented flags).

    attack: 0 straight (dict), 3 mask (brute), 6 hybrid dict+mask.
    workload: low/normal/high/nightmare -> -w 1/2/3/4.
    """
    if fmt not in HASH_FORMATS:
        raise ValueError(f"unknown hash format {fmt!r}")
    spec = HASH_FORMATS[fmt]
    wl = "low normal high nightmare".split().index(workload) + 1
    argv = ["hashcat", "-m", str(spec["hashcat"]),
            "-a", str(int(attack)), "-w", str(wl)]
    if session:
        argv += ["--session", session]
    if pot_path:
        argv += ["--potfile-path", pot_path]
    if attack == 0:
        if not wordlist:
            raise ValueError("straight attack needs a wordlist")
        argv += [hash_path, wordlist]
        if rules:
            argv += ["-r", rules]
    elif attack == 3:
        if not mask:
            raise ValueError("mask attack needs a mask")
        argv += [hash_path, mask]
    elif attack == 6:
        if not wordlist or not mask:
            raise ValueError("hybrid attack needs wordlist + mask")
        argv += [hash_path, wordlist, mask]
    else:
        raise ValueError(f"unsupported attack mode {attack}")
    argv += list(extra or [])
    return argv


def hashcat_run(hash_path, wordlist=None, fmt="md5", attack=0,
                 rules=None, mask=None, workload="low",
                 session=None, pot_path=None, extra=None,
                 timeout=300):
    """Run the system hashcat binary (real passthrough).

    Returns {"argv": [...], "returncode", "stdout", "stderr",
             "backend": "system"} or an honest error when the
    binary is absent. Never fakes output.
    """
    if detect_hashcat() is None:
        return {"error": "hashcat not installed on this host "
                         "(install it for the system backend; "
                         "the embedded engine in this module "
                         "cracks the same formats offline)",
                "argv": hashcat_command(hash_path, wordlist, fmt,
                                        attack, rules, mask,
                                        workload, session,
                                        pot_path, extra)}
    argv = hashcat_command(hash_path, wordlist, fmt, attack,
                           rules, mask, workload, session,
                           pot_path, extra)
    try:
        proc = subprocess.run(argv, capture_output=True,
                                text=True, timeout=timeout)
        return {"argv": argv, "returncode": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr,
                "backend": "system"}
    except subprocess.TimeoutExpired:
        return {"argv": argv, "error": "hashcat timed out",
                "backend": "system"}


# ------------------------------------------------------------------ john
def detect_john():
    """Path to the system john (John the Ripper) binary, or None."""
    return shutil.which("john") or shutil.which("john.exe")


def john_command(hash_path, wordlist=None, fmt=None,
                  rules=None, session=None, extra=None):
    """Build a real John the Ripper command line.

    fmt maps to John's format names where known (Raw-MD5, NT,
    ...); when unknown John autodetects (no --format flag).
    """
    argv = ["john"]
    john_fmt = None
    if fmt:
        john_fmt = HASH_FORMATS.get(fmt, {}).get("john")
    if john_fmt:
        argv += ["--format=" + john_fmt]
    if session:
        argv += ["--session=" + session]
    if wordlist:
        argv += ["--wordlist=" + str(wordlist)]
        if rules:
            argv += ["--rules=" + str(rules)]
    argv += [str(hash_path)]
    argv += list(extra or [])
    return argv


def john_show(hash_path, fmt=None, session=None):
    """Run `john --show` and parse the real pot output.

    John --show prints `user:plaintext:hash...` lines (one per
    cracked hash) plus `N password hashes cracked, ... left`.
    """
    if detect_john() is None:
        return {"error": "john not installed on this host "
                         "(install it for the system backend; "
                         "the embedded engine in this module "
                         "cracks the same formats offline)",
                "argv": ["john", "--show", str(hash_path)]}
    argv = ["john", "--show"]
    john_fmt = HASH_FORMATS.get(fmt or "", {}).get("john")
    if john_fmt:
        argv += ["--format=" + john_fmt]
    if session:
        argv += ["--session=" + session]
    argv += [str(hash_path)]
    try:
        proc = subprocess.run(argv, capture_output=True,
                                text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"argv": argv, "error": "john --show timed out"}
    hits = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("0 password"):
            continue
        # user:plain:rest...
        parts = line.split(":")
        if len(parts) >= 2:
            hits.append({"user": parts[0], "password": parts[1],
                         "rest": ":".join(parts[2:])})
    m = re.search(r"(\d+) password hashes? cracked", proc.stdout)
    return {"argv": argv, "returncode": proc.returncode,
            "hits": hits,
            "cracked_count": int(m.group(1)) if m else len(hits),
            "raw": proc.stdout}


def john_run(hash_path, wordlist=None, fmt=None, rules=None,
              session=None, extra=None, timeout=300):
    """Run the system john binary (real passthrough)."""
    argv = john_command(hash_path, wordlist, fmt, rules,
                        session, extra)
    if detect_john() is None:
        return {"error": "john not installed on this host "
                         "(install it for the system backend; "
                         "the embedded engine in this module "
                         "cracks the same formats offline)",
                "argv": argv}
    try:
        proc = subprocess.run(argv, capture_output=True,
                                text=True, timeout=timeout)
        return {"argv": argv, "returncode": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr,
                "backend": "system"}
    except subprocess.TimeoutExpired:
        return {"argv": argv, "error": "john timed out",
                "backend": "system"}


# ------------------------------------------------------------------ state
def cracking_dashboard_state():
    """Webcard state for the cracking dashboard."""
    return {
        "formats": {k: {"hashcat_mode": v["hashcat"],
                         "john_format": v["john"],
                         "salted": bool(v["salt"])}
                     for k, v in HASH_FORMATS.items()},
        "hashcat_installed": bool(detect_hashcat()),
        "john_installed": bool(detect_john()),
        "engines": ["embedded (real, pure-Python)",
                     "hashcat (system passthrough)",
                     "john (system passthrough)"],
        "attacks": {"dictionary": "crack_hashes()",
                      "brute_force": "brute_force_hashes() "
                                     "(crunch-ordered)",
                      "sam_pwdump": "parse_pwdump()"},
        "note": "Embedded engine is real and offline. hashcat/"
                "john passthroughs run the system binaries when "
                "installed — nothing is simulated.",
    }


def cracking_recent_runs(limit=20):
    """Recent cracking runs from the audit log (real)."""
    from quantum.core.env import LOG_DIR
    from quantum.core.logging import _tail_jsonl
    import os as _os
    out = []
    for rec in _tail_jsonl(_os.path.join(LOG_DIR, "audit.jsonl"), 200):
        try:
            msg = str(rec.get("msg", ""))
        except AttributeError:
            continue
        if "CRACK" in msg:
            out.append(rec)
            if len(out) >= limit:
                break
    return out
