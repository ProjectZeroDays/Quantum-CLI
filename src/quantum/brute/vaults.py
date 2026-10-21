"""quantum.brute.vaults — vault & archive password recovery engine.

Real offline oracles for the encrypted-container formats
operators meet most often. Nothing is simulated: every
verdict comes from actual cryptography or from the real
system binary's exit code.

* VeraCrypt — PBKDF2-HMAC header-key derivation (SHA-512
  default, 500000 iterations non-system; legacy
  RIPEMD-160 655331; PIM support) and a pure-Python
  AES-XTS decrypt of the 448-byte encrypted header
  region (data unit 0), checked against the real
  volume invariants ("VERA" magic, header CRC32,
  key-area CRC32). The XTS GF(2^128) doubling and
  the little-endian unit-number serialization follow
  VeraCrypt's own Xts.c / EncryptionModeXTS.cpp
  source and are verified against the spec-compliant
  `cryptography` library in tests/test_vaults.py.
* TrueCrypt — identical header layout (magic "TRUE")
  with the TrueCrypt PRF-specific iteration counts
  (RIPEMD-160: 2000, SHA-512: 1000, Whirlpool: 1000,
  legacy SHA-1: 1000) tried in likelihood order.
* Cryptomator — scrypt KEK derivation + AES Key Wrap
  (RFC 3394) masterkey unwrap + versionMac HMAC-SHA256.
* ZIP  — pure Python via the zipfile stdlib (ZipCrypto).
* 7z   — real `7z t -p<pw>` passthrough when 7-Zip is
  installed.
* RAR  — real `unrar t -p<pw>` passthrough when unrar is
  installed.
* PDF  — real `qpdf --decrypt --password=<pw>` passthrough
  when qpdf is installed.

System-binary passthroughs (veracrypt/truecrypt CLI) run
when installed; the pure-Python oracles are always the
fallback and need no privileges. PRFs with no
implementation on this host (Whirlpool, Streebog —
neither hashlib nor pycryptodome provides them) are
reported honestly as unavailable and covered by the
CLI passthroughs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import zlib

from Crypto.Cipher import AES
from quantum.core.logging import log

# ------------------------------------------------------------------ XTS
class _PrfUnavailable (Exception):
    """Raised when a PBKDF2 PRF has no implementation on
    this host (e.g. Whirlpool without pycryptodome's
    Whirlpool module) — the caller skips it, never
    fakes a result."""


def _gf_double(tweak: bytes) -> bytes:
    """GF(2^128) doubling, exactly as VeraCrypt's Xts.c
    implements it (the TrueCrypt 7.1a code it derives
    from).

    The 16-byte tweak is a 128-bit little-endian
    integer (byte 0 = least significant byte, matching
    the `Endian::Little` uint64 serialization in
    EncryptionModeXTS::DecryptBufferXTS). Doubling is a
    left shift of that integer; a carry out of bit 127
    (the MSB of byte 15) reduces the result with the
    field polynomial x^128 + x^7 + x^2 + x + 1, i.e.
    XORs 135 (0x87) into byte 0 (the least significant
    byte). This matches the spec-compliant XTS in the
    `cryptography` library's modes.XTS (verified
    against it in tests/test_vaults.py).
    """
    n = int.from_bytes(tweak, "little")
    carry = (n >> 127) & 1
    n = (n << 1) & ((1 << 128) - 1)
    if carry:
        n ^= 0x87
    return n.to_bytes(16, "little")


def xts_decrypt_unit(data_key: bytes, tweak_key: bytes,
                     data: bytes, unit_no: int = 0) -> bytes:
    """Decrypt one XTS-AES data unit (pure Python).

    tweak_0 = AES-ECB(tweak_key, unit_no as a 16-byte
    little-endian value — the sector-number serialization
    VeraCrypt/TrueCrypt use); per 16-byte block:
    P = D_Kd(C ^ T) ^ T, then T = gf_double(T). Data
    must be a whole number of 16-byte blocks, which is
    always the case for the 448-byte encrypted
    volume-header region (ciphertext stealing is never
    needed there).
    """
    if len(data) % 16:
        raise ValueError("XTS data must be a multiple "
                         "of 16 bytes")
    tweak = AES.new(tweak_key, AES.MODE_ECB).encrypt(
        unit_no.to_bytes(16, "little"))
    dec = AES.new(data_key, AES.MODE_ECB)
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        x = bytes(a ^ b for a, b in zip(blk, tweak))
        d = dec.decrypt(x)
        out.extend(bytes(a ^ b for a, b in zip(d, tweak)))
        tweak = _gf_double(tweak)
    return bytes(out)


# ------------------------------------------------------------------ PBKDF2
def _pbkdf2(prf: str, password: bytes, salt: bytes,
            iterations: int, dklen: int) -> bytes:
    """RFC 2898 PBKDF2.

    hashlib.pbkdf2_hmac covers SHA-1/SHA-2 family,
    BLAKE2s and RIPEMD-160 where the platform
    OpenSSL exposes them. Whirlpool has no hashlib
    binding, so it falls back to an hmac-based
    PBKDF2 built on pycryptodome's implementation
    when that module is present. The first dklen
    bytes are identical either way (PBKDF2 is a
    prefix stream), so deriving 192 bytes and
    slicing 64 matches the real VeraCrypt/TrueCrypt
    key split exactly.

    Raises _PrfUnavailable when the PRF has no
    implementation on this host.
    """
    try:
        return hashlib.pbkdf2_hmac(prf, password, salt,
                                   iterations, dklen)
    except ValueError:
        pass
    if prf == "whirlpool":
        try:
            from Crypto.Hash import Whirlpool
        except ImportError:
            raise _PrfUnavailable(
                "whirlpool has no implementation on "
                "this host (hashlib and pycryptodome "
                "both lack it) — use the veracrypt/"
                "truecrypt CLI passthrough")
        digestmod = Whirlpool.new
    elif prf == "streebog":
        raise _PrfUnavailable(
            "streebog has no implementation on this "
            "host — use the veracrypt CLI passthrough")
    else:  # e.g. ripemd160 without the OpenSSL legacy
           # provider — hashlib.new still exposes it
        try:
            hashlib.new(prf)
        except ValueError:
            raise _PrfUnavailable(
                f"hash {prf!r} is not available on "
                "this host")
        digestmod = prf

    def _prf(key: bytes, msg: bytes) -> bytes:
        return hmac_mod.new(key, msg,
                            digestmod=digestmod).digest()

    hlen = len(_prf(b"", b""))
    blocks = -(-dklen // hlen)
    out = bytearray()
    for i in range(1, blocks + 1):
        u = _prf(password, salt + struct.pack(">I", i))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = _prf(password, bytes(u))
            for j in range(hlen):
                t[j] ^= u[j]
        out.extend(t)
    return bytes(out[:dklen])


# ------------------------------------------------------------------ VeraCrypt
VERACRYPT_MAGIC = b"VERA"
TRUECRYPT_MAGIC = b"TRUE"

#: VeraCrypt documented iteration counts (veracrypt.io —
#: "Header Key Derivation, Salt, and Iteration Count",
#: confirmed against the Pkcs5Kdf source):
#: non-system volumes and file containers use 500000 for
#: every PBKDF2-HMAC variant except the legacy RIPEMD-160
#: (655331); system encryption uses 200000 for
#: SHA-256/BLAKE2s-256/Streebog and 327661 for RIPEMD-160.
VC_DEFAULT_ITERATIONS = 500_000
VC_SYSTEM_FAST_ITERATIONS = 200_000
VC_RIPEMD160_ITERATIONS = 655_331
VC_RIPEMD160_SYSTEM_ITERATIONS = 327_661

#: PRFs accepted by the embedded oracle. Whirlpool and
#: Streebog have no implementation on this host (hashlib
#: and pycryptodome both lack them) — the oracle reports
#: them as unavailable and the veracrypt CLI passthrough
#: covers those volumes.
VC_PRFs = ("sha512", "sha256", "blake2s", "ripemd160",
           "whirlpool", "streebog")


def veracrypt_iterations(prf="sha512", pim=None,
                         system=False) -> int:
    """VeraCrypt PBKDF2 iteration count for a PRF/PIM.

    PIM unset/0 -> documented defaults: 500000 for
    SHA-512/SHA-256/BLAKE2s/Whirlpool/Streebog
    (non-system and SHA-512/Whirlpool system),
    655331 for legacy RIPEMD-160, 200000 for the
    fast-PRF system-encryption variants
    (SHA-256/BLAKE2s/Streebog), 327661 for the
    RIPEMD-160 system variant.
    PIM set     -> 15000 + PIM x 1000 (all
    non-system PRFs and SHA-512/Whirlpool system);
    PIM x 2048 (fast-PRF system and RIPEMD-160
    system variants).
    """
    pim = int(pim or 0)
    if pim <= 0:
        if prf == "ripemd160":
            return (VC_RIPEMD160_SYSTEM_ITERATIONS
                    if system
                    else VC_RIPEMD160_ITERATIONS)
        if system and prf in ("sha256", "blake2s",
                              "streebog"):
            return VC_SYSTEM_FAST_ITERATIONS
        return VC_DEFAULT_ITERATIONS
    if prf == "ripemd160":
        # RIPEMD-160 system (boot) variant: PIM x 2048;
        # non-system legacy: 15000 + PIM x 1000
        return pim * 2048 if system else 15_000 + pim * 1000
    if system and prf in ("sha256", "blake2s",
                          "streebog"):
        return pim * 2048
    return 15_000 + pim * 1000


def veracrypt_header_password_check(header, password,
                                    prf="sha512",
                                    pim=None) -> dict:
    """Real offline VeraCrypt password oracle.

    Derives the header key exactly as VeraCrypt does —
    PBKDF2-HMAC-<prf> over the 512-bit salt
    (header[0:64]) to 192 bytes (VeraCrypt's
    GetLargestSerializedKeySize), of which AES-256-XTS
    uses the first 64 (32-byte data key + 32-byte tweak
    key) — then XTS-decrypts the 448-byte encrypted
    header region (header[64:512], data unit 0) and
    checks the real volume invariants (VolumeHeader::
    Deserialize):

      * magic "VERA" at decrypted[0:4]
      * header CRC32: decrypted[188:192] ==
        crc32(decrypted[0:188])  (format version >= 4)
      * key-area CRC32: decrypted[8:12] ==
        crc32(decrypted[192:448])

    header:  512-byte volume header (>= 512 accepted,
             first 512 used — for a hidden volume pass
             the header block at its offset).
    password: str/bytes. Must be the *final* password
             bytes — VeraCrypt keyfile material has to be
             mixed in by the caller before use.
    prf:     sha512 (default), sha256, blake2s,
             ripemd160 (legacy), whirlpool, streebog.
             Whirlpool/Streebog have no implementation
             on this host and return an honest
             "unavailable" result — use
             veracrypt_test_password for those.
    """
    header = bytes(header)
    if len(header) < 512:
        return {"ok": False,
                "error": "header too short (need 512 "
                         "bytes)"}
    password = (password.encode("utf-8")
                if isinstance(password, str)
                else bytes(password))
    salt = header[:64]
    encrypted = header[64:512]
    iterations = veracrypt_iterations(prf, pim)
    try:
        dk = _pbkdf2(prf, password, salt, iterations,
                     192)
    except _PrfUnavailable as exc:
        return {"ok": False, "prf": prf,
                "error": str(exc),
                "backend": "embedded (pure-Python "
                           "PBKDF2 + XTS)"}
    dec = xts_decrypt_unit(dk[:32], dk[32:64], encrypted)
    checks = {
        "magic": dec[:4] == VERACRYPT_MAGIC,
        "header_crc": int.from_bytes(dec[188:192],
                                     "big")
        == (zlib.crc32(dec[:188]) & 0xFFFFFFFF),
        "key_area_crc": int.from_bytes(dec[8:12],
                                       "big")
        == (zlib.crc32(dec[192:448]) & 0xFFFFFFFF),
    }
    ok = all(checks.values())
    out = {
        "ok": ok,
        "checks": checks,
        "prf": prf,
        "pim": int(pim or 0),
        "iterations": iterations,
        "version": int.from_bytes(dec[4:6], "big"),
        "required_version": int.from_bytes(dec[6:8],
                                           "big"),
        "sector_size": int.from_bytes(dec[64:68], "big"),
        "backend": "embedded (pure-Python PBKDF2 + XTS)",
    }
    if not ok:
        # Never return ok=False without saying why — the caller needs to
        # tell "wrong password" apart from "not a VeraCrypt header".
        failed = [k for k, v in checks.items() if not v]
        if "magic" in failed:
            out["error"] = ("header is not a VeraCrypt volume (magic "
                            "mismatch) — wrong volume or wrong header "
                            "block offset")
        else:
            out["error"] = ("password check failed: " + ", ".join(failed)
                            + " did not validate")
    return out


# ------------------------------------------------------------------ TrueCrypt
#: TrueCrypt 7.1a PBKDF2 iteration counts by PRF
#: (RIPEMD-160: 2000; SHA-512/Whirlpool: 1000; the
#: legacy HMAC-SHA-1 PRF of TrueCrypt 3.x volumes:
#: 1000 — TrueCrypt 7.1a still mounts those).
TC_PRF_ITERATIONS = {"ripemd160": 2000, "sha512": 1000,
                     "whirlpool": 1000, "sha1": 1000}

#: PRFs tried when none is given — most common
#: first (TrueCrypt's default RIPEMD-160, then
#: SHA-512, Whirlpool, and the legacy SHA-1 of
#: TrueCrypt 3.x volumes). PRFs without an
#: implementation on this host are skipped.
TC_PRF_ORDER = ("ripemd160", "sha512", "whirlpool",
                "sha1")


def truecrypt_iterations(prf: str) -> int:
    return TC_PRF_ITERATIONS[prf]


def truecrypt_header_password_check(header, password,
                                    prf=None) -> dict:
    """Real offline TrueCrypt 7.1a password oracle.

    Identical 512-byte header layout to VeraCrypt, but the
    magic is "TRUE" and the iteration count is PRF-specific
    (see TC_PRF_ITERATIONS). When prf is None every PRF is
    tried in TrueCrypt's probe order until the header CRC
    validates. The derived material is 192 bytes with the
    first 64 used for AES-256-XTS — identical to deriving
    64 directly (PBKDF2 is a prefix stream).
    """
    header = bytes(header)
    if len(header) < 512:
        return {"ok": False,
                "error": "header too short (need 512 "
                         "bytes)"}
    if prf is None:
        last = None
        for name in TC_PRF_ORDER:
            try:
                res = truecrypt_header_password_check(
                    header, password, name)
            except _PrfUnavailable:
                continue
            if res.get("ok"):
                return res
            last = res
        return {"ok": False, "tried": list(TC_PRF_ORDER),
                "last_check": last,
                "backend": "embedded (pure-Python "
                           "PBKDF2 + XTS)"}
    if prf not in TC_PRF_ITERATIONS:
        return {"ok": False, "prf": prf,
                "error": "unsupported TrueCrypt PRF "
                         f"{prf!r}"}
    password = (password.encode("utf-8")
                if isinstance(password, str)
                else bytes(password))
    salt = header[:64]
    encrypted = header[64:512]
    iterations = TC_PRF_ITERATIONS[prf]
    try:
        dk = _pbkdf2(prf, password, salt, iterations,
                     192)
    except _PrfUnavailable as exc:
        return {"ok": False, "prf": prf,
                "error": str(exc),
                "backend": "embedded (pure-Python "
                           "PBKDF2 + XTS)"}
    dec = xts_decrypt_unit(dk[:32], dk[32:64], encrypted)
    checks = {
        "magic": dec[:4] == TRUECRYPT_MAGIC,
        "header_crc": int.from_bytes(dec[188:192],
                                     "big")
        == (zlib.crc32(dec[:188]) & 0xFFFFFFFF),
        "key_area_crc": int.from_bytes(dec[8:12],
                                       "big")
        == (zlib.crc32(dec[192:448]) & 0xFFFFFFFF),
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "prf": prf,
        "iterations": iterations,
        "version": int.from_bytes(dec[4:6], "big"),
        "required_version": int.from_bytes(dec[6:8],
                                           "big"),
        "sector_size": int.from_bytes(dec[64:68], "big"),
        "backend": "embedded (pure-Python PBKDF2 + XTS)",
    }


# ------------------------------------------------------------------ Cryptomator
def cryptomator_masterkey_check(masterkey, password) -> dict:
    """Real Cryptomator masterkey password oracle.

    masterkey: path to a masterkey.cryptomator file, a
    JSON string, or an already-parsed dict.

    The Cryptomator key-unwrapping chain (docs.cryptomator
    .org — Security Architecture):
      kek    = scrypt(password, scryptSalt, N =
               scryptCostParam, r = scryptBlockSize, p=1,
               dklen=32)
      primary/hmac masterkeys = AES Key Wrap (RFC 3394)
               unwrap with the KEK
      versionMac = HMAC-SHA256(hmacMasterKey, vault
               version as a 4-byte big-endian uint32)

    A candidate is correct only when both AES-KW unwraps
    succeed (RFC 3394 integrity check) and the versionMac
    matches — a wrong password cannot pass all three.
    """
    if isinstance(masterkey, dict):
        mk = masterkey
    elif isinstance(masterkey, (bytes, bytearray)):
        mk = json.loads(bytes(masterkey).decode("utf-8"))
    else:
        text = str(masterkey)
        if os.path.isfile(text):
            with open(text, encoding="utf-8") as fh:
                mk = json.load(fh)
        else:
            mk = json.loads(text)
    password = (password.encode("utf-8")
                if isinstance(password, str)
                else bytes(password))
    version = int(mk.get("version", 0))
    salt = base64.b64decode(mk["scryptSalt"])
    n = int(mk["scryptCostParam"])
    r = int(mk["scryptBlockSize"])
    # memory need ~128*N*r; keep hashlib.scrypt under its
    # maxmem cap for every documented cost parameter
    kek = hashlib.scrypt(password, salt=salt, n=n, r=r,
                         p=1, dklen=32,
                         maxmem=max(128 * n * r * 2,
                                    64 << 20))
    try:
        # RFC 3394 AES Key Wrap (pycryptodome
        # MODE_KW: seal() wraps, unseal() unwraps
        # and raises ValueError when the integrity
        # check fails)
        primary = AES.new(kek, AES.MODE_KW).unseal(
            base64.b64decode(mk["primaryMasterKey"]))
        mac_key = AES.new(kek, AES.MODE_KW).unseal(
            base64.b64decode(mk["hmacMasterKey"]))
    except ValueError:
        return {"ok": False, "version": version,
                "error": "AES-KW integrity check failed "
                         "(wrong password or corrupt "
                         "masterkey)",
                "backend": "embedded (pure-Python scrypt "
                           "+ AES-KW)"}
    expected = hmac_mod.new(mac_key,
                            struct.pack(">I", version),
                            hashlib.sha256).digest()
    ok = expected == base64.b64decode(mk["versionMac"])
    return {
        "ok": ok,
        "version": version,
        "scrypt": {"N": n, "r": r, "p": 1},
        "primary_master_key": primary.hex() if ok else None,
        "hmac_master_key": mac_key.hex() if ok else None,
        "backend": "embedded (pure-Python scrypt + AES-KW)",
    }


# ------------------------------------------------------------------ archives
def zip_password_check(path, password) -> dict:
    """Real ZIP password test via the zipfile stdlib.

    Reads every encrypted member end-to-end with the
    candidate password (the member CRC is verified after
    each full read, so a wrong password cannot pass).
    stdlib zipfile implements ZipCrypto only — AES-
    encrypted zip entries cannot be tested here; use the
    7z passthrough for those.
    """
    import zipfile
    try:
        with zipfile.ZipFile(path) as zf:
            encrypted = [zi for zi in zf.infolist()
                         if zi.flag_bits & 0x1]
            if not encrypted:
                return {"ok": None, "file": str(path),
                        "error": "no encrypted members "
                                 "in archive"}
            pwd = (password.encode("utf-8")
                   if isinstance(password, str)
                   else bytes(password))
            try:
                for zi in encrypted:
                    with zf.open(zi, pwd=pwd) as fh:
                        while fh.read(1 << 16):
                            pass
            except RuntimeError as exc:
                return {"ok": False, "file": str(path),
                        "members": len(encrypted),
                        "error": str(exc),
                        "backend": "embedded (zipfile "
                                   "stdlib, ZipCrypto)"}
            return {"ok": True, "file": str(path),
                    "members": len(encrypted),
                    "backend": "embedded (zipfile stdlib, "
                               "ZipCrypto)"}
    except (zipfile.BadZipFile, OSError) as exc:
        return {"ok": False, "file": str(path),
                "error": f"not a readable zip archive: "
                         f"{exc}"}


def detect_7z():
    """Path to the system 7-Zip binary, or None."""
    for name in ("7z", "7z.exe", "7za", "7za.exe",
                 "7zr", "7zr.exe"):
        hit = shutil.which(name)
        if hit:
            return hit
    return None


def sevenz_test_password(path, password,
                         timeout=180) -> dict:
    """Real 7z archive password test (`7z t -p<pw>`).

    7-Zip exit codes: 0 = archive verified with the
    password, 2 = fatal error (a wrong password prints
    "Wrong password"). Raw output is returned so the
    operator sees the binary's own verdict.
    """
    binary = detect_7z()
    if binary is None:
        return {"ok": None, "file": str(path),
                "error": "7z not installed on this host "
                         "(install 7-Zip for the system "
                         "backend)"}
    argv = [binary, "t", f"-p{password}", "--",
            str(path)]
    try:
        proc = subprocess.run(argv, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"argv": argv, "ok": False,
                "error": "7z timed out", "backend":
                "system (7z)"}
    out = (proc.stdout or "") + (proc.stderr or "")
    wrong_pw = ("wrong password" in out.lower()
                or "incorrect password" in out.lower())
    return {"argv": argv, "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "wrong_password": wrong_pw,
            "output": out.strip(),
            "backend": "system (7z)"}


def detect_unrar():
    """Path to the system unrar binary, or None."""
    return (shutil.which("unrar")
            or shutil.which("unrar.exe"))


def unrar_test_password(path, password,
                        timeout=180) -> dict:
    """Real RAR archive password test (`unrar t -p<pw>`).

    unrar exits 0 only when the archive tests clean with
    the password; a wrong password prints
    "incorrect password" and fails. Raw output is
    returned so the operator sees the binary's verdict.
    """
    binary = detect_unrar()
    if binary is None:
        return {"ok": None, "file": str(path),
                "error": "unrar not installed on this "
                         "host (install unrar for the "
                         "system backend)"}
    argv = [binary, "t", f"-p{password}", "--",
            str(path)]
    try:
        proc = subprocess.run(argv, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"argv": argv, "ok": False,
                "error": "unrar timed out",
                "backend": "system (unrar)"}
    out = (proc.stdout or "") + (proc.stderr or "")
    wrong_pw = "password" in out.lower() and (
        proc.returncode != 0)
    return {"argv": argv, "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "wrong_password": wrong_pw,
            "output": out.strip(),
            "backend": "system (unrar)"}


def detect_qpdf():
    """Path to the system qpdf binary, or None."""
    return shutil.which("qpdf") or shutil.which("qpdf.exe")


def qpdf_test_password(path, password,
                       timeout=180) -> dict:
    """Real PDF password test (`qpdf --decrypt`).

    Decrypts the PDF with the candidate password into a
    temporary file; qpdf exits non-zero (status 3 is its
    documented password error) when the password is
    wrong. The temporary output is removed afterwards.
    """
    binary = detect_qpdf()
    if binary is None:
        return {"ok": None, "file": str(path),
                "error": "qpdf not installed on this "
                         "host (install qpdf for the "
                         "system backend)"}
    tmp = tempfile.NamedTemporaryFile(
        suffix=".pdf", delete=False)
    tmp.close()
    argv = [binary, f"--password={password}",
            "--decrypt", str(path), tmp.name]
    try:
        proc = subprocess.run(argv, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.unlink(tmp.name)
        return {"argv": argv, "ok": False,
                "error": "qpdf timed out",
                "backend": "system (qpdf)"}
    finally:
        if os.path.isfile(tmp.name):
            os.unlink(tmp.name)
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"argv": argv, "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "output": out.strip(),
            "backend": "system (qpdf)"}


def archive_password_check(path, password,
                           timeout=180) -> dict:
    """Password test for ZIP/7z/RAR/PDF by extension.

    ZIP is handled by the embedded stdlib engine; 7z,
    RAR and PDF by their real system binaries (honest
    "not installed" result when the binary is absent).
    Unknown extensions fall back to the zip engine, then
    to 7z when available.
    """
    path = str(path)
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext == "zip":
        return zip_password_check(path, password)
    if ext == "7z":
        return sevenz_test_password(path, password,
                                    timeout)
    if ext == "rar":
        return unrar_test_password(path, password,
                                   timeout)
    if ext == "pdf":
        return qpdf_test_password(path, password,
                                  timeout)
    res = zip_password_check(path, password)
    if res.get("error") and detect_7z():
        seven = sevenz_test_password(path, password,
                                     timeout)
        if seven.get("ok") is not None:
            return seven
    return res


# ------------------------------------------------------------------ system CLI
def detect_veracrypt():
    """Path to the system VeraCrypt binary, or None."""
    return (shutil.which("veracrypt")
            or shutil.which("veracrypt.exe"))


def veracrypt_cli_command(volume, password=None,
                          pim=None, prf="sha512") -> list:
    """Real VeraCrypt CLI password-test command line.

    VeraCrypt's --test switch only exercises its internal
    algorithms — it does not test volume passwords — so
    the CLI path performs a real non-interactive mount
    with --filesystem=none (the volume's virtual device
    is created but no filesystem is mounted; this still
    needs a privileged mount context on the host) and
    interprets the exit code: 0 = password accepted,
    anything else = password rejected. The password is
    fed on stdin (--stdin + --non-interactive) so it
    never appears in process listings — the method
    VeraCrypt documents for exactly this purpose.
    Unix syntax (see VeraCrypt "Command Line Usage for
    Linux and macOS").
    """
    argv = ["veracrypt", "-t", "--non-interactive",
            "--stdin", "--hash=" + prf,
            "--pim=" + str(int(pim or 0)),
            "--protect-hidden=no", "--filesystem=none",
            str(volume)]
    return argv


def veracrypt_test_password(volume, password, pim=None,
                            prf="sha512",
                            timeout=180) -> dict:
    """VeraCrypt password test: CLI mount when the binary
    is installed, embedded header oracle otherwise.

    Both paths apply the same crypto — the CLI path
    delegates to VeraCrypt itself (required for Streebog
    PRF and Argon2id volumes, which the embedded oracle
    does not implement), the embedded path derives and
    verifies the header offline with no privileges.
    """
    binary = detect_veracrypt()
    if binary is None:
        with open(volume, "rb") as fh:
            header = fh.read(512)
        res = veracrypt_header_password_check(
            header, password, prf, pim)
        res["backend"] = ("embedded (pure-Python "
                          "PBKDF2 + XTS; veracrypt CLI "
                          "not installed)")
        return res
    argv = veracrypt_cli_command(volume, pim=pim,
                                 prf=prf)
    try:
        proc = subprocess.run(
            argv,
            input=(password + "\n").encode("utf-8"),
            capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"argv": argv, "ok": False,
                "error": "veracrypt mount timed out",
                "backend": "system (veracrypt CLI)"}
    if proc.returncode == 0:
        # dismount what we just mounted
        subprocess.run(
            ["veracrypt", "-t", "--non-interactive",
             "-u", "--", str(volume)],
            capture_output=True, timeout=60)
    out = (proc.stdout or b"").decode("utf-8",
                                      "replace")
    err = (proc.stderr or b"").decode("utf-8",
                                      "replace")
    return {"argv": argv, "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": out, "stderr": err,
            "backend": "system (veracrypt CLI)"}


def detect_truecrypt():
    """Path to the system TrueCrypt binary, or None."""
    return (shutil.which("truecrypt")
            or shutil.which("truecrypt.exe"))


def truecrypt_test_password(volume, password,
                            timeout=180) -> dict:
    """TrueCrypt password test: CLI --test when the
    binary is installed, embedded header oracle
    otherwise.

    TrueCrypt 7.1a's CLI documents `--test` as "Tests
    the volume password and exits" — a genuinely
    headless password check. The embedded oracle applies
    the same derivation offline when the binary is
    absent.
    """
    binary = detect_truecrypt()
    if binary is None:
        with open(volume, "rb") as fh:
            header = fh.read(512)
        res = truecrypt_header_password_check(
            header, password)
        res["backend"] = ("embedded (pure-Python "
                          "PBKDF2 + XTS; truecrypt CLI "
                          "not installed)")
        return res
    argv = ["truecrypt", "-t", "--test",
            "--password=" + password, str(volume)]
    try:
        proc = subprocess.run(argv, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"argv": argv, "ok": False,
                "error": "truecrypt --test timed out",
                "backend": "system (truecrypt CLI)"}
    return {"argv": argv, "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "backend": "system (truecrypt CLI)"}


# ------------------------------------------------------------------ wordlists
def _words(wordlist):
    """Wordlist path or iterable -> lazy iterator of words."""
    if isinstance(wordlist, (str, bytes)) and os.path.isfile(
            str(wordlist)):
        def gen():
            with open(str(wordlist), encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    yield line.rstrip("\r\n")
        return gen()
    if isinstance(wordlist, (str, bytes)):
        return iter(str(wordlist).splitlines())
    return iter(wordlist)


def _resolve_target(target, kind):
    """Normalize a vault/archive target for the engine.

    bytes        -> 512-byte volume header
    dict/JSON    -> Cryptomator masterkey
    path         -> volume file (header read) when kind
                    names a disk-encryption format,
                    archive file otherwise
    """
    if isinstance(target, (bytes, bytearray,
                           memoryview)):
        return "header", bytes(target)
    if isinstance(target, dict):
        return "cryptomator", target
    if isinstance(target, (str, os.PathLike)):
        text = str(target)
        if text.lstrip().startswith("{"):
            return "cryptomator", json.loads(text)
        if kind in ("veracrypt", "truecrypt"):
            with open(text, "rb") as fh:
                return "header", fh.read(512)
        if os.path.isfile(text):
            return "archive", text
        raise FileNotFoundError(f"no such file: {text}")
    raise TypeError("target must be a 512-byte header, "
                    "a Cryptomator masterkey, or a file "
                    "path")


def vault_brute_force(target, wordlist, kind="auto",
                      prf="sha512", pim=None,
                      stop_on_hit=True, progress=None):
    """Real wordlist attack on any supported vault target.

    kind: "auto" | "veracrypt" | "truecrypt" |
          "cryptomator" | "archive".

    Auto header targets try the VeraCrypt oracle
    (SHA-512, 500000 iterations) and then every
    TrueCrypt PRF in probe order — the magic is inside
    the encrypted header, so the format cannot be
    detected before the derivation. Every candidate is
    verified by real cryptography; a hit is only
    reported when the volume invariants (magic + both
    CRC32s, or the Cryptomator versionMac) hold.
    """
    target_kind, payload = _resolve_target(target, kind)
    hits = []
    tried = 0
    start = time.time()

    def _attempt(candidate):
        if target_kind == "header":
            if kind in ("veracrypt", "auto"):
                res = veracrypt_header_password_check(
                    payload, candidate, prf, pim)
                if res["ok"]:
                    return "veracrypt", res
            if kind in ("truecrypt", "auto"):
                res = truecrypt_header_password_check(
                    payload, candidate)
                if res["ok"]:
                    return "truecrypt", res
        elif target_kind == "cryptomator":
            if kind in ("cryptomator", "auto"):
                res = cryptomator_masterkey_check(
                    payload, candidate)
                if res["ok"]:
                    return "cryptomator", res
        elif target_kind == "archive":
            res = archive_password_check(payload,
                                       candidate)
            if res.get("ok"):
                return "archive", res
        return None, None

    for candidate in _words(wordlist):
        tried += 1
        fmt, res = _attempt(candidate)
        if fmt:
            hits.append({"format": fmt,
                         "password": candidate,
                         "details": res})
            if stop_on_hit:
                break
        if progress and tried % 100 == 0:
            progress(tried, len(hits))
    if hits:
        log(f"VAULT crack hit {target_kind}: "
            f"{hits[0]['format']} / "
            f"{hits[0]['password']}", "VAULT")
    return {"hits": hits, "tried": tried,
            "elapsed_s": round(time.time() - start, 3),
            "kind": kind, "target_kind": target_kind,
            "backend": "embedded"}


# ------------------------------------------------------------------ state
def vaults_dashboard_state():
    """Webcard state for the cracking dashboard."""
    return {
        "engines": {
            "veracrypt": "embedded pure-Python oracle "
                         "(PBKDF2-HMAC + AES-XTS)",
            "truecrypt": "embedded pure-Python oracle "
                         "(PBKDF2-HMAC + AES-XTS)",
            "cryptomator": "embedded pure-Python oracle "
                           "(scrypt + AES-KW + HMAC)",
            "zip": "embedded stdlib engine (ZipCrypto)",
            "7z": "system 7z passthrough",
            "rar": "system unrar passthrough",
            "pdf": "system qpdf passthrough",
        },
        "tools": {
            "veracrypt": bool(detect_veracrypt()),
            "truecrypt": bool(detect_truecrypt()),
            "7z": bool(detect_7z()),
            "unrar": bool(detect_unrar()),
            "qpdf": bool(detect_qpdf()),
        },
        "veracrypt": {
            "magic": "VERA", "prfs": list(VC_PRFs),
            "default_iterations": {
                "sha512/sha256/blake2s/whirlpool/"
                "streebog": VC_DEFAULT_ITERATIONS,
                "ripemd160 (legacy)": VC_RIPEMD160_ITERATIONS,
                "system fast prfs (sha256/blake2s/"
                "streebog)": VC_SYSTEM_FAST_ITERATIONS,
                "system ripemd160": VC_RIPEMD160_SYSTEM_ITERATIONS,
            },
            "pim_formulas": {
                "default": "500000 (655331 legacy "
                           "RIPEMD-160)",
                "pim_set": "15000 + PIM x 1000 "
                           "(all non-system PRFs)",
                "pim_system_fast": "PIM x 2048 "
                                   "(SHA-256/BLAKE2s/"
                                   "Streebog system, "
                                   "RIPEMD-160 system)",
            },
            "unsupported_embedded": ["whirlpool",
                                     "streebog",
                                     "argon2id"],
        },
        "truecrypt": {
            "magic": "TRUE", "prfs": list(TC_PRF_ORDER),
            "iterations": dict(TC_PRF_ITERATIONS),
        },
        "cryptomator": {
            "kdf": "scrypt (p=1, dklen=32)",
            "wrap": "AES Key Wrap (RFC 3394)",
            "mac": "HMAC-SHA256(version, 4-byte BE)",
        },
        "note": "Embedded oracles are real and offline. "
                "System passthroughs run the installed "
                "binaries — nothing is simulated.",
    }


def vault_recent_runs(limit=20):
    """Recent vault-cracking runs from the audit log."""
    from quantum.core.env import LOG_DIR
    from quantum.core.logging import _tail_jsonl
    out = []
    for rec in _tail_jsonl(os.path.join(LOG_DIR,
                                        "audit.jsonl"),
                           200):
        try:
            msg = str(rec.get("msg", ""))
        except AttributeError:
            continue
        if "VAULT" in msg:
            out.append(rec)
            if len(out) >= limit:
                break
    return out
