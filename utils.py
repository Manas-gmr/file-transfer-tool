"""Shared helpers for the file-transfer tool (WarpSend v1.1).

Two checksum levels:
  * per-chunk CRC32  -- fast, catches a corrupt UDP packet at once
  * whole-file SHA-256 -- strong proof the received file is identical

v1.1 additions (from comparing WarpSend with Riptide):
  * `.part` + rename-only-on-match: a received file is written to
    `<name>.part` and renamed to its final name only after the
    SHA-256 matches, so a partial/corrupt file never masquerades
    as a finished one. A `.part.json` sidecar records filename,
    size and checksum, which is what makes TCP resume possible.
  * never overwrite: if the final name already exists, the new
    file is saved as `name (1).ext`, `name (2).ext`, ...
  * shared-key auth: an HMAC-SHA256 over the header, so a server
    that was started with `--key` rejects senders that do not
    know the secret.
  * optional TLS: stdlib `ssl` only; `warpsend cert` generates a
    self-signed cert with the `openssl` binary, and the client
    can pin the server's SHA-256 fingerprint with `--fingerprint`.

Only the standard library is used, so the tool runs with plain
``python3`` -- no pip install needed.
"""

import hashlib
import hmac as hmac_mod
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time
import zlib

VERSION = "1.1.0"

# WarpSend ASCII logo -- printed by the CLI on every run.
BANNER = r"""
██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗███████╗███╗   ██╗██████╗
██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗
██║ █╗ ██║███████║██████╔╝██████╔╝███████╗█████╗  ██╔██╗ ██║██║  ██║
██║███╗██║██╔══██║██╔══██╗██╔═══╝ ╚════██║██╔══╝  ██║╚██╗██║██║  ██║
╚███╔███╔╝██║  ██║██║  ██║██║     ███████║███████╗██║ ╚████║██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝
"""

TAGLINE = "TCP for trust  ·  UDP for speed  ·  SHA-256 verified"


def print_banner():
    """Print the WarpSend logo + tagline (colour when on a terminal)."""
    if sys.stdout.isatty():
        cyan = "\033[96m"
        dim = "\033[90m"
        reset = "\033[0m"
        print(f"{cyan}{BANNER}{reset}")
        print(f"{dim}  {TAGLINE}  ·  v{VERSION}{reset}\n")
    else:
        print(BANNER)
        print(f"  {TAGLINE}  ·  v{VERSION}\n")


CHUNK_TCP = 64 * 1024      # 64 KB chunks for TCP
CHUNK_UDP = 1024           # 1024 bytes of data per UDP packet
# (keeps each datagram well under the ~1400-byte practical limit,
#  so it is not fragmented on the network)


def sha256_of_file(path):
    """SHA-256 hex digest of a whole file, read in 64 KB pieces."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(64 * 1024):
            h.update(chunk)
    return h.hexdigest()


def crc32_of(data: bytes) -> int:
    """CRC32 of one chunk (unsigned 32-bit int)."""
    return zlib.crc32(data) & 0xFFFFFFFF


# --- progress bar with speed + ETA ---------------------------------------

_PROGRESS_START = {}


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def progress(done: int, total: int, label: str = "") -> None:
    """One-line progress bar: [####------] 42% 1.2 MB / 3.0 MB  2.1 MB/s ETA 1s."""
    if total <= 0:
        return
    now = time.monotonic()
    if done <= 0 or label not in _PROGRESS_START:
        _PROGRESS_START[label] = now
    start = _PROGRESS_START[label]
    elapsed = max(now - start, 1e-6)
    rate = done / elapsed if elapsed > 0.05 else 0
    eta = (total - done) / rate if rate > 0 else 0
    pct = done * 100 // total
    bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
    speed = f"  {_fmt_bytes(rate)}/s" if rate else ""
    eta_s = f"  ETA {eta:.0f}s" if rate and done < total else ""
    print(f"\r{label} [{bar}] {pct:3d}%  {_fmt_bytes(done)} / {_fmt_bytes(total)}"
          f"{speed}{eta_s}", end="", flush=True)
    if done >= total:
        print()  # finish the line
        _PROGRESS_START.pop(label, None)


# --- length-prefixed JSON header (TCP) -------------------------------------
# A header is sent as:  4-byte big-endian length  +  JSON bytes.
# The length prefix tells the receiver exactly where the header
# ends and the file data begins.
#
# Header contents: {"filename": ..., "filesize": ..., "checksum": ...,
#                   "auth": ...}   # auth is present only with --key
#   checksum = SHA-256 of the whole file, computed by the sender.

def send_header(sock, filename: str, filesize: int, checksum: str,
                auth: str | None = None) -> None:
    payload_dict = {
        "filename": filename,
        "filesize": filesize,
        "checksum": checksum,
    }
    if auth:
        payload_dict["auth"] = auth
    payload = json.dumps(payload_dict).encode()
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes (recv() may return fewer)."""
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("connection closed while reading header")
        buf += part
    return buf


def recv_header(sock) -> dict:
    raw_len = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", raw_len)
    return json.loads(_recv_exact(sock, length))


def recv_line(sock, timeout: float = 2.0):
    """Read one \\n-terminated line from a TCP socket.

    Returns the line without the newline, or None on timeout /
    closed connection. Used for the server's short reply after
    the header (FRESH / RESUME <offset> / AUTH_FAIL). A timeout
    means the other side is a pre-v1.1 WarpSend that never sends
    a reply -- the caller should then assume a fresh transfer.
    """
    sock.settimeout(timeout)
    buf = b""
    try:
        while not buf.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 64:
                return None
    except (socket.timeout, TimeoutError):
        return None
    finally:
        sock.settimeout(None)
    return buf.decode(errors="replace").strip()


# --- shared-key auth (HMAC over the header) -------------------------------

def header_auth(key: str, filename: str, filesize: int, checksum: str) -> str:
    """HMAC-SHA256 of the header fields under the shared secret."""
    msg = f"{filename}\n{filesize}\n{checksum}".encode()
    return hmac_mod.new(key.encode(), msg, hashlib.sha256).hexdigest()


def auth_ok(key: str | None, header: dict) -> bool:
    """True if the header's auth matches the server's key.

    A server with no key accepts anything (backwards compatible).
    A server with a key rejects a missing or wrong auth tag.
    """
    if not key:
        return True
    return bool(header.get("auth")) and hmac_mod.compare_digest(
        header["auth"], header_auth(key, header["filename"],
                                    header["filesize"], header["checksum"]))


# --- .part files, resume metadata, never-overwrite ------------------------

def part_path(outdir: str, name: str) -> str:
    return os.path.join(outdir, name + ".part")


def meta_path(outdir: str, name: str) -> str:
    return part_path(outdir, name) + ".json"


def save_meta(outdir: str, name: str, filesize: int, checksum: str) -> None:
    with open(meta_path(outdir, name), "w") as f:
        json.dump({"filename": name, "filesize": filesize,
                   "checksum": checksum}, f)


def load_meta(outdir: str, name: str):
    """Return the resume metadata for a .part file, or None."""
    try:
        with open(meta_path(outdir, name)) as f:
            meta = json.load(f)
        if (meta.get("filename") == name
                and isinstance(meta.get("filesize"), int)
                and meta.get("checksum")):
            return meta
    except (OSError, ValueError):
        pass
    return None


def resume_offset(outdir: str, name: str, filesize: int, checksum: str) -> int:
    """Bytes already on disk for this exact file, or 0.

    Only counts when the .part file and its metadata match the
    incoming file (same name, size and SHA-256). Anything else
    is a stale partial from a different file and is not resumed.
    """
    meta = load_meta(outdir, name)
    if not meta or meta["filesize"] != filesize or meta["checksum"] != checksum:
        return 0
    path = part_path(outdir, name)
    if not os.path.isfile(path):
        return 0
    size = os.path.getsize(path)
    return size if 0 < size < filesize else 0


def unique_path(outdir: str, name: str) -> str:
    """A final path that never overwrites an existing file.

    `report.pdf` -> `report (1).pdf` -> `report (2).pdf` ...
    """
    path = os.path.join(outdir, name)
    if not os.path.exists(path):
        return path
    stem, dot, ext = name.rpartition(".")
    if not dot:  # no extension
        stem, ext = name, ""
    else:
        ext = "." + ext
    i = 1
    while True:
        candidate = os.path.join(outdir, f"{stem} ({i}){ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1


def discard_part(outdir: str, name: str) -> None:
    for p in (part_path(outdir, name), meta_path(outdir, name)):
        try:
            os.remove(p)
        except OSError:
            pass


# --- TLS: self-signed certs, fingerprints (stdlib ssl + openssl) ----------

def default_cert_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".warpsend")


def default_cert_path() -> str:
    return os.path.join(default_cert_dir(), "cert.pem")


def default_key_path() -> str:
    return os.path.join(default_cert_dir(), "key.pem")


def fingerprint_of_der(der: bytes) -> str:
    """SHA-256 fingerprint of a certificate, hex, no separators."""
    return hashlib.sha256(der).hexdigest()


def fingerprint_of_cert_file(cert_path: str) -> str:
    with open(cert_path, "rb") as f:
        pem = f.read()
    return fingerprint_of_der(ssl.PEM_cert_to_DER_cert(pem.decode()))


def short_code(fingerprint_hex: str) -> str:
    """6-digit code from the fingerprint, like Riptide's (123-456).

    Only ~20 bits of entropy -- a convenience check, not a
    replacement for comparing the full fingerprint.
    """
    code = int(fingerprint_hex[:6], 16) % 1_000_000
    return f"{code:06d}"[:3] + "-" + f"{code:06d}"[3:]


def generate_cert(cert_path: str | None = None, key_path: str | None = None):
    """Generate a self-signed RSA-2048 cert with the openssl binary.

    Returns (cert_path, key_path, fingerprint_hex). The private
    key is written with mode 0600. Raises RuntimeError if openssl
    is not available.
    """
    cert_path = cert_path or default_cert_path()
    key_path = key_path or default_key_path()
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key_path, "-out", cert_path, "-days", "3650",
         "-subj", "/CN=warpsend"],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"openssl failed: {result.stderr.strip()}")
    os.chmod(key_path, 0o600)
    fp = fingerprint_of_cert_file(cert_path)
    return cert_path, key_path, fp


def server_tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def client_tls_context() -> ssl.SSLContext:
    # CERT_NONE at the library level: self-signed certs would be
    # rejected otherwise. The real check is the fingerprint
    # comparison done by the caller after the handshake.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def peer_fingerprint(tls_sock) -> str:
    der = tls_sock.getpeercert(binary_form=True)
    return fingerprint_of_der(der) if der else ""
