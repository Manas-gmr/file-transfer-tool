"""Shared helpers for the file-transfer tool.

Two checksum levels, exactly as explained in the walkthrough:
  * per-chunk CRC32  -- fast, catches a corrupt UDP packet at once
  * whole-file SHA-256 -- strong proof the received file is identical

Only the standard library is used, so the tool runs with plain
``python3`` -- no pip install needed.
"""

import hashlib
import json
import struct
import sys
import zlib

VERSION = "1.0.0"

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


def progress(done: int, total: int, label: str = "") -> None:
    """One-line progress bar:  [####------]  42%  1.2 MB / 3.0 MB."""
    if total <= 0:
        return
    pct = done * 100 // total
    bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
    print(f"\r{label} [{bar}] {pct:3d}%  {done}/{total} bytes",
          end="", flush=True)
    if done >= total:
        print()  # finish the line


# --- length-prefixed JSON header (TCP) -------------------------------------
# A header is sent as:  4-byte big-endian length  +  JSON bytes.
# The length prefix tells the receiver exactly where the header
# ends and the file data begins.
#
# Header contents: {"filename": ..., "filesize": ..., "checksum": ...}
#   checksum = SHA-256 of the whole file, computed by the sender.

def send_header(sock, filename: str, filesize: int, checksum: str) -> None:
    payload = json.dumps({
        "filename": filename,
        "filesize": filesize,
        "checksum": checksum,
    }).encode()
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
