"""Protocol -- the wire format both modes speak (protocol v2).

A transfer starts with a length-prefixed JSON header:

    4-byte big-endian length  +  JSON bytes

Header contents:
    {"filename": ..., "filesize": ..., "checksum": ...,
     "protocol": 2, "nonce": ..., "auth": ...}
  checksum = SHA-256 of the whole file, computed by the sender.
  nonce/auth are present only with --key (see below).

Rules, all enforced by validate_header() before anything is
trusted: required keys, correct types, filesize >= 0, a sane
filename (basename only, no "", ".", "..", no NUL), a 64-hex
checksum, and a supported protocol version. Headers over
MAX_HEADER_BYTES are rejected before allocation.

Auth (shared key): the HMAC-SHA256 covers the header fields
*and* a per-connection nonce, so a captured header cannot be
replayed. TCP: the nonce is the server's random challenge.
UDP: the client generates a random nonce per transfer and the
server rejects a nonce it has already seen in this run.

UDP packets (see transfer.py) carry a 1-byte type first:
0 = header (JSON), 1 = data, 2 = EOF, 3 = ACK, 4 = header ACK.
"""

import hashlib
import hmac as hmac_mod
import json
import os
import struct

from .config import PROTOCOL_VERSION

CHUNK_TCP = 256 * 1024  # 256 KB chunks for TCP (raised from 64 KB in v1.2)
CHUNK_UDP = 1024  # 1024 bytes of data per UDP packet
# (keeps each datagram well under the ~1400-byte practical limit,
#  so it is not fragmented on the network)

# A header is a small JSON object (filename, size, SHA-256, auth).
# Anything claiming to be larger is malformed, not a header.
MAX_HEADER_BYTES = 8192


def send_header(
    sock,
    filename: str,
    filesize: int,
    checksum: str,
    auth: str | None = None,
    nonce: str | None = None,
) -> None:
    payload_dict = {
        "filename": filename,
        "filesize": filesize,
        "checksum": checksum,
        "protocol": PROTOCOL_VERSION,
    }
    if nonce:
        payload_dict["nonce"] = nonce
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
    if length > MAX_HEADER_BYTES:
        raise ValueError(f"header length {length} exceeds maximum {MAX_HEADER_BYTES}")
    if length == 0:
        raise ValueError("empty header")
    return json.loads(_recv_exact(sock, length))


def validate_header(header) -> dict:
    """Validate an untrusted header; return its normalised fields.

    Raises ValueError on anything malformed: not a dict, missing
    keys, wrong types, negative filesize, empty/dot filename,
    NUL bytes, or a checksum that is not 64 hex characters.
    Callers use the returned dict, never the raw one.
    """
    if not isinstance(header, dict):
        # ValueError (not TypeError) on purpose: the whole
        # validation API raises ValueError, and the tests and
        # both servers rely on catching exactly that.
        raise ValueError("header is not a JSON object")
    for key in ("filename", "filesize", "checksum"):
        if key not in header:
            raise ValueError(f"header missing {key!r}")
    name = header["filename"]
    size = header["filesize"]
    checksum = header["checksum"]
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("bad filename in header")
    name = os.path.basename(name)
    if name in ("", ".", ".."):
        raise ValueError("bad filename in header")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("bad filesize in header")
    if (
        not isinstance(checksum, str)
        or len(checksum) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in checksum)
    ):
        raise ValueError("bad checksum in header")
    auth = header.get("auth")
    if auth is not None and not isinstance(auth, str):
        raise ValueError("bad auth tag in header")
    nonce = header.get("nonce")
    if nonce is not None and not isinstance(nonce, str):
        raise ValueError("bad nonce in header")
    protocol = header.get("protocol")
    if protocol is not None and protocol not in (1, 2):
        raise ValueError(f"unsupported protocol version {protocol!r}")
    return {
        "filename": name,
        "filesize": size,
        "checksum": checksum.lower(),
        "auth": auth,
        "nonce": nonce,
        "protocol": protocol or 1,
    }


def recv_line(sock, timeout: float = 2.0):
    """Read one \\n-terminated line from a TCP socket.

    Returns the line without the newline, or None on timeout /
    closed connection. Used for the server's short replies
    (CHALLENGE / FRESH / RESUME <offset> / DONE / AUTH_FAIL /
    TOO_LARGE / INVALID). A timeout means the other side is a
    pre-v1.1 WarpSend that never sends a reply -- the caller
    should then assume a fresh transfer.
    """
    sock.settimeout(timeout)
    buf = b""
    try:
        while not buf.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 128:
                return None
    except TimeoutError:
        return None
    finally:
        sock.settimeout(None)
    return buf.decode(errors="replace").strip()


def header_auth(key: str, filename: str, filesize: int, checksum: str, nonce: str = "") -> str:
    """HMAC-SHA256 of the header fields under the shared secret."""
    msg = f"{nonce}\n{filename}\n{filesize}\n{checksum}".encode()
    return hmac_mod.new(key.encode(), msg, hashlib.sha256).hexdigest()


def auth_ok(key: str | None, header: dict, nonce: str = "") -> bool:
    """True if the header's auth matches the server's key.

    A server with no key accepts anything (backwards compatible).
    A server with a key rejects a missing or wrong auth tag.
    The nonce used is the one in the header if present, else
    the server's challenge nonce passed in here.
    """
    if not key:
        return True
    tag = header.get("auth")
    if not tag:
        return False
    use_nonce = header.get("nonce") or nonce
    return hmac_mod.compare_digest(
        tag, header_auth(key, header["filename"], header["filesize"], header["checksum"], use_nonce)
    )
