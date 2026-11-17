"""File-transfer client -- TCP mode and UDP mode (WarpSend v1.1).

Usage:
    python3 client.py --mode tcp --file notes.pdf --host 127.0.0.1 --port 5000
    python3 client.py --mode udp --file notes.pdf --host 127.0.0.1 --port 5000

Both modes first compute the file's SHA-256 and send it in the
header, so the server can prove the file arrived intact.

TCP: send header, then the file in 64 KB chunks with sendall().
The OS guarantees order and delivery. v1.1: after the header
the client reads the server's reply -- FRESH 0, or RESUME
<offset> when a matching .part is on the server -- and sends
only the missing bytes. With --key the header carries an
HMAC-SHA256 tag; a server started with the same key verifies
it, anything else is rejected with AUTH_FAIL.

UDP: send header, then 1024-byte chunks, each with a sequence
number, total count and CRC32. Wait for an ACK per chunk
(stop-and-wait); on a 0.5 s timeout, resend (up to 5 tries).
Progress is updated on ACK, not on send -- otherwise it would
lie when a packet is lost. EOF packet ends the transfer.
v1.1: the file is streamed from disk in chunks instead of
being loaded whole into memory.
"""

import argparse
import json
import math
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (CHUNK_TCP, CHUNK_UDP, client_tls_context, crc32_of,
                   default_cert_path, fingerprint_of_cert_file, header_auth,
                   peer_fingerprint, progress, recv_line, send_header,
                   sha256_of_file, short_code)  # noqa: E402

TIMEOUT = 0.5      # seconds to wait for a UDP ACK before resending
MAX_RETRIES = 5


def _wrap_tls(sock, host, fingerprint=None):
    """Wrap a connected socket in TLS and check the fingerprint.

    Returns the wrapped socket, or None if the fingerprint was
    pinned with --fingerprint and did not match (abort).
    """
    tls = client_tls_context().wrap_socket(sock, server_hostname=host)
    fp = peer_fingerprint(tls)
    print(f"server TLS fingerprint: {fp}  (code {short_code(fp)})")
    if fingerprint:
        if fp.lower() != fingerprint.lower().replace(":", ""):
            print("FINGERPRINT MISMATCH -- aborting, possible interception. "
                  "Compare the fingerprint with the receiver out of band.")
            tls.close()
            return None
        print("fingerprint matches the pinned value")
    else:
        print("no --fingerprint given: first-connect trust -- verify "
              "this fingerprint with the receiver before sending "
              "anything sensitive")
    return tls


def send_tcp(host, port, path, key=None, tls=False, fingerprint=None):
    size = os.path.getsize(path)
    checksum = sha256_of_file(path)
    auth = header_auth(key, os.path.basename(path), size, checksum) if key else None
    print(f"{os.path.basename(path)}: {size} bytes, SHA-256 {checksum}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.connect((host, port))
        sock = raw
        if tls:
            sock = _wrap_tls(raw, host, fingerprint)
            if sock is None:
                return False
        with sock:
            send_header(sock, os.path.basename(path), size, checksum, auth=auth)
            # v1.1 reply: FRESH 0 / RESUME <offset> / AUTH_FAIL.
            # A pre-v1.1 server never replies: recv_line times out
            # after 2 s and we fall back to a fresh transfer.
            reply = recv_line(sock, timeout=2.0)
            offset = 0
            if reply == "AUTH_FAIL":
                print("server rejected the transfer: wrong or missing key")
                return False
            if reply and reply.startswith("RESUME "):
                try:
                    offset = int(reply.split()[1])
                except ValueError:
                    offset = 0
                print(f"resuming from byte {offset} of {size}")
            sent = offset
            with open(path, "rb") as f:
                f.seek(offset)
                while chunk := f.read(CHUNK_TCP):
                    sock.sendall(chunk)
                    sent += len(chunk)
                    progress(sent, size, label="sending")
            print("server says:", sock.recv(16).decode(errors="replace"))
            return True


def send_udp(host, port, path, key=None):
    size = os.path.getsize(path)
    checksum = sha256_of_file(path)
    total = max(math.ceil(size / CHUNK_UDP), 1)
    auth = header_auth(key, os.path.basename(path), size, checksum) if key else None
    print(f"{os.path.basename(path)}: {size} bytes, "
          f"{total} chunks, SHA-256 {checksum}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        # header packet: type 0 + JSON
        header = {"filename": os.path.basename(path),
                  "filesize": size, "checksum": checksum}
        if auth:
            header["auth"] = auth
        sock.sendto(b"\x00" + json.dumps(header).encode(), (host, port))
        acked = 0
        # Stream from disk: the whole file is never held in RAM.
        with open(path, "rb") as f:
            for seq in range(total):
                chunk = f.read(CHUNK_UDP)
                packet = (b"\x01" + struct.pack("!III", seq, total,
                                                crc32_of(chunk)) + chunk)
                for attempt in range(MAX_RETRIES):
                    sock.sendto(packet, (host, port))
                    try:
                        ack, _ = sock.recvfrom(64)
                        if ack[0] == 3 and struct.unpack("!I", ack[1:5])[0] == seq:
                            acked += 1
                            progress(acked * CHUNK_UDP if acked < total else size,
                                     size, label="sending")
                            break
                    except socket.timeout:
                        print(f"\nchunk {seq}: no ACK, resending "
                              f"(attempt {attempt + 2}/{MAX_RETRIES})")
                else:
                    print(f"\nchunk {seq}: giving up after {MAX_RETRIES} tries")
                    return False
        sock.sendto(b"\x02", (host, port))       # EOF
        try:
            print("server says:", sock.recvfrom(64)[0].decode())
        except socket.timeout:
            print("no final reply from server (file may still be saved)")
        return True


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-transfer client")
    ap.add_argument("--mode", choices=["tcp", "udp"], required=True)
    ap.add_argument("--file", required=True, help="file to send")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default=None, help="shared secret")
    ap.add_argument("--tls", action="store_true", help="wrap TCP in TLS")
    ap.add_argument("--fingerprint", default=None,
                    help="expected server TLS fingerprint (hex)")
    args = ap.parse_args()
    key = args.key or os.environ.get("WARPSEND_KEY")
    if not os.path.isfile(args.file):
        sys.exit(f"file not found: {args.file}")
    if args.mode == "tcp":
        ok = send_tcp(args.host, args.port, args.file, key=key,
                      tls=args.tls, fingerprint=args.fingerprint)
    else:
        ok = send_udp(args.host, args.port, args.file, key=key)
    sys.exit(0 if ok else 1)
