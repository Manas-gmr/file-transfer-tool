"""File-transfer client -- TCP mode and UDP mode (WarpSend v1.2).

Usage:
    python3 client.py --mode tcp --file notes.pdf --host 127.0.0.1 --port 5000
    python3 client.py --mode udp --file notes.pdf --host 127.0.0.1 --port 5000

Both modes first compute the file's SHA-256 and send it in the
header, so the server can prove the file arrived intact.

TCP: the server first sends a random CHALLENGE; the header's
HMAC covers it, so a captured header cannot be replayed. Then
the file is sent in 256 KB chunks -- with socket.sendfile()
on the plain-TCP path, or read/sendall under TLS. The OS
guarantees order and delivery. v1.1+: after the header the
client reads the server's reply -- FRESH 0, RESUME <offset>
when a matching .part is on the server, DONE when the .part
is already complete -- and sends only the missing bytes.
The return value now follows the server's verdict: False on
CORRUPT, AUTH_FAIL, TOO_LARGE or INVALID, so a script can
react to a failed transfer (exit code 1).

UDP: send header, then 1024-byte chunks, each with a sequence
number, total count and CRC32. Wait for an ACK per chunk
(stop-and-wait); on a 0.5 s timeout, resend (up to 5 tries).
Progress is updated on ACK, not on send -- otherwise it would
lie when a packet is lost. v1.2: the header itself is ACKed
and retried (packet type 4), the EOF is retried until the
SUCCESS/FAIL reply arrives, and 'no final reply' now means
failure (False), not success. The file is streamed from disk
in chunks instead of being loaded whole into memory.
"""

import argparse
import json
import math
import os
import secrets
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (CHUNK_TCP, CHUNK_UDP, client_tls_context, crc32_of,
                   default_known_hosts_path, header_auth, load_known_hosts,
                   peer_fingerprint, progress, recv_line, save_known_host,
                   send_header, sha256_of_file, short_code)  # noqa: E402

TIMEOUT = 0.5      # seconds to wait for a UDP ACK before resending
MAX_RETRIES = 5


def _wrap_tls(sock, host, fingerprint=None, trust_new=False,
              known_hosts_path=None):
    """Wrap a connected socket in TLS and check the fingerprint.

    Returns the wrapped socket, or None if the fingerprint check
    fails. Trust on first use: a fingerprint remembered for this
    host must match on later connects; a new host is accepted
    only with --fingerprint (which must match) or --trust-new
    (explicit), and is then remembered. Without any of those,
    the client aborts instead of sending a file to a server it
    has never verified.
    """
    tls = client_tls_context().wrap_socket(sock, server_hostname=host)
    fp = peer_fingerprint(tls)
    print(f"server TLS fingerprint: {fp}  (code {short_code(fp)})")
    known = load_known_hosts(known_hosts_path)
    if host in known:
        if known[host].lower() != fp.lower():
            print("FINGERPRINT CHANGED for a known host -- aborting. "
                  "The server's certificate changed; verify out of band "
                  "before trusting it again.")
            tls.close()
            return None
        print("fingerprint matches the remembered host")
        return tls
    if fingerprint:
        if fp.lower() != fingerprint.lower().replace(":", ""):
            print("FINGERPRINT MISMATCH -- aborting, possible interception. "
                  "Compare the fingerprint with the receiver out of band.")
            tls.close()
            return None
        print("fingerprint matches the pinned value")
    elif not trust_new:
        print("this host is not in the known-hosts file and no "
              "--fingerprint was given -- aborting. Re-run with "
              "--fingerprint <hex> or --trust-new to trust it once, "
              "after verifying the fingerprint out of band.")
        tls.close()
        return None
    else:
        print("trusting this host for the first time -- fingerprint saved")
    save_known_host(known_hosts_path, host, fp)
    return tls


def send_tcp(host, port, path, key=None, tls=False, fingerprint=None,
             trust_new=False, known_hosts_path=None):
    size = os.path.getsize(path)
    print(f"hashing {os.path.basename(path)} ...")
    checksum = sha256_of_file(
        path, on_progress=lambda d, t: progress(d, t, label="hashing"))
    print(f"{os.path.basename(path)}: {size} bytes, SHA-256 {checksum}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.connect((host, port))
        sock = raw
        if tls:
            sock = _wrap_tls(raw, host, fingerprint, trust_new,
                             known_hosts_path)
            if sock is None:
                return False
        with sock:
            # v1.2 challenge-response: the server sends CHALLENGE
            # first. A pre-v1.2 server never does, so a timeout
            # means no challenge -- fall back to a nonce-less HMAC.
            challenge = recv_line(sock, timeout=1.5) or ""
            nonce = ""
            if challenge.startswith("CHALLENGE "):
                nonce = challenge.split(None, 1)[1]
            auth = header_auth(key, os.path.basename(path), size,
                               checksum, nonce) if key else None
            send_header(sock, os.path.basename(path), size, checksum,
                        auth=auth, nonce=nonce or None)
            reply = recv_line(sock, timeout=2.0)
            offset = 0
            if reply in ("AUTH_FAIL", "TOO_LARGE", "INVALID"):
                print(f"server rejected the transfer: {reply}")
                return False
            if reply == "DONE":
                print("server already has the complete file -- nothing to send")
                return True
            if reply and reply.startswith("RESUME "):
                try:
                    offset = int(reply.split()[1])
                except ValueError:
                    offset = 0
                print(f"resuming from byte {offset} of {size}")
            sent = offset
            with open(path, "rb") as f:
                if not tls:
                    # sendfile() moves bytes kernel-side; do it in
                    # 256 KB slices so progress stays live.
                    remaining = size - offset
                    pos = offset
                    while remaining > 0:
                        n = sock.sendfile(f, pos, min(CHUNK_TCP, remaining))
                        if n == 0:
                            break
                        pos += n
                        sent += n
                        remaining -= n
                        progress(sent, size, label="sending", base=offset)
                else:
                    f.seek(offset)
                    while chunk := f.read(CHUNK_TCP):
                        sock.sendall(chunk)
                        sent += len(chunk)
                        progress(sent, size, label="sending", base=offset)
            verdict = sock.recv(16).decode(errors="replace").strip()
            print("server says:", verdict)
            # A pre-v1.2 server's first reply here is the FRESH
            # line the new client already consumed; anything
            # else is the verdict.
            if verdict == "CORRUPT":
                return False
            return True


def send_udp(host, port, path, key=None):
    size = os.path.getsize(path)
    print(f"hashing {os.path.basename(path)} ...")
    checksum = sha256_of_file(
        path, on_progress=lambda d, t: progress(d, t, label="hashing"))
    total = max(math.ceil(size / CHUNK_UDP), 1)
    # Per-transfer nonce, covered by the HMAC; the server
    # rejects a nonce it has already seen, so this header
    # cannot be replayed within a server run.
    nonce = secrets.token_hex(8)
    auth = header_auth(key, os.path.basename(path), size, checksum,
                       nonce) if key else None
    print(f"{os.path.basename(path)}: {size} bytes, "
          f"{total} chunks, SHA-256 {checksum}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        header = {"filename": os.path.basename(path),
                  "filesize": size, "checksum": checksum,
                  "protocol": 2, "nonce": nonce}
        if auth:
            header["auth"] = auth
        header_packet = b"\x00" + json.dumps(header).encode()
        # Reliable header: retry until the server ACKs it (type 4).
        for attempt in range(MAX_RETRIES):
            sock.sendto(header_packet, (host, port))
            try:
                reply, _ = sock.recvfrom(64)
                if reply == b"\x04":
                    break
                if reply == b"FAIL":
                    print("server rejected the header")
                    return False
            except socket.timeout:
                print(f"header: no ACK, resending "
                      f"(attempt {attempt + 2}/{MAX_RETRIES})")
        else:
            print("header: giving up after "
                  f"{MAX_RETRIES} tries -- server never ACKed it")
            return False
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
        # Reliable EOF: retry until the final verdict arrives.
        for attempt in range(MAX_RETRIES):
            sock.sendto(b"\x02", (host, port))       # EOF
            try:
                reply = sock.recvfrom(64)[0].decode()
                print("server says:", reply)
                return reply == "SUCCESS"
            except socket.timeout:
                print(f"EOF: no reply, resending "
                      f"(attempt {attempt + 2}/{MAX_RETRIES})")
        print("no final reply from server -- transfer outcome unknown, "
              "treating as failure")
        return False


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-transfer client")
    ap.add_argument("--mode", choices=["tcp", "udp"], required=True)
    ap.add_argument("--file", required=True, help="file to send")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default=None, help="shared secret")
    ap.add_argument("--key-file", default=None,
                    help="file containing the shared secret")
    ap.add_argument("--tls", action="store_true", help="wrap TCP in TLS")
    ap.add_argument("--fingerprint", default=None,
                    help="expected server TLS fingerprint (hex)")
    ap.add_argument("--trust-new", action="store_true",
                    help="trust a new TLS host and remember it")
    args = ap.parse_args()
    key = None
    if args.key_file:
        with open(args.key_file) as f:
            key = f.read().strip()
    elif args.key:
        print("warning: --key appears in process listings and shell "
              "history; prefer --key-file or WARPSEND_KEY", file=sys.stderr)
        key = args.key
    else:
        key = os.environ.get("WARPSEND_KEY")
    if not os.path.isfile(args.file):
        sys.exit(f"file not found: {args.file}")
    if args.mode == "tcp":
        ok = send_tcp(args.host, args.port, args.file, key=key,
                      tls=args.tls, fingerprint=args.fingerprint,
                      trust_new=args.trust_new)
    else:
        ok = send_udp(args.host, args.port, args.file, key=key)
    sys.exit(0 if ok else 1)
