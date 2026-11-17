"""File-transfer server -- TCP mode and UDP mode (WarpSend v1.2).

Usage:
    python3 server.py --mode tcp --port 5000
    python3 server.py --mode udp --port 5000

TCP: reliability comes from the OS (ordering, no loss, no
duplicates), so the server just reads the header, then reads
exactly `filesize` bytes, verifies SHA-256 and replies OK/CORRUPT.

v1.2 changes (from the 17 Nov 2026 code review):
  * Crash-proofing (B2): one `validate_header()` for both modes,
    per-connection/per-packet exception handling, so a malformed
    peer is logged and dropped instead of killing the receiver.
  * Size limits (S1): headers over 8 KB are rejected before
    allocation; a transfer larger than the free disk space (or
    --max-size) is rejected with TOO_LARGE before any bytes.
  * Concurrency + timeouts (S2): thread per TCP connection with
    a 120 s socket timeout; transfers of the same filename are
    serialised by a per-name lock so their .part files cannot
    collide, different names run in parallel.
  * Challenge-response auth (S3): the server sends a random
    CHALLENGE on accept; the HMAC covers it, so a captured
    header cannot be replayed.
  * Output directory (B6): files go to ./received (the current
    working directory), not next to the script; --outdir
    overrides it.
  * Complete .part (B7): a .part that is already complete is
    hash-verified and finalised (server replies DONE) instead
    of restarted from zero.
  * Incremental hashing (P3): the SHA-256 is updated as TCP
    bytes arrive (the existing prefix is hashed first on
    resume), instead of re-reading the whole file at the end.
  * Atomic rename (S6): the final name is claimed with a hard
    link, so a file created between check and rename cannot
    be silently replaced.
  * UDP (B3/B4/B5/P2/S5): a new header resets all per-transfer
    state; the header is ACKed and retried (new packet type 4);
    EOF is retried until the SUCCESS/FAIL reply arrives; the
    server ignores packets from any address other than the
    header sender and has a 30 s idle timeout; chunks are
    written straight to the .part file at seq * 1024 with a
    running byte counter, instead of being held in RAM and
    re-summed per packet.

UDP: reliability is built here. Every datagram carries
    [type=1][seq (4B)][total (4B)][crc32 (4B)][data]
The server stores chunks by sequence number, ACKs each one
(duplicates are ignored), reorders at the end, then verifies
SHA-256. A lost packet is never ACKed, so the client resends it.
Packet types: 0 = header (JSON), 1 = data, 2 = EOF, 3 = ACK,
4 = header ACK.
"""

import argparse
import json
import os
import secrets
import shutil
import socket
import struct
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (CHUNK_TCP, CHUNK_UDP, auth_ok, claim_final_name,
                   crc32_of, default_cert_path, default_key_path,
                   discard_part, fingerprint_of_cert_file, load_meta,
                   meta_path, part_path, progress, recv_header,
                   resume_offset, save_meta, server_tls_context,
                   sha256_of_file, short_code, validate_header)  # noqa: E402

# Default output directory: the current working directory, so a
# pip-installed WarpSend does not try to write inside its own
# package location. --outdir overrides it.
OUTDIR = os.path.join(os.getcwd(), "received")

CONN_TIMEOUT = 120   # seconds of silence before a TCP connection is dropped
UDP_IDLE_TIMEOUT = 30  # seconds of silence before a UDP transfer is abandoned

_NAME_LOCKS = {}
_NAME_LOCKS_GUARD = threading.Lock()


def _lock_for(outdir, name):
    key = (outdir, name)
    with _NAME_LOCKS_GUARD:
        lock = _NAME_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _NAME_LOCKS[key] = lock
        return lock


def _finish_part(outdir, name, expected_hash, hasher=None,
                 conn=None, udp_sock=None, udp_addr=None):
    """Verify a completed .part file, rename on match, reply.

    Returns True on a verified transfer. On a hash mismatch the
    partial is deleted (its prefix is untrustworthy) and False
    is returned. With `hasher` (TCP, incremental) the digest
    comes from the bytes as they arrived; without it (UDP) the
    file is read back once.
    """
    path = part_path(outdir, name)
    got = hasher.hexdigest() if hasher is not None else sha256_of_file(path)
    ok = got == expected_hash
    print(f"expected SHA-256: {expected_hash}")
    print(f"received SHA-256: {got}")
    if ok:
        final = claim_final_name(outdir, name)
        try:
            os.remove(meta_path(outdir, name))
        except OSError:
            pass
        print(f"Transfer verified, file intact -> {final}")
        if os.path.basename(final) != name:
            print(f"(renamed: {name} already existed)")
    else:
        print("File corrupted -- checksum mismatch, partial deleted")
        discard_part(outdir, name)
    reply = b"OK" if ok else b"CORRUPT"
    if conn is not None:
        try:
            conn.sendall(reply)
        except OSError:
            pass
    elif udp_sock is not None:
        udp_sock.sendto(b"SUCCESS" if ok else b"FAIL", udp_addr)
    return ok


def _handle_tcp_conn(conn, key, outdir, max_size, challenge=""):
    """Receive one file on an already-accepted TCP connection."""
    try:
        raw_header = recv_header(conn)
    except (ConnectionError, ValueError, OSError) as e:
        print(f"bad header, closing connection: {e}")
        return
    try:
        header = validate_header(raw_header)
    except ValueError as e:
        print(f"invalid header, closing connection: {e}")
        try:
            conn.sendall(b"INVALID\n")
        except OSError:
            pass
        return
    name = header["filename"]
    size = header["filesize"]
    if not auth_ok(key, header, nonce=challenge):
        print(f"auth failed for {name} -- wrong or missing key, rejected")
        try:
            conn.sendall(b"AUTH_FAIL\n")
        except OSError:
            pass
        return
    if max_size and size > max_size:
        print(f"rejecting {name}: {size} bytes exceeds --max-size {max_size}")
        try:
            conn.sendall(b"TOO_LARGE\n")
        except OSError:
            pass
        return
    try:
        free = shutil.disk_usage(outdir).free
    except OSError:
        free = size  # cannot check; let the write fail later if needed
    if size > free:
        print(f"rejecting {name}: {size} bytes but only {free} free on disk")
        try:
            conn.sendall(b"TOO_LARGE\n")
        except OSError:
            pass
        return
    print(f"receiving {name} ({size} bytes)")
    os.makedirs(outdir, exist_ok=True)
    with _lock_for(outdir, name):
        offset = resume_offset(outdir, name, size, header["checksum"])
        if offset == size and size > 0:
            # Complete .part left by a crash after the last byte
            # but before the rename: verify and finalise it.
            path = part_path(outdir, name)
            if sha256_of_file(path) == header["checksum"]:
                final = claim_final_name(outdir, name)
                try:
                    os.remove(meta_path(outdir, name))
                except OSError:
                    pass
                print(f"already complete, verified -> {final}")
                try:
                    conn.sendall(b"DONE\n")
                except OSError:
                    pass
                return
            print(f"complete .part for {name} failed its hash -- restarting")
            discard_part(outdir, name)
            offset = 0
        if offset:
            print(f"resuming {name} from byte {offset} of {size}")
            conn.sendall(f"RESUME {offset}\n".encode())
        else:
            discard_part(outdir, name)
            save_meta(outdir, name, size, header["checksum"])
            conn.sendall(b"FRESH 0\n")
        path = part_path(outdir, name)
        import hashlib
        hasher = hashlib.sha256()
        if offset:
            # Hash the existing prefix first, so the final digest
            # covers the whole file, not just the resumed tail.
            with open(path, "rb") as f:
                while chunk := f.read(64 * 1024):
                    hasher.update(chunk)
        received = offset
        buf = bytearray(CHUNK_TCP)
        try:
            with open(path, "ab" if offset else "wb") as f:
                while received < size:
                    want = min(CHUNK_TCP, size - received)
                    n = conn.recv_into(memoryview(buf)[:want])
                    if n == 0:
                        print(f"connection lost at {received}/{size} bytes "
                              f"-- partial kept, send again to resume")
                        return
                    f.write(buf[:n])
                    hasher.update(buf[:n])
                    received += n
                    progress(received, size, label="receiving", base=offset)
        except (OSError, ValueError) as e:
            print(f"receive error: {e} -- partial kept")
            return
        print(f"saved to {path}")
        _finish_part(outdir, name, header["checksum"],
                     hasher=hasher, conn=conn)


def _serve_one_tcp(conn, addr, ctx, key, outdir, max_size):
    print(f"connected: {addr}")
    if ctx is not None:
        try:
            conn = ctx.wrap_socket(conn, server_side=True)
        except Exception as e:
            print(f"TLS handshake failed: {e}")
            conn.close()
            return
    with conn:
        try:
            conn.settimeout(CONN_TIMEOUT)
        except OSError:
            pass
        challenge = secrets.token_hex(16)
        try:
            conn.sendall(f"CHALLENGE {challenge}\n".encode())
        except OSError:
            return
        try:
            _handle_tcp_conn(conn, key, outdir, max_size, challenge=challenge)
        except Exception as e:  # a bad peer must not kill the receiver
            print(f"connection error for {addr}: {type(e).__name__}: {e} "
                  f"-- partial kept if any")


def serve_tcp(host, port, key=None, tls=False, cert=None, keyfile=None,
              outdir=None, max_size=0):
    outdir = outdir or OUTDIR
    os.makedirs(outdir, exist_ok=True)
    ctx = None
    if tls:
        cert = cert or default_cert_path()
        keyfile = keyfile or default_key_path()
        if not (os.path.isfile(cert) and os.path.isfile(keyfile)):
            print(f"no certificate at {cert} -- run `warpsend cert` first")
            return
        ctx = server_tls_context(cert, keyfile)
        fp = fingerprint_of_cert_file(cert)
        print(f"TLS on, server fingerprint: {fp}  (code {short_code(fp)})")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        print(f"TCP server listening on {host}:{port}, saving to {outdir} "
              f"... (Ctrl-C to stop)")
        while True:
            try:
                conn, addr = srv.accept()
            except KeyboardInterrupt:
                print("\nserver stopped")
                return
            t = threading.Thread(target=_serve_one_tcp,
                                 args=(conn, addr, ctx, key, outdir, max_size),
                                 daemon=True)
            t.start()


def serve_udp(host, port, key=None, outdir=None, max_size=0):
    outdir = outdir or OUTDIR
    os.makedirs(outdir, exist_ok=True)
    seen_nonces = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        sock.settimeout(UDP_IDLE_TIMEOUT)
        print(f"UDP server listening on {host}:{port}, saving to {outdir} "
              f"... (Ctrl-C to stop)")
        while True:
            # Per-transfer state; a new header resets all of it.
            header, total, sender = None, None, None
            received_seqs, received_bytes = set(), 0
            part_file = None
            try:
                while True:
                    try:
                        packet, addr = sock.recvfrom(2048)
                    except socket.timeout:
                        if header is not None:
                            print("UDP transfer timed out -- partial kept, "
                                  "state reset")
                            if part_file is not None:
                                part_file.close()
                        break
                    if not packet:
                        continue  # empty datagram: ignore, no crash
                    ptype = packet[0]
                    if ptype == 0:                       # header (JSON)
                        try:
                            raw = json.loads(packet[1:])
                            new_header = validate_header(raw)
                        except (ValueError, UnicodeDecodeError) as e:
                            print(f"invalid UDP header from {addr}: {e}")
                            continue
                        if header is not None and addr[0] != sender[0]:
                            print(f"ignoring header from {addr}: transfer "
                                  f"in progress from {sender}")
                            continue
                        if header is not None:
                            # New header from the same sender: the old
                            # transfer is abandoned -- reset its state.
                            print("new UDP header -- resetting old transfer")
                            if part_file is not None:
                                part_file.close()
                            received_seqs, received_bytes = set(), 0
                            total = None
                        nonce = new_header.get("nonce")
                        if key and nonce and nonce in seen_nonces:
                            print(f"replayed UDP header from {addr} -- ignored")
                            continue
                        if not auth_ok(key, new_header):
                            print(f"auth failed for {new_header['filename']} "
                                  f"-- packet ignored")
                            sock.sendto(b"FAIL", addr)
                            continue
                        size = new_header["filesize"]
                        if (max_size and size > max_size) or \
                                size > shutil.disk_usage(outdir).free:
                            print(f"rejecting {new_header['filename']}: too large")
                            sock.sendto(b"FAIL", addr)
                            continue
                        header, sender = new_header, addr
                        if nonce:
                            seen_nonces.add(nonce)
                        name = header["filename"]
                        print(f"receiving {name} ({size} bytes)")
                        discard_part(outdir, name)
                        save_meta(outdir, name, size, header["checksum"])
                        part_file = open(part_path(outdir, name), "wb")
                        sock.sendto(b"\x04", addr)  # header ACK
                    elif ptype == 1:                     # data chunk
                        if header is None or addr[0] != sender[0]:
                            continue  # no transfer, or wrong sender: ignore
                        if len(packet) < 13:
                            continue
                        seq, pkt_total, crc = struct.unpack("!III", packet[1:13])
                        if total is None:
                            total = pkt_total
                        elif pkt_total != total:
                            continue
                        if seq >= total:
                            continue
                        data = packet[13:]
                        if crc32_of(data) != crc:
                            print(f"chunk {seq}: bad CRC32, dropped (no ACK)")
                            continue             # no ACK -> client resends
                        if seq not in received_seqs:
                            part_file.seek(seq * CHUNK_UDP)
                            part_file.write(data)
                            received_seqs.add(seq)
                            received_bytes += len(data)
                        sock.sendto(b"\x03" + struct.pack("!I", seq), addr)
                        progress(received_bytes, header["filesize"],
                                 label="receiving")
                    elif ptype == 2:                     # EOF
                        if header is None or addr[0] != sender[0]:
                            continue
                        break
                    # Unknown packet types are ignored.
            except KeyboardInterrupt:
                print("\nserver stopped")
                if part_file is not None:
                    part_file.close()
                return
            if header is None:
                continue
            if part_file is not None:
                part_file.close()
            name = header["filename"]
            if total is None or len(received_seqs) != total:
                print(f"incomplete: {len(received_seqs)}/{total} chunks, "
                      f".part kept")
                sock.sendto(b"FAIL", sender)
                continue
            print(f"saved to {part_path(outdir, name)} "
                  f"({len(received_seqs)}/{total} chunks)")
            _finish_part(outdir, name, header["checksum"],
                         udp_sock=sock, udp_addr=sender)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-transfer server")
    ap.add_argument("--mode", choices=["tcp", "udp"], required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default=None,
                    help="shared secret; senders without it are rejected")
    ap.add_argument("--key-file", default=None,
                    help="file containing the shared secret")
    ap.add_argument("--tls", action="store_true", help="wrap TCP in TLS")
    ap.add_argument("--cert", default=None)
    ap.add_argument("--keyfile", default=None,
                    help="TLS private key file (not the shared secret)")
    ap.add_argument("--outdir", default=None,
                    help="where received files go (default: ./received)")
    ap.add_argument("--max-size", type=int, default=0,
                    help="reject files larger than this many bytes (0 = no limit)")
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
    if args.mode == "tcp":
        serve_tcp(args.host, args.port, key=key, tls=args.tls,
                  cert=args.cert, keyfile=args.keyfile,
                  outdir=args.outdir, max_size=args.max_size)
    else:
        serve_udp(args.host, args.port, key=key,
                  outdir=args.outdir, max_size=args.max_size)
