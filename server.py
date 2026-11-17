"""File-transfer server -- TCP mode and UDP mode (WarpSend v1.1).

Usage:
    python3 server.py --mode tcp --port 5000
    python3 server.py --mode udp --port 5000

TCP: reliability comes from the OS (ordering, no loss, no
duplicates), so the server just reads the header, then reads
exactly `filesize` bytes, verifies SHA-256 and replies OK/CORRUPT.

v1.1 changes:
  * Persistent: the TCP server keeps listening and accepts file
    after file until Ctrl-C, instead of exiting after one file.
  * `.part` + rename: bytes go to `<name>.part`; the file is
    renamed to its final name only if the SHA-256 matches, and
    never overwrites an existing file (`name (1).ext` ...).
  * Resume: if a `.part` + `.part.json` for the same file
    (same name, size, checksum) is on disk, the server tells
    the client the offset and the client sends only the rest.
    A hash mismatch at full size deletes the partial -- its
    prefix cannot be trusted, so it is not resumed.
  * Auth: with `--key`, a header whose HMAC does not match is
    rejected with AUTH_FAIL and nothing is saved.
  * TLS: with `--tls`, the socket is wrapped in TLS using the
    given (or default ~/.warpsend) self-signed certificate.

UDP: reliability is built here. Every datagram carries
    [type=1][seq (4B)][total (4B)][crc32 (4B)][data]
The server stores chunks by sequence number, ACKs each one
(duplicates are ignored), reorders at the end, then verifies
SHA-256. A lost packet is never ACKed, so the client resends it.
Packet types: 0 = header (JSON), 1 = data, 2 = EOF, 3 = ACK.
v1.1: the UDP server also keeps listening for the next file,
and an EOF with chunks missing no longer crashes with a
KeyError -- it replies FAIL and keeps the received prefix as
a .part instead of writing a corrupt file.
"""

import argparse
import json
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (CHUNK_TCP, auth_ok, crc32_of, default_cert_path,
                   default_key_path, discard_part, fingerprint_of_cert_file,
                   load_meta, meta_path, part_path, progress, recv_header,
                   resume_offset, save_meta, server_tls_context, sha256_of_file,
                   short_code, unique_path)  # noqa: E402

OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received")


def _finish_part(name, expected_hash, conn=None, udp_sock=None, udp_addr=None):
    """Verify a completed .part file, rename on match, reply.

    Returns True on a verified transfer. On a hash mismatch the
    partial is deleted (its prefix is untrustworthy) and False
    is returned.
    """
    path = part_path(OUTDIR, name)
    got = sha256_of_file(path)
    ok = got == expected_hash
    print(f"expected SHA-256: {expected_hash}")
    print(f"received SHA-256: {got}")
    if ok:
        final = unique_path(OUTDIR, name)
        os.rename(path, final)
        try:
            os.remove(meta_path(OUTDIR, name))
        except OSError:
            pass
        print(f"Transfer verified, file intact -> {final}")
        if os.path.basename(final) != name:
            print(f"(renamed: {name} already existed)")
    else:
        print("File corrupted -- checksum mismatch, partial deleted")
        discard_part(OUTDIR, name)
    reply = b"OK" if ok else b"CORRUPT"
    if conn is not None:
        try:
            conn.sendall(reply)
        except OSError:
            pass
    elif udp_sock is not None:
        udp_sock.sendto(b"SUCCESS" if ok else b"FAIL", udp_addr)
    return ok


def _handle_tcp_conn(conn, key=None):
    """Receive one file on an already-accepted TCP connection."""
    try:
        header = recv_header(conn)
    except (ConnectionError, ValueError, OSError) as e:
        print(f"bad header, closing connection: {e}")
        return
    name = os.path.basename(header["filename"])
    size = header["filesize"]
    if not auth_ok(key, header):
        print(f"auth failed for {name} -- wrong or missing key, rejected")
        try:
            conn.sendall(b"AUTH_FAIL\n")
        except OSError:
            pass
        return
    print(f"receiving {name} ({size} bytes)")
    os.makedirs(OUTDIR, exist_ok=True)
    offset = resume_offset(OUTDIR, name, size, header["checksum"])
    if offset:
        print(f"resuming {name} from byte {offset} of {size}")
        conn.sendall(f"RESUME {offset}\n".encode())
    else:
        # Fresh transfer: drop any stale partial for another file.
        discard_part(OUTDIR, name)
        save_meta(OUTDIR, name, size, header["checksum"])
        conn.sendall(b"FRESH 0\n")
    path = part_path(OUTDIR, name)
    received = offset
    try:
        with open(path, "ab" if offset else "wb") as f:
            while received < size:
                chunk = conn.recv(min(CHUNK_TCP, size - received))
                if not chunk:
                    print(f"connection lost at {received}/{size} bytes "
                          f"-- partial kept, send again to resume")
                    return
                f.write(chunk)
                received += len(chunk)
                progress(received, size, label="receiving")
    except OSError as e:
        print(f"write error: {e} -- partial kept")
        return
    print(f"saved to {path}")
    _finish_part(name, header["checksum"], conn=conn)


def serve_tcp(host, port, key=None, tls=False, cert=None, keyfile=None):
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
        print(f"TCP server listening on {host}:{port} ... (Ctrl-C to stop)")
        while True:
            try:
                conn, addr = srv.accept()
            except KeyboardInterrupt:
                print("\nserver stopped")
                return
            print(f"connected: {addr}")
            if ctx is not None:
                try:
                    conn = ctx.wrap_socket(conn, server_side=True)
                except Exception as e:
                    print(f"TLS handshake failed: {e}")
                    conn.close()
                    continue
            with conn:
                try:
                    _handle_tcp_conn(conn, key=key)
                except (ConnectionError, OSError) as e:
                    print(f"connection error: {e} -- partial kept if any")


def serve_udp(host, port, key=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"UDP server listening on {host}:{port} ... (Ctrl-C to stop)")
        while True:
            chunks, total, header, addr = {}, None, None, None
            try:
                while True:
                    packet, addr = sock.recvfrom(2048)
                    ptype = packet[0]
                    if ptype == 0:                       # header (JSON)
                        header = json.loads(packet[1:])
                        if not auth_ok(key, header):
                            print(f"auth failed for {header.get('filename')} "
                                  f"-- packet ignored")
                            header = None
                            continue
                        print(f"receiving {header['filename']} "
                              f"({header['filesize']} bytes)")
                    elif ptype == 1 and header is not None:  # data chunk
                        seq, total, crc = struct.unpack("!III", packet[1:13])
                        data = packet[13:]
                        if crc32_of(data) != crc:
                            print(f"chunk {seq}: bad CRC32, dropped (no ACK)")
                            continue             # no ACK -> client resends
                        if seq not in chunks:    # ignore duplicates
                            chunks[seq] = data
                        sock.sendto(b"\x03" + struct.pack("!I", seq), addr)
                        progress(sum(len(c) for c in chunks.values()),
                                 header["filesize"], label="receiving")
                    elif ptype == 2 and header is not None:  # EOF
                        break
            except KeyboardInterrupt:
                print("\nserver stopped")
                return
            if header is None:
                continue
            name = os.path.basename(header["filename"])
            os.makedirs(OUTDIR, exist_ok=True)
            if total is None or len(chunks) != total:
                # Missing chunks: do NOT reassemble (that used to
                # crash with KeyError). Keep the contiguous prefix
                # as a .part so the failure is visible, reply FAIL.
                got = sorted(chunks)
                prefix = 0
                while prefix in chunks:
                    prefix += 1
                path = part_path(OUTDIR, name)
                with open(path, "wb") as f:
                    for seq in range(prefix):
                        f.write(chunks[seq])
                save_meta(OUTDIR, name, header["filesize"],
                          header["checksum"])
                print(f"incomplete: {len(chunks)}/{total} chunks, "
                      f"kept {prefix} contiguous chunks as .part")
                sock.sendto(b"FAIL", addr)
                continue
            path = part_path(OUTDIR, name)
            save_meta(OUTDIR, name, header["filesize"], header["checksum"])
            with open(path, "wb") as f:              # reassemble in order
                for seq in range(total):
                    f.write(chunks[seq])
            print(f"saved to {path} ({len(chunks)}/{total} chunks)")
            _finish_part(name, header["checksum"],
                         udp_sock=sock, udp_addr=addr)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-transfer server")
    ap.add_argument("--mode", choices=["tcp", "udp"], required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--key", default=None,
                    help="shared secret; senders without it are rejected")
    ap.add_argument("--tls", action="store_true", help="wrap TCP in TLS")
    ap.add_argument("--cert", default=None)
    ap.add_argument("--keyfile", default=None,
                    help="TLS private key file (not the shared secret)")
    args = ap.parse_args()
    key = args.key or os.environ.get("WARPSEND_KEY")
    if args.mode == "tcp":
        serve_tcp(args.host, args.port, key=key, tls=args.tls,
                  cert=args.cert, keyfile=args.keyfile)
    else:
        serve_udp(args.host, args.port, key=key)
