"""File-transfer server -- TCP mode and UDP mode.

Usage:
    python3 server.py --mode tcp --port 5000
    python3 server.py --mode udp --port 5000

TCP: reliability comes from the OS (ordering, no loss, no
duplicates), so the server just reads the header, then reads
exactly `filesize` bytes, verifies SHA-256 and replies OK/CORRUPT.

UDP: reliability is built here. Every datagram carries
    [type=1][seq (4B)][total (4B)][crc32 (4B)][data]
The server stores chunks by sequence number, ACKs each one
(duplicates are ignored), reorders at the end, then verifies
SHA-256. A lost packet is never ACKed, so the client resends it.
Packet types: 0 = header (JSON), 1 = data, 2 = EOF, 3 = ACK.
"""

import argparse
import json
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (CHUNK_TCP, crc32_of, progress, recv_header,
                   sha256_of_file)  # noqa: E402

OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received")


def _verify_and_reply(path, expected_hash, conn=None):
    """Compute SHA-256 of the received file, compare, report, reply."""
    got = sha256_of_file(path)
    ok = got == expected_hash
    print(f"expected SHA-256: {expected_hash}")
    print(f"received SHA-256: {got}")
    print("Transfer verified, file intact" if ok else
          "File corrupted -- checksum mismatch, ask sender to resend")
    if conn is not None:
        conn.sendall(b"OK" if ok else b"CORRUPT")
    return ok


def serve_tcp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        print(f"TCP server listening on {host}:{port} ...")
        conn, addr = srv.accept()
        with conn:
            print(f"connected: {addr}")
            header = recv_header(conn)
            name = os.path.basename(header["filename"])
            size = header["filesize"]
            print(f"receiving {name} ({size} bytes)")
            path = os.path.join(OUTDIR, name)
            os.makedirs(OUTDIR, exist_ok=True)
            received = 0
            with open(path, "wb") as f:
                while received < size:
                    chunk = conn.recv(min(CHUNK_TCP, size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    progress(received, size, label="receiving")
            print(f"saved to {path}")
            _verify_and_reply(path, header["checksum"], conn)


def serve_udp(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"UDP server listening on {host}:{port} ...")
        chunks, total, header = {}, None, None
        while True:
            packet, addr = sock.recvfrom(2048)
            ptype = packet[0]
            if ptype == 0:                       # header (JSON)
                header = json.loads(packet[1:])
                print(f"receiving {header['filename']} "
                      f"({header['filesize']} bytes)")
            elif ptype == 1:                     # data chunk
                seq, total, crc = struct.unpack("!III", packet[1:13])
                data = packet[13:]
                if crc32_of(data) != crc:
                    print(f"chunk {seq}: bad CRC32, dropped (no ACK)")
                    continue                     # no ACK -> client resends
                if seq not in chunks:            # ignore duplicates
                    chunks[seq] = data
                sock.sendto(b"\x03" + struct.pack("!I", seq), addr)
                progress(sum(len(c) for c in chunks.values()),
                         header["filesize"], label="receiving")
            elif ptype == 2:                     # EOF: all chunks sent
                break
        name = os.path.basename(header["filename"])
        path = os.path.join(OUTDIR, name)
        os.makedirs(OUTDIR, exist_ok=True)
        with open(path, "wb") as f:              # reassemble in order
            for seq in range(total):
                f.write(chunks[seq])
        print(f"saved to {path} ({len(chunks)}/{total} chunks)")
        ok = _verify_and_reply(path, header["checksum"])
        sock.sendto(b"SUCCESS" if ok else b"FAIL", addr)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-transfer server")
    ap.add_argument("--mode", choices=["tcp", "udp"], required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    if args.mode == "tcp":
        serve_tcp(args.host, args.port)
    else:
        serve_udp(args.host, args.port)
