"""File-transfer client -- TCP mode and UDP mode.

Usage:
    python3 client.py --mode tcp --file notes.pdf --host 127.0.0.1 --port 5000
    python3 client.py --mode udp --file notes.pdf --host 127.0.0.1 --port 5000

Both modes first compute the file's SHA-256 and send it in the
header, so the server can prove the file arrived intact.

TCP: send header, then the file in 64 KB chunks with sendall().
The OS guarantees order and delivery.

UDP: send header, then 1024-byte chunks, each with a sequence
number, total count and CRC32. Wait for an ACK per chunk
(stop-and-wait); on a 0.5 s timeout, resend (up to 5 tries).
Progress is updated on ACK, not on send -- otherwise it would
lie when a packet is lost. EOF packet ends the transfer.
"""

import argparse
import json
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import (CHUNK_TCP, CHUNK_UDP, crc32_of, progress,
                   send_header, sha256_of_file)  # noqa: E402

TIMEOUT = 0.5      # seconds to wait for a UDP ACK before resending
MAX_RETRIES = 5


def send_tcp(host, port, path):
    size = os.path.getsize(path)
    checksum = sha256_of_file(path)
    print(f"{os.path.basename(path)}: {size} bytes, SHA-256 {checksum}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        send_header(sock, os.path.basename(path), size, checksum)
        sent = 0
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_TCP):
                sock.sendall(chunk)
                sent += len(chunk)
                progress(sent, size, label="sending")
        print("server says:", sock.recv(16).decode())


def send_udp(host, port, path):
    size = os.path.getsize(path)
    checksum = sha256_of_file(path)
    data = open(path, "rb").read()
    chunks = [data[i:i + CHUNK_UDP]
              for i in range(0, len(data), CHUNK_UDP)] or [b""]
    total = len(chunks)
    print(f"{os.path.basename(path)}: {size} bytes, "
          f"{total} chunks, SHA-256 {checksum}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        # header packet: type 0 + JSON
        header = json.dumps({"filename": os.path.basename(path),
                             "filesize": size,
                             "checksum": checksum}).encode()
        sock.sendto(b"\x00" + header, (host, port))
        acked = 0
        for seq, chunk in enumerate(chunks):
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
                return
        sock.sendto(b"\x02", (host, port))       # EOF
        try:
            print("server says:", sock.recvfrom(64)[0].decode())
        except socket.timeout:
            print("no final reply from server (file may still be saved)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-transfer client")
    ap.add_argument("--mode", choices=["tcp", "udp"], required=True)
    ap.add_argument("--file", required=True, help="file to send")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()
    if not os.path.isfile(args.file):
        sys.exit(f"file not found: {args.file}")
    if args.mode == "tcp":
        send_tcp(args.host, args.port, args.file)
    else:
        send_udp(args.host, args.port, args.file)
