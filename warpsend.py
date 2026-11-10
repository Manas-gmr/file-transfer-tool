#!/usr/bin/env python3
"""WarpSend -- a fast file-transfer CLI over TCP / UDP.

One command, two modes:

    warpsend send    notes.pdf --mode tcp --host 127.0.0.1 --port 5000
    warpsend receive --mode tcp --port 5000

    warpsend send    notes.pdf --mode udp
    warpsend receive --mode udp

Design:
  * TCP -- reliable by default. 64 KB chunks, the OS handles
    ordering, loss and duplicates.
  * UDP -- fast, with reliability built in the app: 1024-byte
    chunks, sequence numbers, per-chunk CRC32, ACKs and
    retransmission on timeout.
  * Both modes -- the sender's SHA-256 travels in the header and
    the receiver recomputes it after saving. A match means the
    file arrived intact.

Stdlib only -- no pip install needed to run it directly:
    python3 warpsend.py send notes.pdf
Install it as a real command with:
    pip install .
    warpsend send notes.pdf
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client import send_tcp, send_udp      # noqa: E402
from server import serve_tcp, serve_udp    # noqa: E402
from utils import VERSION, print_banner    # noqa: E402


def _add_mode_args(p):
    p.add_argument("--mode", choices=["tcp", "udp"], default="tcp",
                   help="transfer mode (default: tcp)")
    p.add_argument("--port", type=int, default=5000,
                   help="port to use (default: 5000)")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="warpsend",
        description="WarpSend -- send files at warp speed. "
                    "TCP for trust, UDP for speed, SHA-256 verified.")
    parser.add_argument("--version", action="version",
                        version=f"WarpSend v{VERSION}")
    parser.add_argument("--banner", action="store_true",
                        help="print the WarpSend logo and exit")
    parser.add_argument("--no-banner", action="store_true",
                        help="hide the logo")
    sub = parser.add_subparsers(dest="command")

    send = sub.add_parser("send", help="send a file to a WarpSend receiver")
    send.add_argument("file", help="file to send")
    send.add_argument("--host", default="127.0.0.1",
                      help="receiver host (default: 127.0.0.1)")
    _add_mode_args(send)

    recv = sub.add_parser("receive", help="wait for a file and save it")
    recv.add_argument("--host", default="0.0.0.0",
                      help="listen host (default: 0.0.0.0)")
    _add_mode_args(recv)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.banner:
        print_banner()
        return 0

    if not args.no_banner:
        print_banner()

    if args.command == "send":
        if not os.path.isfile(args.file):
            parser.error(f"file not found: {args.file}")
        print(f">> sending {args.file} over {args.mode.upper()} "
              f"to {args.host}:{args.port}")
        if args.mode == "tcp":
            send_tcp(args.host, args.port, args.file)
        else:
            send_udp(args.host, args.port, args.file)
    elif args.command == "receive":
        print(f">> WarpSend receiver listening on "
              f"{args.host}:{args.port} over {args.mode.upper()} ...")
        if args.mode == "tcp":
            serve_tcp(args.host, args.port)
        else:
            serve_udp(args.host, args.port)
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
