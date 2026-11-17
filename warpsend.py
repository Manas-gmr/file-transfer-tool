#!/usr/bin/env python3
"""WarpSend -- a fast file-transfer CLI over TCP / UDP (v1.1).

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

v1.1 (improvements taken from the Riptide comparison):
  * `.part` + rename: files land as `<name>.part` and are renamed
    only after the SHA-256 matches; existing files are never
    overwritten (`name (1).ext`).
  * TCP resume: re-send after a dropped connection and only the
    missing bytes go over the wire.
  * Persistent receiver: `receive` keeps listening for the next
    file until Ctrl-C, and accepts several files in one `send`.
  * Shared-key auth (`--key` or WARPSEND_KEY): HMAC-SHA256 over
    the header; a keyed receiver rejects anyone without it.
  * Optional TLS (`--tls`): stdlib ssl, self-signed cert from
    `warpsend cert`, fingerprint pinning with `--fingerprint`.
  * Progress now shows speed and ETA; UDP streams from disk
    instead of loading the whole file into memory.

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
from utils import (VERSION, default_cert_path, default_key_path,
                   fingerprint_of_cert_file, generate_cert, print_banner,
                   short_code)  # noqa: E402


def _key_from(args):
    return getattr(args, "key", None) or os.environ.get("WARPSEND_KEY")


def _add_banner_opt(p):
    # default=SUPPRESS so a top-level --no-banner is not clobbered
    # by the subparser's default when the flag is given before `send`.
    p.add_argument("--no-banner", action="store_true",
                   default=argparse.SUPPRESS, help="hide the logo")


def _add_common(p):
    p.add_argument("--key", default=None,
                   help="shared secret (or set WARPSEND_KEY); "
                        "both sides must use the same one")


def _add_mode_args(p):
    p.add_argument("--mode", choices=["tcp", "udp"], default="tcp",
                   help="transfer mode (default: tcp)")
    p.add_argument("--port", type=int, default=5000,
                   help="port to use (default: 5000)")


def _add_tls_args(p):
    p.add_argument("--tls", action="store_true",
                   help="wrap TCP in TLS (server needs a certificate)")
    p.add_argument("--fingerprint", default=None,
                   help="expected server TLS fingerprint (send side); "
                        "abort if it does not match")


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

    send = sub.add_parser("send", help="send file(s) to a WarpSend receiver")
    send.add_argument("file", nargs="+", help="file(s) to send")
    send.add_argument("--host", default="127.0.0.1",
                      help="receiver host (default: 127.0.0.1)")
    _add_mode_args(send)
    _add_common(send)
    _add_tls_args(send)
    _add_banner_opt(send)

    recv = sub.add_parser("receive", help="wait for files and save them")
    recv.add_argument("--host", default="0.0.0.0",
                      help="listen host (default: 0.0.0.0)")
    _add_mode_args(recv)
    _add_common(recv)
    recv.add_argument("--tls", action="store_true",
                      help="wrap TCP in TLS")
    recv.add_argument("--cert", default=None,
                      help="TLS certificate file (default: ~/.warpsend/cert.pem)")
    recv.add_argument("--tls-key", default=None, dest="tls_key",
                      help="TLS private key file (default: ~/.warpsend/key.pem)")
    _add_banner_opt(recv)

    cert = sub.add_parser("cert", help="generate a self-signed TLS certificate")
    cert.add_argument("--cert", default=None,
                      help="where to write the certificate "
                           "(default: ~/.warpsend/cert.pem)")
    cert.add_argument("--key", default=None,
                      help="where to write the private key "
                           "(default: ~/.warpsend/key.pem)")
    _add_banner_opt(cert)

    fp = sub.add_parser("fingerprint",
                        help="show the SHA-256 fingerprint of a certificate")
    fp.add_argument("--cert", default=None,
                    help="certificate file (default: ~/.warpsend/cert.pem)")
    _add_banner_opt(fp)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.banner:
        print_banner()
        return 0

    if not args.no_banner:
        print_banner()

    if args.command == "cert":
        try:
            cert_path, key_path, fp_hex = generate_cert(args.cert, args.key)
        except RuntimeError as e:
            print(f"could not generate a certificate: {e}")
            return 1
        print(f"certificate: {cert_path}")
        print(f"private key: {key_path} (0600, never share it)")
        print(f"fingerprint: {fp_hex}")
        print(f"code: {short_code(fp_hex)}  (share this with the sender, "
              f"or the full fingerprint for sensitive transfers)")
        print("start the receiver with: warpsend receive --tls")
        return 0

    if args.command == "fingerprint":
        cert_path = args.cert or default_cert_path()
        if not os.path.isfile(cert_path):
            print(f"no certificate at {cert_path} -- run `warpsend cert` first")
            return 1
        fp_hex = fingerprint_of_cert_file(cert_path)
        print(f"fingerprint: {fp_hex}")
        print(f"code: {short_code(fp_hex)}")
        return 0

    if args.command == "send":
        missing = [f for f in args.file if not os.path.isfile(f)]
        if missing:
            parser.error(f"file not found: {', '.join(missing)}")
        key = _key_from(args)
        failures = 0
        for path in args.file:
            print(f">> sending {path} over {args.mode.upper()} "
                  f"to {args.host}:{args.port}")
            if args.mode == "tcp":
                ok = send_tcp(args.host, args.port, path, key=key,
                              tls=args.tls, fingerprint=args.fingerprint)
            else:
                if args.tls:
                    print("TLS is TCP-only; UDP sends are not encrypted")
                ok = send_udp(args.host, args.port, path, key=key)
            if not ok:
                failures += 1
        return 1 if failures else 0
    elif args.command == "receive":
        print(f">> WarpSend receiver listening on "
              f"{args.host}:{args.port} over {args.mode.upper()} ...")
        key = _key_from(args)
        if args.mode == "tcp":
            serve_tcp(args.host, args.port, key=key, tls=args.tls,
                      cert=args.cert, keyfile=args.tls_key)
        else:
            if args.tls:
                print("TLS is TCP-only; UDP receives are not encrypted")
            serve_udp(args.host, args.port, key=key)
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
