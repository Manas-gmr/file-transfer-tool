"""WarpSend -- a fast file-transfer CLI over TCP / UDP (v1.4).

One command, two modes:

    warpsend send    notes.pdf --mode tcp --host 127.0.0.1 --port 5000
    warpsend receive --mode tcp --port 5000

    warpsend send    notes.pdf --mode udp
    warpsend receive --mode udp

Design:
  * TCP -- reliable by default. 256 KB chunks, the OS handles
    ordering, loss and duplicates.
  * UDP -- fast, with reliability built in the app: 1024-byte
    chunks, sequence numbers, per-chunk CRC32, ACKs and
    retransmission on timeout.
  * Both modes -- the sender's SHA-256 travels in the header and
    the receiver recomputes it after saving. A match means the
    file arrived intact.

Stdlib only -- no pip install needed to run it from a checkout:
    python -m warpsend send notes.pdf
Install it as a real command with:
    pip install .
    warpsend send notes.pdf
"""

import argparse
import logging
import os
import sys

from .config import VERSION
from .identity import (
    default_cert_path,
    fingerprint_of_cert_file,
    generate_cert,
    short_code,
)
from .transfer import send_tcp, send_udp, serve_tcp, serve_udp

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


def _read_key_file(path):
    with open(path) as f:
        return f.read().strip()


def _key_from(args):
    """Shared secret, safest source first.

    --key-file, then WARPSEND_KEY, then --key (which warns:
    it shows up in process listings and shell history).
    """
    if getattr(args, "key_file", None):
        return _read_key_file(args.key_file)
    env_key = os.environ.get("WARPSEND_KEY")
    if env_key:
        return env_key
    if getattr(args, "key", None):
        print(
            "warning: --key appears in process listings and shell "
            "history; prefer --key-file or WARPSEND_KEY",
            file=sys.stderr,
        )
        return args.key
    return None


def _add_common(p):
    p.add_argument(
        "--key",
        default=None,
        help="shared secret (or set WARPSEND_KEY); both sides must use the same one",
    )
    p.add_argument("--key-file", default=None, help="file containing the shared secret")


def _add_mode_args(p):
    p.add_argument(
        "--mode", choices=["tcp", "udp"], default="tcp", help="transfer mode (default: tcp)"
    )
    p.add_argument("--port", type=int, default=5000, help="port to use (default: 5000)")


def _add_tls_args(p):
    p.add_argument(
        "--tls", action="store_true", help="wrap TCP in TLS (server needs a certificate)"
    )
    p.add_argument(
        "--fingerprint",
        default=None,
        help="expected server TLS fingerprint (send side); abort if it does not match",
    )
    p.add_argument(
        "--trust-new",
        action="store_true",
        help="trust a new TLS host once and remember it in the known-hosts file",
    )


def _add_banner_opt(p):
    # default=SUPPRESS so a top-level --no-banner is not clobbered
    # by the subparser's default when the flag is given before `send`.
    p.add_argument(
        "--no-banner", action="store_true", default=argparse.SUPPRESS, help="hide the logo"
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="warpsend",
        description="WarpSend -- send files at warp speed. "
        "TCP for trust, UDP for speed, SHA-256 verified.",
    )
    parser.add_argument("--version", action="version", version=f"WarpSend v{VERSION}")
    parser.add_argument("--banner", action="store_true", help="print the WarpSend logo and exit")
    parser.add_argument("--no-banner", action="store_true", help="hide the logo")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log connection, auth and transfer events to stderr (level DEBUG)",
    )
    sub = parser.add_subparsers(dest="command")

    send = sub.add_parser("send", help="send file(s) to a WarpSend receiver")
    send.add_argument("file", nargs="+", help="file(s) to send")
    send.add_argument("--host", default="127.0.0.1", help="receiver host (default: 127.0.0.1)")
    _add_mode_args(send)
    _add_common(send)
    _add_tls_args(send)
    _add_banner_opt(send)

    recv = sub.add_parser("receive", help="wait for files and save them")
    recv.add_argument("--host", default="0.0.0.0", help="listen host (default: 0.0.0.0)")
    _add_mode_args(recv)
    _add_common(recv)
    recv.add_argument("--tls", action="store_true", help="wrap TCP in TLS")
    recv.add_argument(
        "--cert", default=None, help="TLS certificate file (default: ~/.warpsend/cert.pem)"
    )
    recv.add_argument(
        "--tls-key",
        default=None,
        dest="tls_key",
        help="TLS private key file (default: ~/.warpsend/key.pem)",
    )
    recv.add_argument(
        "--outdir", default=None, help="where received files go (default: ./received)"
    )
    recv.add_argument(
        "--max-size",
        type=int,
        default=0,
        help="reject files larger than this many bytes (0 = no limit besides free disk space)",
    )
    _add_banner_opt(recv)

    cert = sub.add_parser("cert", help="generate a self-signed TLS certificate")
    cert.add_argument(
        "--cert",
        default=None,
        help="where to write the certificate (default: ~/.warpsend/cert.pem)",
    )
    cert.add_argument(
        "--key", default=None, help="where to write the private key (default: ~/.warpsend/key.pem)"
    )
    _add_banner_opt(cert)

    fp = sub.add_parser("fingerprint", help="show the SHA-256 fingerprint of a certificate")
    fp.add_argument("--cert", default=None, help="certificate file (default: ~/.warpsend/cert.pem)")
    _add_banner_opt(fp)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            stream=sys.stderr,
        )
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
        print(
            f"code: {short_code(fp_hex)}  (share this with the sender, "
            f"or the full fingerprint for sensitive transfers)"
        )
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
            print(f">> sending {path} over {args.mode.upper()} to {args.host}:{args.port}")
            if args.mode == "tcp":
                ok = send_tcp(
                    args.host,
                    args.port,
                    path,
                    key=key,
                    tls=args.tls,
                    fingerprint=args.fingerprint,
                    trust_new=args.trust_new,
                )
            else:
                if args.tls:
                    print("TLS is TCP-only; UDP sends are not encrypted")
                ok = send_udp(args.host, args.port, path, key=key)
            if not ok:
                failures += 1
        return 1 if failures else 0
    elif args.command == "receive":
        print(
            f">> WarpSend receiver listening on "
            f"{args.host}:{args.port} over {args.mode.upper()} ..."
        )
        key = _key_from(args)
        if args.mode == "tcp":
            serve_tcp(
                args.host,
                args.port,
                key=key,
                tls=args.tls,
                cert=args.cert,
                keyfile=args.tls_key,
                outdir=args.outdir,
                max_size=args.max_size,
            )
        else:
            if args.tls:
                print("TLS is TCP-only; UDP receives are not encrypted")
            serve_udp(args.host, args.port, key=key, outdir=args.outdir, max_size=args.max_size)
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
