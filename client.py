"""Legacy import shim (v1.3 moved the code into src/warpsend/).

Old code that did `from client import send_tcp` keeps working.
New code should import from the package instead:

    from warpsend.transfer import send_tcp, send_udp
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src"))

from warpsend.config import UDP_MAX_RETRIES, UDP_TIMEOUT  # noqa: E402,F401
from warpsend.transfer import MAX_RETRIES, TIMEOUT, send_tcp, send_udp  # noqa: E402,F401

__all__ = ["send_tcp", "send_udp", "TIMEOUT", "MAX_RETRIES"]

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
