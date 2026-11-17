"""Legacy import shim (v1.3 moved the code into src/warpsend/).

Old code that did `from server import serve_tcp` keeps working.
New code should import from the package instead:

    from warpsend.transfer import serve_tcp, serve_udp
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src"))

from warpsend.config import CONN_TIMEOUT, UDP_IDLE_TIMEOUT  # noqa: E402,F401
from warpsend.transfer import OUTDIR, serve_tcp, serve_udp  # noqa: E402,F401

__all__ = ["serve_tcp", "serve_udp", "OUTDIR", "CONN_TIMEOUT",
           "UDP_IDLE_TIMEOUT"]

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
