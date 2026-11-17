"""WarpSend -- a fast file-transfer CLI over TCP / UDP (v1.6).

One command, two modes:

    warpsend send    notes.pdf --mode tcp --host 127.0.0.1 --port 5000
    warpsend receive --mode tcp --port 5000

    warpsend send    notes.pdf --mode udp
    warpsend receive --mode udp

Saved peers (~/.warpsend/config.toml):

    warpsend peer add laptop 192.168.1.10
    warpsend peer list
    warpsend send notes.pdf @laptop
    warpsend peer remove laptop

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
import socket
import sys

from .config import VERSION
from .identity import (
    default_cert_path,
    fingerprint_of_cert_file,
    generate_cert,
    short_code,
)
from .mdns import browse, discover_peer, sanitize_instance
from .peers import (
    add_peer,
    default_config_path,
    load_config,
    remove_peer,
    resolve_peer,
    resolve_target,
    save_config,
)
from .transfer import TransferCancelled, prompt_approve, send_tcp, send_udp, serve_tcp, serve_udp

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


def _key_from(args, config_key_file=None):
    """Shared secret, safest source first.

    --key-file, then WARPSEND_KEY, then the key file from the
    peer or [defaults] in the config, then --key (which warns:
    it shows up in process listings and shell history).
    """
    if getattr(args, "key_file", None):
        return _read_key_file(args.key_file)
    env_key = os.environ.get("WARPSEND_KEY")
    if env_key:
        return env_key
    if config_key_file:
        return _read_key_file(config_key_file)
    if getattr(args, "key", None):
        print(
            "warning: --key appears in process listings and shell "
            "history; prefer --key-file or WARPSEND_KEY",
            file=sys.stderr,
        )
        return args.key
    return None


def _extract_peer(files, peer_flag):
    """Pull an @name argument out of the file list.

    `warpsend send notes.pdf @laptop` -- the @name is the peer,
    not a file. --peer wins if both are given; a mismatch, or
    more than one @name, is an error. A file literally named
    "@x" must be spelled "./@x" to be sent as a file.
    """
    names = [f[1:] for f in files if f.startswith("@")]
    rest = [f for f in files if not f.startswith("@")]
    if len(names) > 1:
        raise ValueError("only one @peer per send")
    if names and peer_flag and names[0] != peer_flag:
        raise ValueError(f"--peer {peer_flag!r} conflicts with @{names[0]!r}")
    return (peer_flag or (names[0] if names else None)), rest


def _load_config():
    """(config, error): the config file, or the reason it failed."""
    try:
        return load_config(), None
    except (OSError, ValueError) as e:
        return None, e


def _add_common(p):
    p.add_argument(
        "--key",
        default=None,
        help="shared secret (or set WARPSEND_KEY); both sides must use the same one",
    )
    p.add_argument("--key-file", default=None, help="file containing the shared secret")


def _add_mode_args(p):
    p.add_argument(
        "--mode",
        choices=["tcp", "udp"],
        default=None,
        help="transfer mode (default: peer, [defaults], then tcp)",
    )
    p.add_argument(
        "--port", type=int, default=None, help="port to use (default: peer, [defaults], then 5000)"
    )


def _add_tls_args(p):
    p.add_argument(
        "--tls",
        action="store_true",
        default=None,
        help="wrap TCP in TLS (server needs a certificate)",
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
    send.add_argument(
        "--host", default=None, help="receiver host (default: peer, [defaults], then 127.0.0.1)"
    )
    send.add_argument(
        "--peer",
        default=None,
        help="saved peer to send to (or pass @name as a file argument)",
    )
    _add_mode_args(send)
    _add_common(send)
    _add_tls_args(send)
    _add_banner_opt(send)

    recv = sub.add_parser("receive", help="wait for files and save them")
    recv.add_argument(
        "--host", default=None, help="listen host (default: [defaults], then 0.0.0.0)"
    )
    _add_mode_args(recv)
    _add_common(recv)
    recv.add_argument("--tls", action="store_true", default=None, help="wrap TCP in TLS")
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
    recv.add_argument(
        "--approve",
        choices=["auto", "prompt"],
        default=None,
        help="per-file approval: prompt asks before accepting each file "
        "(default when stdin is a terminal), auto never asks "
        "(default when stdin is piped, e.g. scripts and CI)",
    )
    recv.add_argument(
        "--announce",
        nargs="?",
        const="",
        default=None,
        help="announce this receiver on the LAN via mDNS, so senders "
        "can find it by name (default name: this machine's hostname; "
        "pass a name to use that instead)",
    )
    _add_banner_opt(recv)

    disc = sub.add_parser("discover", help="find WarpSend receivers on the local network (mDNS)")
    disc.add_argument(
        "--timeout", type=float, default=3.0, help="seconds to listen for replies (default: 3)"
    )
    _add_banner_opt(disc)

    peer = sub.add_parser("peer", help="manage saved peers (~/.warpsend/config.toml)")
    peer_sub = peer.add_subparsers(dest="peer_command")
    peer_add = peer_sub.add_parser("add", help="save a peer")
    peer_add.add_argument("name", help="peer name (letters, digits, '-', '_')")
    peer_add.add_argument("host", help="hostname or IP address")
    peer_add.add_argument("--port", type=int, default=None, help="port (default: 5000)")
    peer_add.add_argument(
        "--mode", choices=["tcp", "udp"], default=None, help="mode (default: tcp)"
    )
    peer_add.add_argument("--tls", action="store_true", help="this peer uses TLS")
    peer_add.add_argument("--fingerprint", default=None, help="pinned server TLS fingerprint")
    peer_add.add_argument("--key-file", default=None, help="file containing the shared secret")
    peer_sub.add_parser("list", help="list saved peers")
    peer_rm = peer_sub.add_parser("remove", help="remove a saved peer")
    peer_rm.add_argument("name", help="peer name")
    _add_banner_opt(peer)

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

    if args.command == "peer":
        config, err = _load_config()
        if err is not None:
            print(f"could not load config: {err}")
            return 1
        path = default_config_path()
        if args.peer_command == "add":
            try:
                add_peer(
                    config,
                    args.name,
                    args.host,
                    port=args.port,
                    mode=args.mode,
                    tls=args.tls,
                    fingerprint=args.fingerprint,
                    key_file=args.key_file,
                )
                save_config(config, path)
            except ValueError as e:
                print(f"cannot add peer: {e}")
                return 1
            saved = resolve_peer(config, args.name)
            print(
                f"saved peer {args.name!r}: {saved['host']}:{saved.get('port', 5000)} "
                f"{saved.get('mode', 'tcp')}{' + TLS' if saved.get('tls') else ''} (config: {path})"
            )
            return 0
        if args.peer_command == "remove":
            try:
                remove_peer(config, args.name)
                save_config(config, path)
            except KeyError as e:
                print(e)
                return 1
            print(f"removed peer {args.name!r}")
            return 0
        # list (also the default for a bare `warpsend peer`)
        peers = config.get("peers", {})
        if not peers:
            print(f"no peers saved yet -- `warpsend peer add <name> <host>` (config: {path})")
        else:
            for name in sorted(peers):
                p = peers[name]
                print(
                    f"{name}: {p['host']}:{p.get('port', 5000)} "
                    f"{p.get('mode', 'tcp')}{' + TLS' if p.get('tls') else ''}"
                )
        return 0

    if args.command == "discover":
        try:
            found = browse(timeout=args.timeout)
        except OSError as e:
            print(f"mDNS is not available here: {e}")
            return 1
        if not found:
            print(f"no WarpSend receivers found on this network (listened {args.timeout:g}s)")
            return 0
        for p in found:
            print(
                f"{p['name']}: {p['host']}:{p['port']} {p['mode']}"
                f"{' + TLS' if p['tls'] else ''}"
                f"  (send with: warpsend send <file> @{p['name']})"
            )
        return 0

    if args.command == "send":
        config, err = _load_config()
        if err is not None:
            print(f"could not load config: {err}")
            return 1
        try:
            peer_name, files = _extract_peer(args.file, args.peer)
        except ValueError as e:
            print(f"error: {e}")
            return 1
        missing = [f for f in files if not os.path.isfile(f)]
        if missing:
            parser.error(f"file not found: {', '.join(missing)}")
        try:
            target = resolve_target(
                config,
                peer=peer_name,
                host=args.host,
                port=args.port,
                mode=args.mode,
                tls=args.tls,
                fingerprint=args.fingerprint,
                key_file=args.key_file,
            )
            key = _key_from(args, target["key_file"])
        except KeyError as e:
            if peer_name is None:
                print(f"error: {e}")
                return 1
            # Not saved -- maybe it is announcing on the LAN.
            print(f"peer {peer_name!r} is not saved -- looking for it on the LAN ...")
            try:
                found = discover_peer(peer_name, timeout=2.5)
            except OSError as mdns_err:
                print(f"error: {e} (mDNS unavailable: {mdns_err})")
                return 1
            if found is None:
                print(f"error: {e} (and no receiver named {peer_name!r} answered on the LAN)")
                return 1
            print(f"found {peer_name!r} on the LAN at {found['host']}:{found['port']}")
            try:
                target = resolve_target(
                    config,
                    host=args.host or found["host"],
                    port=args.port if args.port is not None else found["port"],
                    mode=args.mode or found["mode"],
                    tls=args.tls if args.tls is not None else found["tls"],
                    fingerprint=args.fingerprint or found["fingerprint"],
                    key_file=args.key_file,
                )
                key = _key_from(args, target["key_file"])
            except (ValueError, OSError) as e2:
                print(f"error: {e2}")
                return 1
        except (ValueError, OSError) as e:
            print(f"error: {e}")
            return 1
        failures = 0
        try:
            for path in files:
                print(
                    f">> sending {path} over {target['mode'].upper()} "
                    f"to {target['host']}:{target['port']}"
                )
                if target["mode"] == "tcp":
                    ok = send_tcp(
                        target["host"],
                        target["port"],
                        path,
                        key=key,
                        tls=target["tls"],
                        fingerprint=target["fingerprint"],
                        trust_new=args.trust_new,
                    )
                else:
                    if target["tls"]:
                        print("TLS is TCP-only; UDP sends are not encrypted")
                    ok = send_udp(target["host"], target["port"], path, key=key)
                if not ok:
                    failures += 1
        except (KeyboardInterrupt, TransferCancelled):
            # Ctrl-C: the socket closes on the way out, which is
            # the cancel signal -- the receiver keeps the .part
            # for resume. No traceback, exit code 130 (SIGINT).
            print(
                "\nCancelled -- partial kept on the receiver, send again to resume",
                file=sys.stderr,
            )
            return 130
        return 1 if failures else 0
    elif args.command == "receive":
        config, err = _load_config()
        if err is not None:
            print(f"could not load config: {err}")
            return 1
        try:
            target = resolve_target(
                config,
                host=args.host,
                port=args.port,
                mode=args.mode,
                tls=args.tls,
                outdir=args.outdir,
            )
            key = _key_from(args, target["key_file"])
        except (ValueError, OSError) as e:
            print(f"error: {e}")
            return 1
        print(
            f">> WarpSend receiver listening on "
            f"{target['host']}:{target['port']} over {target['mode'].upper()} ..."
        )
        if args.approve == "auto":
            approve = None
        elif args.approve == "prompt":
            approve = prompt_approve
        else:
            # Default: ask when run in a terminal, never ask when
            # stdin is piped or redirected (scripts, CI).
            approve = prompt_approve if sys.stdin.isatty() else None
        announce = None
        if args.announce is not None:
            # Bare --announce uses this machine's hostname.
            announce = sanitize_instance(args.announce or socket.gethostname())
        if target["mode"] == "tcp":
            serve_tcp(
                target["host"],
                target["port"],
                key=key,
                tls=target["tls"],
                cert=args.cert,
                keyfile=args.tls_key,
                outdir=target["outdir"],
                max_size=args.max_size,
                approve=approve,
                announce=announce,
            )
        else:
            if target["tls"]:
                print("TLS is TCP-only; UDP receives are not encrypted")
            serve_udp(
                target["host"],
                target["port"],
                key=key,
                outdir=target["outdir"],
                max_size=args.max_size,
                approve=approve,
                announce=announce,
            )
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
