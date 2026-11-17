"""WarpSend v1.9.2 tests -- run from the project directory:

    python3 tests/test_warpsend.py
    python -m pytest tests/ -v

Starts real TCP servers on localhost in background threads and
checks: fresh transfer, no-overwrite, TCP resume, a complete
.part being finalised, shared-key auth, TLS with a pinned
fingerprint, TLS trust-on-first-use, malformed headers keeping
the server alive, and the client exit code following the
server's CORRUPT verdict. v1.5 adds: receiver approval
(accept and decline, TCP and UDP), sender cancel keeping the
.part with the server staying alive, Ctrl-C exiting 130 with
no traceback (POSIX only), and protocol v3 enforcement.
v1.6 adds: saved peers and config file (add/list/remove,
@peer sends, flag > peer > defaults > built-in precedence,
malformed config rejected). v1.7 adds: mDNS discovery --
packet encode/decode roundtrips, compression pointers, the
query answerer, a live announce+browse (skips where multicast
is blocked, as in this sandbox), and proof that a failed
announce never kills the receiver. v1.8 adds: bidirectional
sessions -- frame roundtrips, two-way transfer on one
connection, decline with no file, resume of a half .part,
wrong-key auth rejection, and a CLI two-way test with two
real subprocesses. v1.9 adds: the Textual TUI -- peer
merge/label/target helpers, and a pilot test that queues a
file in the app and sends it to a live receiver. UDP tests run when loopback datagrams
are allowed (they are on CI runners) and skip gracefully
when they are blocked, as in this sandbox.
"""

import asyncio
import contextlib
import io
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from warpsend.cli import main
from warpsend.config import PROTOCOL_VERSION
from warpsend.identity import generate_cert
from warpsend.mdns import (
    SERVICE,
    TYPE_A,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    answer_query,
    browse,
    build_announcement,
    build_query,
    parse_message,
    start_announcer,
)
from warpsend.peers import (
    add_peer,
    load_config,
    remove_peer,
    resolve_peer,
    resolve_target,
    save_config,
)
from warpsend.protocol import validate_header
from warpsend.session import join_session, recv_frame, send_data_frame, send_frame, serve_session
from warpsend.transfer import (
    TransferCancelled,
    part_path,
    progress,
    resume_offset,
    save_meta,
    send_tcp,
    send_udp,
    serve_tcp,
    serve_udp,
    sha256_of_file,
)
from warpsend.tui import WarpSendApp, merge_peers, peer_label, target_for_peer

try:
    import textual  # noqa: F401

    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_file(name, size, byte=b"A"):
    path = os.path.join(tempfile.gettempdir(), name)
    with open(path, "wb") as f:
        f.write(byte * size)
    return path


def wait_for_file(path, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if os.path.isfile(path):
            return True
        time.sleep(0.1)
    return False


def temp_outdir():
    return tempfile.mkdtemp(prefix="warpsend-out-")


def start_tcp(port, outdir, **kwargs):
    threading.Thread(
        target=serve_tcp, args=("127.0.0.1", port), kwargs={"outdir": outdir, **kwargs}, daemon=True
    ).start()
    time.sleep(0.3)


def test_fresh_and_no_overwrite():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)
    src = make_file("ws-test.txt", 200_000)
    assert send_tcp("127.0.0.1", port, src), "fresh send failed"
    assert wait_for_file(os.path.join(outdir, "ws-test.txt"))
    assert sha256_of_file(os.path.join(outdir, "ws-test.txt")) == sha256_of_file(src)
    # Second send of the same name must not overwrite the first.
    assert send_tcp("127.0.0.1", port, src), "second send failed"
    assert wait_for_file(os.path.join(outdir, "ws-test (1).txt"))
    assert sha256_of_file(os.path.join(outdir, "ws-test (1).txt")) == sha256_of_file(src)
    print("ok: fresh transfer + no-overwrite")


def test_resume():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)
    src = make_file("ws-resume.bin", 300_000, byte=b"R")
    digest = sha256_of_file(src)
    # Simulate a dropped connection halfway: .part + metadata.
    with open(src, "rb") as f:
        prefix = f.read(120_000)
    with open(part_path(outdir, "ws-resume.bin"), "wb") as f:
        f.write(prefix)
    save_meta(outdir, "ws-resume.bin", 300_000, digest)
    assert send_tcp("127.0.0.1", port, src), "resume send failed"
    final = os.path.join(outdir, "ws-resume.bin")
    assert wait_for_file(final)
    assert sha256_of_file(final) == digest, "resumed file hash mismatch"
    assert not os.path.exists(part_path(outdir, "ws-resume.bin"))
    print("ok: TCP resume from .part")


def test_complete_part_finalised():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)
    src = make_file("ws-done.bin", 100_000, byte=b"D")
    digest = sha256_of_file(src)
    # Simulate a crash after the last byte but before rename.
    shutil.copyfile(src, part_path(outdir, "ws-done.bin"))
    save_meta(outdir, "ws-done.bin", 100_000, digest)
    assert resume_offset(outdir, "ws-done.bin", 100_000, digest) == 100_000
    assert send_tcp("127.0.0.1", port, src), "complete-part send failed"
    final = os.path.join(outdir, "ws-done.bin")
    assert wait_for_file(final)
    assert sha256_of_file(final) == digest
    assert not os.path.exists(part_path(outdir, "ws-done.bin"))
    print("ok: complete .part verified and finalised (DONE)")


def test_auth_reject():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir, key="correct-horse")
    src = make_file("ws-auth.txt", 1_000)
    assert not send_tcp("127.0.0.1", port, src, key="wrong-key"), "server accepted a wrong key"
    assert not os.path.exists(os.path.join(outdir, "ws-auth.txt"))
    assert send_tcp("127.0.0.1", port, src, key="correct-horse"), "server rejected the right key"
    assert wait_for_file(os.path.join(outdir, "ws-auth.txt"))
    print("ok: shared-key auth (reject wrong, accept right)")


def _tls_server(port, outdir):
    tmp = tempfile.mkdtemp()
    cert, keyfile, fp = generate_cert(os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem"))
    start_tcp(port, outdir, tls=True, cert=cert, keyfile=keyfile)
    return fp, os.path.join(tmp, "known_hosts.json")


def test_tls_pinned_and_tofu():
    outdir = temp_outdir()
    port = free_port()
    fp, known = _tls_server(port, outdir)
    src = make_file("ws-tls.txt", 50_000, byte=b"T")
    # No fingerprint, no --trust-new: must abort, nothing saved.
    assert not send_tcp("127.0.0.1", port, src, tls=True, known_hosts_path=known), (
        "TLS sent a file to an unverified host"
    )
    assert not os.path.exists(os.path.join(outdir, "ws-tls.txt"))
    # Wrong fingerprint: abort.
    assert not send_tcp(
        "127.0.0.1", port, src, tls=True, fingerprint="00" * 32, known_hosts_path=known
    ), "TLS accepted a bad fingerprint"
    # Right fingerprint: succeeds and remembers the host.
    assert send_tcp("127.0.0.1", port, src, tls=True, fingerprint=fp, known_hosts_path=known), (
        "TLS failed with the right fingerprint"
    )
    assert wait_for_file(os.path.join(outdir, "ws-tls.txt"))
    assert sha256_of_file(os.path.join(outdir, "ws-tls.txt")) == sha256_of_file(src)
    with open(known) as f:
        assert json.load(f).get("127.0.0.1") == fp
    # A changed cert for the same host must now abort loudly.
    port2 = free_port()
    fp2, _ = _tls_server(port2, temp_outdir())
    assert fp2 != fp
    assert not send_tcp("127.0.0.1", port2, src, tls=True, known_hosts_path=known), (
        "TLS accepted a changed fingerprint for a known host"
    )
    print("ok: TLS pinned fingerprint + trust-on-first-use")


def test_malformed_header_keeps_server_alive():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)

    def raw(payload: bytes):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.settimeout(2)
            try:
                s.recv(128)  # the CHALLENGE line; ignore it
            except TimeoutError:
                pass
            s.sendall(payload)

    # Header claiming 2 GB: rejected before allocation.
    raw(struct.pack("!I", 2_000_000_000))
    # Bad JSON, missing keys, wrong types.
    raw(struct.pack("!I", 8) + b"not json")
    raw(struct.pack("!I", len(b'{"filename": "x"}')) + b'{"filename": "x"}')
    raw(
        struct.pack("!I", len(b'{"filename": "x", "filesize": "big", "checksum": "00"}'))
        + b'{"filename": "x", "filesize": "big", "checksum": "00"}'
    )
    time.sleep(0.3)
    # The server must still be alive for a normal transfer.
    src = make_file("ws-alive.txt", 5_000)
    assert send_tcp("127.0.0.1", port, src), "server died on bad headers"
    assert wait_for_file(os.path.join(outdir, "ws-alive.txt"))
    print("ok: malformed headers dropped, server stays alive")


def test_corrupt_verdict_is_failure():
    # A fake server that always answers CORRUPT: the client
    # must return False (exit code 1), not True.
    port = free_port()

    def fake_server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                conn.sendall(b"CHALLENGE abc\n")
                raw_len = conn.recv(4)
                (length,) = struct.unpack("!I", raw_len)
                buf = b""
                while len(buf) < length:
                    part = conn.recv(length - len(buf))
                    if not part:
                        break
                    buf += part
                header = json.loads(buf)
                conn.sendall(b"FRESH 0\n")
                remaining = header["filesize"]
                while remaining > 0:
                    chunk = conn.recv(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                conn.sendall(b"CORRUPT")

    threading.Thread(target=fake_server, daemon=True).start()
    time.sleep(0.3)
    src = make_file("ws-corrupt.txt", 10_000)
    assert not send_tcp("127.0.0.1", port, src), "client reported success on a CORRUPT verdict"
    print("ok: CORRUPT verdict -> client failure (exit code 1)")


def test_validate_header():
    good = validate_header(
        {"filename": "a.txt", "filesize": 10, "checksum": "ab" * 32, "protocol": 3}
    )
    assert good["filename"] == "a.txt" and good["filesize"] == 10
    for bad in (
        {},
        {"filename": "a.txt"},
        {"filename": "", "filesize": 1, "checksum": "ab" * 32},
        {"filename": "..", "filesize": 1, "checksum": "ab" * 32},
        {"filename": "a.txt", "filesize": -1, "checksum": "ab" * 32},
        {"filename": "a.txt", "filesize": "10", "checksum": "ab" * 32},
        {"filename": "a.txt", "filesize": 1, "checksum": "xyz"},
        {"filename": "a.txt", "filesize": 1, "checksum": "ab" * 32, "protocol": 99},
        {"filename": "a.txt", "filesize": 1, "checksum": "ab" * 32, "protocol": 2},
        {"filename": "a.txt", "filesize": 1, "checksum": "ab" * 32},
    ):
        try:
            validate_header(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"validate_header accepted {bad!r}")
    # Progress with a resume base must not crash or inflate.
    progress(150_000, 300_000, label="test-progress", base=120_000)
    progress(300_000, 300_000, label="test-progress", base=120_000)
    print("ok: header validation + resume-aware progress")


def _udp_allowed():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"hi", ("127.0.0.1", 5002))
        return True
    except OSError:
        return False


def test_udp_transfer_and_state_reset():
    if not _udp_allowed():
        print("skip: UDP datagrams blocked in this sandbox (runs on CI)")
        return
    outdir = temp_outdir()
    port = free_port()
    threading.Thread(
        target=serve_udp, args=("127.0.0.1", port), kwargs={"outdir": outdir}, daemon=True
    ).start()
    time.sleep(0.3)
    # Abandon a transfer midway (header + one chunk, no EOF).
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        header = json.dumps(
            {
                "filename": "ws-abandoned.txt",
                "filesize": 5000,
                "checksum": "ab" * 32,
                "protocol": PROTOCOL_VERSION,
                "nonce": "n1",
            }
        ).encode()
        s.sendto(b"\x00" + header, ("127.0.0.1", port))
        try:
            s.recvfrom(64)  # header ACK
        except TimeoutError:
            pass
        import zlib

        chunk = b"A" * 1024
        s.sendto(
            b"\x01" + struct.pack("!III", 0, 5, zlib.crc32(chunk)) + chunk, ("127.0.0.1", port)
        )
    # A full transfer of a different file must not pick up the
    # abandoned file's chunks.
    src = make_file("ws-udp.txt", 5_000, byte=b"U")
    assert send_udp("127.0.0.1", port, src), "UDP send failed"
    final = os.path.join(outdir, "ws-udp.txt")
    assert wait_for_file(final)
    assert sha256_of_file(final) == sha256_of_file(src)
    print("ok: UDP transfer + state reset after abandoned transfer")


def test_package_layout():
    import warpsend

    assert warpsend.__version__ == "1.9.2"
    assert warpsend.PROTOCOL_VERSION == 3
    # The old flat modules are gone: importing one must fail,
    # so a stale `python3 server.py` cannot silently run old code.
    for stale in ("client", "server", "utils"):
        try:
            __import__(stale)
        except ImportError:
            pass
        else:
            raise AssertionError(f"stale top-level module {stale!r} still importable")
    print("ok: src/warpsend layout, no stale flat modules")


def test_receiver_rejects_when_approval_declines():
    outdir = temp_outdir()
    port = free_port()
    seen = []

    def decline(header, addr):
        seen.append(header["filename"])
        return False

    start_tcp(port, outdir, approve=decline)
    src = make_file("ws-declined.txt", 5_000)
    assert not send_tcp("127.0.0.1", port, src), "server accepted a declined file"
    assert seen == ["ws-declined.txt"], "approval hook never saw the header"
    assert not os.path.exists(os.path.join(outdir, "ws-declined.txt"))
    assert not os.path.exists(part_path(outdir, "ws-declined.txt"))
    print("ok: receiver approval decline (no file, no .part)")


def test_receiver_accepts_when_approval_accepts():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir, approve=lambda h, a: True)
    src = make_file("ws-accepted.txt", 5_000)
    assert send_tcp("127.0.0.1", port, src), "server rejected an accepted file"
    assert wait_for_file(os.path.join(outdir, "ws-accepted.txt"))
    assert sha256_of_file(os.path.join(outdir, "ws-accepted.txt")) == sha256_of_file(src)
    print("ok: receiver approval accept")


def test_sender_cancel_keeps_part_and_server_alive():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)
    src = make_file("ws-cancel.bin", 5_000_000, byte=b"X")
    cancel = threading.Event()
    cancel.set()  # cancel before the first chunk: deterministic
    try:
        send_tcp("127.0.0.1", port, src, cancel=cancel)
    except TransferCancelled:
        pass
    else:
        raise AssertionError("cancelled send did not raise TransferCancelled")
    assert os.path.exists(part_path(outdir, "ws-cancel.bin")), ".part missing after cancel"
    # The server must still be alive for the next transfer.
    src2 = make_file("ws-after-cancel.txt", 5_000)
    assert send_tcp("127.0.0.1", port, src2), "server died after a cancelled transfer"
    assert wait_for_file(os.path.join(outdir, "ws-after-cancel.txt"))
    print("ok: sender cancel keeps .part, server stays alive")


def test_ctrl_c_send_exits_130():
    # Ctrl-C mid-send must exit 130 with a clean message, no traceback.
    # POSIX only: SIGINT delivery to a subprocess is not reliable on Windows.
    if os.name == "nt":
        print("skip: Ctrl-C exit-code test is POSIX-only (runs on Linux/macOS CI)")
        return
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)
    # 500 MB: hashing alone takes longer than the wait below, so the
    # SIGINT is guaranteed to land mid-transfer, not after it.
    # Sparse file (truncate): no disk used, but hashing still reads
    # 500 MB of zeros -- /tmp here is a small tmpfs.
    src = os.path.join(tempfile.gettempdir(), "ws-big.bin")
    with open(src, "wb") as f:
        f.truncate(500 * 1024 * 1024)
    env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "src"))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "warpsend",
            "send",
            src,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-banner",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    time.sleep(0.5)
    proc.send_signal(signal.SIGINT)
    _, stderr = proc.communicate(timeout=30)
    assert proc.returncode == 130, f"Ctrl-C exit code was {proc.returncode}"
    assert b"Traceback" not in stderr, "Ctrl-C printed a traceback"
    assert b"Cancelled" in stderr, "Ctrl-C printed no cancel message"
    try:
        os.remove(src)
    except OSError:
        pass
    print("ok: Ctrl-C during send exits 130, no traceback")


def test_udp_receiver_rejects_when_approval_declines():
    if not _udp_allowed():
        print("skip: UDP datagrams blocked in this sandbox (runs on CI)")
        return
    outdir = temp_outdir()
    port = free_port()
    threading.Thread(
        target=serve_udp,
        args=("127.0.0.1", port),
        kwargs={"outdir": outdir, "approve": lambda h, a: False},
        daemon=True,
    ).start()
    time.sleep(0.3)
    src = make_file("ws-udp-reject.txt", 5_000, byte=b"J")
    assert not send_udp("127.0.0.1", port, src), "UDP server accepted a declined file"
    assert not os.path.exists(os.path.join(outdir, "ws-udp-reject.txt"))
    assert not os.path.exists(part_path(outdir, "ws-udp-reject.txt"))
    print("ok: UDP receiver approval decline (no file, no .part)")


def temp_config_path():
    return os.path.join(tempfile.mkdtemp(prefix="warpsend-cfg-"), "config.toml")


def test_peer_add_list_remove_roundtrip():
    path = temp_config_path()
    cfg = load_config(path)
    assert cfg == {"defaults": {}, "peers": {}}, "missing config file should load empty"
    add_peer(cfg, "laptop", "192.168.1.10", port=5000, mode="tcp")
    add_peer(cfg, "pi", "192.168.1.20", tls=True, fingerprint="ab" * 32)
    save_config(cfg, path)
    assert oct(os.stat(path).st_mode & 0o777) == "0o600", "config file must be 0600"
    loaded = load_config(path)
    assert loaded["peers"]["laptop"] == {"host": "192.168.1.10", "port": 5000, "mode": "tcp"}
    assert loaded["peers"]["pi"]["tls"] is True
    assert loaded["peers"]["pi"]["fingerprint"] == "ab" * 32
    assert resolve_peer(loaded, "laptop")["host"] == "192.168.1.10"
    remove_peer(loaded, "pi")
    save_config(loaded, path)
    assert "pi" not in load_config(path)["peers"]
    assert "laptop" in load_config(path)["peers"]
    print("ok: peer add/list/remove roundtrip (0600 config)")


def test_peer_validation():
    cfg = {"defaults": {}, "peers": {}}
    for bad_name in ("", "a b", "../x", "-x", "a/b"):
        try:
            add_peer(cfg, bad_name, "127.0.0.1")
        except ValueError:
            pass
        else:
            raise AssertionError(f"peer name {bad_name!r} accepted")
    add_peer(cfg, "ok", "127.0.0.1")
    try:
        add_peer(cfg, "ok", "127.0.0.1")
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate peer accepted")
    for bad in (
        {"host": "127.0.0.1", "port": 0},
        {"host": "127.0.0.1", "port": 70000},
        {"host": "127.0.0.1", "mode": "sctp"},
        {"host": "127.0.0.1", "fingerprint": "xyz"},
        {"host": "has space"},
    ):
        try:
            add_peer(cfg, "t", **{k: v for k, v in bad.items() if k != "host"}, host=bad["host"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"peer fields {bad!r} accepted")
    try:
        remove_peer(cfg, "nope")
    except KeyError as e:
        assert "ok" in str(e), "unknown-peer error should name the known peers"
    else:
        raise AssertionError("removing an unknown peer did not raise")
    print("ok: peer validation (names, ports, modes, fingerprints, unknown keys)")


def test_resolve_target_precedence():
    cfg = {
        "defaults": {"host": "10.0.0.1", "port": 6000, "mode": "udp"},
        "peers": {"laptop": {"host": "192.168.1.10", "port": 5001, "mode": "tcp"}},
    }
    # Built-ins only.
    t = resolve_target({"defaults": {}, "peers": {}})
    assert (t["host"], t["port"], t["mode"]) == ("127.0.0.1", 5000, "tcp")
    t = resolve_target({"defaults": {}, "peers": {}}, receive=True)
    assert t["host"] == "0.0.0.0", "receive default host must be 0.0.0.0"
    # Defaults fill the gaps.
    t = resolve_target(cfg)
    assert (t["host"], t["port"], t["mode"]) == ("10.0.0.1", 6000, "udp")
    # Peer beats defaults.
    t = resolve_target(cfg, peer="laptop")
    assert (t["host"], t["port"], t["mode"]) == ("192.168.1.10", 5001, "tcp")
    # Explicit flags beat peer and defaults.
    t = resolve_target(cfg, peer="laptop", host="8.8.8.8", port=7000, mode="udp")
    assert (t["host"], t["port"], t["mode"]) == ("8.8.8.8", 7000, "udp")
    # Unknown peer names its known peers.
    try:
        resolve_target(cfg, peer="nope")
    except KeyError as e:
        assert "laptop" in str(e)
    else:
        raise AssertionError("unknown peer did not raise")
    print("ok: resolve precedence (flag > peer > defaults > built-in)")


def test_config_defaults_applied():
    path = temp_config_path()
    cfg = {"defaults": {"host": "10.1.1.1", "port": 7001, "mode": "udp"}, "peers": {}}
    save_config(cfg, path)
    loaded = load_config(path)
    t = resolve_target(loaded)
    assert (t["host"], t["port"], t["mode"]) == ("10.1.1.1", 7001, "udp")
    print("ok: [defaults] applied on load")


def test_malformed_config_rejected():
    path = temp_config_path()
    with open(path, "w") as f:
        f.write("this is [not valid toml")
    try:
        load_config(path)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed TOML accepted")
    with open(path, "w") as f:
        f.write('[peers.laptop]\nhost = "127.0.0.1"\nbogus = 1\n')
    try:
        load_config(path)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown key accepted")
    with open(path, "w") as f:
        f.write("[peers.laptop]\nport = 5000\n")
    try:
        load_config(path)
    except ValueError:
        pass
    else:
        raise AssertionError("peer without a host accepted")
    print("ok: malformed config rejected (bad TOML, unknown key, missing host)")


def test_cli_peer_send_end_to_end():
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir)
    cfg_path = temp_config_path()
    old = os.environ.get("WARPSEND_CONFIG")
    os.environ["WARPSEND_CONFIG"] = cfg_path
    try:
        assert main(["--no-banner", "peer", "add", "local", "127.0.0.1", "--port", str(port)]) == 0
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            assert main(["--no-banner", "peer", "list"]) == 0
        assert "local" in buf.getvalue() and "127.0.0.1" in buf.getvalue()
        src = make_file("ws-peer.txt", 5_000)
        assert main(["--no-banner", "send", src, "@local"]) == 0, "@peer send failed"
        assert wait_for_file(os.path.join(outdir, "ws-peer.txt"))
        assert sha256_of_file(os.path.join(outdir, "ws-peer.txt")) == sha256_of_file(src)
        # Unknown peer: clean failure, exit 1.
        assert main(["--no-banner", "send", src, "@nope"]) == 1, "unknown peer did not fail"
        assert main(["--no-banner", "peer", "remove", "local"]) == 0
        assert "local" not in load_config(cfg_path)["peers"]
    finally:
        if old is None:
            os.environ.pop("WARPSEND_CONFIG", None)
        else:
            os.environ["WARPSEND_CONFIG"] = old
    print("ok: CLI peer add/list/send @peer/remove end to end")


def test_mdns_encode_decode_roundtrip():
    query = build_query()
    parsed = parse_message(query)
    assert len(parsed["questions"]) == 1
    name, qtype, qclass = parsed["questions"][0]
    assert name == SERVICE and qtype == TYPE_PTR and qclass & 0x8000
    assert not parsed["answers"]

    txt = {"version": "1.7.0", "mode": "tcp", "tls": "0"}
    ann = build_announcement("laptop", "laptop", "192.168.1.10", 5000, txt)
    parsed = parse_message(ann)
    assert len(parsed["answers"]) == 4
    by_type = {a[1]: a for a in parsed["answers"]}
    assert by_type[TYPE_PTR][4] == "laptop." + SERVICE
    srv = by_type[TYPE_SRV][4]
    assert srv["port"] == 5000 and srv["target"] == "laptop.local"
    txt_items = dict(item.split("=", 1) for item in by_type[TYPE_TXT][4])
    assert txt_items == txt
    assert by_type[TYPE_A][4] == "192.168.1.10"
    print("ok: mDNS encode/decode roundtrip (query + PTR/SRV/TXT/A)")


def test_mdns_compression_pointer_decode():
    # A hand-built message: the answer name is a pointer (0xC00C)
    # back to the question name at offset 12.
    name = "laptop." + SERVICE
    question = (
        b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        + b"\x00"
        + struct.pack("!HH", TYPE_PTR, 1)
    )
    rdata = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    answer = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_PTR, 1, 120, len(rdata)) + rdata
    msg = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0) + question + answer
    parsed = parse_message(msg)
    assert parsed["questions"][0][0] == name
    assert parsed["answers"][0][0] == name
    assert parsed["answers"][0][4] == name
    # A pointer loop must not hang.
    loop = (
        struct.pack("!HHHHHH", 0, 0x8400, 1, 0, 0, 0)
        + b"\xc0\x0c"
        + struct.pack("!HH", TYPE_PTR, 1)
    )
    try:
        parse_message(loop)
    except ValueError:
        pass
    else:
        raise AssertionError("compression pointer loop accepted")
    print("ok: mDNS compression pointer decode (and loop rejected)")


def test_mdns_answer_query():
    txt = {"version": "1.7.0", "mode": "tcp", "tls": "0"}
    reply, unicast = answer_query(build_query(), "laptop", "laptop", "192.168.1.10", 5000, txt)
    assert reply is not None and unicast, "QU question must get a unicast reply"
    parsed = parse_message(reply)
    assert len(parsed["answers"]) == 4
    # A multicast question gets a multicast reply.
    qm = build_query().replace(b"\x80\x01", b"\x00\x01")
    reply, unicast = answer_query(qm, "laptop", "laptop", "192.168.1.10", 5000, txt)
    assert reply is not None and not unicast
    # A query for another service is ignored; garbage is ignored.
    assert (
        answer_query(
            build_query("_other._tcp.local"), "laptop", "laptop", "192.168.1.10", 5000, txt
        )[0]
        is None
    )
    assert answer_query(b"garbage", "laptop", "laptop", "192.168.1.10", 5000, txt)[0] is None
    # A direct SRV question for our instance gets just the SRV record.
    from warpsend.mdns import encode_name

    srv_q = (
        struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        + encode_name("laptop." + SERVICE)
        + struct.pack("!HH", TYPE_SRV, 1)
    )
    reply, _ = answer_query(srv_q, "laptop", "laptop", "192.168.1.10", 5000, txt)
    parsed = parse_message(reply)
    assert len(parsed["answers"]) == 1 and parsed["answers"][0][1] == TYPE_SRV
    print("ok: mDNS query answerer (PTR all-records, QU unicast, other service ignored)")


def test_mdns_browse_live():
    started = start_announcer("testbox", "127.0.0.1", 5999, mode="tcp")
    if started is None:
        print("skip: multicast blocked in this sandbox (runs on CI / your machine)")
        return
    _thread, stop = started
    try:
        found = browse(timeout=2.0)
    except OSError:
        # The announcer bound fine but sending the query is
        # blocked here (this sandbox); that is a skip, not a fail.
        print("skip: multicast blocked in this sandbox (runs on CI / your machine)")
        return
    finally:
        stop.set()
    match = [p for p in found if p["name"] == "testbox"]
    assert match, f"announced receiver not found: {found}"
    assert match[0]["port"] == 5999 and match[0]["host"] == "127.0.0.1"
    print("ok: mDNS live announce + browse found the receiver")


def test_announce_failure_does_not_kill_receiver():
    # In this sandbox mDNS is blocked; the receiver must still
    # serve files. (On a real network the announcer just works.)
    outdir = temp_outdir()
    port = free_port()
    start_tcp(port, outdir, announce="testbox")
    src = make_file("ws-announce.txt", 3_000)
    assert send_tcp("127.0.0.1", port, src)
    assert wait_for_file(os.path.join(outdir, "ws-announce.txt"))
    assert sha256_of_file(os.path.join(outdir, "ws-announce.txt")) == sha256_of_file(src)
    print("ok: receiver serves files even when mDNS announce fails")


def test_cli_discover():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(["--no-banner", "discover", "--timeout", "0.2"])
    out = buf.getvalue()
    assert rc in (0, 1), f"discover exited {rc}"
    assert "receivers" in out or "mDNS" in out, f"discover said nothing useful: {out!r}"
    print("ok: CLI discover runs and reports honestly")


def test_cli_send_unknown_peer_falls_back_to_lan():
    cfg_path = temp_config_path()
    old = os.environ.get("WARPSEND_CONFIG")
    os.environ["WARPSEND_CONFIG"] = cfg_path
    try:
        src = make_file("ws-ghost.txt", 1_000)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--no-banner", "send", src, "@ghost"])
        assert rc == 1, "send to a ghost peer should fail"
        assert "LAN" in buf.getvalue(), f"no LAN fallback mentioned: {buf.getvalue()!r}"
    finally:
        if old is None:
            os.environ.pop("WARPSEND_CONFIG", None)
        else:
            os.environ["WARPSEND_CONFIG"] = old
    print("ok: CLI send to an unknown peer falls back to a LAN lookup, then fails cleanly")


def test_session_frame_roundtrip():
    a, b = socket.socketpair()
    try:
        send_frame(a, {"type": "ping", "n": 42})
        assert recv_frame(b) == ("control", {"type": "ping", "n": 42}, None)
        send_frame(b, {"type": "pong"})
        assert recv_frame(a) == ("control", {"type": "pong"}, None)
        send_data_frame(a, 7, b"hello-bytes")
        assert recv_frame(b) == ("data", 7, b"hello-bytes")
        try:
            send_frame(a, {"type": "x", "pad": "y" * 9000})
        except ValueError:
            pass
        else:
            raise AssertionError("oversized frame accepted")
    finally:
        a.close()
        b.close()
    print("ok: session frame roundtrip (control + data, oversized rejected)")


def _serve_session_thread(port, outdir, **kwargs):
    kwargs.setdefault("once", True)
    t = threading.Thread(
        target=serve_session,
        args=("127.0.0.1", port),
        kwargs={"outdir": outdir, **kwargs},
        daemon=True,
    )
    t.start()
    time.sleep(0.3)
    return t


def test_session_two_way_transfer():
    host_dir = temp_outdir()
    join_dir = temp_outdir()
    port = free_port()
    file_a = make_file("ws-sess-a.txt", 8_000)
    file_b = make_file("ws-sess-b.txt", 5_000)

    def _on_session(sess):
        assert sess.send_file(file_a), "host could not send file A"
        sess.wait_closed()

    t = _serve_session_thread(port, host_dir, on_session=_on_session)
    sess = join_session("127.0.0.1", port, outdir=join_dir)
    assert sess is not None, "join failed"
    assert sess.send_file(file_b), "joiner could not send file B"
    assert wait_for_file(os.path.join(join_dir, "ws-sess-a.txt"))
    assert wait_for_file(os.path.join(host_dir, "ws-sess-b.txt"))
    assert sha256_of_file(os.path.join(join_dir, "ws-sess-a.txt")) == sha256_of_file(file_a)
    assert sha256_of_file(os.path.join(host_dir, "ws-sess-b.txt")) == sha256_of_file(file_b)
    sess.close()
    t.join(timeout=10)
    assert not t.is_alive(), "host session thread did not exit"
    print("ok: session two-way transfer (both directions, one connection)")


def test_session_decline():
    host_dir = temp_outdir()
    port = free_port()

    def _on_session(sess):
        sess.wait_closed()

    t = _serve_session_thread(port, host_dir, approve=lambda h, a: False, on_session=_on_session)
    sess = join_session("127.0.0.1", port, outdir=temp_outdir())
    assert sess is not None, "join failed"
    src = make_file("ws-sess-decline.txt", 2_000)
    assert not sess.send_file(src), "declined file reported as sent"
    assert not os.path.exists(os.path.join(host_dir, "ws-sess-decline.txt"))
    assert not os.path.exists(part_path(host_dir, "ws-sess-decline.txt"))
    sess.close()
    t.join(timeout=10)
    print("ok: session decline (no file, no .part)")


def test_session_resume():
    host_dir = temp_outdir()
    port = free_port()
    src = make_file("ws-sess-resume.txt", 10_000)
    checksum = sha256_of_file(src)
    with open(part_path(host_dir, "ws-sess-resume.txt"), "wb") as f:
        f.write(open(src, "rb").read(5_000))
    save_meta(host_dir, "ws-sess-resume.txt", 10_000, checksum)

    def _on_session(sess):
        sess.wait_closed()

    t = _serve_session_thread(port, host_dir, on_session=_on_session)
    sess = join_session("127.0.0.1", port, outdir=temp_outdir())
    assert sess is not None, "join failed"
    assert sess.send_file(src), "resumed send failed"
    assert wait_for_file(os.path.join(host_dir, "ws-sess-resume.txt"))
    assert sha256_of_file(os.path.join(host_dir, "ws-sess-resume.txt")) == checksum
    sess.close()
    t.join(timeout=10)
    print("ok: session resume (half .part completed over the session)")


def test_session_auth_reject():
    port = free_port()
    _serve_session_thread(port, temp_outdir(), key="right")
    sess = join_session("127.0.0.1", port, key="wrong", outdir=temp_outdir())
    assert sess is None, "wrong key was accepted"
    print("ok: session auth rejects a wrong key")


def test_cli_session_two_way():
    host_dir = temp_outdir()
    join_dir = temp_outdir()
    port = free_port()
    file_a = make_file("ws-cli-sess-a.txt", 6_000)
    file_b = make_file("ws-cli-sess-b.txt", 4_000)
    src_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    env = dict(os.environ, PYTHONPATH=src_dir)
    host = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "warpsend",
            "--no-banner",
            "session",
            "--port",
            str(port),
            "--outdir",
            host_dir,
            "--send",
            file_a,
            "--once",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    time.sleep(1)  # let the listener bind before the joiner connects
    joiner = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "warpsend",
            "--no-banner",
            "session",
            "--join",
            f"127.0.0.1:{port}",
            "--outdir",
            join_dir,
            "--send",
            file_b,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    try:
        assert wait_for_file(os.path.join(join_dir, "ws-cli-sess-a.txt"), timeout=15), (
            "file A never arrived;\n"
            f"host out: {host.stdout.read() if host.poll() is not None else '(still running)'}\n"
            f"joiner out: {joiner.stdout.read() if joiner.poll() is not None else '(still running)'}"
        )
        assert wait_for_file(os.path.join(host_dir, "ws-cli-sess-b.txt"), timeout=15)
        assert sha256_of_file(os.path.join(join_dir, "ws-cli-sess-a.txt")) == sha256_of_file(file_a)
        assert sha256_of_file(os.path.join(host_dir, "ws-cli-sess-b.txt")) == sha256_of_file(file_b)
    finally:
        # EOF on stdin ends both sessions.
        host.stdin.close()
        joiner.stdin.close()
    assert host.wait(timeout=10) == 0, f"host exited {host.returncode}: {host.stdout.read()}"
    assert joiner.wait(timeout=10) == 0, (
        f"joiner exited {joiner.returncode}: {joiner.stdout.read()}"
    )
    print("ok: CLI session two-way (subprocesses, --send both ways, EOF ends it)")


def test_tui_merge_peers():
    saved = [
        {
            "name": "laptop",
            "host": "10.0.0.2",
            "port": 5000,
            "mode": "tcp",
            "tls": False,
            "fingerprint": None,
            "key_file": None,
        }
    ]
    discovered = [
        {"name": "LAPTOP", "host": "10.0.0.3", "port": 5000, "mode": "tcp", "tls": False},
        {"name": "desk", "host": "10.0.0.4", "port": 5001, "mode": "tcp", "tls": False},
    ]
    merged = merge_peers(saved, discovered)
    assert [p["name"] for p in merged] == ["laptop", "desk"]
    assert merged[0]["source"] == "saved"
    assert merged[1]["source"] == "lan"
    assert "(LAN)" in peer_label(merged[1])
    print("ok: TUI peer merge (saved first, LAN deduped by name)")


def test_tui_target_for_peer():
    cfg_path = temp_config_path()
    cfg = load_config(cfg_path)
    add_peer(cfg, "laptop", "10.0.0.2", port=5001)
    save_config(cfg, cfg_path)
    config = load_config(cfg_path)
    saved = {
        "name": "laptop",
        "host": "10.0.0.2",
        "port": 5001,
        "mode": "tcp",
        "tls": False,
        "fingerprint": None,
        "key_file": None,
        "source": "saved",
    }
    target = target_for_peer(saved, config)
    assert target["host"] == "10.0.0.2" and target["port"] == 5001
    lan = {
        "name": "desk",
        "host": "10.0.0.9",
        "port": 5002,
        "mode": "tcp",
        "tls": True,
        "fingerprint": "ab" * 32,
        "key_file": None,
        "source": "lan",
    }
    target2 = target_for_peer(lan, config)
    assert target2["host"] == "10.0.0.9" and target2["tls"] is True
    assert target2["fingerprint"] == "ab" * 32
    print("ok: TUI peer target resolution (saved + LAN)")


def test_tui_app_send_end_to_end():
    if not HAS_TEXTUAL:
        print("skip: TUI pilot test needs textual (pip install warpsend[tui])")
        return
    src_dir = temp_outdir()
    recv_dir = temp_outdir()
    port = free_port()
    src = os.path.join(src_dir, "ws-tui-send.txt")
    with open(src, "wb") as f:
        f.write(b"A" * 4_000)
    cfg_path = temp_config_path()
    cfg = load_config(cfg_path)
    add_peer(cfg, "recv", "127.0.0.1", port=port)
    save_config(cfg, cfg_path)
    old = os.environ.get("WARPSEND_CONFIG")
    os.environ["WARPSEND_CONFIG"] = cfg_path
    start_tcp(port, recv_dir)

    async def _run():
        app = WarpSendApp(start_dir=src_dir)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert len(app.peers) >= 1, "saved peer did not appear in the TUI"
            assert app.peers[0]["name"] == "recv"
            app._queue_file(src)
            assert len(app.queue) == 1
            app.action_send()
            # Poll with awaits (never block the loop: the send
            # worker only starts when the loop iterates).
            dest = os.path.join(recv_dir, "ws-tui-send.txt")
            for _ in range(100):
                if os.path.isfile(dest):
                    break
                await asyncio.sleep(0.1)
            assert os.path.isfile(dest), "file never arrived at the receiver"
            assert sha256_of_file(dest) == sha256_of_file(src)
            await pilot.pause()
            assert app.queue == [], "sent file stayed in the queue"
            await pilot.press("q")

    try:
        asyncio.run(_run())
    finally:
        if old is None:
            os.environ.pop("WARPSEND_CONFIG", None)
        else:
            os.environ["WARPSEND_CONFIG"] = old
    print("ok: TUI send end to end (pilot: queue a file, send to a live receiver)")


if __name__ == "__main__":
    test_package_layout()
    test_fresh_and_no_overwrite()
    test_resume()
    test_complete_part_finalised()
    test_auth_reject()
    test_tls_pinned_and_tofu()
    test_malformed_header_keeps_server_alive()
    test_corrupt_verdict_is_failure()
    test_validate_header()
    test_udp_transfer_and_state_reset()
    test_receiver_rejects_when_approval_declines()
    test_receiver_accepts_when_approval_accepts()
    test_sender_cancel_keeps_part_and_server_alive()
    test_ctrl_c_send_exits_130()
    test_udp_receiver_rejects_when_approval_declines()
    test_peer_add_list_remove_roundtrip()
    test_peer_validation()
    test_resolve_target_precedence()
    test_config_defaults_applied()
    test_malformed_config_rejected()
    test_cli_peer_send_end_to_end()
    test_mdns_encode_decode_roundtrip()
    test_mdns_compression_pointer_decode()
    test_mdns_answer_query()
    test_mdns_browse_live()
    test_announce_failure_does_not_kill_receiver()
    test_cli_discover()
    test_cli_send_unknown_peer_falls_back_to_lan()
    test_session_frame_roundtrip()
    test_session_two_way_transfer()
    test_session_decline()
    test_session_resume()
    test_session_auth_reject()
    test_cli_session_two_way()
    test_tui_merge_peers()
    test_tui_target_for_peer()
    test_tui_app_send_end_to_end()
    print("all WarpSend v1.9.2 tests passed")
