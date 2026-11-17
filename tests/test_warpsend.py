"""WarpSend v1.4 tests -- run from the project directory:

    python3 tests/test_warpsend.py
    python -m pytest tests/ -v

Starts real TCP servers on localhost in background threads and
checks: fresh transfer, no-overwrite, TCP resume, a complete
.part being finalised, shared-key auth, TLS with a pinned
fingerprint, TLS trust-on-first-use, malformed headers keeping
the server alive, and the client exit code following the
server's CORRUPT verdict. UDP tests run when loopback
datagrams are allowed (they are on CI runners) and skip
gracefully when they are blocked, as in this sandbox.
"""

import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from warpsend.identity import generate_cert
from warpsend.protocol import validate_header
from warpsend.transfer import (
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
    good = validate_header({"filename": "a.txt", "filesize": 10, "checksum": "ab" * 32})
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
                "protocol": 2,
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

    assert warpsend.__version__ == "1.4.0"
    assert warpsend.PROTOCOL_VERSION == 2
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
    print("all WarpSend v1.4 tests passed")
