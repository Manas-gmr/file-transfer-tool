"""WarpSend v1.1 smoke tests -- run from the project directory:

    python3 tests/test_warpsend.py

Starts real TCP servers on localhost in background threads and
checks: fresh transfer, no-overwrite, resume from a .part,
shared-key rejection, and TLS with a pinned fingerprint.
UDP is not tested here: datagrams are blocked in this sandbox.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import send_tcp  # noqa: E402
from server import OUTDIR, serve_tcp  # noqa: E402
from utils import (generate_cert, meta_path, part_path, save_meta,  # noqa: E402
                   sha256_of_file)

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECEIVED = os.path.join(HERE, "received")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def clean_received():
    shutil.rmtree(RECEIVED, ignore_errors=True)
    os.makedirs(RECEIVED, exist_ok=True)


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


def test_fresh_and_no_overwrite():
    clean_received()
    port = free_port()
    threading.Thread(target=serve_tcp, args=("127.0.0.1", port),
                     daemon=True).start()
    time.sleep(0.3)
    src = make_file("ws-test.txt", 200_000)
    assert send_tcp("127.0.0.1", port, src), "fresh send failed"
    assert wait_for_file(os.path.join(RECEIVED, "ws-test.txt"))
    assert sha256_of_file(os.path.join(RECEIVED, "ws-test.txt")) == sha256_of_file(src)
    # Second send of the same name must not overwrite the first.
    assert send_tcp("127.0.0.1", port, src), "second send failed"
    assert wait_for_file(os.path.join(RECEIVED, "ws-test (1).txt"))
    assert sha256_of_file(os.path.join(RECEIVED, "ws-test (1).txt")) == sha256_of_file(src)
    print("ok: fresh transfer + no-overwrite")


def test_resume():
    clean_received()
    port = free_port()
    threading.Thread(target=serve_tcp, args=("127.0.0.1", port),
                     daemon=True).start()
    time.sleep(0.3)
    src = make_file("ws-resume.bin", 300_000, byte=b"R")
    digest = sha256_of_file(src)
    # Simulate a dropped connection halfway: .part + metadata.
    with open(src, "rb") as f:
        prefix = f.read(120_000)
    with open(part_path(RECEIVED, "ws-resume.bin"), "wb") as f:
        f.write(prefix)
    save_meta(RECEIVED, "ws-resume.bin", 300_000, digest)
    assert send_tcp("127.0.0.1", port, src), "resume send failed"
    final = os.path.join(RECEIVED, "ws-resume.bin")
    assert wait_for_file(final)
    assert sha256_of_file(final) == digest, "resumed file hash mismatch"
    assert not os.path.exists(part_path(RECEIVED, "ws-resume.bin"))
    print("ok: TCP resume from .part")


def test_auth_reject():
    clean_received()
    port = free_port()
    threading.Thread(target=serve_tcp, args=("127.0.0.1", port),
                     kwargs={"key": "correct-horse"}, daemon=True).start()
    time.sleep(0.3)
    src = make_file("ws-auth.txt", 1_000)
    assert not send_tcp("127.0.0.1", port, src, key="wrong-key"), \
        "server accepted a wrong key"
    assert not os.path.exists(os.path.join(RECEIVED, "ws-auth.txt"))
    assert send_tcp("127.0.0.1", port, src, key="correct-horse"), \
        "server rejected the right key"
    assert wait_for_file(os.path.join(RECEIVED, "ws-auth.txt"))
    print("ok: shared-key auth (reject wrong, accept right)")


def test_tls_pinned():
    clean_received()
    tmp = tempfile.mkdtemp()
    cert, keyfile, fp = generate_cert(os.path.join(tmp, "cert.pem"),
                                      os.path.join(tmp, "key.pem"))
    port = free_port()
    threading.Thread(target=serve_tcp, args=("127.0.0.1", port),
                     kwargs={"tls": True, "cert": cert, "keyfile": keyfile},
                     daemon=True).start()
    time.sleep(0.3)
    src = make_file("ws-tls.txt", 50_000, byte=b"T")
    assert not send_tcp("127.0.0.1", port, src, tls=True,
                        fingerprint="00" * 32), "TLS accepted a bad fingerprint"
    assert send_tcp("127.0.0.1", port, src, tls=True, fingerprint=fp), \
        "TLS failed with the right fingerprint"
    assert wait_for_file(os.path.join(RECEIVED, "ws-tls.txt"))
    assert sha256_of_file(os.path.join(RECEIVED, "ws-tls.txt")) == sha256_of_file(src)
    print("ok: TLS with pinned fingerprint")


if __name__ == "__main__":
    test_fresh_and_no_overwrite()
    test_resume()
    test_auth_reject()
    test_tls_pinned()
    clean_received()
    print("all WarpSend v1.1 tests passed")
