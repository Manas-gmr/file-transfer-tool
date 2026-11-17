"""Transfer -- sending and receiving files, over TCP and UDP.

Two checksum levels:
  * per-chunk CRC32  -- fast, catches a corrupt UDP packet at once
  * whole-file SHA-256 -- strong proof the received file is identical

TCP: reliability comes from the OS (ordering, no loss, no
duplicates), so the receiver reads the header, then reads
exactly `filesize` bytes, verifies SHA-256 and replies
OK/CORRUPT. Thread per connection, 120 s timeout, per-name
locks so two transfers of the same filename cannot collide.

UDP: reliability is built here. Every datagram carries
    [type=1][seq (4B)][total (4B)][crc32 (4B)][data]
Chunks are ACKed per chunk (duplicates ignored), the header is
ACKed (type 4) and retried, EOF is retried until the
SUCCESS/FAIL reply arrives, and chunks are written straight
to the .part file at seq * 1024 instead of being held in RAM.
Packet types: 0 = header (JSON), 1 = data, 2 = EOF, 3 = ACK,
4 = header ACK.

Both modes: the receiver writes to `<name>.part` and verifies
SHA-256 after saving -- only a match renames it to the final
name, claimed atomically with a hard link, and an existing
file is never overwritten (`name (1).ext`, ...). A hash
mismatch deletes the partial: its prefix cannot be trusted,
so it is not resumed. A complete .part is verified and
finalised (DONE) instead of restarted.

Approval (v1.5): serve_tcp / serve_udp take an `approve`
callable (header, addr) -> bool. When set, the receiver asks
it before answering the header -- FRESH / RESUME / DONE on
accept, REJECTED on decline (TCP), header ACK on accept,
FAIL on decline (UDP). A decline creates no file and no
.part. The CLI wires it to an interactive prompt when stdin
is a terminal, `--approve prompt` to force it, `--approve
auto` to never ask.

Cancel (v1.5): send_tcp / send_udp take an optional `cancel`
threading.Event, checked per chunk; Ctrl-C raises
TransferCancelled instead. Either way the socket closes, the
receiver keeps the .part for resume, and a TCP receiver keeps
listening. There is no in-band cancel packet: after the header
the TCP stream is raw file bytes, so extra bytes would be
written as file data.

User-facing messages go to stdout/stderr with print(); the
same events are also logged on the "warpsend" logger so
`--verbose` (or a future config file) can capture them.
"""

import hashlib
import json
import logging
import math
import os
import secrets
import shutil
import socket
import struct
import sys
import threading
import time

from .config import (
    CONN_TIMEOUT,
    PROTOCOL_VERSION,
    UDP_IDLE_TIMEOUT,
    UDP_MAX_RETRIES,
    UDP_TIMEOUT,
    default_outdir,
)
from .identity import (
    client_tls_context,
    default_cert_path,
    default_key_path,
    fingerprint_of_cert_file,
    load_known_hosts,
    peer_fingerprint,
    save_known_host,
    server_tls_context,
    short_code,
)
from .mdns import start_announcer
from .protocol import (
    CHUNK_TCP,
    CHUNK_UDP,
    auth_ok,
    header_auth,
    recv_header,
    recv_line,
    send_header,
    validate_header,
)

log = logging.getLogger("warpsend.transfer")

# Default output directory: the current working directory, so a
# pip-installed WarpSend does not try to write inside its own
# package location. --outdir overrides it.
OUTDIR = default_outdir()


# --- hashing and progress -------------------------------------------------


def sha256_of_file(path, on_progress=None):
    """SHA-256 hex digest of a whole file, read in 64 KB pieces.

    `on_progress(done, total)` is called per chunk, so a caller
    can show that a large file is hashing instead of frozen.
    """
    h = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while chunk := f.read(64 * 1024):
            h.update(chunk)
            done += len(chunk)
            if on_progress:
                on_progress(done, total)
    return h.hexdigest()


def crc32_of(data: bytes) -> int:
    """CRC32 of one chunk (unsigned 32-bit int)."""
    import zlib

    return zlib.crc32(data) & 0xFFFFFFFF


_PROGRESS = {}  # label -> (start_time, base_bytes)


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


def progress(done: int, total: int, label: str = "", base: int = 0) -> None:
    """One-line progress bar: [####------] 42% 1.2 MB / 3.0 MB  2.1 MB/s ETA 1s.

    Speed and ETA are computed from `done - base`, i.e. bytes
    moved in this session. On a resume, `base` is the offset
    already on disk, so the pre-existing bytes do not inflate
    the displayed speed. The bar goes to stderr so stdout
    stays machine-readable.
    """
    if total <= 0:
        return
    now = time.monotonic()
    if label not in _PROGRESS or _PROGRESS[label][1] != base:
        _PROGRESS[label] = (now, base)
    start, _ = _PROGRESS[label]
    elapsed = max(now - start, 1e-6)
    moved = max(done - base, 0)
    rate = moved / elapsed if elapsed > 0.05 else 0
    eta = (total - done) / rate if rate > 0 else 0
    pct = done * 100 // total
    bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
    speed = f"  {_fmt_bytes(rate)}/s" if rate else ""
    eta_s = f"  ETA {eta:.0f}s" if rate and done < total else ""
    print(
        f"\r{label} [{bar}] {pct:3d}%  {_fmt_bytes(done)} / {_fmt_bytes(total)}{speed}{eta_s}",
        end="",
        flush=True,
        file=sys.stderr,
    )
    if done >= total:
        print(file=sys.stderr)  # finish the line
        _PROGRESS.pop(label, None)


# --- approval and cancel (v1.5) -------------------------------------------


class TransferCancelled(Exception):
    """A transfer stopped by the user (Ctrl-C, or a cancel event).

    The receiver keeps the .part file, so the same file can be
    sent again to resume. The CLI maps this to exit code 130.
    """


def prompt_approve(header, addr):
    """Ask the operator whether to accept an incoming file.

    Prints who is sending what, then reads one line from stdin.
    EOF (piped stdin closed, Ctrl-D) means No. KeyboardInterrupt
    is deliberately not swallowed: on the UDP server it stops
    the server, and on TCP it is delivered to the main thread.
    """
    name = header["filename"]
    size = header["filesize"]
    print(
        f"incoming file from {addr[0]}:{addr[1]}: {name} "
        f"({_fmt_bytes(size)}, SHA-256 {header['checksum'][:16]}...)"
    )
    try:
        answer = input("Accept? [y/N] ")
    except EOFError:
        print("no answer -- rejected")
        return False
    ok = answer.strip().lower() in ("y", "yes")
    print("accepted" if ok else "rejected")
    return ok


# --- .part files, resume metadata, never-overwrite ------------------------


def part_path(outdir: str, name: str) -> str:
    return os.path.join(outdir, name + ".part")


def meta_path(outdir: str, name: str) -> str:
    return part_path(outdir, name) + ".json"


def save_meta(outdir: str, name: str, filesize: int, checksum: str) -> None:
    with open(meta_path(outdir, name), "w") as f:
        json.dump({"filename": name, "filesize": filesize, "checksum": checksum}, f)


def load_meta(outdir: str, name: str):
    """Return the resume metadata for a .part file, or None."""
    try:
        with open(meta_path(outdir, name)) as f:
            meta = json.load(f)
        if (
            meta.get("filename") == name
            and isinstance(meta.get("filesize"), int)
            and meta.get("checksum")
        ):
            return meta
    except (OSError, ValueError):
        pass
    return None


def resume_offset(outdir: str, name: str, filesize: int, checksum: str) -> int:
    """Bytes already on disk for this exact file, or 0.

    Only counts when the .part file and its metadata match the
    incoming file (same name, size and SHA-256). Anything else
    is a stale partial from a different file and is not resumed.
    A return of `filesize` (for a non-empty file) means the
    .part is complete and only needs its hash verified.
    """
    meta = load_meta(outdir, name)
    if not meta or meta["filesize"] != filesize or meta["checksum"] != checksum:
        return 0
    path = part_path(outdir, name)
    if not os.path.isfile(path):
        return 0
    size = os.path.getsize(path)
    if size > filesize:
        return 0
    return size


def unique_path(outdir: str, name: str) -> str:
    """A final path that never overwrites an existing file.

    `report.pdf` -> `report (1).pdf` -> `report (2).pdf` ...
    (A candidate name only; see claim_final_name for the
    atomic version used at rename time.)
    """
    path = os.path.join(outdir, name)
    if not os.path.exists(path):
        return path
    stem, dot, ext = name.rpartition(".")
    if not dot:  # no extension
        stem, ext = name, ""
    else:
        ext = "." + ext
    i = 1
    while True:
        candidate = os.path.join(outdir, f"{stem} ({i}){ext}")
        if not os.path.exists(candidate):
            return candidate
        i += 1


def claim_final_name(outdir: str, name: str) -> str:
    """Atomically claim a final name for a finished .part file.

    Tries each candidate with os.link(): creating the hard link
    fails if the name already exists, so no file created between
    the check and the rename can be silently replaced. On
    success the .part is unlinked and the claimed path returned.
    Falls back to os.rename when hard links are unavailable.
    """
    part = part_path(outdir, name)
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    else:
        ext = "." + ext
    candidates = [name] + [f"{stem} ({i}){ext}" for i in range(1, 1000)]
    for candidate in candidates:
        dest = os.path.join(outdir, candidate)
        try:
            os.link(part, dest)
        except FileExistsError:
            continue
        except OSError:
            if not os.path.exists(dest):
                os.rename(part, dest)
                return dest
            continue
        os.unlink(part)
        return dest
    raise OSError("could not claim a free final name")


def discard_part(outdir: str, name: str) -> None:
    for p in (part_path(outdir, name), meta_path(outdir, name)):
        try:
            os.remove(p)
        except OSError:
            pass


# --- server ----------------------------------------------------------------

_NAME_LOCKS = {}
_NAME_LOCKS_GUARD = threading.Lock()


def _lock_for(outdir, name):
    key = (outdir, name)
    with _NAME_LOCKS_GUARD:
        lock = _NAME_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _NAME_LOCKS[key] = lock
        return lock


def _finish_part(outdir, name, expected_hash, hasher=None, conn=None, udp_sock=None, udp_addr=None):
    """Verify a completed .part file, rename on match, reply.

    Returns True on a verified transfer. On a hash mismatch the
    partial is deleted (its prefix is untrustworthy) and False
    is returned. With `hasher` (TCP, incremental) the digest
    comes from the bytes as they arrived; without it (UDP) the
    file is read back once.
    """
    path = part_path(outdir, name)
    got = hasher.hexdigest() if hasher is not None else sha256_of_file(path)
    ok = got == expected_hash
    print(f"expected SHA-256: {expected_hash}")
    print(f"received SHA-256: {got}")
    if ok:
        final = claim_final_name(outdir, name)
        try:
            os.remove(meta_path(outdir, name))
        except OSError:
            pass
        print(f"Transfer verified, file intact -> {final}")
        log.info("verified %s -> %s", name, final)
        if os.path.basename(final) != name:
            print(f"(renamed: {name} already existed)")
    else:
        print("File corrupted -- checksum mismatch, partial deleted")
        log.warning("checksum mismatch for %s, partial deleted", name)
        discard_part(outdir, name)
    reply = b"OK" if ok else b"CORRUPT"
    if conn is not None:
        try:
            conn.sendall(reply)
        except OSError:
            pass
    elif udp_sock is not None:
        udp_sock.sendto(b"SUCCESS" if ok else b"FAIL", udp_addr)
    return ok


def _handle_tcp_conn(conn, key, outdir, max_size, challenge="", approve=None, addr=None):
    """Receive one file on an already-accepted TCP connection."""
    try:
        raw_header = recv_header(conn)
    except (ConnectionError, ValueError, OSError) as e:
        print(f"bad header, closing connection: {e}")
        log.warning("bad TCP header: %s", e)
        return
    try:
        header = validate_header(raw_header)
    except ValueError as e:
        print(f"invalid header, closing connection: {e}")
        log.warning("invalid TCP header: %s", e)
        try:
            conn.sendall(b"INVALID\n")
        except OSError:
            pass
        return
    name = header["filename"]
    size = header["filesize"]
    if not auth_ok(key, header, nonce=challenge):
        print(f"auth failed for {name} -- wrong or missing key, rejected")
        log.warning("auth failed for %s", name)
        try:
            conn.sendall(b"AUTH_FAIL\n")
        except OSError:
            pass
        return
    if max_size and size > max_size:
        print(f"rejecting {name}: {size} bytes exceeds --max-size {max_size}")
        try:
            conn.sendall(b"TOO_LARGE\n")
        except OSError:
            pass
        return
    try:
        free = shutil.disk_usage(outdir).free
    except OSError:
        free = size  # cannot check; let the write fail later if needed
    if size > free:
        print(f"rejecting {name}: {size} bytes but only {free} free on disk")
        try:
            conn.sendall(b"TOO_LARGE\n")
        except OSError:
            pass
        return
    if approve is not None:
        try:
            peer = addr or conn.getpeername()
        except OSError:
            peer = ("?", 0)
        if not approve(header, peer):
            print(f"rejected {name} from {peer} -- receiver declined")
            log.info("rejected %s from %s", name, peer)
            try:
                conn.sendall(b"REJECTED\n")
            except OSError:
                pass
            return
    print(f"receiving {name} ({size} bytes)")
    log.info("receiving %s (%d bytes)", name, size)
    os.makedirs(outdir, exist_ok=True)
    with _lock_for(outdir, name):
        offset = resume_offset(outdir, name, size, header["checksum"])
        if offset == size and size > 0:
            # Complete .part left by a crash after the last byte
            # but before the rename: verify and finalise it.
            path = part_path(outdir, name)
            if sha256_of_file(path) == header["checksum"]:
                final = claim_final_name(outdir, name)
                try:
                    os.remove(meta_path(outdir, name))
                except OSError:
                    pass
                print(f"already complete, verified -> {final}")
                try:
                    conn.sendall(b"DONE\n")
                except OSError:
                    pass
                return
            print(f"complete .part for {name} failed its hash -- restarting")
            discard_part(outdir, name)
            offset = 0
        if offset:
            print(f"resuming {name} from byte {offset} of {size}")
            conn.sendall(f"RESUME {offset}\n".encode())
        else:
            discard_part(outdir, name)
            save_meta(outdir, name, size, header["checksum"])
            conn.sendall(b"FRESH 0\n")
        path = part_path(outdir, name)
        hasher = hashlib.sha256()
        if offset:
            # Hash the existing prefix first, so the final digest
            # covers the whole file, not just the resumed tail.
            with open(path, "rb") as f:
                while chunk := f.read(64 * 1024):
                    hasher.update(chunk)
        received = offset
        buf = bytearray(CHUNK_TCP)
        try:
            with open(path, "ab" if offset else "wb") as f:
                while received < size:
                    want = min(CHUNK_TCP, size - received)
                    n = conn.recv_into(memoryview(buf)[:want])
                    if n == 0:
                        print(
                            f"connection lost at {received}/{size} bytes "
                            f"-- partial kept, send again to resume"
                        )
                        log.warning("connection lost at %d/%d bytes for %s", received, size, name)
                        return
                    f.write(buf[:n])
                    hasher.update(buf[:n])
                    received += n
                    progress(received, size, label="receiving", base=offset)
        except (OSError, ValueError) as e:
            print(f"receive error: {e} -- partial kept")
            return
        print(f"saved to {path}")
        _finish_part(outdir, name, header["checksum"], hasher=hasher, conn=conn)


def _serve_one_tcp(conn, addr, ctx, key, outdir, max_size, approve=None):
    print(f"connected: {addr}")
    log.info("connected: %s", addr)
    if ctx is not None:
        try:
            conn = ctx.wrap_socket(conn, server_side=True)
        except Exception as e:  # noqa: BLE001 -- any handshake failure
            # must be contained; a bad peer must not kill the receiver.
            print(f"TLS handshake failed: {e}")
            log.warning("TLS handshake failed for %s: %s", addr, e)
            conn.close()
            return
    with conn:
        try:
            conn.settimeout(CONN_TIMEOUT)
        except OSError:
            pass
        challenge = secrets.token_hex(16)
        try:
            conn.sendall(f"CHALLENGE {challenge}\n".encode())
        except OSError:
            return
        try:
            _handle_tcp_conn(
                conn, key, outdir, max_size, challenge=challenge, approve=approve, addr=addr
            )
        except Exception as e:  # noqa: BLE001 -- a bad peer must not
            # kill the receiver; the connection is dropped, the partial kept.
            print(f"connection error for {addr}: {type(e).__name__}: {e} -- partial kept if any")
            log.warning("connection error for %s: %s: %s", addr, type(e).__name__, e)


def serve_tcp(
    host,
    port,
    key=None,
    tls=False,
    cert=None,
    keyfile=None,
    outdir=None,
    max_size=0,
    approve=None,
    announce=None,
):
    outdir = outdir or OUTDIR
    os.makedirs(outdir, exist_ok=True)
    ctx = None
    if tls:
        cert = cert or default_cert_path()
        keyfile = keyfile or default_key_path()
        if not (os.path.isfile(cert) and os.path.isfile(keyfile)):
            print(f"no certificate at {cert} -- run `warpsend cert` first")
            return
        ctx = server_tls_context(cert, keyfile)
        fp = fingerprint_of_cert_file(cert)
        print(f"TLS on, server fingerprint: {fp}  (code {short_code(fp)})")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        print(f"TCP server listening on {host}:{port}, saving to {outdir} ... (Ctrl-C to stop)")
        if announce is not None:
            if start_announcer(
                announce, host, port, mode="tcp", tls=tls, fingerprint=fp if tls else None
            ):
                print(f"announcing as {announce!r} on the LAN (mDNS _warpsend._tcp)")
        while True:
            try:
                conn, addr = srv.accept()
            except KeyboardInterrupt:
                print("\nserver stopped")
                return
            t = threading.Thread(
                target=_serve_one_tcp,
                args=(conn, addr, ctx, key, outdir, max_size, approve),
                daemon=True,
            )
            t.start()


def serve_udp(host, port, key=None, outdir=None, max_size=0, approve=None, announce=None):
    outdir = outdir or OUTDIR
    os.makedirs(outdir, exist_ok=True)
    seen_nonces = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        sock.settimeout(UDP_IDLE_TIMEOUT)
        print(f"UDP server listening on {host}:{port}, saving to {outdir} ... (Ctrl-C to stop)")
        if announce is not None:
            if start_announcer(announce, host, port, mode="udp"):
                print(f"announcing as {announce!r} on the LAN (mDNS _warpsend._tcp)")
        while True:
            # Per-transfer state; a new header resets all of it.
            header, total, sender = None, None, None
            received_seqs, received_bytes = set(), 0
            part_file = None
            try:
                while True:
                    try:
                        packet, addr = sock.recvfrom(2048)
                    except TimeoutError:
                        if header is not None:
                            print("UDP transfer timed out -- partial kept, state reset")
                            if part_file is not None:
                                part_file.close()
                        break
                    if not packet:
                        continue  # empty datagram: ignore, no crash
                    ptype = packet[0]
                    if ptype == 0:  # header (JSON)
                        try:
                            raw = json.loads(packet[1:])
                            new_header = validate_header(raw)
                        except (ValueError, UnicodeDecodeError) as e:
                            print(f"invalid UDP header from {addr}: {e}")
                            continue
                        if header is not None and addr[0] != sender[0]:
                            print(
                                f"ignoring header from {addr}: transfer in progress from {sender}"
                            )
                            continue
                        if header is not None:
                            # New header from the same sender: the old
                            # transfer is abandoned -- reset its state.
                            print("new UDP header -- resetting old transfer")
                            if part_file is not None:
                                part_file.close()
                            received_seqs, received_bytes = set(), 0
                            total = None
                        nonce = new_header.get("nonce")
                        if key and nonce and nonce in seen_nonces:
                            print(f"replayed UDP header from {addr} -- ignored")
                            continue
                        if not auth_ok(key, new_header):
                            print(f"auth failed for {new_header['filename']} -- packet ignored")
                            sock.sendto(b"FAIL", addr)
                            continue
                        size = new_header["filesize"]
                        if (max_size and size > max_size) or size > shutil.disk_usage(outdir).free:
                            print(f"rejecting {new_header['filename']}: too large")
                            sock.sendto(b"FAIL", addr)
                            continue
                        if approve is not None and not approve(new_header, addr):
                            print(
                                f"rejected {new_header['filename']} from {addr} "
                                "-- receiver declined"
                            )
                            sock.sendto(b"FAIL", addr)
                            continue
                        header, sender = new_header, addr
                        if nonce:
                            seen_nonces.add(nonce)
                        name = header["filename"]
                        print(f"receiving {name} ({size} bytes)")
                        discard_part(outdir, name)
                        save_meta(outdir, name, size, header["checksum"])
                        # Long-lived handle on purpose: it stays open
                        # across packets and is closed on reset, timeout
                        # and EOF. A `with` block cannot span the loop.
                        part_file = open(part_path(outdir, name), "wb")
                        sock.sendto(b"\x04", addr)  # header ACK
                    elif ptype == 1:  # data chunk
                        if header is None or addr[0] != sender[0]:
                            continue  # no transfer, or wrong sender: ignore
                        if len(packet) < 13:
                            continue
                        seq, pkt_total, crc = struct.unpack("!III", packet[1:13])
                        if total is None:
                            total = pkt_total
                        elif pkt_total != total:
                            continue
                        if seq >= total:
                            continue
                        data = packet[13:]
                        if crc32_of(data) != crc:
                            print(f"chunk {seq}: bad CRC32, dropped (no ACK)")
                            continue  # no ACK -> client resends
                        if seq not in received_seqs:
                            part_file.seek(seq * CHUNK_UDP)
                            part_file.write(data)
                            received_seqs.add(seq)
                            received_bytes += len(data)
                        sock.sendto(b"\x03" + struct.pack("!I", seq), addr)
                        progress(received_bytes, header["filesize"], label="receiving")
                    elif ptype == 2:  # EOF
                        if header is None or addr[0] != sender[0]:
                            continue
                        break
                    # Unknown packet types are ignored.
            except KeyboardInterrupt:
                print("\nserver stopped")
                if part_file is not None:
                    part_file.close()
                return
            if header is None:
                continue
            if part_file is not None:
                part_file.close()
            name = header["filename"]
            if total is None or len(received_seqs) != total:
                print(f"incomplete: {len(received_seqs)}/{total} chunks, .part kept")
                sock.sendto(b"FAIL", sender)
                continue
            print(f"saved to {part_path(outdir, name)} ({len(received_seqs)}/{total} chunks)")
            _finish_part(outdir, name, header["checksum"], udp_sock=sock, udp_addr=sender)


# --- client ----------------------------------------------------------------

TIMEOUT = UDP_TIMEOUT  # seconds to wait for a UDP ACK before resending
MAX_RETRIES = UDP_MAX_RETRIES


def _wrap_tls(sock, host, fingerprint=None, trust_new=False, known_hosts_path=None):
    """Wrap a connected socket in TLS and check the fingerprint.

    Returns the wrapped socket, or None if the fingerprint check
    fails. Trust on first use: a fingerprint remembered for this
    host must match on later connects; a new host is accepted
    only with --fingerprint (which must match) or --trust-new
    (explicit), and is then remembered. Without any of those,
    the client aborts instead of sending a file to a server it
    has never verified.
    """
    tls = client_tls_context().wrap_socket(sock, server_hostname=host)
    fp = peer_fingerprint(tls)
    print(f"server TLS fingerprint: {fp}  (code {short_code(fp)})")
    known = load_known_hosts(known_hosts_path)
    if host in known:
        if known[host].lower() != fp.lower():
            print(
                "FINGERPRINT CHANGED for a known host -- aborting. "
                "The server's certificate changed; verify out of band "
                "before trusting it again."
            )
            log.warning("fingerprint changed for known host %s -- aborting", host)
            tls.close()
            return None
        print("fingerprint matches the remembered host")
        return tls
    if fingerprint:
        if fp.lower() != fingerprint.lower().replace(":", ""):
            print(
                "FINGERPRINT MISMATCH -- aborting, possible interception. "
                "Compare the fingerprint with the receiver out of band."
            )
            log.warning("fingerprint mismatch for %s -- aborting", host)
            tls.close()
            return None
        print("fingerprint matches the pinned value")
    elif not trust_new:
        print(
            "this host is not in the known-hosts file and no "
            "--fingerprint was given -- aborting. Re-run with "
            "--fingerprint <hex> or --trust-new to trust it once, "
            "after verifying the fingerprint out of band."
        )
        tls.close()
        return None
    else:
        print("trusting this host for the first time -- fingerprint saved")
    save_known_host(known_hosts_path, host, fp)
    return tls


def send_tcp(
    host,
    port,
    path,
    key=None,
    tls=False,
    fingerprint=None,
    trust_new=False,
    known_hosts_path=None,
    cancel=None,
):
    """Send one file over TCP.

    `cancel` is an optional threading.Event: when set, the send
    stops at the next chunk boundary and raises
    TransferCancelled. The socket closes on the way out, which
    is the cancel signal -- the receiver keeps the .part for
    resume and keeps listening. Ctrl-C raises KeyboardInterrupt
    in the caller; the CLI converts it to the same outcome.
    """
    size = os.path.getsize(path)
    print(f"hashing {os.path.basename(path)} ...")
    checksum = sha256_of_file(path, on_progress=lambda d, t: progress(d, t, label="hashing"))
    print(f"{os.path.basename(path)}: {size} bytes, SHA-256 {checksum}")
    log.info(
        "sending %s (%d bytes) to %s:%d over TCP%s",
        path,
        size,
        host,
        port,
        " with TLS" if tls else "",
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.connect((host, port))
        sock = raw
        if tls:
            sock = _wrap_tls(raw, host, fingerprint, trust_new, known_hosts_path)
            if sock is None:
                return False
        with sock:
            # v1.2 challenge-response: the server sends CHALLENGE
            # first. A pre-v1.2 server never does, so a timeout
            # means no challenge -- fall back to a nonce-less HMAC.
            challenge = recv_line(sock, timeout=1.5) or ""
            nonce = ""
            if challenge.startswith("CHALLENGE "):
                nonce = challenge.split(None, 1)[1]
            auth = header_auth(key, os.path.basename(path), size, checksum, nonce) if key else None
            send_header(
                sock, os.path.basename(path), size, checksum, auth=auth, nonce=nonce or None
            )
            reply = recv_line(sock, timeout=2.0)
            offset = 0
            if reply == "REJECTED":
                print("receiver declined the transfer")
                log.warning("receiver declined %s", path)
                return False
            if reply in ("AUTH_FAIL", "TOO_LARGE", "INVALID"):
                print(f"server rejected the transfer: {reply}")
                log.warning("server rejected %s: %s", path, reply)
                return False
            if reply == "DONE":
                print("server already has the complete file -- nothing to send")
                return True
            if reply and reply.startswith("RESUME "):
                try:
                    offset = int(reply.split()[1])
                except ValueError:
                    offset = 0
                print(f"resuming from byte {offset} of {size}")
            if cancel is not None and cancel.is_set():
                raise TransferCancelled("cancelled by user")
            sent = offset
            with open(path, "rb") as f:
                if not tls:
                    # sendfile() moves bytes kernel-side; do it in
                    # 256 KB slices so progress stays live.
                    remaining = size - offset
                    pos = offset
                    while remaining > 0:
                        if cancel is not None and cancel.is_set():
                            raise TransferCancelled("cancelled by user")
                        n = sock.sendfile(f, pos, min(CHUNK_TCP, remaining))
                        if n == 0:
                            break
                        pos += n
                        sent += n
                        remaining -= n
                        progress(sent, size, label="sending", base=offset)
                else:
                    f.seek(offset)
                    while chunk := f.read(CHUNK_TCP):
                        if cancel is not None and cancel.is_set():
                            raise TransferCancelled("cancelled by user")
                        sock.sendall(chunk)
                        sent += len(chunk)
                        progress(sent, size, label="sending", base=offset)
            verdict = sock.recv(16).decode(errors="replace").strip()
            print("server says:", verdict)
            # A pre-v1.2 server's first reply here is the FRESH
            # line the new client already consumed; anything
            # else is the verdict.
            if verdict == "CORRUPT":
                log.warning("server reported CORRUPT for %s", path)
                return False
            log.info("sent %s, server verdict: %s", path, verdict)
            return True


def send_udp(host, port, path, key=None, cancel=None):
    """Send one file over UDP. `cancel` works as in send_tcp:
    a set event stops the send at the next chunk boundary and
    raises TransferCancelled; the receiver's idle timeout then
    abandons the transfer and keeps the .part.
    """
    size = os.path.getsize(path)
    print(f"hashing {os.path.basename(path)} ...")
    checksum = sha256_of_file(path, on_progress=lambda d, t: progress(d, t, label="hashing"))
    total = max(math.ceil(size / CHUNK_UDP), 1)
    # Per-transfer nonce, covered by the HMAC; the server
    # rejects a nonce it has already seen, so this header
    # cannot be replayed within a server run.
    nonce = secrets.token_hex(8)
    auth = header_auth(key, os.path.basename(path), size, checksum, nonce) if key else None
    print(f"{os.path.basename(path)}: {size} bytes, {total} chunks, SHA-256 {checksum}")
    log.info("sending %s (%d bytes, %d chunks) to %s:%d over UDP", path, size, total, host, port)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        header = {
            "filename": os.path.basename(path),
            "filesize": size,
            "checksum": checksum,
            "protocol": PROTOCOL_VERSION,
            "nonce": nonce,
        }
        if auth:
            header["auth"] = auth
        header_packet = b"\x00" + json.dumps(header).encode()
        # Reliable header: retry until the server ACKs it (type 4).
        for attempt in range(MAX_RETRIES):
            if cancel is not None and cancel.is_set():
                raise TransferCancelled("cancelled by user")
            sock.sendto(header_packet, (host, port))
            try:
                reply, _ = sock.recvfrom(64)
                if reply == b"\x04":
                    break
                if reply == b"FAIL":
                    print("server rejected the header")
                    return False
            except TimeoutError:
                print(f"header: no ACK, resending (attempt {attempt + 2}/{MAX_RETRIES})")
        else:
            print(f"header: giving up after {MAX_RETRIES} tries -- server never ACKed it")
            return False
        acked = 0
        # Stream from disk: the whole file is never held in RAM.
        with open(path, "rb") as f:
            for seq in range(total):
                if cancel is not None and cancel.is_set():
                    raise TransferCancelled("cancelled by user")
                chunk = f.read(CHUNK_UDP)
                packet = b"\x01" + struct.pack("!III", seq, total, crc32_of(chunk)) + chunk
                for attempt in range(MAX_RETRIES):
                    sock.sendto(packet, (host, port))
                    try:
                        ack, _ = sock.recvfrom(64)
                        if ack[0] == 3 and struct.unpack("!I", ack[1:5])[0] == seq:
                            acked += 1
                            progress(
                                acked * CHUNK_UDP if acked < total else size, size, label="sending"
                            )
                            break
                    except TimeoutError:
                        print(
                            f"\nchunk {seq}: no ACK, resending "
                            f"(attempt {attempt + 2}/{MAX_RETRIES})"
                        )
                else:
                    print(f"\nchunk {seq}: giving up after {MAX_RETRIES} tries")
                    return False
        # Reliable EOF: retry until the final verdict arrives.
        for attempt in range(MAX_RETRIES):
            if cancel is not None and cancel.is_set():
                raise TransferCancelled("cancelled by user")
            sock.sendto(b"\x02", (host, port))  # EOF
            try:
                reply = sock.recvfrom(64)[0].decode()
                print("server says:", reply)
                return reply == "SUCCESS"
            except TimeoutError:
                print(f"EOF: no reply, resending (attempt {attempt + 2}/{MAX_RETRIES})")
        print("no final reply from server -- transfer outcome unknown, treating as failure")
        return False
