"""Bidirectional session -- one persistent TCP connection, files
either way (WarpSend v1.8, Phase 4 R3).

Two machines run `warpsend session`: one listens, one joins
with `--join host` or `--peer name`. The connection stays open
until either side ends it, and either side can send files at
any time -- even both at once, since reads and writes run on
different threads and all writes go through one lock.

Session protocol v1 (TCP only; the one-shot protocol stays v3):

    hello    host -> joiner: {"type": "hello", "session": 1,
                              "challenge": <hex>}
             joiner -> host: {"type": "hello",
                              "auth": HMAC(key, challenge + "\\nsession")}
             host -> joiner: {"type": "welcome"}  (auth passed)
    file     {"type": "file", "id": N, "filename": ...,
              "filesize": ..., "checksum": ..., "protocol": 3}
    accept   {"type": "accept", "id": N, "offset": M}
    decline  {"type": "decline", "id": N, "reason": ...}
    have     {"type": "have", "id": N}   -- receiver already has it
    data     binary frames {"id": N} + raw file bytes, in chunks
    eof      {"type": "eof", "id": N}
    received {"type": "received", "id": N, "ok": true|false}
    bye      {"type": "bye"}

Every frame on the wire is 4-byte big-endian length + a
1-byte marker (0x00 control, 0x01 data) + payload. Control
payloads are JSON, capped at 8 KB; data payloads are a
4-byte transfer id + up to 256 KB of raw file bytes. File
data is framed -- never raw on the stream -- so control
frames can interleave with it: both directions can transfer
at once, and a reply to one transfer is never swallowed as
another transfer's file bytes. (An earlier draft sent file
bytes raw and serialised transfers with a lock; that
deadlocked the two-way case, because each side's sender
held its lock while waiting for a reply its own reader
could not deliver. Framing is the fix.)

File offers are validated with the same validate_header() as
the one-shot protocol, and received files use the same .part
+ metadata + resume + never-overwrite machinery (see
transfer.py). One peer at a time; a second peer waits for
the listener to accept it after the first session ends.
No keepalive frames -- the socket uses TCP keepalive instead.
"""

import hashlib
import hmac as hmac_mod
import itertools
import json
import logging
import os
import secrets
import shutil
import socket
import struct
import threading

from .identity import (
    default_cert_path,
    default_key_path,
    fingerprint_of_cert_file,
    server_tls_context,
    short_code,
)
from .mdns import start_announcer
from .protocol import PROTOCOL_VERSION, validate_header
from .transfer import (
    OUTDIR,
    _finish_part,
    _wrap_tls,
    claim_final_name,
    discard_part,
    meta_path,
    part_path,
    progress,
    resume_offset,
    save_meta,
    sha256_of_file,
)

log = logging.getLogger("warpsend.session")

SESSION_VERSION = 1
MAX_FRAME_BYTES = 8192
MAX_DATA_BYTES = 256 * 1024  # one data frame carries at most this many file bytes
REPLY_TIMEOUT = 120  # seconds to wait for an offer reply / receipt


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def send_frame(sock, obj):
    """One length-prefixed JSON control frame (marker 0x00)."""
    payload = json.dumps(obj).encode()
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("frame too large")
    sock.sendall(struct.pack("!I", 1 + len(payload)) + b"\x00" + payload)


def send_data_frame(sock, msg_id, chunk):
    """One data frame (marker 0x01): 4-byte id + raw bytes."""
    payload = struct.pack("!I", msg_id) + chunk
    sock.sendall(struct.pack("!I", 1 + len(payload)) + b"\x01" + payload)


def recv_frame(sock):
    """Read one frame -> ("control", dict) or ("data", id, bytes).

    Raises ConnectionError / ValueError on a closed or
    malformed stream.
    """
    raw_len = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", raw_len)
    if length < 1 or length > 1 + MAX_DATA_BYTES:
        raise ValueError(f"bad frame length {length}")
    marker = _recv_exact(sock, 1)
    payload = _recv_exact(sock, length - 1)
    if marker == b"\x00":
        if len(payload) > MAX_FRAME_BYTES:
            raise ValueError("control frame too large")
        return "control", json.loads(payload), None
    if marker == b"\x01":
        if len(payload) < 4:
            raise ValueError("short data frame")
        (msg_id,) = struct.unpack("!I", payload[:4])
        return "data", msg_id, payload[4:]
    raise ValueError(f"bad frame marker {marker!r}")


def _session_auth(key, challenge):
    """HMAC-SHA256 of the challenge under the shared secret."""
    msg = f"{challenge}\nsession".encode()
    return hmac_mod.new(key.encode(), msg, hashlib.sha256).hexdigest()


# One lock for all stdin reads in a session: the command loop
# and the approval prompt share the terminal, and whichever
# reads first must get a whole line. The CLI's command loop
# uses it; approval goes through locked_approve().
STDIN_LOCK = threading.Lock()


def locked_approve(approve):
    """Wrap an approve callable so its prompt cannot interleave
    with the session command loop's stdin reads."""

    def _approve(header, addr):
        with STDIN_LOCK:
            return approve(header, addr)

    return _approve


class Session:
    """One live session: a socket, a reader thread, and the
    send/receive machinery. Either side can send at any time."""

    def __init__(
        self, sock, key=None, outdir=None, max_size=0, approve=None, peer_addr=None, tls=False
    ):
        self.sock = sock
        self.key = key
        self.outdir = outdir or OUTDIR
        self.max_size = max_size
        self.approve = approve
        self.peer_addr = peer_addr or ("?", 0)
        self._tls = tls
        self._write_lock = threading.Lock()
        self._next_id = itertools.count(1)
        self._pending = {}  # id -> {"event": Event, "result": dict|None}
        self._pending_lock = threading.Lock()
        # Incoming transfers, by id: only the reader thread
        # touches these, so no lock is needed for them.
        self._incoming = {}  # id -> state dict (see _receive_offer)
        self._active_names = set()  # filenames being received now
        self._closed = threading.Event()
        self._reader = None
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

    # -- lifecycle ------------------------------------------------------

    def start(self):
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()

    @property
    def closed(self):
        return self._closed.is_set()

    def wait_closed(self, timeout=None):
        return self._closed.wait(timeout)

    def close(self):
        """End the session politely (BYE), then close the socket."""
        if self._closed.is_set():
            return
        try:
            self._send_frame({"type": "bye"})
        except (OSError, ValueError):
            pass
        self._close_socket()

    def _close_socket(self):
        if not self._closed.is_set():
            self._closed.set()
            self._fail_pending()
            # A transfer cut short keeps its .part for resume;
            # close the open handles so the files are not left
            # half-flushed.
            for state in self._incoming.values():
                try:
                    state["handle"].close()
                except OSError:
                    pass
            self._incoming.clear()
            self._active_names.clear()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    # -- framing --------------------------------------------------------

    def _send_frame(self, obj):
        with self._write_lock:
            send_frame(self.sock, obj)

    def _send_data(self, msg_id, chunk):
        with self._write_lock:
            send_data_frame(self.sock, msg_id, chunk)

    def _register(self, msg_id):
        entry = {"event": threading.Event(), "result": None}
        with self._pending_lock:
            self._pending[msg_id] = entry
        return entry

    def _deliver(self, frame):
        msg_id = frame.get("id")
        with self._pending_lock:
            entry = self._pending.get(msg_id)
        if entry is not None:
            entry["result"] = frame
            entry["event"].set()

    def _fail_pending(self):
        with self._pending_lock:
            for entry in self._pending.values():
                entry["event"].set()

    def _wait_reply(self, entry, timeout):
        if not entry["event"].wait(timeout):
            return None
        entry["event"].clear()
        return entry["result"]

    # -- reader ---------------------------------------------------------

    def _reader_loop(self):
        try:
            while not self._closed.is_set():
                try:
                    kind, first, second = recv_frame(self.sock)
                except (ConnectionError, ValueError, OSError) as e:
                    if not self._closed.is_set():
                        print(f"session with {self.peer_addr} ended: {e}")
                    break
                if kind == "data":
                    self._handle_data_chunk(first, second)
                    continue
                frame = first
                if not isinstance(frame, dict):
                    continue
                ftype = frame.get("type")
                if ftype == "file":
                    self._receive_offer(frame)
                elif ftype == "eof":
                    self._handle_eof(frame)
                elif ftype in ("accept", "decline", "have", "received"):
                    self._deliver(frame)
                elif ftype == "bye":
                    print(f"peer {self.peer_addr} ended the session")
                    break
                # hello mid-session and unknown types: ignore.
        finally:
            self._close_socket()

    # -- receiving ------------------------------------------------------

    def _receive_offer(self, frame):
        msg_id = frame.get("id")
        try:
            header = validate_header(frame)
        except ValueError as e:
            print(f"invalid file offer, ignoring: {e}")
            return
        name = header["filename"]
        size = header["filesize"]
        if self.max_size and size > self.max_size:
            print(f"rejecting {name}: {size} bytes exceeds --max-size {self.max_size}")
            self._send_frame({"type": "decline", "id": msg_id, "reason": "too large"})
            return
        try:
            free = shutil.disk_usage(self.outdir).free
        except OSError:
            free = size
        if size > free:
            print(f"rejecting {name}: {size} bytes but only {free} free on disk")
            self._send_frame({"type": "decline", "id": msg_id, "reason": "no disk space"})
            return
        if self.approve is not None:
            try:
                if not self.approve(header, self.peer_addr):
                    print(f"rejected {name} from {self.peer_addr} -- declined")
                    self._send_frame(
                        {"type": "decline", "id": msg_id, "reason": "rejected by operator"}
                    )
                    return
            except KeyboardInterrupt:
                # The operator stopped the prompt: decline this
                # file, keep the session alive.
                self._send_frame(
                    {"type": "decline", "id": msg_id, "reason": "rejected by operator"}
                )
                return
        if name in self._active_names:
            print(f"already receiving {name} -- declining the second offer")
            self._send_frame({"type": "decline", "id": msg_id, "reason": "already receiving"})
            return
        print(f"receiving {name} ({size} bytes) from {self.peer_addr}")
        os.makedirs(self.outdir, exist_ok=True)
        offset = resume_offset(self.outdir, name, size, header["checksum"])
        if offset == size and size > 0:
            # Complete .part left by a crash after the last byte:
            # verify and finalise it, exactly like the one-shot
            # receiver does.
            path = part_path(self.outdir, name)
            if sha256_of_file(path) == header["checksum"]:
                final = claim_final_name(self.outdir, name)
                try:
                    os.remove(meta_path(self.outdir, name))
                except OSError:
                    pass
                print(f"already complete, verified -> {final}")
                self._send_frame({"type": "have", "id": msg_id})
                return
            print(f"complete .part for {name} failed its hash -- restarting")
            discard_part(self.outdir, name)
            offset = 0
        if offset:
            print(f"resuming {name} from byte {offset} of {size}")
        else:
            discard_part(self.outdir, name)
            save_meta(self.outdir, name, size, header["checksum"])
        path = part_path(self.outdir, name)
        hasher = hashlib.sha256()
        if offset:
            # Hash the existing prefix first, so the final digest
            # covers the whole file, not just the resumed tail.
            with open(path, "rb") as f:
                while chunk := f.read(64 * 1024):
                    hasher.update(chunk)
        try:
            handle = open(path, "ab" if offset else "wb")
        except OSError as e:
            print(f"cannot write {path}: {e}")
            self._send_frame({"type": "decline", "id": msg_id, "reason": "cannot write file"})
            return
        self._incoming[msg_id] = {
            "name": name,
            "size": size,
            "checksum": header["checksum"],
            "hasher": hasher,
            "handle": handle,
            "received": offset,
            "offset": offset,
        }
        self._active_names.add(name)
        self._send_frame({"type": "accept", "id": msg_id, "offset": offset})

    def _handle_data_chunk(self, msg_id, chunk):
        """Append one framed data chunk to its transfer."""
        state = self._incoming.get(msg_id)
        if state is None:
            return  # chunk for an unknown or finished transfer: ignore
        remaining = state["size"] - state["received"]
        if remaining <= 0:
            return
        chunk = chunk[:remaining]
        try:
            state["handle"].write(chunk)
        except OSError as e:
            print(f"write error for {state['name']}: {e} -- partial kept")
            self._abort_incoming(msg_id)
            return
        state["hasher"].update(chunk)
        state["received"] += len(chunk)
        progress(state["received"], state["size"], label="receiving", base=state["offset"])

    def _abort_incoming(self, msg_id):
        state = self._incoming.pop(msg_id, None)
        if state is not None:
            try:
                state["handle"].close()
            except OSError:
                pass
            self._active_names.discard(state["name"])

    def _handle_eof(self, frame):
        """The sender finished a file: verify and finalise it."""
        msg_id = frame.get("id")
        state = self._incoming.pop(msg_id, None)
        if state is None:
            return
        self._active_names.discard(state["name"])
        try:
            state["handle"].close()
        except OSError:
            pass
        if state["received"] < state["size"]:
            print(
                f"short file {state['name']}: got {state['received']} of "
                f"{state['size']} bytes -- partial kept"
            )
            return
        ok = _finish_part(
            self.outdir, state["name"], state["checksum"], hasher=state["hasher"], conn=None
        )
        self._send_frame({"type": "received", "id": msg_id, "ok": ok})

    # -- sending --------------------------------------------------------

    def send_file(self, path, timeout=REPLY_TIMEOUT):
        """Offer a file, stream it on acceptance, wait for the
        receipt. Returns True on a verified transfer (or when
        the peer already has it)."""
        if not os.path.isfile(path):
            print(f"file not found: {path}")
            return False
        size = os.path.getsize(path)
        name = os.path.basename(path)
        print(f"hashing {name} ...")
        checksum = sha256_of_file(path, on_progress=lambda d, t: progress(d, t, label="hashing"))
        print(f"{name}: {size} bytes, SHA-256 {checksum}")
        msg_id = next(self._next_id)
        entry = self._register(msg_id)
        try:
            self._send_frame(
                {
                    "type": "file",
                    "id": msg_id,
                    "filename": name,
                    "filesize": size,
                    "checksum": checksum,
                    "protocol": PROTOCOL_VERSION,
                }
            )
        except (OSError, ValueError) as e:
            print(f"could not offer {name}: {e}")
            return False
        reply = self._wait_reply(entry, timeout)
        if reply is None:
            print(f"no reply from {self.peer_addr} for {name} -- session may be down")
            return False
        if reply.get("type") == "decline":
            print(f"peer declined {name}: {reply.get('reason', '')}")
            return False
        if reply.get("type") == "have":
            print(f"peer already has the complete {name} -- nothing to send")
            return True
        if reply.get("type") != "accept":
            print(f"unexpected reply for {name}: {reply.get('type')}")
            return False
        offset = reply.get("offset", 0)
        if offset:
            print(f"resuming {name} from byte {offset} of {size}")
        sent = offset
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                # Framed data chunks, one frame at a time under
                # the write lock: control frames from the reader
                # thread interleave freely between chunks.
                while True:
                    chunk = f.read(MAX_DATA_BYTES)
                    if not chunk:
                        break
                    self._send_data(msg_id, chunk)
                    sent += len(chunk)
                    progress(sent, size, label="sending", base=offset)
            self._send_frame({"type": "eof", "id": msg_id})
        except (OSError, ValueError) as e:
            print(f"send error for {name}: {e} -- partial kept on the peer")
            return False
        receipt = self._wait_reply(entry, timeout)
        if receipt is None:
            print(f"no receipt from {self.peer_addr} for {name}")
            return False
        if receipt.get("type") != "received" or not receipt.get("ok"):
            print(f"peer reported a failed transfer for {name}")
            return False
        print(f"sent {name} -- verified by peer")
        return True


# --- handshake ------------------------------------------------------------


def _host_handshake(conn, key):
    """Listener side: send the challenge, check the reply."""
    challenge = secrets.token_hex(16)
    try:
        send_frame(conn, {"type": "hello", "session": SESSION_VERSION, "challenge": challenge})
    except (OSError, ValueError) as e:
        print(f"session handshake failed: {e}")
        return False
    conn.settimeout(30)
    try:
        kind, reply, _ = recv_frame(conn)
    except (ConnectionError, ValueError, OSError, TimeoutError) as e:
        print(f"session handshake failed: {e}")
        return False
    finally:
        conn.settimeout(None)
    if kind != "control" or not isinstance(reply, dict) or reply.get("type") != "hello":
        print("session handshake failed: bad hello")
        return False
    if key:
        import hmac as _hmac

        if not _hmac.compare_digest(reply.get("auth", ""), _session_auth(key, challenge)):
            print("session auth failed -- wrong or missing key")
            return False
    try:
        send_frame(conn, {"type": "welcome"})
    except (OSError, ValueError) as e:
        print(f"session handshake failed: {e}")
        return False
    return True


def _join_handshake(conn, key):
    """Joiner side: read the challenge, answer it, wait for the
    welcome that proves the host accepted the auth."""
    conn.settimeout(30)
    try:
        kind, hello, _ = recv_frame(conn)
    except (ConnectionError, ValueError, OSError, TimeoutError) as e:
        print(f"session handshake failed: {e}")
        return False
    finally:
        conn.settimeout(None)
    if kind != "control" or not isinstance(hello, dict) or hello.get("type") != "hello":
        print("session handshake failed: bad hello")
        return False
    auth = _session_auth(key, hello["challenge"]) if key else None
    try:
        send_frame(conn, {"type": "hello", "auth": auth})
    except (OSError, ValueError) as e:
        print(f"session handshake failed: {e}")
        return False
    conn.settimeout(30)
    try:
        kind, welcome, _ = recv_frame(conn)
    except (ConnectionError, ValueError, OSError, TimeoutError) as e:
        print(f"session auth failed: {e}")
        return False
    finally:
        conn.settimeout(None)
    if kind != "control" or not isinstance(welcome, dict) or welcome.get("type") != "welcome":
        print("session auth failed: host did not welcome us")
        return False
    return True


# --- serve / join ---------------------------------------------------------


def serve_session(
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
    once=False,
    on_session=None,
):
    """Listen for session peers. For each one, run the handshake,
    build a Session, and call on_session(session) -- which sends
    the local files and runs the command loop. Returns after one
    session when once=True, or on Ctrl-C."""
    outdir = outdir or OUTDIR
    os.makedirs(outdir, exist_ok=True)
    ctx = None
    fp = None
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
        print(f"session listener on {host}:{port}, saving to {outdir} ... (Ctrl-C to stop)")
        if announce is not None:
            if start_announcer(announce, host, port, mode="tcp", tls=tls, fingerprint=fp):
                print(f"announcing as {announce!r} on the LAN (mDNS _warpsend._tcp)")
        while True:
            try:
                conn, addr = srv.accept()
            except KeyboardInterrupt:
                print("\nserver stopped")
                return
            print(f"session peer connected: {addr}")
            wrapped = conn
            if ctx is not None:
                try:
                    wrapped = ctx.wrap_socket(conn, server_side=True)
                except Exception as e:  # noqa: BLE001 -- a bad peer
                    # must not kill the listener.
                    print(f"TLS handshake failed: {e}")
                    conn.close()
                    continue
            if not _host_handshake(wrapped, key):
                try:
                    wrapped.close()
                except OSError:
                    pass
                continue
            session = Session(
                wrapped,
                key=key,
                outdir=outdir,
                max_size=max_size,
                approve=approve,
                peer_addr=addr,
                tls=tls,
            )
            session.start()
            print(f"session open with {addr} -- either side can send now")
            try:
                if on_session is not None:
                    on_session(session)
                else:
                    session.wait_closed()
            finally:
                session.close()
            print(f"session with {addr} ended")
            if once:
                return
            print("waiting for the next peer ...")


def join_session(
    host,
    port,
    key=None,
    tls=False,
    fingerprint=None,
    trust_new=False,
    outdir=None,
    max_size=0,
    approve=None,
):
    """Connect to a listening session. Returns a started Session,
    or None on connection, TLS or auth failure."""
    outdir = outdir or OUTDIR
    os.makedirs(outdir, exist_ok=True)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(30)
        raw.connect((host, port))
    except OSError as e:
        print(f"could not connect to {host}:{port}: {e}")
        return None
    sock = raw
    if tls:
        sock = _wrap_tls(raw, host, fingerprint, trust_new)
        if sock is None:
            raw.close()
            return None
    try:
        sock.settimeout(None)
        if not _join_handshake(sock, key):
            try:
                sock.close()
            except OSError:
                pass
            return None
    except OSError as e:
        print(f"session handshake failed: {e}")
        return None
    try:
        peer = sock.getpeername()
    except OSError:
        peer = (host, port)
    session = Session(
        sock, key=key, outdir=outdir, max_size=max_size, approve=approve, peer_addr=peer, tls=tls
    )
    session.start()
    print(f"session open with {host}:{port} -- either side can send now")
    return session
