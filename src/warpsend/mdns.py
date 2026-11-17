"""mDNS discovery -- find WarpSend receivers on the LAN by name.

Minimal multicast DNS (RFC 6762) + DNS-SD (RFC 6763), stdlib
only -- no zeroconf dependency. A receiver announces the
service `_warpsend._tcp.local` and answers queries for it; a
sender browses for that service and gets back instance names,
hosts and ports, so `warpsend send file @laptop` works with
no saved peer and no typed IP.

Wire format (the only part that must be exact):
  * UDP to 224.0.0.251:5353, TTL 255, loopback on.
  * PTR: `_warpsend._tcp.local` -> `<instance>._warpsend._tcp.local`
  * SRV: `<instance>...` -> `<hostname>.local`, port
  * TXT: `<instance>...` -> version=... mode=... tls=0|1 [fp=<hex>]
  * A: `<hostname>.local` -> LAN IPv4 address
  * Browsing uses QU questions (unicast replies), so the
    browser needs no port-5353 bind; the announcer binds 5353
    with SO_REUSEPORT so it shares the port with Avahi/Bonjour.

Limits, stated plainly: same subnet only (multicast does not
cross routers), no goodbye packets on shutdown (a stale entry
lingers until its 120 s TTL expires), and nothing here has
been verified on a real network -- the sandbox blocks UDP
entirely, so live announce/browse is only exercised on CI if
its runners allow multicast, and on your own machine.
"""

import socket
import struct
import threading
import time

from .config import VERSION

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SERVICE = "_warpsend._tcp.local"
TTL = 120  # seconds; a stale announcement lingers at most this long

# DNS types / classes.
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_SRV = 33
CLASS_IN = 1
CLASS_QU = 0x8000  # question: please answer by unicast
CLASS_FLUSH = 0x8000  # record: flush the cache for this name/type


# --- DNS name coding ------------------------------------------------------


def encode_name(name: str) -> bytes:
    """'a.b.local' -> b'\\x01a\\x01b\\x05local\\x00' (no compression)."""
    out = b""
    for label in name.split("."):
        raw = label.encode()
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(msg: bytes, off: int):
    """Decode a name at off, following 0xC0 compression pointers.

    Returns (name, next_offset). A pointer loop raises ValueError.
    """
    labels = []
    next_off = None
    seen = set()
    while True:
        if off >= len(msg):
            raise ValueError("name runs past the end of the message")
        length = msg[off]
        if length == 0:
            return ".".join(labels), (next_off if next_off is not None else off + 1)
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | msg[off + 1]
            if target in seen:
                raise ValueError("compression pointer loop")
            seen.add(target)
            if next_off is None:
                next_off = off + 2
            off = target
            continue
        if length & 0xC0:
            raise ValueError("bad label length byte")
        off += 1
        if off + length > len(msg):
            raise ValueError("label runs past the end of the message")
        labels.append(msg[off : off + length].decode(errors="replace"))
        off += length


# --- message building -----------------------------------------------------


def build_query(service: str = SERVICE) -> bytes:
    """A PTR question for the service, QU bit set (unicast reply)."""
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    question = encode_name(service) + struct.pack("!HH", TYPE_PTR, CLASS_IN | CLASS_QU)
    return header + question


def _record(name, rtype, rdata, ttl=TTL):
    return (
        encode_name(name)
        + struct.pack("!HHIH", rtype, CLASS_IN | CLASS_FLUSH, ttl, len(rdata))
        + rdata
    )


def build_announcement(instance: str, hostname: str, ip: str, port: int, txt: dict) -> bytes:
    """One response carrying PTR + SRV + TXT + A for an instance.

    `instance` is the bare name ("laptop"); the service suffix
    is added here. TXT values are `key=value` strings.
    """
    full = f"{instance}.{SERVICE}"
    host_full = f"{hostname}.local"
    ptr = _record(SERVICE, TYPE_PTR, encode_name(full))
    srv = _record(full, TYPE_SRV, struct.pack("!HHH", 0, 0, port) + encode_name(host_full))
    txt_data = b"".join(
        bytes([len(item)]) + item.encode() for item in (f"{k}={v}" for k, v in txt.items())
    )
    txt_rec = _record(full, TYPE_TXT, txt_data)
    a_rec = _record(host_full, TYPE_A, socket.inet_aton(ip))
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 4, 0, 0)
    return header + ptr + srv + txt_rec + a_rec


# --- message parsing ------------------------------------------------------


def _parse_rdata(msg, off, rtype, rdlength):
    end = off + rdlength
    if rtype == TYPE_PTR:
        name, _ = decode_name(msg, off)
        return name
    if rtype == TYPE_SRV:
        if rdlength < 6:
            raise ValueError("short SRV record")
        _prio, _weight, port = struct.unpack("!HHH", msg[off : off + 6])
        target, _ = decode_name(msg, off + 6)
        return {"port": port, "target": target}
    if rtype == TYPE_TXT:
        items = []
        p = off
        while p < end:
            n = msg[p]
            p += 1
            items.append(msg[p : p + n].decode(errors="replace"))
            p += n
        return items
    if rtype == TYPE_A:
        if rdlength != 4:
            raise ValueError("bad A record")
        return socket.inet_ntoa(msg[off:end])
    return msg[off:end]


def parse_message(data: bytes):
    """Parse a DNS message -> {"questions": [...], "answers": [...]}.

    Questions are (name, qtype, qclass); answers are
    (name, rtype, rclass, ttl, rdata) with rdata decoded for
    the types above. Raises ValueError on a malformed message.
    """
    if len(data) < 12:
        raise ValueError("message shorter than the DNS header")
    _id, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    questions = []
    for _ in range(qd):
        name, off = decode_name(data, off)
        if off + 4 > len(data):
            raise ValueError("truncated question")
        qtype, qclass = struct.unpack("!HH", data[off : off + 4])
        off += 4
        questions.append((name, qtype, qclass))
    answers = []
    for _ in range(an):
        name, off = decode_name(data, off)
        if off + 10 > len(data):
            raise ValueError("truncated answer")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[off : off + 10])
        off += 10
        if off + rdlength > len(data):
            raise ValueError("truncated rdata")
        answers.append((name, rtype, rclass, ttl, _parse_rdata(data, off, rtype, rdlength)))
        off += rdlength
    return {"questions": questions, "answers": answers}


# --- answering ------------------------------------------------------------


def answer_query(data, instance, hostname, ip, port, txt):
    """Answer a query for our service, or None if it is not for us.

    Returns (response_bytes, unicast): unicast is True when any
    question asked with the QU bit, in which case the reply goes
    to the querier instead of the multicast group.
    """
    try:
        msg = parse_message(data)
    except ValueError:
        return None, False
    full = f"{instance}.{SERVICE}"
    host_full = f"{hostname}.local"
    unicast = False
    want = None
    for name, qtype, qclass in msg["questions"]:
        if qclass & CLASS_QU:
            unicast = True
        if name == SERVICE and qtype == TYPE_PTR:
            want = "all"
        elif name == full and qtype in (TYPE_SRV, TYPE_TXT, TYPE_A):
            want = qtype
    if want is None:
        return None, False
    if want == "all":
        return build_announcement(instance, hostname, ip, port, txt), unicast
    if want == TYPE_SRV:
        rec = _record(full, TYPE_SRV, struct.pack("!HHH", 0, 0, port) + encode_name(host_full))
    elif want == TYPE_TXT:
        txt_data = b"".join(
            bytes([len(item)]) + item.encode() for item in (f"{k}={v}" for k, v in txt.items())
        )
        rec = _record(full, TYPE_TXT, txt_data)
    else:
        rec = _record(host_full, TYPE_A, socket.inet_aton(ip))
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    return header + rec, unicast


# --- sockets --------------------------------------------------------------


def get_lan_ip() -> str:
    """The machine's LAN address (no packet is actually sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def sanitize_instance(name: str) -> str:
    """Make a hostname safe as one mDNS instance label."""
    name = name.removesuffix(".local")
    cleaned = "".join(c if c.isalnum() or c in " _-" else "-" for c in name).strip()
    return cleaned or "warpsend"


def open_mdns_socket():
    """A UDP socket bound to 5353 and joined to the mDNS group.

    SO_REUSEPORT lets it share the port with Avahi/Bonjour.
    Raises OSError when multicast is unavailable here.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(("", MDNS_PORT))
    mreq = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    return sock


def _txt_for(mode, tls, fingerprint=None):
    txt = {"version": VERSION, "mode": mode, "tls": "1" if tls else "0"}
    if fingerprint:
        txt["fp"] = fingerprint
    return txt


def start_announcer(instance, listen_host, port, mode="tcp", tls=False, fingerprint=None):
    """Announce a receiver on the LAN in a daemon thread.

    Returns (thread, stop_event), or None when mDNS is
    unavailable here -- the receiver still works, peers just
    have to use IPs or saved peers instead.
    """
    hostname = socket.gethostname().removesuffix(".local")
    instance = sanitize_instance(instance)
    ip = listen_host if listen_host != "0.0.0.0" else get_lan_ip()
    txt = _txt_for(mode, tls, fingerprint)
    try:
        sock = open_mdns_socket()
    except OSError as e:
        print(f"mDNS announce unavailable ({e}) -- receiver still works without it")
        return None
    stop = threading.Event()

    def _run():
        announcement = build_announcement(instance, hostname, ip, port, txt)
        try:
            sock.sendto(announcement, (MDNS_GROUP, MDNS_PORT))
        except OSError as e:
            print(f"mDNS announce failed ({e}) -- stopping announcements")
            sock.close()
            return
        sock.settimeout(1.0)
        last = time.monotonic()
        while not stop.is_set():
            if time.monotonic() - last > 120:
                try:
                    sock.sendto(announcement, (MDNS_GROUP, MDNS_PORT))
                except OSError:
                    break
                last = time.monotonic()
            try:
                data, addr = sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            reply, unicast = answer_query(data, instance, hostname, ip, port, txt)
            if reply is None:
                continue
            try:
                sock.sendto(reply, addr if unicast else (MDNS_GROUP, MDNS_PORT))
            except OSError:
                break
        sock.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread, stop


# --- browsing -------------------------------------------------------------


def browse(timeout: float = 3.0):
    """Find WarpSend receivers on the LAN.

    Sends one QU query and collects replies for `timeout`
    seconds. Returns [{"name", "host", "port", "mode", "tls",
    "fingerprint"}] sorted by name. Raises OSError when
    multicast is unavailable here.
    """
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.sendto(build_query(), (MDNS_GROUP, MDNS_PORT))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = sock.recvfrom(4096)
            except TimeoutError:
                continue
            try:
                msg = parse_message(data)
            except ValueError:
                continue
            for name, rtype, _cls, _ttl, rdata in msg["answers"]:
                if rtype == TYPE_PTR and name == SERVICE:
                    instance = rdata.removesuffix("." + SERVICE)
                    found.setdefault(instance, {"name": instance, "host": addr[0]})
                elif rtype == TYPE_SRV:
                    instance = name.removesuffix("." + SERVICE)
                    peer = found.setdefault(instance, {"name": instance, "host": addr[0]})
                    peer["port"] = rdata["port"]
                    peer["_target"] = rdata["target"]
                elif rtype == TYPE_TXT:
                    instance = name.removesuffix("." + SERVICE)
                    peer = found.setdefault(instance, {"name": instance, "host": addr[0]})
                    for item in rdata:
                        if "=" in item:
                            k, v = item.split("=", 1)
                            peer[k] = v
                elif rtype == TYPE_A:
                    for peer in found.values():
                        if peer.get("_target") == name:
                            peer["host"] = rdata
    peers = []
    for peer in found.values():
        if "port" not in peer:
            continue
        peers.append(
            {
                "name": peer["name"],
                "host": peer["host"],
                "port": peer["port"],
                "mode": peer.get("mode", "tcp"),
                "tls": peer.get("tls") == "1",
                "fingerprint": peer.get("fp"),
            }
        )
    return sorted(peers, key=lambda p: p["name"].lower())


def discover_peer(name: str, timeout: float = 2.5):
    """Find one receiver by instance name (case-insensitive), or None."""
    for peer in browse(timeout=timeout):
        if peer["name"].lower() == name.lower():
            return peer
    return None
