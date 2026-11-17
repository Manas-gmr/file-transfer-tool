"""Peers and config -- saved machines and defaults.

The config file is TOML (tomllib, Python 3.11+ -- see
requires-python) at ~/.warpsend/config.toml, or wherever
WARPSEND_CONFIG points (tests and power users):

    [defaults]
    host = "192.168.1.10"
    port = 5000
    mode = "tcp"            # tcp | udp
    outdir = "~/received"
    key_file = "~/.warpsend/secret.txt"

    [peers.laptop]
    host = "192.168.1.10"
    port = 5000
    mode = "tcp"
    tls = true
    fingerprint = "<64 hex chars>"
    key_file = "~/.warpsend/laptop-secret.txt"

Precedence, highest first: explicit CLI flag > peer >
[defaults] > built-in default (send host 127.0.0.1, receive
host 0.0.0.0, port 5000, mode tcp, outdir ./received).

The file holds no secrets -- only paths to key files and
fingerprints (trust data). It is still written 0600.
Unknown keys and bad values are rejected on load, so a typo
fails loudly instead of being silently ignored.
"""

import os
import re
import tomllib

from .identity import default_cert_dir

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_HEX = set("0123456789abcdefABCDEF")

# What each table may contain. Anything else is a typo.
_DEFAULT_KEYS = {"host", "port", "mode", "outdir", "key_file", "tls"}
_PEER_KEYS = {"host", "port", "mode", "tls", "fingerprint", "key_file"}


def default_config_path() -> str:
    env = os.environ.get("WARPSEND_CONFIG")
    if env:
        return os.path.expanduser(env)
    return os.path.join(default_cert_dir(), "config.toml")


def _validate_name(name) -> None:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ValueError(
            f"bad peer name {name!r}: use letters, digits, '-' and '_', starting with a letter or digit"
        )


def _validate_host(host) -> None:
    if not isinstance(host, str) or not host or any(c.isspace() for c in host):
        raise ValueError(f"bad host {host!r}: a hostname or IP address, no spaces")


def _validate_port(port) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"bad port {port!r}: an integer from 1 to 65535")


def _validate_mode(mode) -> None:
    if mode not in ("tcp", "udp"):
        raise ValueError(f"bad mode {mode!r}: 'tcp' or 'udp'")


def _validate_bool(value, field) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"bad {field} {value!r}: true or false")


def _validate_fingerprint(fp) -> None:
    if not isinstance(fp, str) or len(fp) != 64 or any(c not in _HEX for c in fp):
        raise ValueError("bad fingerprint: 64 hex characters")


def _validate_path(value, field) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"bad {field} {value!r}: a file path")


def _validate_fields(table, allowed, what) -> None:
    for key in table:
        if key not in allowed:
            raise ValueError(f"unknown key {key!r} in {what} (allowed: {sorted(allowed)})")
    if "host" in table:
        _validate_host(table["host"])
    if "port" in table:
        _validate_port(table["port"])
    if "mode" in table:
        _validate_mode(table["mode"])
    if "tls" in table:
        _validate_bool(table["tls"], "tls")
    if "fingerprint" in table:
        _validate_fingerprint(table["fingerprint"])
    if "key_file" in table:
        _validate_path(table["key_file"], "key_file")
    if "outdir" in table:
        _validate_path(table["outdir"], "outdir")


def load_config(path: str | None = None) -> dict:
    """Load the config file: {"defaults": {...}, "peers": {...}}.

    A missing file means "no config yet" (empty dicts). Bad TOML
    or bad values raise ValueError; unreadable files raise OSError.
    """
    path = path or default_config_path()
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        return {"defaults": {}, "peers": {}}
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"invalid TOML in {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"invalid config in {path}: expected TOML tables")
    defaults = data.get("defaults", {})
    peers = data.get("peers", {})
    for key in data:
        if key not in ("defaults", "peers"):
            raise ValueError(f"unknown top-level key {key!r} in {path} (allowed: defaults, peers)")
    if not isinstance(defaults, dict):
        raise ValueError("[defaults] must be a table")
    if not isinstance(peers, dict):
        raise ValueError("[peers] must be a table of tables")
    _validate_fields(defaults, _DEFAULT_KEYS, "[defaults]")
    for name, fields in peers.items():
        _validate_name(name)
        if not isinstance(fields, dict):
            raise ValueError(f"peer {name!r} must be a table")
        _validate_fields(fields, _PEER_KEYS, f"[peers.{name}]")
        if "host" not in fields:
            raise ValueError(f"peer {name!r} is missing its host")
    return {"defaults": defaults, "peers": peers}


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _dump_table(lines, fields, order) -> None:
    for key in order:
        if key not in fields:
            continue
        value = fields[key]
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f"{key} = {_toml_str(value)}")


def dump_config(config: dict) -> str:
    """Serialise a config dict to TOML text (our schema only)."""
    lines = [
        "# WarpSend config -- saved peers and defaults.",
        "# Written by `warpsend peer add`. Edit by hand if you like;",
        "# unknown keys and bad values are rejected on load.",
        "",
    ]
    defaults = config.get("defaults", {})
    if defaults:
        lines.append("[defaults]")
        _dump_table(lines, defaults, ["host", "port", "mode", "outdir", "key_file", "tls"])
        lines.append("")
    for name in sorted(config.get("peers", {})):
        lines.append(f"[peers.{name}]")
        _dump_table(
            lines,
            config["peers"][name],
            ["host", "port", "mode", "tls", "fingerprint", "key_file"],
        )
        lines.append("")
    return "\n".join(lines)


def save_config(config: dict, path: str | None = None) -> str:
    """Write the config atomically (temp file + rename), mode 0600.

    Returns the path written.
    """
    path = path or default_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(dump_config(config))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return path


def add_peer(config, name, host, port=None, mode=None, tls=False, fingerprint=None, key_file=None):
    """Add a peer to a loaded config dict (in memory only).

    Raises ValueError on a duplicate name or a bad value.
    Call save_config() to persist it.
    """
    _validate_name(name)
    if name in config.get("peers", {}):
        raise ValueError(f"peer {name!r} already exists -- remove it first to replace it")
    peer = {"host": host}
    if port is not None:
        peer["port"] = port
    if mode is not None:
        peer["mode"] = mode
    if tls:
        peer["tls"] = True
    if fingerprint is not None:
        peer["fingerprint"] = fingerprint
    if key_file is not None:
        peer["key_file"] = key_file
    _validate_fields(peer, _PEER_KEYS, f"[peers.{name}]")
    config.setdefault("peers", {})[name] = peer
    return peer


def remove_peer(config, name):
    """Remove a peer from a loaded config dict (in memory only).

    Raises KeyError on an unknown name. Call save_config() to persist it.
    """
    try:
        del config["peers"][name]
    except KeyError:
        known = sorted(config.get("peers", {}))
        hint = f" (known peers: {', '.join(known)})" if known else " (no peers saved yet)"
        raise KeyError(f"unknown peer {name!r}{hint}") from None


def resolve_peer(config, name):
    """Return one peer's fields, or raise KeyError naming the known peers."""
    try:
        return config["peers"][name]
    except KeyError:
        known = sorted(config.get("peers", {}))
        hint = f" (known peers: {', '.join(known)})" if known else " (no peers saved yet)"
        raise KeyError(f"unknown peer {name!r}{hint}") from None


def resolve_target(
    config,
    peer=None,
    host=None,
    port=None,
    mode=None,
    tls=None,
    fingerprint=None,
    key_file=None,
    outdir=None,
    receive=False,
):
    """Merge explicit flags, peer, [defaults] and built-ins.

    Returns a dict with host, port, mode, tls, fingerprint,
    key_file and outdir. `receive` picks the built-in listen
    host (0.0.0.0) instead of the send host (127.0.0.1).
    """
    defaults = config.get("defaults", {})
    peer_cfg = resolve_peer(config, peer) if peer else {}
    merged_host = host or peer_cfg.get("host") or defaults.get("host")
    merged_host = merged_host or ("0.0.0.0" if receive else "127.0.0.1")
    if port is not None:
        merged_port = port
    elif "port" in peer_cfg:
        merged_port = peer_cfg["port"]
    else:
        merged_port = defaults.get("port", 5000)
    merged_mode = mode or peer_cfg.get("mode") or defaults.get("mode") or "tcp"
    if tls is not None:
        merged_tls = tls
    elif "tls" in peer_cfg:
        merged_tls = peer_cfg["tls"]
    else:
        merged_tls = defaults.get("tls", False)
    merged_fp = fingerprint or peer_cfg.get("fingerprint")
    merged_key = key_file or peer_cfg.get("key_file") or defaults.get("key_file")
    merged_outdir = outdir or defaults.get("outdir")
    if merged_outdir:
        merged_outdir = os.path.expanduser(merged_outdir)
    _validate_host(merged_host)
    _validate_port(merged_port)
    _validate_mode(merged_mode)
    _validate_bool(merged_tls, "tls")
    if merged_fp is not None:
        _validate_fingerprint(merged_fp)
    return {
        "host": merged_host,
        "port": merged_port,
        "mode": merged_mode,
        "tls": merged_tls,
        "fingerprint": merged_fp,
        "key_file": merged_key,
        "outdir": merged_outdir,
    }
