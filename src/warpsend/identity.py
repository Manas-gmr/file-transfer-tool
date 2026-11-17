"""Identity -- who the other side is, and how we know.

WarpSend's trust model is deliberately small:

* A receiver generates a self-signed RSA-2048 certificate
  (`warpsend cert`, stored in ~/.warpsend/ with the key at 0600).
* The sender checks the certificate's SHA-256 fingerprint --
  either against a pinned value (--fingerprint) or against the
  known-hosts file (~/.warpsend/known_hosts.json, trust on
  first use). A fingerprint that changes for a known host
  aborts the transfer.
* The 6-digit code (short_code) is a convenience check only:
  ~20 bits, so it must never replace comparing the full
  fingerprint for anything sensitive. See docs/security.md.

The TLS contexts here set a TLS 1.2 floor. The client context
uses CERT_NONE at the library level because self-signed certs
would otherwise be rejected; the real check is the fingerprint
comparison in transfer._wrap_tls, after the handshake.
"""

import hashlib
import json
import os
import ssl
import subprocess

# --- paths ---------------------------------------------------------------


def default_cert_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".warpsend")


def default_cert_path() -> str:
    return os.path.join(default_cert_dir(), "cert.pem")


def default_key_path() -> str:
    return os.path.join(default_cert_dir(), "key.pem")


def default_known_hosts_path() -> str:
    return os.path.join(default_cert_dir(), "known_hosts.json")


# --- fingerprints --------------------------------------------------------


def fingerprint_of_der(der: bytes) -> str:
    """SHA-256 fingerprint of a certificate, hex, no separators."""
    return hashlib.sha256(der).hexdigest()


def fingerprint_of_cert_file(cert_path: str) -> str:
    with open(cert_path, "rb") as f:
        pem = f.read()
    return fingerprint_of_der(ssl.PEM_cert_to_DER_cert(pem.decode()))


def short_code(fingerprint_hex: str) -> str:
    """6-digit code from the fingerprint, like Riptide's (123-456).

    Only ~20 bits of entropy -- a convenience check, not a
    replacement for comparing the full fingerprint.
    """
    code = int(fingerprint_hex[:6], 16) % 1_000_000
    return f"{code:06d}"[:3] + "-" + f"{code:06d}"[3:]


# --- known hosts (trust on first use) ------------------------------------


def load_known_hosts(path: str | None = None) -> dict:
    """host -> fingerprint, from the known-hosts file ({} if none)."""
    path = path or default_known_hosts_path()
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_known_host(path: str | None, host: str, fingerprint_hex: str) -> None:
    """Remember a host's fingerprint (trust on first use)."""
    path = path or default_known_hosts_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    hosts = load_known_hosts(path)
    hosts[host] = fingerprint_hex
    with open(path, "w") as f:
        json.dump(hosts, f, indent=2, sort_keys=True)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# --- certificates ---------------------------------------------------------


def generate_cert(cert_path: str | None = None, key_path: str | None = None):
    """Generate a self-signed RSA-2048 cert with the openssl binary.

    Returns (cert_path, key_path, fingerprint_hex). The private
    key is written with mode 0600. Raises RuntimeError if openssl
    is not available.
    """
    cert_path = cert_path or default_cert_path()
    key_path = key_path or default_key_path()
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "3650",
            "-subj",
            "/CN=warpsend",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"openssl failed: {result.stderr.strip()}")
    os.chmod(key_path, 0o600)
    fp = fingerprint_of_cert_file(cert_path)
    return cert_path, key_path, fp


def server_tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def client_tls_context() -> ssl.SSLContext:
    # CERT_NONE at the library level: self-signed certs would be
    # rejected otherwise. The real check is the fingerprint
    # comparison done by the caller after the handshake, plus
    # the known-hosts file (trust on first use).
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def peer_fingerprint(tls_sock) -> str:
    der = tls_sock.getpeercert(binary_form=True)
    return fingerprint_of_der(der) if der else ""
