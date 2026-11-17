"""Legacy import shim (v1.3 moved the code into src/warpsend/).

Old code that did `from utils import sha256_of_file` keeps
working. New code should import from the package instead:

    from warpsend.protocol import validate_header
    from warpsend.transfer import sha256_of_file
    from warpsend.identity import generate_cert
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src"))

from warpsend.cli import BANNER, TAGLINE, print_banner  # noqa: E402,F401
from warpsend.config import PROTOCOL_VERSION, VERSION  # noqa: E402,F401
from warpsend.identity import (client_tls_context,  # noqa: E402,F401
                               default_cert_dir, default_cert_path,
                               default_key_path, default_known_hosts_path,
                               fingerprint_of_cert_file, fingerprint_of_der,
                               generate_cert, load_known_hosts,
                               peer_fingerprint, save_known_host,
                               server_tls_context, short_code)
from warpsend.protocol import (CHUNK_TCP, CHUNK_UDP, MAX_HEADER_BYTES,  # noqa: E402,F401
                               auth_ok, header_auth, recv_header,
                               recv_line, send_header, validate_header)
from warpsend.transfer import (claim_final_name, crc32_of, discard_part,  # noqa: E402,F401
                               load_meta, meta_path, part_path, progress,
                               resume_offset, save_meta, sha256_of_file,
                               unique_path)

__all__ = ["VERSION", "PROTOCOL_VERSION", "BANNER", "TAGLINE",
           "print_banner", "CHUNK_TCP", "CHUNK_UDP", "MAX_HEADER_BYTES",
           "sha256_of_file", "crc32_of", "progress", "send_header",
           "recv_header", "validate_header", "recv_line", "header_auth",
           "auth_ok", "part_path", "meta_path", "save_meta", "load_meta",
           "resume_offset", "unique_path", "claim_final_name",
           "discard_part", "default_cert_dir", "default_cert_path",
           "default_key_path", "default_known_hosts_path",
           "fingerprint_of_der", "fingerprint_of_cert_file", "short_code",
           "load_known_hosts", "save_known_host", "generate_cert",
           "server_tls_context", "client_tls_context", "peer_fingerprint"]
