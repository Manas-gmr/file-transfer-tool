"""WarpSend defaults -- the knobs a user or a future config file sets.

These are the values the CLI uses when no flag overrides them.
Phase 4 will read them from a TOML config file
(~/.warpsend/config.toml); until then they live here, in one
place, instead of scattered through the code.
"""

import os

VERSION = "1.4.0"
PROTOCOL_VERSION = 2

# Network defaults.
DEFAULT_PORT = 5000
DEFAULT_SEND_HOST = "127.0.0.1"  # `send` talks to localhost by default
DEFAULT_LISTEN_HOST = "0.0.0.0"  # `receive` listens on all interfaces

# Where received files go when --outdir is not given, relative
# to the current working directory (never inside the package).
DEFAULT_OUTDIR_NAME = "received"

# Timeouts and retries.
CONN_TIMEOUT = 120  # seconds of silence before a TCP connection is dropped
UDP_IDLE_TIMEOUT = 30  # seconds of silence before a UDP transfer is abandoned
UDP_TIMEOUT = 0.5  # seconds to wait for a UDP ACK before resending
UDP_MAX_RETRIES = 5


def default_outdir() -> str:
    """The default receive directory for this working directory."""
    return os.path.join(os.getcwd(), DEFAULT_OUTDIR_NAME)
