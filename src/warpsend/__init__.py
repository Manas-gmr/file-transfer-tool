"""WarpSend -- send files at warp speed over TCP/UDP, SHA-256 verified.

Public API (stable for the 1.x line):
    warpsend.VERSION, warpsend.PROTOCOL_VERSION
    warpsend.identity   -- certificates, fingerprints, known hosts
    warpsend.protocol   -- headers, auth, wire constants
    warpsend.transfer   -- send_tcp / send_udp / serve_tcp / serve_udp
    warpsend.peers      -- saved peers and config file (~/.warpsend/config.toml)
    warpsend.mdns       -- mDNS discovery (announce + browse, _warpsend._tcp)
    warpsend.session    -- bidirectional persistent sessions
    warpsend.tui        -- Textual file manager (optional extra)
    warpsend.config     -- defaults (port, hosts, timeouts)
    warpsend.cli        -- the `warpsend` command (argparse + main)

Run it with `warpsend ...` after `pip install .`, or
`python -m warpsend ...` from a checkout.
"""

from .config import PROTOCOL_VERSION, VERSION

__version__ = VERSION
__all__ = ["PROTOCOL_VERSION", "VERSION", "__version__"]
