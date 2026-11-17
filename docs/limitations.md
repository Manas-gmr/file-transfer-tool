# Limitations

Honest limits, with what is verified and what is not. Every
claim here is tied to a test or to a stated gap -- see the
comparison doc's warning about README claims that no test
backs up.

## Verified (tests in `tests/test_warpsend.py`, 15 passing)

- TCP fresh transfer, never-overwrite, resume from `.part`,
  complete `.part` finalised.
- Shared-key auth: wrong key rejected, right key accepted.
- TLS: pinned fingerprint works, untrusted host aborts,
  changed fingerprint for a known host aborts.
- Malformed headers (2 GB header claim, bad JSON, missing
  keys, wrong types) are dropped and the server stays alive.
- A `CORRUPT` verdict makes the client fail (exit code 1).
- Receiver approval: decline creates no file and no `.part`
  (TCP and UDP), accept completes the transfer (TCP).
- Sender cancel keeps the `.part` and the server stays
  alive; Ctrl-C exits 130 with no traceback (POSIX only).
- Protocol v3 is enforced: older versions are rejected.
- UDP transfer and state reset after an abandoned transfer
  -- **on CI only** (see below).

## Not verified here

- **UDP on a real network.** Datagrams are blocked in this
  sandbox, so the UDP tests skip here and run on CI, where
  loopback UDP is allowed. Run the UDP commands on your own
  machine before trusting them.
- **Windows and macOS.** CI runs pytest on Linux, macOS and
  Windows on every push. The first run (17 Nov 2026) failed
  on Windows -- CRLF line endings breaking `ruff format
  --check` -- fixed with a `.gitattributes` forcing LF;
  check the Actions tab for the latest result. Nothing here
  has been run on Windows or macOS by hand yet.

## Known limitations

- **UDP is stop-and-wait with 1 KB packets** -- about
  20 KB/s at 50 ms RTT regardless of bandwidth. A sliding
  window is the biggest remaining performance item and needs
  a loss/latency simulator to measure properly.
- **No folder sending**, no parallel streams, no compression.
- **No LAN discovery, no relay, no NAT traversal.** Both
  machines must be directly reachable; CGNAT pairs fail
  without IPv6. No firewall automation.
- **No saved peers / config file.** Host and port are typed
  every time. (Phase 4, still open.)
- **No bidirectional session.** Each file is a fresh
  connection from sender to receiver. (Phase 4, still open.)
- **No expiry for stale `.part` files.** They stay until a
  matching transfer resumes or restarts them. (Phase 4,
  still open.)
- **The 6-digit code is ~20 bits** -- see docs/security.md.
  It is a convenience check, not authentication.
- **No mutual TLS.** The server does not verify the client.
- **Python >= 3.10 required** (the code uses `X | None`
  annotations). The `openssl` binary is needed for
  `warpsend cert`.
- **CI runs on every push.** The workflow file
  (`.github/workflows/ci.yml`) is on GitHub since 17 Nov
  2026; the first run failed on Windows (CRLF line endings
  breaking `ruff format --check`) and was fixed with a
  `.gitattributes` forcing LF -- check the Actions tab for
  the latest result.
- **Not on PyPI yet.** The name `warpsend` was checked on
  17 Nov 2026 and does not exist on PyPI, so it is free to
  claim -- but no release has been published. See
  CHANGELOG.md for the release steps.
