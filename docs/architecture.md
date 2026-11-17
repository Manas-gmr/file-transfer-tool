# Architecture

WarpSend is a small, stdlib-only file-transfer CLI. One command,
two modes: `warpsend send` and `warpsend receive`, over TCP or UDP.

## Layout (v1.3)

```
src/warpsend/
  __init__.py    -- VERSION, PROTOCOL_VERSION, public API
  __main__.py    -- `python -m warpsend`
  cli.py         -- argparse, the `warpsend` command, --verbose logging
  config.py      -- defaults: port, hosts, timeouts (Phase 4: TOML file)
  identity.py    -- certs, fingerprints, known hosts (trust on first use)
  protocol.py    -- wire format: headers, validation, HMAC auth
  transfer.py    -- send_tcp / send_udp / serve_tcp / serve_udp,
                    hashing, progress, .part files, never-overwrite
tests/           -- pytest, real servers on localhost in threads
docs/            -- architecture (this file), security, limitations,
                    advantages
```

The top level keeps nothing but the package, the tests and
the docs. `warpsend.py` at the top level was removed in v1.3:
a file of that name shadowed the package whenever the checkout
directory was on `sys.path`. The legacy shims (`server.py`,
`client.py`, `utils.py`) were removed in v1.4 for the same
reason -- a stale `python3 server.py` must fail loudly
instead of silently running old code. From a checkout, run
`PYTHONPATH=src python -m warpsend ...` or `pip install -e .`.

## The transfer, step by step

1. **Hash.** The sender computes the file's SHA-256 (with a
   "hashing..." progress bar) and puts it in the header.
2. **Header.** A length-prefixed JSON object:
   `{"filename", "filesize", "checksum", "protocol": 2,
   "nonce", "auth"}`. The receiver validates it with
   `protocol.validate_header()` before trusting anything:
   required keys, types, `filesize >= 0`, a sane filename
   (basename only), a 64-hex checksum, a supported protocol
   version. Headers over 8 KB are rejected before allocation.
3. **Auth.** With `--key`, the header carries an HMAC-SHA256
   over the fields plus a per-connection nonce: the server's
   random `CHALLENGE` on TCP, a fresh client nonce on UDP
   (rejected on replay). A captured header cannot be replayed.
4. **Bytes.** TCP sends 256 KB chunks with `socket.sendfile()`
   (read/`sendall` under TLS); the OS guarantees order and
   delivery. UDP sends 1024-byte chunks with sequence number,
   total count and CRC32, one ACK per chunk, resend on timeout.
5. **Verify.** The receiver writes to `<name>.part`, updates
   the SHA-256 incrementally as bytes arrive (the existing
   prefix is hashed first on resume), and only renames to the
   final name when the digest matches -- claimed atomically
   with a hard link, never overwriting an existing file
   (`name (1).ext`, ...). A mismatch deletes the partial.
6. **Verdict.** TCP replies `OK`/`CORRUPT`; UDP replies
   `SUCCESS`/`FAIL`. The client's exit code follows the
   verdict (0/1), so scripts and CI can react.

## Resume

The receiver keeps `<name>.part` plus `<name>.part.json`
(filename, filesize, checksum). On a new transfer of the same
file it replies `RESUME <offset>` and the client sends only
the missing bytes. A complete `.part` is hash-verified and
finalised (`DONE`) instead of restarted. A `.part` whose
metadata does not match the incoming file is not resumed.
UDP has no resume: a failed UDP transfer restarts from zero.

## Concurrency

TCP is thread-per-connection with a 120 s socket timeout;
transfers of the same filename are serialised by a per-name
lock, different names run in parallel. UDP is single-transfer
at a time: a new header from the same sender resets the state,
packets from other IPs are ignored, and a 30 s idle timeout
abandons a dead transfer.

## Logging

User-facing messages use `print()`; the same events are also
logged on the `warpsend` logger (`transfer.py`). `warpsend
--verbose` sets the level to DEBUG on stderr. Progress bars go
to stderr so stdout stays machine-readable.

## What lives where, and why

* `identity.py` -- everything about *who* the peer is
  (certs, fingerprints, known hosts). Nothing here knows
  about sockets or files.
* `protocol.py` -- everything about *what bytes mean on the
  wire* (headers, validation, auth tags). Nothing here opens
  a socket or a file.
* `transfer.py` -- everything about *moving bytes* (both
  modes, both directions). It is the only module that does
  I/O, which is why the session protocol (Phase 4) will be
  built on top of it, not inside the CLI.
* `cli.py` -- argument parsing and exit codes only.
* `config.py` -- the defaults, in one place, so a config file
  can replace them without touching the other modules.
