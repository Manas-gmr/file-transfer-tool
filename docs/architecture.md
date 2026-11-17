# Architecture

WarpSend is a small, stdlib-only file-transfer CLI. One command,
two modes: `warpsend send` and `warpsend receive`, over TCP or UDP.

## Layout (v1.9)

```
src/warpsend/
  __init__.py    -- VERSION, PROTOCOL_VERSION, public API
  __main__.py    -- `python -m warpsend`
  cli.py         -- argparse, the `warpsend` command, --verbose logging
  config.py      -- defaults: port, hosts, timeouts (a TOML
                    config file may replace these in a future release)
  identity.py    -- certs, fingerprints, known hosts (trust on first use)
  protocol.py    -- wire format: headers, validation, HMAC auth
  peers.py       -- saved peers and config file (TOML), resolution
  mdns.py        -- mDNS discovery: DNS packets, announce, browse
  session.py     -- bidirectional sessions: framing, Session, serve/join
  tui.py         -- Textual file manager (optional extra)
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
   `{"filename", "filesize", "checksum", "protocol": 3,
   "nonce", "auth"}`. The receiver validates it with
   `protocol.validate_header()` before trusting anything:
   required keys, types, `filesize >= 0`, a sane filename
   (basename only), a 64-hex checksum, protocol version 3
   (older versions are rejected). Headers over 8 KB are
   rejected before allocation.
3. **Auth.** With `--key`, the header carries an HMAC-SHA256
   over the fields plus a per-connection nonce: the server's
   random `CHALLENGE` on TCP, a fresh client nonce on UDP
   (rejected on replay). A captured header cannot be replayed.
4. **Approval.** After the checks pass, the receiver may ask
   its operator whether to accept the file (`approve`
   callable, wired to an interactive prompt by the CLI when
   stdin is a terminal). TCP answers `FRESH 0` / `RESUME
   <offset>` / `DONE` on accept and `REJECTED` on decline;
   UDP answers the header ACK on accept and `FAIL` on
   decline. A decline creates no file and no `.part`.
5. **Bytes.** TCP sends 256 KB chunks with `socket.sendfile()`
   (read/`sendall` under TLS); the OS guarantees order and
   delivery. UDP sends 1024-byte chunks with sequence number,
   total count and CRC32, one ACK per chunk, resend on timeout.
6. **Verify.** The receiver writes to `<name>.part`, updates
   the SHA-256 incrementally as bytes arrive (the existing
   prefix is hashed first on resume), and only renames to the
   final name when the digest matches -- claimed atomically
   with a hard link, never overwriting an existing file
   (`name (1).ext`, ...). A mismatch deletes the partial.
7. **Verdict.** TCP replies `OK`/`CORRUPT`; UDP replies
   `SUCCESS`/`FAIL`. The client's exit code follows the
   verdict (0/1), so scripts and CI can react. A decline
   exits 1; a cancel (Ctrl-C) exits 130.

## Peers and config

`peers.py` owns `~/.warpsend/config.toml` (or `WARPSEND_CONFIG`):
`[defaults]` plus one `[peers.<name>]` table per saved machine.
Loading validates everything -- unknown keys, bad names,
bad ports, bad modes, bad fingerprints and peers without a
host are all rejected with a clear message, so a typo fails
loudly. Saving is atomic (temp file + rename) and the file
is written 0600, even though it holds no secrets (only paths
to key files and fingerprints).

`resolve_target()` merges the four layers -- explicit flag >
peer > `[defaults]` > built-in -- for host, port, mode, TLS,
fingerprint, key file and outdir. The CLI resolves once per
invocation and passes plain values down, so `transfer.py`
never knows the config exists. `warpsend peer add/list/remove`
are thin wrappers over `add_peer` / `remove_peer` /
`save_config`; `@name` on the `send` command line is pulled
out of the file list by the CLI (`_extract_peer`), with
`--peer` as the explicit form.

## mDNS discovery

`mdns.py` is a minimal mDNS (RFC 6762) + DNS-SD (RFC 6763)
implementation in stdlib only. The receiver announces the
service `_warpsend._tcp.local` with four records -- PTR,
SRV (hostname + port), TXT (`version`, `mode`, `tls`, and
the fingerprint when TLS is on) and A (the LAN address) --
and a daemon thread answers queries for it. The sender
browses with a single QU question (unicast reply), so the
browser never binds port 5353; the announcer does, with
SO_REUSEPORT so it shares the port with Avahi/Bonjour.
`@peer` on the send command line resolves in this order:
saved peer, then a ~2.5 s LAN lookup, then a clean error.

The packet layer is deliberately small: names are encoded
without compression, decoded with compression pointers and
a loop guard. Nothing about mDNS has been verified on a
real network -- the sandbox blocks UDP, so the live
announce+browse test skips there and runs wherever
multicast is allowed. A failed announce never kills the
receiver: `start_announcer` returns None on setup failure
and the announcer thread stops itself on a later send
failure, printing a warning either way.

## Bidirectional session

`session.py` is the persistent-connection counterpart to the
one-shot transfer. One side listens (`serve_session`), the
other joins (`join_session`); after a hello/welcome handshake
with an HMAC challenge, both sides hold a `Session`: a reader
thread dispatching frames, a write lock that makes each
frame atomic, and a pending-reply registry keyed by message
id so a send can wait for its own accept/receipt while the
reader keeps working.

The framing is the point: every frame is length + a marker
byte + payload, control frames carrying JSON and data frames
carrying a transfer id + up to 256 KB of file bytes. File
data is never raw on the stream, so control frames interleave
with it and both directions transfer concurrently -- an
earlier draft sent file bytes raw and serialised transfers
with a lock, which deadlocked the two-way case (each side's
sender held its lock while waiting for a reply its own
reader could not deliver). Offers reuse `validate_header()`
and the `.part` + resume + never-overwrite machinery from
`transfer.py`; a second offer for a filename already being
received is declined. The CLI drives a session with
`--send` files up front, then a `send <file>` / `quit`
command loop reading stdin under a lock shared with the
approval prompt, so the prompt can never steal half a typed
command. EOF on stdin ends the session.

## TUI

`tui.py` is the optional Textual interface (`pip install
warpsend[tui]`). The app is a thin shell over the existing
machinery: a `DirectoryTree` for files, the config file plus
`browse()` for peers, and `send_tcp` for sending. Two
design points matter. First, sending runs in a worker
thread through `send_tcp`'s `on_progress` / `on_message`
hooks, so the progress bar shows exact percentages and
nothing prints to the terminal behind the app. Second,
receiving runs as a `warpsend receive` subprocess whose
output is piped into the log widget -- its prints never
reach the screen, so the display stays clean. Sends are
TCP only; the peer's mode is ignored.

## Cancel

Cancelling is closing the connection. There is deliberately
no in-band cancel packet: after the header the TCP stream is
raw file bytes, so any extra bytes would be written as file
data (and a hash mismatch would then *delete* the partial --
the opposite of what a cancel wants). On Ctrl-C the sender
exits 130 with a clean message; the receiver sees EOF, keeps
the `.part` for resume, and keeps listening. `send_tcp` /
`send_udp` also accept a `cancel` threading.Event, checked
per chunk, which raises `TransferCancelled`. On UDP the
sender simply stops and the receiver's 30 s idle timeout
abandons the transfer, keeping the `.part`. The receiver
side has no per-transfer cancel of its own: its control
point is the approval prompt, and Ctrl-C stops the server
(the in-progress `.part` is still kept).

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
* `tui.py` -- everything about *the interface* (file tree,
  peer list, send queue, progress, log). It owns no
  protocol: it calls `send_tcp`, `browse()` and the
  config helpers, and shells out to `warpsend receive`.
* `session.py` -- everything about *a live session* (framing,
  handshake, sending and receiving inside a session). It
  reuses the .part machinery from `transfer.py` and never
  touches the one-shot protocol.
* `mdns.py` -- everything about *finding receivers*
  (DNS packets, announce, browse). It never moves a file.
* `peers.py` -- everything about *where to send and what the
  defaults are* (TOML config, peer tables, resolution). It
  never opens a socket or moves a file.
* `transfer.py` -- everything about *moving bytes* (both
  modes, both directions). It is the only module that does
  I/O, which is why the session protocol (Phase 4: approval
  and cancel, done in v1.5) is built on top of it, not
  inside the CLI.
* `cli.py` -- argument parsing and exit codes only.
* `config.py` -- the defaults, in one place, so a config file
  can replace them without touching the other modules.
