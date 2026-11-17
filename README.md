# WarpSend v1.7.0

[![CI](https://github.com/Manas-gmr/file-transfer-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/Manas-gmr/file-transfer-tool/actions/workflows/ci.yml)

```
██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗███████╗███╗   ██╗██████╗
██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗
██║ █╗ ██║███████║██████╔╝██████╔╝███████╗█████╗  ██╔██╗ ██║██║  ██║
██║███╗██║██╔══██║██╔══██╗██╔═══╝ ╚════██║██╔══╝  ██║╚██╗██║██║  ██║
╚███╔███╔╝██║  ██║██║  ██║██║     ███████║███████╗██║ ╚████║██████╔╝
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═══╝╚═════╝
```

**TCP for trust · UDP for speed · SHA-256 verified**

WarpSend is a one-command file-transfer CLI. Send any file over
TCP or UDP with a live progress bar (speed + ETA), and prove it
arrived intact with a checksum. Stdlib only — no dependencies
to install.

v1.7 adds mDNS discovery (Phase 4, part 3), stdlib only:
`warpsend receive --announce` makes the receiver findable
on the LAN by name, `warpsend discover` lists receivers,
and `warpsend send file @laptop` falls back to a LAN lookup
when the peer is not saved. No IPs at all. All 28 tests pass.

## Install

```bash
git clone https://github.com/Manas-gmr/file-transfer-tool.git
cd file-transfer-tool

# Install it as a real command:
pip install .
warpsend send notes.pdf

# Or, from a checkout without installing:
pip install -e .
warpsend send notes.pdf
# or: PYTHONPATH=src python -m warpsend send notes.pdf
```

## Usage

```bash
# Terminal 1 — receiver (keeps listening for file after file)
warpsend receive --mode tcp --port 5000

# Terminal 2 — sender (several files in one command)
warpsend send notes.pdf slides.pdf --mode tcp --host 127.0.0.1 --port 5000

# Saved peers — add once, then send with @name
warpsend peer add laptop 192.168.1.10 --port 5000
warpsend send notes.pdf @laptop
warpsend peer list
warpsend peer remove laptop

# No IPs at all — the receiver announces itself on the LAN
# Terminal 1 (laptop): warpsend receive --announce
# Terminal 2: warpsend discover
#             laptop: 192.168.1.10:5000 tcp
warpsend send notes.pdf @laptop   # not saved? looked up on the LAN
```

UDP mode — same commands with `--mode udp`. Received files land in `./received/` (or `--outdir`).

```bash
warpsend --help            # all commands and options
warpsend --version         # WarpSend v1.7.0
warpsend --banner          # print just the logo
warpsend --verbose send notes.pdf   # also log events to stderr
warpsend send --help       # options for send
warpsend receive --help    # options for receive
```

| Command | What it does |
|---|---|
| `warpsend send <file...> [--mode tcp\|udp] [--host H] [--port P] [--peer NAME]` | Send file(s) to a receiver; exit code 1 on failure, 130 on Ctrl-C cancel |
| `warpsend receive [--mode tcp\|udp] [--host H] [--port P] [--outdir D] [--max-size N] [--approve auto\|prompt] [--announce [NAME]]` | Wait for files and save them (until Ctrl-C); asks before accepting each file by default in a terminal; `--announce` advertises the receiver on the LAN via mDNS (default name: hostname) |
| `warpsend discover [--timeout S]` | List WarpSend receivers announcing on the local network (mDNS) |
| `warpsend peer add <name> <host> [--port P] [--mode tcp\|udp] [--tls] [--fingerprint HEX] [--key-file PATH]` | Save a peer in `~/.warpsend/config.toml` |
| `warpsend peer list` | List saved peers |
| `warpsend peer remove <name>` | Remove a saved peer |
| `warpsend cert` | Generate a self-signed TLS certificate in `~/.warpsend/` |
| `warpsend fingerprint [--cert PATH]` | Show a certificate's SHA-256 fingerprint + 6-digit code |

Defaults: `--mode tcp`, `--port 5000`, send host `127.0.0.1`, receive host `0.0.0.0`, outdir `./received`.

## Saved peers and config (`~/.warpsend/config.toml`)

```toml
[defaults]
host = "192.168.1.10"
port = 5000
mode = "tcp"
outdir = "~/received"
key_file = "~/.warpsend/secret.txt"

[peers.laptop]
host = "192.168.1.10"
port = 5000
mode = "tcp"
tls = true
fingerprint = "<64 hex chars>"
key_file = "~/.warpsend/laptop-secret.txt"
```

Precedence, highest first: an explicit flag (`--host`,
`--port`, `--mode`, `--tls`, `--fingerprint`, `--key-file`)
beats the peer, which beats `[defaults]`, which beats the
built-in default. `WARPSEND_CONFIG` points at a different
config file. The file holds no secrets -- only paths to key
files and fingerprints -- but is still written 0600.
Unknown keys and bad values are rejected on load, so a typo
fails loudly instead of being silently ignored. A file
literally named `@x` must be spelled `./@x` when sending,
since a bare `@name` always means a peer.

## Security (optional, both sides must agree)

```bash
# Shared secret — the receiver rejects senders without it.
# Prefer --key-file or the env var; --key shows in process listings.
printf 'correct-horse' > secret.txt
warpsend receive --key-file secret.txt
warpsend send notes.pdf --key-file secret.txt
# or: export WARPSEND_KEY='correct-horse'

# TLS — encrypted, with fingerprint pinning (TCP only).
warpsend cert                                   # receiver, once
warpsend receive --tls                          # receiver
warpsend send notes.pdf --tls --fingerprint <hex from the receiver>
# or --trust-new to trust a new host once and remember it
warpsend send notes.pdf --tls --trust-new
```

### Threat model — what is and is not protected

- **Protected:** file integrity — SHA-256 over the whole file, verified before rename, plus CRC32 per UDP chunk. Authenticated headers — HMAC-SHA256 over filename, size, checksum *and* a per-connection nonce (the server's random TCP challenge, or a fresh client nonce for UDP that the server rejects on replay). Confidentiality — only with `--tls` (TLS 1.2 minimum, self-signed cert, fingerprint pinned or remembered per host in `~/.warpsend/known_hosts.json`; a changed fingerprint aborts).
- **Not protected:** without `--tls`, file contents travel in plaintext and anyone on the path can read them; the HMAC only proves the sender knew the key, and the final SHA-256 is the only check on the bytes themselves. Without `--key`, anyone who can reach the port can push a file -- unless approval asks first (it does by default in a terminal; `--approve auto` turns it off, so only use that with peers you trust). The server does not verify the *client's* certificate. UDP has no TLS and no encryption at all. The receiver never overwrites, but it does listen on a port: keep it closed when you are not transferring.

The 6-digit code is only ~20 bits -- a convenience check for
the first connect, never a replacement for the full
fingerprint. Full details: [docs/security.md](docs/security.md).

## Docs

- [docs/architecture.md](docs/architecture.md) — layout, the transfer step by step, resume, concurrency, logging
- [docs/security.md](docs/security.md) — threat model, the 6-digit-code weakness, header/file handling, practice
- [docs/limitations.md](docs/limitations.md) — what is verified, what is not, known limits (including CI and PyPI status)
- [docs/advantages.md](docs/advantages.md) — why WarpSend, why not, provenance
- [CHANGELOG.md](CHANGELOG.md) — release history and migration notes

## Files

| Path | What it does |
|---|---|
| `src/warpsend/cli.py` | The CLI — `send` / `receive` / `cert` / `fingerprint`, logo, argument parsing, `--verbose` |
| `src/warpsend/config.py` | Defaults: port, hosts, timeouts (a TOML config file may replace these in a future release) |
| `src/warpsend/identity.py` | Certificates, fingerprints, known hosts (trust on first use) |
| `src/warpsend/mdns.py` | mDNS discovery: DNS packet encode/decode, announce (`_warpsend._tcp.local`) and browse |
| `src/warpsend/peers.py` | Saved peers and config file: TOML load/save, validation, flag > peer > defaults > built-in resolution |
| `src/warpsend/protocol.py` | Wire format: length-prefixed JSON header, validation, HMAC auth |
| `src/warpsend/transfer.py` | Sender + receiver engines, both modes; hashing, progress, `.part` files, never-overwrite |
| `src/warpsend/__main__.py` | `python -m warpsend` |
| `tests/test_warpsend.py` | pytest suite: fresh transfer, no-overwrite, TCP resume, complete `.part`, auth, TLS + trust-on-first-use, malformed headers, CORRUPT verdict, header validation, UDP transfer + state reset, package layout, receiver approval (accept/decline, TCP + UDP), sender cancel, Ctrl-C exit 130, peer add/list/remove roundtrip, peer validation, resolve precedence, defaults, malformed config, CLI `@peer` end to end, mDNS packet roundtrips, compression pointers, query answering, live announce+browse, announce failure not killing the receiver, CLI discover, `@peer` LAN fallback |
| `.github/workflows/ci.yml` | GitHub Actions: ruff + pytest on Linux, macOS and Windows, Python 3.11/3.12 (see note below) |
| `LICENSE` | MIT |
| `pyproject.toml` | Installs the `warpsend` command (`pip install .`); ruff + pytest config |

## How it works

**Both modes:** sender hashes the file (with a visible "hashing..."
progress bar), then sends a length-prefixed JSON header
(`filename`, `filesize`, `checksum`, `protocol: 3`, plus a nonce
and an HMAC tag when `--key` is set). Headers over 8 KB are
rejected, and every header is validated (required keys, types,
`filesize >= 0`, sane filename, 64-hex checksum, protocol
version 3) before anything is trusted. After the checks pass,
the receiver may ask its operator whether to accept the file
(`--approve prompt`, or the default when stdin is a terminal):
a decline answers `REJECTED` (TCP) or `FAIL` (UDP) and
creates no file. The receiver writes to `<name>.part` and verifies
SHA-256 after saving — only a match renames it to the final
name, claimed atomically with a hard link, and an existing file
is never overwritten (`name (1).ext`, `name (2).ext`, ...).
A hash mismatch deletes the partial: its prefix cannot be
trusted, so it is not resumed. Files larger than `--max-size`
or the free disk space are rejected with `TOO_LARGE` before
any bytes are sent. Ctrl-C during a send exits 130 with a
clean message: the socket closes, the receiver keeps the
`.part` for resume, and a TCP receiver keeps listening.

**TCP:** 256 KB chunks, sent with `socket.sendfile()` on the
plain path (read/`sendall` under TLS). Ordering, loss and
duplicates are handled by the OS. The server sends a random
`CHALLENGE` on accept; the HMAC covers it. After the header
it replies `FRESH 0`, `RESUME <offset>` when a `.part` +
`.part.json` for the same file (same name, size and checksum)
is already on disk, or `DONE` when that `.part` is already
complete — the client then verifies nothing and sends nothing.
The SHA-256 is updated incrementally as bytes arrive (the
existing prefix is hashed first on resume), so there is no
second full read at the end. Connections run in threads with
a 120 s timeout, and transfers of the same filename are
serialised by a per-name lock.

**UDP:** 1024-byte chunks, each packet carrying
`[type][sequence number][total chunks][CRC32][data]`. The header
is ACKed (type 4) and retried up to 5 times, data chunks are
ACKed per chunk (duplicates ignored), and EOF is retried until
the SUCCESS/FAIL reply arrives — "no final reply" now counts
as failure, not success. Chunks are written straight to the
`.part` file at `seq * 1024` with a running byte counter,
instead of being held in RAM. Packets from any IP other than
the header sender are ignored, a new header resets all
per-transfer state, and a 30 s idle timeout abandons a dead
transfer. A chunk with a bad CRC32 gets no ACK, so the client
resends it after a 0.5 s timeout (up to 5 tries). Progress
updates on ACK, not on send — otherwise it would lie when a
packet is lost. An EOF with chunks missing replies FAIL and
keeps the `.part`. UDP has no resume: a failed UDP transfer
restarts from the start.

**Compatibility:** headers carry `protocol: 3`, and v1.5
enforces it: a v1.4 or older peer is rejected as `INVALID`.
Both ends must be v1.5+ to talk to each other.

## Tests

```bash
python -m pytest tests/ -v
ruff check src tests && ruff format --check src tests
```

28 tests, all passing locally (Nov 17, 2026, ~6 s): fresh
transfer + no-overwrite, TCP resume, complete `.part`
finalised, auth reject/accept, TLS pinned fingerprint +
trust-on-first-use + changed-fingerprint abort, malformed
headers (2 GB header claim, bad JSON, missing keys, wrong
types) with the server staying alive, CORRUPT verdict giving
a client failure, header validation, UDP transfer +
state reset after an abandoned transfer, the package
layout (including a check that no stale flat module is
importable), receiver approval decline and accept (TCP),
receiver approval decline (UDP), sender cancel keeping the
`.part` with the server staying alive, and Ctrl-C during a
send exiting 130 with no traceback (POSIX only), peer
add/list/remove roundtrip (config written 0600), peer
validation (names, ports, modes, fingerprints, unknown
keys), resolve precedence (flag > peer > defaults >
built-in), `[defaults]` applied on load, malformed config
rejected (bad TOML, unknown key, peer without a host), and
a CLI end to end (peer add/list/send `@peer`/remove, unknown
peer failing cleanly), mDNS packet encode/decode roundtrips,
compression pointers (and a pointer loop rejected), the
query answerer (QU unicast vs multicast replies, other
services ignored), a live announce+browse (skips where
multicast is blocked), a failed announce not killing the
receiver, CLI discover, and the `@peer` LAN fallback failing
cleanly. The UDP and mDNS live tests skip gracefully where
loopback datagrams or multicast are blocked (this sandbox)
and run on CI, where loopback UDP is allowed.

## Known limitations

- UDP is stop-and-wait with 1 KB packets — about 20 KB/s at
  50 ms RTT regardless of bandwidth. A sliding window is the
  biggest remaining performance item (Phase 5).
- No folder sending, no parallel streams, no compression,
  no LAN discovery, no relay/NAT traversal, no client
  certificate (mutual TLS).
- CI runs on every push now that the workflow file is on
  GitHub (added 17 Nov 2026). The first run failed on
  Windows -- CRLF line endings breaking `ruff format
  --check` -- fixed with a `.gitattributes` forcing LF;
  check the Actions tab for the latest result.
- Not on PyPI yet: the name `warpsend` was checked on
  17 Nov 2026 and does not exist, so it is free to claim.
  Release steps (tag, CI file, PyPI upload) are in
  [CHANGELOG.md](CHANGELOG.md).
- UDP is still unverified on a real network from here —
  run the UDP commands on your own machine to verify them.

Full list: [docs/limitations.md](docs/limitations.md).

## Try yourself

1. Send a larger file (e.g. 50 MB) in both modes and compare the time.
2. Corruption test: change one byte in `received/<file>` and re-run
   `sha256sum` — it will no longer match the sender's hash.
3. Resume test: start a big TCP transfer, kill the sender with
   Ctrl-C mid-way, then send the same file again and watch it
   finish from where it stopped.
4. UDP loss test: add a random 10% drop on the server side and
   confirm retransmission still completes the file — including
   dropping header and EOF packets specifically.

## Viva one-liner

*TCP gives reliability, flow control and congestion control by
default. UDP gives speed and low overhead, but reliability,
ordering and retransmission must be implemented in the
application layer — which is what the UDP mode here does.*
