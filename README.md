# WarpSend v1.2.0

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

v1.2 applies the 17 Nov 2026 code review (Phases 1–2, plus the
cheap performance fixes): header validation and size limits,
a crash-proof receiver, exit codes that follow the server's
verdict, thread-per-connection TCP with timeouts, challenge–
response auth, TLS 1.2 with trust-on-first-use, `--outdir`,
`--key-file`, `--max-size`, and a protocol version in the header.

## Install

```bash
git clone https://github.com/Manas-gmr/file-transfer-tool.git
cd file-transfer-tool

# Run it directly, no install needed:
python3 warpsend.py send notes.pdf

# Or install it as a real command:
pip install .
warpsend send notes.pdf
```

## Usage

```bash
# Terminal 1 — receiver (keeps listening for file after file)
warpsend receive --mode tcp --port 5000

# Terminal 2 — sender (several files in one command)
warpsend send notes.pdf slides.pdf --mode tcp --host 127.0.0.1 --port 5000
```

UDP mode — same commands with `--mode udp`. Received files land in `./received/` (or `--outdir`).

```bash
warpsend --help            # all commands and options
warpsend --version         # WarpSend v1.2.0
warpsend --banner          # print just the logo
warpsend send --help       # options for send
warpsend receive --help    # options for receive
```

| Command | What it does |
|---|---|
| `warpsend send <file...> [--mode tcp\|udp] [--host H] [--port P]` | Send file(s) to a receiver; exit code 1 on failure |
| `warpsend receive [--mode tcp\|udp] [--host H] [--port P] [--outdir D] [--max-size N]` | Wait for files and save them (until Ctrl-C) |
| `warpsend cert` | Generate a self-signed TLS certificate in `~/.warpsend/` |
| `warpsend fingerprint [--cert PATH]` | Show a certificate's SHA-256 fingerprint + 6-digit code |

Defaults: `--mode tcp`, `--port 5000`, send host `127.0.0.1`, receive host `0.0.0.0`, outdir `./received`.

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
- **Not protected:** without `--tls`, file contents travel in plaintext and anyone on the path can read them; the HMAC only proves the sender knew the key, and the final SHA-256 is the only check on the bytes themselves. Without `--key`, anyone who can reach the port can push a file. The server does not verify the *client's* certificate. UDP has no TLS and no encryption at all. A trusted session can still push files without per-file approval — only receive from peers you trust. The receiver never overwrites, but it does listen on a port: keep it closed when you are not transferring.

## Files

| File | What it does |
|---|---|
| `warpsend.py` | The CLI — `send` / `receive` / `cert` / `fingerprint`, logo, argument parsing |
| `utils.py` | SHA-256 of a whole file, CRC32 per chunk, progress bar (speed + ETA, stderr), length-prefixed JSON header, header validation, HMAC auth, `.part`/resume metadata, never-overwrite naming (atomic hard-link claim), TLS cert + fingerprint + known-hosts helpers, ASCII logo |
| `server.py` | Receiver engine — thread-per-connection TCP, UDP with sender binding and idle timeout, saves to the outdir, verifies SHA-256, replies OK / CORRUPT (TCP) or SUCCESS / FAIL (UDP) |
| `client.py` | Sender engine — sends file(s) in TCP (sendfile) or UDP mode with a live progress bar; exit code follows the server's verdict |
| `tests/test_warpsend.py` | pytest suite: fresh transfer, no-overwrite, TCP resume, complete `.part`, auth, TLS + trust-on-first-use, malformed headers, CORRUPT verdict, header validation, UDP transfer + state reset |
| `.github/workflows/ci.yml` | GitHub Actions: pytest on Linux, macOS and Windows, Python 3.11/3.12 |
| `LICENSE` | MIT |
| `pyproject.toml` | Installs the `warpsend` command (`pip install .`) |

The old scripts still work directly if you prefer them:
`python3 server.py --mode tcp --port 5000` and
`python3 client.py --mode tcp --file notes.pdf`.

## How it works

**Both modes:** sender hashes the file (with a visible "hashing..."
progress bar), then sends a length-prefixed JSON header
(`filename`, `filesize`, `checksum`, `protocol: 2`, plus a nonce
and an HMAC tag when `--key` is set). Headers over 8 KB are
rejected, and every header is validated (required keys, types,
`filesize >= 0`, sane filename, 64-hex checksum) before anything
is trusted. The receiver writes to `<name>.part` and verifies
SHA-256 after saving — only a match renames it to the final
name, claimed atomically with a hard link, and an existing file
is never overwritten (`name (1).ext`, `name (2).ext`, ...).
A hash mismatch deletes the partial: its prefix cannot be
trusted, so it is not resumed. Files larger than `--max-size`
or the free disk space are rejected with `TOO_LARGE` before
any bytes are sent.

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

**Compatibility:** headers carry `protocol: 2`. A v1.2 client
talking to a pre-v1.2 server falls back to a nonce-less HMAC
after a short wait for the challenge that never comes; a v1.2
server accepts older clients (challenge-response auth needs
v1.2 on both sides to protect against replay).

## Tests

```bash
python -m pytest tests/ -v
```

9 tests, all passing locally (Nov 17, 2026, 3.4 s): fresh
transfer + no-overwrite, TCP resume, complete `.part`
finalised, auth reject/accept, TLS pinned fingerprint +
trust-on-first-use + changed-fingerprint abort, malformed
headers (2 GB header claim, bad JSON, missing keys, wrong
types) with the server staying alive, CORRUPT verdict giving
a client failure, header validation, and UDP transfer +
state reset after an abandoned transfer. The UDP test skips
gracefully where loopback datagrams are blocked (this
sandbox) and runs on CI, where loopback UDP is allowed.

## Known limitations

- UDP is stop-and-wait with 1 KB packets — about 20 KB/s at
  50 ms RTT regardless of bandwidth. A sliding window (the
  review's P1) is the biggest remaining performance item and
  is deliberately not in v1.2: it needs a loss/latency
  simulator to measure properly, and UDP cannot be exercised
  in this sandbox.
- No folder sending, no parallel streams, no compression,
  no LAN discovery, no relay/NAT traversal, no client
  certificate (mutual TLS), no per-file approval prompt.
- Flat module layout (`utils.py` etc. with a `sys.path`
  insert) is kept for v1.2; the `src/warpsend/` package
  move, plus ruff/mypy, is still to do.
- UDP is still unverified on a real network from here —
  run the UDP commands on your own machine to verify them.

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
