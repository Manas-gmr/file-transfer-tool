# WarpSend v1.1.0

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

v1.1 adds what the Riptide comparison showed was missing:
`.part` + rename-only-on-match, never-overwrite, TCP resume,
a persistent receiver, shared-key auth, and optional TLS with
fingerprint pinning.

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

UDP mode — same commands with `--mode udp`. Received files land in `received/`.

```bash
warpsend --help            # all commands and options
warpsend --version         # WarpSend v1.1.0
warpsend --banner          # print just the logo
warpsend send --help       # options for send
warpsend receive --help    # options for receive
```

| Command | What it does |
|---|---|
| `warpsend send <file...> [--mode tcp\|udp] [--host H] [--port P]` | Send file(s) to a receiver |
| `warpsend receive [--mode tcp\|udp] [--host H] [--port P]` | Wait for files and save them to `received/` (until Ctrl-C) |
| `warpsend cert` | Generate a self-signed TLS certificate in `~/.warpsend/` |
| `warpsend fingerprint [--cert PATH]` | Show a certificate's SHA-256 fingerprint + 6-digit code |

Defaults: `--mode tcp`, `--port 5000`, send host `127.0.0.1`, receive host `0.0.0.0`.

## Security (optional, both sides must agree)

```bash
# Shared secret — the receiver rejects senders without it.
# Prefer the env var so the key is not in shell history.
export WARPSEND_KEY='correct-horse'
warpsend receive --key 'correct-horse'
warpsend send notes.pdf --key 'correct-horse'

# TLS — encrypted, with fingerprint pinning (TCP only).
warpsend cert                                   # receiver, once
warpsend receive --tls                          # receiver
warpsend send notes.pdf --tls --fingerprint <hex from the receiver>
```

Without `--tls` / `--key`, transfers are plaintext and
unauthenticated — fine on localhost, not on a network you
don't trust. The receiver prints its TLS fingerprint and
6-digit code; compare the code out of band on first connect,
the full fingerprint for anything sensitive. Note the limits:
the server does not verify the *client's* certificate, and
UDP has no TLS (auth still applies to UDP headers).

## Files

| File | What it does |
|---|---|
| `warpsend.py` | The CLI — `send` / `receive` / `cert` / `fingerprint`, logo, argument parsing |
| `utils.py` | SHA-256 of a whole file, CRC32 per chunk, progress bar (speed + ETA), length-prefixed JSON header, HMAC auth, `.part`/resume metadata, never-overwrite naming, TLS cert + fingerprint helpers, ASCII logo |
| `server.py` | Receiver engine — listens in TCP or UDP mode, saves to `received/`, verifies SHA-256, replies OK / CORRUPT (TCP) or SUCCESS / FAIL (UDP) |
| `client.py` | Sender engine — sends file(s) in TCP or UDP mode with a live progress bar |
| `tests/test_warpsend.py` | Smoke tests: fresh transfer, no-overwrite, TCP resume, auth, TLS |
| `pyproject.toml` | Installs the `warpsend` command (`pip install .`) |

The old scripts still work directly if you prefer them:
`python3 server.py --mode tcp --port 5000` and
`python3 client.py --mode tcp --file notes.pdf`.

## How it works

**Both modes:** sender computes the file's SHA-256, sends it in a
length-prefixed JSON header (`filename`, `filesize`, `checksum`,
plus an HMAC tag when `--key` is set), then sends the file in
chunks. The receiver writes to `<name>.part` and recomputes
SHA-256 after saving — only a match renames it to the final
name, and an existing file is never overwritten
(`name (1).ext`, `name (2).ext`, ...). A hash mismatch deletes
the partial: its prefix cannot be trusted, so it is not resumed.

**TCP:** 64 KB chunks via `sendall()`. Ordering, loss and duplicates
are handled by the OS, so no sequence numbers are needed. After
the header the server replies `FRESH 0`, or `RESUME <offset>`
when a `.part` + `.part.json` for the same file (same name, size
and checksum) is already on disk — the client then seeks to the
offset and sends only the missing bytes. A dropped connection
keeps the partial, so re-sending resumes it.

**UDP:** 1024-byte chunks, each packet carrying
`[type][sequence number][total chunks][CRC32][data]`. The server
stores chunks by sequence number, ACKs each one, ignores
duplicates, and reassembles in order at EOF. A chunk with a bad
CRC32 gets no ACK, so the client resends it after a 0.5 s timeout
(up to 5 tries). Progress updates on ACK, not on send — otherwise
it would lie when a packet is lost. An EOF with chunks missing
replies FAIL instead of writing a corrupt file. UDP has no
resume: a failed UDP transfer restarts from the start.

**Compatibility:** a v1.1 client talking to a pre-v1.1 server
falls back to a fresh transfer (after a ~2 s wait for the
reply that never comes); a v1.1 server accepts a pre-v1.1
client. Resume, auth and TLS need v1.1 on both sides.

## Tests run

```bash
python3 tests/test_warpsend.py
```

- TCP (Nov 17, 2026, localhost): fresh 200 KB transfer byte-identical, SHA-256 matched; second send of the same name saved as `ws-test (1).txt` instead of overwriting.
- TCP resume (Nov 17, 2026): a 300 KB file with only the first 120 KB present as `.part` + metadata resumed and finished byte-identical, SHA-256 matched, `.part` cleaned up.
- Auth (Nov 17, 2026): server with `--key` rejected a wrong key (nothing saved) and accepted the right one.
- TLS (Nov 17, 2026): server with a generated self-signed cert rejected a wrong pinned fingerprint and accepted the right one; file byte-identical.
- CLI (Nov 17, 2026): `warpsend send a.txt b.txt` to a persistent receiver delivered both files, SHA-256 matched; `--version`, `--banner`, `cert` and `fingerprint` all work.
- UDP: **not verified in this sandbox** — even a bare `socket.sendto(b'hi', ('127.0.0.1', 5002))` fails here with `PermissionError: [Errno 1] Operation not permitted`, so UDP datagrams are blocked by the environment, not by the code. Run the UDP commands above on your own machine to verify it.

## Try yourself

1. Send a larger file (e.g. 50 MB) in both modes and compare the time.
2. Corruption test: change one byte in `received/<file>` and re-run
   `sha256sum` — it will no longer match the sender's hash.
3. Resume test: start a big TCP transfer, kill the sender with
   Ctrl-C mid-way, then send the same file again and watch it
   finish from where it stopped.
4. UDP loss test: add a random 10% drop on the server side and
   confirm retransmission still completes the file.

## Viva one-liner

*TCP gives reliability, flow control and congestion control by
default. UDP gives speed and low overhead, but reliability,
ordering and retransmission must be implemented in the
application layer — which is what the UDP mode here does.*
