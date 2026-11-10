# WarpSend

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
TCP or UDP with a live progress bar, and prove it arrived intact
with a checksum. Stdlib only — no dependencies to install.

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
# Terminal 1 — receiver
warpsend receive --mode tcp --port 5000

# Terminal 2 — sender
warpsend send notes.pdf --mode tcp --host 127.0.0.1 --port 5000
```

UDP mode — same commands with `--mode udp`. Received files land in `received/`.

```bash
warpsend --help            # all commands and options
warpsend --version         # WarpSend v1.0.0
warpsend --banner          # print just the logo
warpsend send --help       # options for send
warpsend receive --help    # options for receive
```

| Command | What it does |
|---|---|
| `warpsend send <file> [--mode tcp\|udp] [--host H] [--port P]` | Send a file to a receiver |
| `warpsend receive [--mode tcp\|udp] [--host H] [--port P]` | Wait for a file and save it to `received/` |

Defaults: `--mode tcp`, `--port 5000`, send host `127.0.0.1`, receive host `0.0.0.0`.

## Files

| File | What it does |
|---|---|
| `warpsend.py` | The CLI — `send` / `receive` commands, logo, argument parsing |
| `utils.py` | SHA-256 of a whole file, CRC32 per chunk, progress bar, length-prefixed JSON header, ASCII logo |
| `server.py` | Receiver engine — listens in TCP or UDP mode, saves to `received/`, verifies SHA-256, replies OK / CORRUPT (TCP) or SUCCESS / FAIL (UDP) |
| `client.py` | Sender engine — sends a file in TCP or UDP mode with a live progress bar |
| `pyproject.toml` | Installs the `warpsend` command (`pip install .`) |

The old scripts still work directly if you prefer them:
`python3 server.py --mode tcp --port 5000` and
`python3 client.py --mode tcp --file notes.pdf`.

## How it works

**Both modes:** sender computes the file's SHA-256, sends it in a
length-prefixed JSON header (`filename`, `filesize`, `checksum`),
then sends the file in chunks. Receiver recomputes SHA-256 after
saving and compares — match means the transfer is verified intact.

**TCP:** 64 KB chunks via `sendall()`. Ordering, loss and duplicates
are handled by the OS, so no sequence numbers are needed.

**UDP:** 1024-byte chunks, each packet carrying
`[type][sequence number][total chunks][CRC32][data]`. The server
stores chunks by sequence number, ACKs each one, ignores
duplicates, and reassembles in order at EOF. A chunk with a bad
CRC32 gets no ACK, so the client resends it after a 0.5 s timeout
(up to 5 tries). Progress updates on ACK, not on send — otherwise
it would lie when a packet is lost.

## Tests run

- TCP (Nov 10, 2026, localhost): 200 KB test file → received byte-identical, SHA-256 matched (`88139157…`), server replied `OK`. Verified.
- CLI (Nov 10, 2026): `warpsend --help`, `--version` and `--banner` all work; TCP send/receive through the new `warpsend send` / `warpsend receive` commands re-tested byte-identical.
- UDP: **not verified in this sandbox** — even a bare `socket.sendto(b'hi', ('127.0.0.1', 5002))` fails here with `PermissionError: [Errno 1] Operation not permitted`, so UDP datagrams are blocked by the environment, not by the code. Run the UDP commands above on your own machine to verify it.

## Try yourself

1. Send a larger file (e.g. 50 MB) in both modes and compare the time.
2. Corruption test: change one byte in `received/<file>` and re-run
   `sha256sum` — it will no longer match the sender's hash.
3. UDP loss test: add a random 10% drop on the server side and
   confirm retransmission still completes the file.

## Viva one-liner

*TCP gives reliability, flow control and congestion control by
default. UDP gives speed and low overhead, but reliability,
ordering and retransmission must be implemented in the
application layer — which is what the UDP mode here does.*
