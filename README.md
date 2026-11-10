# File Transfer Tool — TCP / UDP with progress + checksum verification

Built from the Nov 9 walkthrough. Stdlib only — no `pip install` needed.

## Files

| File | What it does |
|---|---|
| `utils.py` | SHA-256 of a whole file, CRC32 per chunk, progress bar, length-prefixed JSON header |
| `server.py` | Listens in TCP or UDP mode, saves to `received/`, verifies SHA-256, replies OK / CORRUPT (TCP) or SUCCESS / FAIL (UDP) |
| `client.py` | Sends a file in TCP or UDP mode with a live progress bar |

## Run it (two terminals, localhost)

```bash
# Terminal 1 — server
python3 server.py --mode tcp --port 5000
# Terminal 2 — client
python3 client.py --mode tcp --file notes.pdf --host 127.0.0.1 --port 5000
```

UDP mode — same commands with `--mode udp`. Received files land in `received/`.

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

## Tests run (2026-11-10, localhost)

- TCP: 200 KB test file → received byte-identical, SHA-256 matched (`88139157…`), server replied `OK`. Verified.
- UDP: **not verified in this sandbox** — even a bare `socket.sendto(b'hi', ('127.0.0.1', 5002))` fails here with `PermissionError: [Errno 1] Operation not permitted`, so UDP datagrams are blocked by the environment, not by the code. Run the UDP commands above on your own machine to verify it — the code path (sequence numbers, CRC32, ACKs, retransmit, reassembly, SHA-256 check) is the same design as the walkthrough.

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
