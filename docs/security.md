# Security

## Threat model -- what is and is not protected

### Protected (when the options below are used)

- **File integrity.** SHA-256 over the whole file, verified
  before rename, plus CRC32 per UDP chunk. A file that arrives
  corrupted is deleted, never delivered as if it were fine.
- **Authenticated headers.** With `--key`, the HMAC-SHA256
  covers filename, size, checksum *and* a per-connection
  nonce (the server's random TCP challenge, or a fresh client
  nonce for UDP that the server rejects on replay). A captured
  header cannot be replayed for the same file.
- **Confidentiality, with `--tls` only.** TLS 1.2 minimum,
  self-signed certificate, fingerprint pinned (`--fingerprint`)
  or remembered per host in `~/.warpsend/known_hosts.json`
  (trust on first use). A changed fingerprint for a known host
  aborts the transfer loudly.

### Not protected

- **Without `--tls`, file contents travel in plaintext** and
  anyone on the path can read them. The HMAC only proves the
  sender knew the key; the final SHA-256 is the only check on
  the bytes themselves.
- **Without `--key`, anyone who can reach the port can push a
  file -- unless approval asks first.** Approval is on by
  default when the receiver runs in a terminal
  (`--approve prompt` forces it, `--approve auto` turns it
  off); a decline creates no file. With `--approve auto`,
  only receive from peers you trust.
- **The server does not verify the client's certificate.**
  TLS authenticates the server to the client, not the other
  way round. Mutual TLS is not implemented.
- **UDP has no TLS and no encryption at all.**
- **A cancel is a dropped connection.** There is no
  in-band cancel packet, so a cancelled transfer looks
  like a network drop to the receiver -- which is why the
  `.part` is kept either way.
- **The receiver listens on a port.** Keep it closed when
  you are not transferring. There is no rate limiting or
  IP allow-listing.
- **Announcing broadcasts that you are here.** A receiver
  started with `--announce` tells everyone on the LAN its
  hostname, listening port, WarpSend version and mode.
  That is the point of discovery, but only announce on a
  network you trust, and use `--key` (or `--tls`) if the
  files matter -- an announcer that anyone can see is
  still an approver that anyone must get past.

## The 6-digit code is weak -- say so plainly

`short_code()` takes the first 6 hex characters of the
certificate fingerprint: about 20 bits. An attacker in the
middle can generate self-signed certificates until one
produces the same 6-digit code as the real server (about a
million tries -- trivial), so a user comparing only the code
can be fooled. The code is a convenience check for the first
connect only. For anything sensitive, compare the **full
fingerprint**. After the first trusted connect, the full
fingerprint is pinned in the known-hosts file, so the weak
code only protects one moment. A proper fix (a pairing
protocol such as SPAKE2, where guessing the code must happen
online and per attempt) is a Phase 6 idea, not done here.

## Header and file handling

- Headers are length-prefixed JSON, capped at 8 KB and
  validated (`protocol.validate_header()`) before use:
  required keys, types, `filesize >= 0`, sane filename,
  64-hex checksum, supported protocol version.
- Filenames are reduced to their basename; `..`, `/`, NUL
  bytes and empty names are rejected, so a sender cannot
  write outside the output directory.
- Files larger than `--max-size` or the free disk space are
  rejected with `TOO_LARGE` before any bytes are sent.
- The final name is claimed atomically with a hard link, so
  a file created between the check and the rename cannot be
  silently replaced. Existing files are never overwritten.
- The private key is written with mode 0600 and the
  known-hosts file with 0600. The config file
  (`~/.warpsend/config.toml`) is also written 0600, even
  though it holds no secrets -- only paths to key files and
  fingerprints. The shared secret is never stored in a
  config file; `--key-file` or `WARPSEND_KEY` only. `--key`
  itself warns: it shows in process listings and shell history.

## What to do in practice

```bash
# Trusted LAN, quick transfer:
warpsend receive --key-file secret.txt
warpsend send notes.pdf --key-file secret.txt

# Anything sensitive, or across the internet:
warpsend cert                                   # receiver, once
warpsend receive --tls --key-file secret.txt
warpsend send notes.pdf --tls --key-file secret.txt \
    --fingerprint <full hex from the receiver>
```

Never share the private key (`~/.warpsend/key.pem`). If a
certificate is ever compromised, delete it, run `warpsend
cert` again, and tell every sender the new fingerprint --
their known-hosts entry for you will (correctly) refuse the
new certificate until they remove the old one.
