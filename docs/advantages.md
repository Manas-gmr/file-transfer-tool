# Advantages -- why WarpSend, and why not

## Why choose WarpSend

- **No third-party storage, no account, no size limit.** A
  file moves directly from one machine to another -- one
  transfer, not an upload and then a download.
- **Scriptable one-shot mode with exit codes.** `warpsend
  send` returns 0 on success and 1 on failure, following
  the server's verdict. It fits cron, CI and automation --
  a persistent receiver plus a one-line sender.
- **Stdlib-only core.** Nothing to install beyond Python
  (>= 3.10) and the `openssl` binary for `warpsend cert`.
  The whole program is small enough to read in an evening
  and audit by hand -- no supply-chain surface beyond
  Python itself.
- **A real protocol-design exercise.** The UDP mode is a
  hand-built reliable protocol (sequence numbers, CRC32,
  ACKs, retransmission, state reset, idle timeout), and the
  TCP mode shows what the OS gives you for free. Both are
  documented in docs/architecture.md.
- **Honest verification.** SHA-256 over the whole file,
  verified before rename; resume that only counts a
  matching `.part`; malformed input dropped without killing
  the receiver. What is not verified is stated in
  docs/limitations.md instead of hidden.

## Why not WarpSend (yet)

- If you want a graphical or interactive session -- a file
  manager, saved devices, approval clicks, cancel without
  dropping the session -- Riptide (and the Phase 4 session
  mode) is ahead. WarpSend is a CLI, one transfer at a time.
- If you need to reach a machine behind CGNAT or without a
  port forward, WarpSend has no relay. It needs both sides
  directly reachable.
- If you need folders, parallel streams or high-throughput
  UDP, those are Phase 5/6, not here yet.

## Provenance

WarpSend was written by Manas Rajput with AI assistance
(Shion/Muse) through its v1.1-v1.3 development: the design
decisions, the review-driven fixes and the real-machine
verification were the author's; the AI drafted code and
docs, which were then tested (10 pytest tests, CLI end to
end, editable install, sdist/wheel build with `twine
check`) before each release. The Riptide comparison that
drove v1.1-v1.3 is documented in the repo's history and in
`docs/` -- including where Riptide is still ahead.
