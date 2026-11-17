# Changelog

## 1.5.0 -- 17 Nov 2026 (Phase 4, part 1: approval + cancel)

- **Receiver approval.** `receive` now asks before accepting
  each file: name, size, sender address and the first 16
  hex of the SHA-256, then `Accept? [y/N]`. Default is
  prompt-when-interactive: it asks when stdin is a terminal
  and never asks when stdin is piped (scripts, CI).
  `--approve prompt` forces the prompt, `--approve auto`
  never asks. A decline answers `REJECTED` (TCP) or `FAIL`
  (UDP) and creates no file and no `.part`. The sender exits
  1 with "receiver declined the transfer".
- **Cancel.** Ctrl-C during `send` now exits 130 with a
  clean "Cancelled -- partial kept on the receiver, send
  again to resume" instead of a traceback. The socket
  closes, which is the cancel signal: the receiver keeps
  the `.part` for resume and a TCP receiver keeps
  listening. There is no in-band cancel packet -- after the
  header the TCP stream is raw file bytes, so extra bytes
  would be written as file data. `send_tcp` / `send_udp`
  also take an optional `cancel` threading.Event, checked
  per chunk, which raises `TransferCancelled`.
- **Protocol v3.** Headers must now carry `protocol: 3`;
  older versions are rejected as `INVALID`. Both ends must
  be v1.5+ to talk to each other.
- **Tests.** 15 pytest tests (was 10): approval decline and
  accept (TCP), approval decline (UDP), cancel keeping the
  `.part` with the server staying alive, Ctrl-C exiting 130
  with no traceback (POSIX only), protocol v3 enforcement.

Migration notes (from 1.4.0):

- A v1.5 receiver rejects v1.4 and older senders (and vice
  versa): the protocol version is now enforced, not just
  advertised. Upgrade both ends.
- `receive` in a terminal now prompts per file. Pass
  `--approve auto` to restore the old never-ask behaviour,
  e.g. for scripted receivers.
- `send_tcp` / `send_udp` take a new optional `cancel`
  keyword argument; existing calls are unaffected.
- Everything else is unchanged: same command, same flags,
  same behaviour, all 15 tests pass.

## 1.4.0 -- 17 Nov 2026 (cleanup)

- **Removed the legacy shims.** The top-level `server.py`,
  `client.py` and `utils.py` (thin re-exports kept for one
  release) are deleted, locally and from the repository.
  The repo root is now just the package, the tests and the
  docs. A test asserts the old modules are *not*
  importable, so a stale `python3 server.py` fails loudly
  instead of silently running old code.
- **Removed local clutter.** `__pycache__` directories,
  `.ruff_cache`, `.pytest_cache`, `*.egg-info` and the empty
  `received/` directory are gone (all git-ignored).
- **Repo hygiene.** Added `CONTRIBUTING.md` and GitHub
  issue templates (bug report, feature request).

Migration notes (from 1.3.0):

- `from server import serve_tcp`, `from client import
  send_tcp` and `from utils import ...` no longer work.
  Import from the package instead:
  `from warpsend.transfer import serve_tcp, send_tcp`,
  `from warpsend.protocol import validate_header`,
  `from warpsend.identity import generate_cert`.
- `python3 server.py` / `python3 client.py` no longer work
  either. Use `warpsend ...` after install, or
  `PYTHONPATH=src python -m warpsend ...` from a checkout.
- Everything else is unchanged: same command, same flags,
  same behaviour, all 10 tests pass.

## 1.3.0 -- 17 Nov 2026 (Phase 3: structure and pipeline)

- **Package layout.** Flat modules moved to `src/warpsend/`:
  `identity.py` (certs, fingerprints, known hosts),
  `protocol.py` (headers, validation, HMAC auth),
  `transfer.py` (send/receive, both modes, hashing, `.part`),
  `config.py` (defaults), `cli.py` (the `warpsend` command).
  `pip install .` installs the `warpsend` command;
  `python -m warpsend` works from a checkout (with
  `PYTHONPATH=src` or an editable install).
- **Logging.** `warpsend --verbose` logs connection, auth
  and transfer events to stderr (level DEBUG) on the
  `warpsend` logger; progress bars already went to stderr.
- **Linting.** `ruff check` + `ruff format --check` on
  `src` and `tests`, configured in `pyproject.toml`
  (SIM/TRY rules deliberately off -- see the comment there).
- **Docs.** `docs/architecture.md`, `docs/security.md`
  (including the 6-digit-code weakness, stated plainly),
  `docs/limitations.md`, `docs/advantages.md`.
- **CI.** Workflow updated to run ruff + pytest on Linux,
  macOS and Windows, Python 3.11/3.12.
- **Release hygiene.** This changelog; `requires-python`
  corrected to >= 3.10 (the code already used `X | None`
  annotations); project URLs added.

Migration notes (from 1.2.0):

- The command is unchanged: `warpsend send` / `receive` /
  `cert` / `fingerprint`, same flags. Behaviour is
  unchanged -- all 10 tests pass unmodified in intent.
- `python3 warpsend.py` no longer works: the top-level
  `warpsend.py` file shadowed the package and was removed.
  Use `warpsend ...` after install, or
  `PYTHONPATH=src python -m warpsend ...` from a checkout.
- `python3 server.py` / `python3 client.py` still work:
  they are thin shims over the package now. `from utils
  import ...` still works for the same reason.
- The PyPI name `warpsend` was checked on 17 Nov 2026 and
  does not exist, so it is free to claim. No release has
  been published yet.

Release steps (maintainer, not automated):

1. Tag the release: `git tag v1.5.0 && git push origin
   v1.5.0` (or create the tag on the GitHub website --
   the GitHub app cannot create tags through the API).
2. Add `.github/workflows/ci.yml` via the GitHub website
   or a git push from your own machine -- the app cannot
   create workflow files through the API, so CI does not
   run until this is done.
3. Publish to PyPI (needs a PyPI account + API token):
   `python -m build && python -m twine check dist/* &&
   python -m twine upload dist/*`. The sdist and wheel
   already build cleanly and pass `twine check`.

## 1.2.0 -- 17 Nov 2026 (review Phases 1-2)

Header validation + 8 KB cap, size/disk limits, crash-proof
receiver, exit codes follow the server verdict,
thread-per-connection TCP with 120 s timeout,
challenge-response HMAC (no replay), TLS 1.2 floor +
trust-on-first-use known hosts, `--key-file`, `--outdir`
(default `./received`), `--max-size`, protocol v2,
incremental hashing, `sendfile()`, UDP written straight to
disk + reliable header/EOF + sender binding + idle timeout,
atomic hard-link rename, complete `.part` finalised (DONE).
9 pytest tests. MIT LICENSE + GitHub Actions CI added
(CI file local-only -- see the 1.3.0 release steps).

## 1.1.0 -- 17 Nov 2026

`.part` + rename-only-on-SHA-match, never-overwrite, TCP
resume, persistent receiver + multi-file `send`, shared-key
HMAC auth, optional TLS with fingerprint pinning, speed/ETA
progress, UDP streaming from disk, UDP missing-chunk fix.
4 smoke tests.

## 1.0.0 -- 10 Nov 2026

First version: TCP + UDP file transfer, SHA-256 + per-chunk
CRC32, stdlib only, Python >= 3.8.
