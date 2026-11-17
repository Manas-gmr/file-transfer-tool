# Contributing to WarpSend

## Setup

```bash
git clone https://github.com/Manas-gmr/file-transfer-tool.git
cd file-transfer-tool
python3 -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e . pytest ruff build twine
```

Requires Python >= 3.10 and the `openssl` binary (for
`warpsend cert`).

## Workflow

```bash
# Run the tests (real servers on localhost, in threads):
python -m pytest tests/ -v

# Lint and format:
ruff check src tests
ruff format --check src tests

# Build the package and check it:
python -m build
python -m twine check dist/*
```

All three must pass before a change is pushed. The UDP test
skips gracefully where loopback datagrams are blocked (the
sandbox) and runs on CI, where loopback UDP is allowed.

## Rules of the codebase

- **Stdlib only.** No new dependencies for the core. An
  optional extra (e.g. a TUI) must stay an extra, never a
  requirement.
- **Behaviour first.** A refactor must keep all tests
  passing with the same intent. If a test changes, say why
  in the commit message.
- **Honesty about verification.** If something was not run
  on a real network or a real machine, say so in
  `docs/limitations.md` -- never present untested work as
  verified.
- **One validation path.** Untrusted input goes through
  `protocol.validate_header()`; do not add a second one.
- **Exit codes follow the server's verdict.** A failed
  transfer returns `False` / exit code 1, never silent
  success.
- **Ruff config is in `pyproject.toml`.** SIM and TRY rules
  are deliberately off (see the comment there); do not
  re-enable them without fixing the patterns they flag.
- **Update the docs with the code.** A behaviour change
  touches `README.md` and/or `docs/`, and a release
  touches `CHANGELOG.md`.

## Releases

See the release steps at the top of `CHANGELOG.md` (tag,
CI workflow file, PyPI upload). The GitHub app cannot
create workflow files or tags through the API, so those two
steps are manual, on the GitHub website or from your own
machine.
