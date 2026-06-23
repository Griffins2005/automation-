# AGENTS.md

## Cursor Cloud specific instructions

This is a pure-Python CLI tool (no services, servers, databases, ports, or Docker). "Running the app" means invoking the `crypto_validation` CLI, which executes once and exits.

### Environment
- Dependencies are installed into a virtual environment at `.venv/` (the startup update script creates it and runs `pip install -e ".[dev]"`). Creating a venv on this image requires the system package `python3.12-venv`; it is already present, so the update script does not reinstall it.
- Activate the environment before running anything: `. .venv/bin/activate` (or call binaries directly, e.g. `.venv/bin/python`, `.venv/bin/pytest`).

### Test / run (standard commands live in `README.md`)
- Tests: `python3 -m pytest` (config in `pyproject.toml`; `testpaths=tests`).
- Run a validation (see `README.md` "Quick Start" for full examples):
  `python3 -m crypto_validation --algorithm AES --mode CBC --operation encrypt --test-type KAT --vector-file sample_vectors/aes/aes_cbc_128.rsp --dut python --report-format json --report-dir reports`
- Console entry point `crypto-validate` is equivalent to `python3 -m crypto_validation`.

### Notes
- No linter/formatter is configured (no ruff/flake8/black). `python3 -m py_compile` can be used as a basic syntax check.
- CLI exit codes are meaningful: `0` = all passed, `1` = validation failures, `2` = config/parser/DUT/internal error.
- JSON reports are written under `reports/` (gitignored).
