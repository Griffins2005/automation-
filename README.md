# Cryptographic Validation Automation

This repository contains a terminal-first Python MVP for validating cryptographic
algorithm outputs against NIST-style test vectors.

The first implemented flow supports AES Known Answer Tests from `.rsp` files
using a Python DUT backed by PyCryptodome.

## What This Project Does

The framework automates this validation pipeline:

```text
Configuration
  -> Load vector file
  -> Compute vector checksum
  -> Parse inputs and expected outputs
  -> Run selected DUT
  -> Compare actual output against golden expected output
  -> Generate console/JSON report
```

Current MVP support:

| Area | Supported |
| --- | --- |
| Algorithm | AES |
| Modes | ECB, CBC, CTR |
| Operations | encrypt, decrypt |
| Test type | KAT |
| Vector format | NIST-style `.rsp` |
| DUT backend | Python/PyCryptodome |
| Reports | console, JSON |

## Quick Start

Install the package with development dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

Run the sample AES-CBC encryption validation:

```bash
python3 -m crypto_validation \
  --algorithm AES \
  --mode CBC \
  --operation encrypt \
  --test-type KAT \
  --vector-file sample_vectors/aes/aes_cbc_128.rsp \
  --dut python \
  --report-format json \
  --report-dir reports
```

Expected summary:

```text
Total Tests: 2
Passed: 2
Validation Failures: 0
```

Run the sample AES-CBC decryption validation:

```bash
python3 -m crypto_validation \
  --algorithm AES \
  --mode CBC \
  --operation decrypt \
  --test-type KAT \
  --vector-file sample_vectors/aes/aes_cbc_128.rsp \
  --dut python \
  --report-format json \
  --report-dir reports
```

## Run Tests

```bash
python3 -m pytest
```

## CLI Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | All tests passed |
| `1` | One or more validation failures |
| `2` | Config, parser, DUT, unsupported-test, or internal error |

## Project Layout

```text
crypto_validation/
  cli.py                  # command-line entry point
  config.py               # config normalization and validation
  models.py               # shared data contracts
  vectors.py              # vector loading and checksum helpers
  parsers/                # vector format parsers
  dut/                    # DUT adapters
  validation/             # executor, comparator, engine
  reporting/              # console and JSON reports

sample_vectors/
  aes/                    # sample AES .rsp vectors

tests/                    # pytest coverage
docs/                     # developer-facing docs
```

## Key Design Principle

The codebase keeps responsibilities separated:

```text
Parser parses.
DUT runs.
Executor controls test-type behavior.
Comparator compares.
Reporter reports.
Validation engine coordinates.
```

This keeps the MVP understandable and makes it easier to add SHA, HMAC, MCT,
ACVP JSON, RTL DUTs, and new report formats later.

## Developer Documentation

- [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md): implemented behavior,
  data contracts, parser rules, AES assumptions, reports, and exit codes.
- [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md): module/class/function API
  overview.
- [`docs/EXTENSION_GUIDE.md`](docs/EXTENSION_GUIDE.md): how to add algorithms,
  DUTs, parsers, test types, and reporters.
- [`CRYPTO_VALIDATION_FRAMEWORK.md`](CRYPTO_VALIDATION_FRAMEWORK.md): full
  proposal, architecture, roadmap, risks, and business context.

## Detailed Proposal

See [`CRYPTO_VALIDATION_FRAMEWORK.md`](CRYPTO_VALIDATION_FRAMEWORK.md) for the
full technical proposal, architecture, roadmap, data contracts, and design
considerations.
