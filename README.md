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

Strict AES validation is applied before DUT execution:

- AES keys must be 128, 192, or 256 bits.
- AES-CBC and AES-CTR require a 128-bit IV/counter.
- AES-ECB must not include IV.
- AES-ECB and AES-CBC plaintext/ciphertext must be block-aligned.
- AES-CTR uses a 128-bit big-endian initial counter block, matching the NIST
  SP 800-38A Appendix F.5 style sample in `sample_vectors/aes/aes_ctr_128.rsp`.

## Quick Start

Install the package with development dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

Start the interactive wizard:

```bash
python3 -m crypto_validation
```

Windows PowerShell:

```powershell
python -m crypto_validation
```

The wizard asks step by step:

1. Algorithm
2. Test type
3. Operation, including auto-detect from file
4. Single vector file or folder of `.rsp` files
5. AES mode or automatic mode detection from filenames
6. DUT backend
7. Report format
8. Report directory for JSON reports
9. Whether to run immediately

If you enter an invalid option, the wizard reprints the step with a short retry
message. If you choose `console` reporting, it skips the report directory step.

For file selection, the wizard supports:

```text
1. A specific vector file
2. All supported .rsp vector files inside a folder
```

When folder mode is selected, the wizard scans for `.rsp` files recursively,
auto-detects supported AES modes from filenames such as `CBCVarKey128.rsp`, and
skips unsupported files such as `CFB1VarKey256.rsp`.

By default, folder mode also auto-detects operation from each file's `[ENCRYPT]`
or `[DECRYPT]` section. This allows mixed folders containing both encrypt and
decrypt vector files to run without parse errors.

If you force a mode in folder mode, files that appear to belong to another
supported mode are skipped instead of being run with incompatible settings.
Folder runs print a global summary with total files, tests, elapsed time, and
throughput.

## Understand the CLI Inputs

The terminal command does **not** ask users to type vector values such as
`KEY`, `IV`, `PLAINTEXT`, or `CIPHERTEXT`.

Those values must already exist inside the vector file passed with
`--vector-file`.

The terminal arguments tell the tool how to interpret and run that file:

| CLI argument | What it means | Current values |
| --- | --- | --- |
| `--algorithm` | Which algorithm family to validate | `AES` |
| `--mode` | Which AES mode the file belongs to | `ECB`, `CBC`, `CTR` |
| `--operation` | Which section to run in direct CLI mode | `encrypt`, `decrypt` |
| `--test-type` | Which validation method to use | `KAT` |
| `--vector-file` | Path to the `.rsp` vector file | user path |
| `--dut` | Which implementation to test | `python` |
| `--report-format` | Report output type | `console`, `json` |

The interactive wizard additionally supports operation auto-detection from
`[ENCRYPT]` and `[DECRYPT]` sections.

Discovery commands:

```bash
python3 -m crypto_validation --interactive
python3 -m crypto_validation --list-supported
python3 -m crypto_validation --show-format
```

Windows PowerShell:

```powershell
python -m crypto_validation --interactive
python -m crypto_validation --list-supported
python -m crypto_validation --show-format
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

Windows PowerShell equivalent:

```powershell
python -m crypto_validation `
  --algorithm AES `
  --mode CBC `
  --operation encrypt `
  --test-type KAT `
  --vector-file sample_vectors/aes/aes_cbc_128.rsp `
  --dut python `
  --report-format json `
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

Run the sample AES-CTR encryption validation:

```bash
python3 -m crypto_validation \
  --algorithm AES \
  --mode CTR \
  --operation encrypt \
  --test-type KAT \
  --vector-file sample_vectors/aes/aes_ctr_128.rsp \
  --dut python \
  --report-format json \
  --report-dir reports
```

## Currently Supported `.rsp` Shape

AES-CBC or AES-CTR encryption records:

```text
[ENCRYPT]
COUNT = 0
KEY = <hex>
IV = <hex>
PLAINTEXT = <hex>
CIPHERTEXT = <hex>
```

AES-CBC or AES-CTR decryption records:

```text
[DECRYPT]
COUNT = 0
KEY = <hex>
IV = <hex>
CIPHERTEXT = <hex>
PLAINTEXT = <hex>
```

AES-ECB records are the same but omit `IV`.

Important limitation:

```text
AES-CFB, AES-OFB, bit-level CFB1 vectors, Monte Carlo Tests, ACVP JSON,
SHA, HMAC, RSA, ECC, and DRBG are not supported by the current MVP yet.
```

If your vector file is named like `CFB1VarKey256.rsp`, it is an AES-CFB1
bit-level vector. The current MVP will explain the supported format, but it
does not run CFB1 validation yet.

## Run Tests

```bash
python3 -m pytest
```

## Manual Failure-Injection Vector Files

Standalone bad `.rsp` files are available here:

```text
sample_vectors/aes/failure_injection/
```

These files are intentionally wrong and are meant for manual validation checks.
Examples:

```bash
python3 -m crypto_validation --algorithm AES --mode CBC --operation encrypt \
  --vector-file sample_vectors/aes/failure_injection/cbc_encrypt_bad_ciphertext.rsp

python3 -m crypto_validation --algorithm AES --mode CTR --operation encrypt \
  --vector-file sample_vectors/aes/failure_injection/ctr_encrypt_bad_counter.rsp
```

They include bad CBC, ECB, and CTR vectors with modified ciphertext, plaintext,
key, or counter values.

## CLI Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | All tests passed |
| `1` | One or more validation failures |
| `2` | Config, parser, DUT, unsupported-test, or internal error |

## Reports and Metrics

Console reports include pass/fail counts, error counts, elapsed time, and
throughput in tests per second.

JSON report filenames include algorithm, mode, operation, test type, vector file
stem, and a high-resolution UTC timestamp. If a name collision still occurs, the
reporter appends a numeric suffix instead of overwriting an existing report.

JSON metadata includes:

- vector file path
- vector SHA-256 checksum
- elapsed seconds
- throughput in tests per second

Folder runs also print a global summary across all executed files.

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
