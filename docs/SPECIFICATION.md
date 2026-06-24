# Crypto Validation Framework Specification

This document describes the implemented MVP behavior and the contracts that
developers should preserve when extending the framework.

## 1. Purpose

The framework validates cryptographic DUT outputs against NIST-style test
vectors.

Current MVP:

- Algorithm: AES
- Modes: ECB, CBC, CTR
- Operations: encrypt, decrypt
- Test type: KAT
- Vector format: `.rsp`
- DUT backend: Python/PyCryptodome
- Reports: console and JSON

## 2. Execution Pipeline

```text
CLI arguments
  -> ValidationConfig
  -> config validation
  -> vector provenance/checksum
  -> parser registry
  -> .rsp parser
  -> TestCase objects
  -> DUT registry
  -> KAT executor
  -> AES Python DUT
  -> comparator
  -> TestResult objects
  -> console/JSON reports
  -> exit code
```

The CLI arguments provide run configuration. The vector file provides test data.

Users should not type vector values such as `KEY`, `IV`, `PLAINTEXT`, or
`CIPHERTEXT` directly into the terminal. Those values belong inside the `.rsp`
file referenced by `--vector-file`.

If no arguments are provided, the CLI starts an interactive wizard. The wizard
collects the same run configuration step by step and can run either:

1. one specific vector file, or
2. every supported `.rsp` file found under a selected folder.

For folder runs, the wizard scans recursively. It can auto-detect supported AES
modes from filenames containing `ECB`, `CBC`, or `CTR`. Files that look like
unsupported AES modes, such as `CFB1VarKey256.rsp`, are skipped with a message.
If a user forces a mode, files whose filename indicates another supported mode
are skipped to avoid incompatible validation runs.

The wizard can also auto-detect operation from each file's `[ENCRYPT]` and
`[DECRYPT]` sections. This is the default behavior for mixed folders and avoids
reporting decrypt-only files as parse errors when the folder also contains
encrypt-only files.

Discovery commands:

```bash
python -m crypto_validation --interactive
python -m crypto_validation --list-supported
python -m crypto_validation --show-format
```

## 3. Data Contracts

### 3.1 ValidationConfig

Represents one validation run.

Required fields:

| Field | Meaning | Example |
| --- | --- | --- |
| `algorithm` | Algorithm family | `AES` |
| `mode` | Algorithm mode | `CBC` |
| `operation` | Operation under test | `encrypt` |
| `test_type` | Validation category | `KAT` |
| `vector_file` | Source vector path | `sample_vectors/aes/aes_cbc_128.rsp` |
| `vector_format` | Parser format | `rsp` |
| `dut` | DUT backend | `python` |
| `report_format` | File report type | `json` |
| `report_dir` | Report output directory | `reports` |

Required terminal arguments for a validation run:

```text
--algorithm
--mode
--vector-file
```

Commonly specified optional arguments:

```text
--operation
--test-type
--dut
--report-format
--report-dir
```

### 3.2 TestCase

The parser output and engine input.

```json
{
  "test_id": "0",
  "algorithm": "AES",
  "mode": "CBC",
  "operation": "encrypt",
  "test_type": "KAT",
  "input": {
    "operation": "encrypt",
    "key": "...",
    "iv": "...",
    "plaintext": "..."
  },
  "expected_output": {
    "ciphertext": "..."
  },
  "metadata": {
    "source_file": "...",
    "source_format": "rsp",
    "source_checksum_sha256": "..."
  }
}
```

### 3.3 DUT Contract

Every DUT adapter must expose:

```python
def run(input_data: dict[str, Any]) -> dict[str, Any]:
    ...
```

Rules:

1. Inputs are parser-produced dictionaries.
2. Outputs are comparator-ready dictionaries.
3. Field names must match expected output fields.
4. Expected DUT failures should raise `DutError`.
5. The validation engine should not know backend-specific details.

### 3.4 TestResult

One result is produced per executed test case.

Important statuses:

| Status | Meaning |
| --- | --- |
| `PASS` | DUT output matched expected output |
| `VALIDATION_FAIL` | DUT ran but output mismatched |
| `DUT_ERROR` | DUT failed or returned invalid output |
| `PARSE_ERROR` | Vector parsing failed |
| `CONFIG_ERROR` | User config is invalid |
| `UNSUPPORTED_TEST` | Requested feature is not implemented |
| `INTERNAL_ERROR` | Unexpected framework failure |

## 4. AES Rules

### AES-ECB

- Does not use IV.
- Encryption input: `key`, `plaintext`.
- Decryption input: `key`, `ciphertext`.
- Input and expected output data must be block-aligned.
- Vector records must not include `IV`.

### AES-CBC

- Requires IV.
- IV must be 128 bits.
- No automatic padding is applied.
- Payload must be block-aligned.

### AES-CTR

- Requires IV.
- IV/counter must be 128 bits.
- MVP convention: the IV is interpreted as the full 128-bit big-endian initial
  counter value.
- This matches the NIST SP 800-38A Appendix F.5 style sample vector included in
  `sample_vectors/aes/aes_ctr_128.rsp`.
- CTR payloads do not need to be block-aligned.
- Future ACVP vectors may require explicit nonce/counter metadata.

### AES Key Sizes

All AES modes require keys of 128, 192, or 256 bits.

## 5. Parser Rules

The `.rsp` parser:

- Supports `[ENCRYPT]` and `[DECRYPT]` sections.
- Uses `COUNT` as `test_id`.
- Preserves section/group metadata.
- Normalizes hex values to lowercase.
- Removes spaces inside hex fields.
- Preserves empty hex values.
- Validates basic hex syntax.
- Splits inputs and expected outputs according to operation.

The parser does not:

- Run cryptographic algorithms.
- Decide pass/fail.
- Enforce AES key length or block size. The DUT handles that.

### 5.1 Supported `.rsp` Examples

AES-CBC/CTR encrypt:

```text
[ENCRYPT]
COUNT = 0
KEY = <hex>
IV = <hex>
PLAINTEXT = <hex>
CIPHERTEXT = <hex>
```

AES-CBC/CTR decrypt:

```text
[DECRYPT]
COUNT = 0
KEY = <hex>
IV = <hex>
CIPHERTEXT = <hex>
PLAINTEXT = <hex>
```

AES-ECB records omit `IV`.

### 5.2 Explicitly Unsupported in MVP

The MVP does not yet support:

- AES-CFB
- AES-OFB
- bit-level CFB1 vectors
- Monte Carlo Tests
- SHA/HMAC/RSA/ECC/DRBG
- ACVP JSON

For example, a file named `CFB1VarKey256.rsp` is an AES-CFB1 vector file and is
outside the current MVP support matrix.

## 6. Reporting Rules

Console reports are concise and human-readable.

JSON reports contain:

- `run_metadata`
- `summary`
- `results`

Every JSON report includes:

- Tool version
- Timestamp
- Algorithm/mode/operation/test type
- DUT backend
- Vector file path
- Vector file SHA-256 checksum
- Per-test output or error details
- Elapsed execution time
- Throughput in tests per second

Report filenames include algorithm, mode, operation, test type, vector file
stem, and a high-resolution UTC timestamp. If a collision occurs, a numeric
suffix is added instead of overwriting an existing report.

Folder/multi-file runs print a global summary across all executed files.

## 7. Failure Detection Expectations

The system must detect incorrect expected outputs or incompatible input fields.
Standalone bad vector files are provided for manual failure-detection checks.

Manual failure-injection vectors live in:

```text
sample_vectors/aes/failure_injection/
```

They are plain `.rsp` files with intentionally modified values. The framework
does not generate or mutate them.

Current failure-injection coverage includes:

- CBC encrypt and decrypt
- ECB encrypt and decrypt
- CTR encrypt and decrypt
- CTR modified key
- CTR modified counter block

## 8. Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | All tests passed |
| `1` | One or more validation failures |
| `2` | Framework/config/parser/DUT/system error |

System errors take priority over validation failures.
