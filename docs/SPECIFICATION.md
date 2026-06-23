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

Discovery commands:

```bash
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

### AES-CBC

- Requires IV.
- No automatic padding is applied.
- Payload must be block-aligned.

### AES-CTR

- Requires IV.
- MVP convention: the IV is interpreted as the full 128-bit big-endian initial
  counter value.
- Future ACVP vectors may require explicit nonce/counter metadata.

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

## 7. Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | All tests passed |
| `1` | One or more validation failures |
| `2` | Framework/config/parser/DUT/system error |

System errors take priority over validation failures.
