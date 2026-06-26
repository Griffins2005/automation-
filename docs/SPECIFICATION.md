# Crypto Validation Framework Specification

This document describes the implemented MVP behavior and the contracts that
developers should preserve when extending the framework.

## 1. Purpose

The framework validates cryptographic DUT outputs against NIST-style test
vectors.

Current MVP:

- Algorithm: AES
- Modes: ECB, CBC, CTR, CFB1, CFB8, CFB128, OFB
- Operations: encrypt, decrypt
- Test type: KAT
- Vector formats: `.rsp`, JSON
- DUT backend: Python/PyCryptodome
- Reports: console and JSON

## 2. Execution Pipeline

```text
CLI arguments
  -> ValidationConfig
  -> config validation
  -> vector provenance/checksum
  -> parser registry
  -> selected vector parser
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
2. every supported `.rsp` or `.json` file found under a selected folder.

For folder runs, the wizard scans recursively. It can auto-detect supported AES
modes from filenames containing `ECB`, `CBC`, or `CTR`. Files that look like
unsupported AES modes, such as `CFB1VarKey256.rsp`, are skipped with a message.
If a user forces a mode, files whose filename indicates another supported mode
are skipped to avoid incompatible validation runs.

The wizard can also auto-detect operation from each file's `[ENCRYPT]` /
`[DECRYPT]` sections or JSON `direction` / `operation` fields. This is the
default behavior for mixed folders and avoids reporting decrypt-only files as
parse errors when the folder also contains encrypt-only files.

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
| `vector_format` | Parser format | `rsp` or `json` |
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
    "source_format": "rsp or json",
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

### AES-CFB1

- Requires a 128-bit IV.
- Plaintext and ciphertext are bit strings.
- The shift register is updated one bit at a time with ciphertext bits.

### AES-CFB8

- Requires a 128-bit IV.
- Plaintext and ciphertext must be byte-aligned.

### AES-CFB128

- Requires a 128-bit IV.
- Plaintext and ciphertext must be block-aligned.

### AES-OFB

- Requires a 128-bit IV.
- Plaintext and ciphertext must be byte-aligned.

### AES Key Sizes

All AES modes require keys of 128, 192, or 256 bits.

## 5. Parser Rules

Both supported parsers:

- Return the same internal `TestCase` contract.
- Split inputs and expected outputs according to operation.
- Enforce current AES KAT field requirements before DUT execution.

The `.rsp` parser:

- Supports `[ENCRYPT]` and `[DECRYPT]` sections.
- Uses `COUNT` as `test_id`.
- Preserves section/group metadata.
- Normalizes hex values to lowercase.
- Removes spaces inside hex fields.
- Preserves empty hex values.
- Validates basic hex syntax.

The JSON parser:

- Supports a top-level `tests` list for framework-native JSON.
- Supports ACVP-like `testGroups` / `tests` structures.
- Accepts common AES aliases such as `tcId`, `pt`, `ct`, and `direction`.
- Rejects JSON files whose declared AES mode conflicts with selected config.

The parsers do not:

- Run cryptographic algorithms.
- Decide pass/fail.
- Support non-AES algorithms yet.

### 5.1 Supported `.rsp` Examples

IV/counter-based AES encrypt:

```text
[ENCRYPT]
COUNT = 0
KEY = <hex>
IV = <hex>
PLAINTEXT = <hex>
CIPHERTEXT = <hex>
```

IV/counter-based AES decrypt:

```text
[DECRYPT]
COUNT = 0
KEY = <hex>
IV = <hex>
CIPHERTEXT = <hex>
PLAINTEXT = <hex>
```

AES-ECB records omit `IV`.

AES-CFB1 records use bit strings for `PLAINTEXT` and `CIPHERTEXT`.

### 5.2 Supported JSON Shapes

Framework-native JSON uses a top-level `tests` list. ACVP-like JSON uses
`testGroups` containing `tests`. In both cases, parsed records are normalized
into the same internal `TestCase` format as `.rsp` vectors.

### 5.3 Explicitly Unsupported in MVP

The MVP does not yet support:

- Monte Carlo Tests
- SHA/HMAC/RSA/ECC/DRBG
- Full ACVP protocol workflows

AES-CFB1, AES-CFB8, AES-CFB128, and AES-OFB are supported for KAT vectors.

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
- CFB1 encrypt and decrypt
- CFB8 encrypt
- CFB128 encrypt
- OFB encrypt
- CTR modified key
- CTR modified counter block

## 8. Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | All tests passed |
| `1` | One or more validation failures |
| `2` | Framework/config/parser/DUT/system error |

System errors take priority over validation failures.
