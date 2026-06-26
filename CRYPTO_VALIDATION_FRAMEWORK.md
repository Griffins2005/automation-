# Automated Cryptographic Algorithm Validation Framework

## NIST-Compliant Test Suite for Cryptographic Algorithm and SoC Security IP Validation

---

## 1. Executive Summary

This document proposes a Python-based automated validation framework for cryptographic algorithms using NIST test vectors. The framework is intended to automate the validation flow from configuration to vector parsing, DUT execution, output comparison, and report generation.

The project is motivated by the need to reduce manual cryptographic validation effort, improve correctness, standardize test execution, and create a reusable validation environment for software, RTL, and SoC security IP implementations.

At its core, the system performs the following flow:

```text
Configuration
    ->
Load NIST Test Vectors
    ->
Parse Inputs and Expected Outputs
    ->
Run Inputs on Selected DUT
    ->
Capture Actual Outputs
    ->
Compare Actual Outputs Against Golden Expected Outputs
    ->
Generate Validation Reports
```

The first implementation is a terminal-first Python backend focused on AES Known Answer Tests using NIST `.rsp` and JSON-style vectors with a Python reference DUT. After proving the full end-to-end pipeline, the framework can be extended to SHA-2, SHA-3, HMAC, RSA, ECC, DRBG, Monte Carlo Tests, full ACVP workflows, RTL simulators, C models, and hardware accelerators.

The key design principle is that this should not be a one-off validation script. It should be a modular and extensible validation framework.

---

## 2. Project Title

**Automated Cryptographic Algorithm Validation Framework Using NIST Test Vectors**

Alternative title:

**NIST-Compliant Automated Test Suite for Cryptographic Algorithm Validation**

---

## 3. Project Context

### 3.1 Internship Domain

```text
Company Domain: Semiconductor and Communications Technology
Project Domain: Cybersecurity Engineering
Application Area: Cryptographic algorithm validation and SoC security IP verification
```

### 3.2 Job Description Alignment

The project aligns with the following responsibilities:

1. Identify and understand NIST-approved cryptographic algorithms:
   - AES
   - SHA-2
   - SHA-3
   - HMAC
   - RSA
   - ECC
   - DRBG

2. Study NIST CAVP and ACVP validation methodology.

3. Automate extraction and parsing of NIST test vectors:
   - JSON
   - CSV
   - TXT
   - `.rsp`

4. Develop a Python-based validation suite.

5. Integrate with:
   - Software reference models
   - RTL models
   - SoC models
   - Hardware implementations

6. Automate pass/fail comparison for:
   - Known Answer Tests
   - Monte Carlo Tests
   - Multi-block messages
   - Edge-case test vectors

7. Generate standard-aligned validation reports.

---

## 4. Problem Statement

Cryptographic algorithms used in security-sensitive systems must be validated against trusted, standard-defined test vectors. In a semiconductor environment, cryptographic IP may exist in multiple forms:

- Python prototype
- C/C++ reference model
- RTL block
- Firmware implementation
- SoC integrated accelerator
- Hardware simulation or emulation model

Manual validation creates several issues:

1. **Manual parsing overhead**
   - NIST vector files can be large and inconsistent across algorithms.
   - Engineers may manually extract inputs and expected outputs.

2. **Human error risk**
   - Manual copy-paste and comparison can introduce mistakes.

3. **Inconsistent validation flows**
   - Different engineers may write different scripts for different algorithms.
   - This makes results difficult to compare or audit.

4. **Limited reusability**
   - One-off scripts may work for AES but not SHA, HMAC, or RSA.

5. **Weak reporting**
   - Manual validation often lacks structured pass/fail summaries and failure details.

6. **Difficult DUT integration**
   - Software models, RTL simulators, and hardware accelerators expose different interfaces.

7. **Certification-readiness gap**
   - NIST CAVP/ACVP-style validation requires deterministic, reproducible, and traceable results.

This project addresses these issues by building a standardized validation framework.

---

## 5. Project Objective

The objective is to design and implement a deterministic, modular, and extensible validation framework that:

- Automatically loads NIST test vectors.
- Parses test vectors into structured test cases.
- Separates test inputs from golden expected outputs.
- Runs inputs on a selected DUT.
- Captures actual DUT outputs.
- Compares actual outputs to expected outputs.
- Classifies results as pass, validation failure, or system error.
- Generates clear and traceable validation reports.
- Supports future integration with different algorithms, vector formats, DUTs, and execution environments.

---

## 6. Important Terminology

### 6.1 DUT

Device Under Test.

In this project, a DUT may be:

- Python reference implementation
- C model
- RTL simulator
- SoC simulation model
- Hardware accelerator
- External command-line executable

### 6.2 Golden Output

The trusted expected output from the NIST test vector.

For example:

```text
Input:
    key
    plaintext
    IV

DUT output:
    actual ciphertext

NIST golden output:
    expected ciphertext
```

Validation rule:

```text
actual output == golden expected output -> PASS
actual output != golden expected output -> FAIL
```

If the phrase "golden input" is used, it should be clarified. In standard validation language, the golden value usually means the expected output supplied by the trusted test vector source.

### 6.3 KAT

Known Answer Test.

A test where inputs and expected outputs are predefined.

```text
Known input -> Algorithm -> Must match known expected output
```

### 6.4 MCT

Monte Carlo Test.

A repeated execution test where output from one iteration may influence the next iteration.

```text
Initial input
    ->
Run algorithm
    ->
Use result to update next input
    ->
Repeat for defined number of iterations
```

### 6.5 ACVP

Automated Cryptographic Validation Protocol.

ACVP is the modern NIST approach that uses JSON-based vector formats and automated validation workflows.

### 6.6 CAVP

Cryptographic Algorithm Validation Program.

CAVP legacy vector files often use `.rsp` style text formats.

---

## 7. Recommended Scope

### 7.1 Initial MVP Scope

The first milestone should be narrow but complete.

Recommended MVP:

```text
Algorithm: AES
Modes: CBC first, then ECB and CTR
Operation: Encrypt first, then decrypt
Test Type: KAT
Vector Formats: NIST .rsp and JSON
DUT: Python reference implementation
Interface: Terminal CLI
Reports: Console and JSON
Testing: pytest unit tests
```

The MVP should demonstrate a full end-to-end pipeline:

```text
NIST AES vector file
    ->
Parser
    ->
Structured test cases
    ->
AES DUT driver
    ->
Comparator
    ->
Validation report
```

### 7.2 Extended Scope

After the MVP is stable, extend to:

- Additional AES modes:
  - ECB
  - CBC
  - CTR
  - CFB1
  - CFB8
  - CFB128
  - OFB
- AES key sizes:
  - 128-bit
  - 192-bit
  - 256-bit
- AES decrypt tests
- SHA-256
- SHA-512
- SHA-3
- HMAC-SHA256
- HMAC-SHA512
- Monte Carlo Tests
- Multi-block tests
- Full ACVP protocol workflow support
- CSV report output
- HTML report output
- External DUT command adapter
- C model adapter
- RTL simulator adapter
- CI/CD integration

### 7.3 Out of Initial Scope

The following should not be part of the first implementation unless required by the manager:

- Full web dashboard
- Distributed job scheduling
- Database-backed result storage
- AI debugging
- Full RSA/ECC/DRBG support
- ACVP server integration

These are valuable future enhancements, but the first priority should be correctness of the deterministic validation core.

---

## 8. High-Level System Architecture

```text
+---------------------------------------------------------------+
|        Automated Cryptographic Validation Framework            |
+---------------------------------------------------------------+

 User / CLI / Config File
        |
        v
+--------------------+
| Configuration      |
| Module             |
+--------------------+
        |
        v
+--------------------+
| Vector Loader      |
+--------------------+
        |
        v
+--------------------+
| Parser             |
| - RSP              |
| - JSON             |
| - CSV future       |
+--------------------+
        |
        v
+-----------------------------+
| Structured Test Case Model  |
| - input                     |
| - expected_output           |
| - metadata                  |
+-----------------------------+
        |
        v
+--------------------+
| Test Executor      |
| - KAT executor     |
| - MCT executor     |
+--------------------+
        |
        v
+--------------------+
| DUT Driver         |
| - Python DUT       |
| - RTL DUT future   |
| - C model future   |
+--------------------+
        |
        v
+--------------------+
| Actual Output      |
+--------------------+
        |
        v
+--------------------+
| Comparator         |
+--------------------+
        |
        v
+--------------------+
| Reporter           |
| - Console          |
| - JSON             |
| - CSV future       |
| - HTML future      |
+--------------------+
```

---

## 9. System Execution Process

### 9.1 Step-by-Step Flow

```text
Step 1:
    User starts tool from terminal or supplies config file.

Step 2:
    Configuration module validates algorithm, mode, test type, vector file,
    DUT selection, and report format.

Step 3:
    Vector loader reads the raw NIST test vector file.

Step 4:
    Parser converts raw vectors into structured test cases.

Step 5:
    Parser separates input fields from expected output fields.

Step 6:
    Validation engine selects the proper test executor.

Step 7:
    Executor sends test input to selected DUT driver.

Step 8:
    DUT driver executes the algorithm or forwards input to the DUT.

Step 9:
    DUT returns actual output.

Step 10:
    Comparator compares expected output with actual output.

Step 11:
    Result is classified as PASS, VALIDATION_FAIL, DUT_ERROR,
    PARSE_ERROR, CONFIG_ERROR, UNSUPPORTED_TEST, or INTERNAL_ERROR.

Step 12:
    Reporter generates terminal and file-based reports.

Step 13:
    Tool exits with a meaningful exit code for automation.
```

### 9.2 Process Diagram

```text
+----------------------+
| User runs command    |
+----------+-----------+
           |
           v
+----------------------+
| Load configuration   |
+----------+-----------+
           |
           v
+----------------------+
| Validate config      |
+----------+-----------+
           |
           v
+----------------------+
| Load vector file     |
+----------+-----------+
           |
           v
+----------------------+
| Parse vector file    |
+----------+-----------+
           |
           v
+------------------------------+
| Build structured test cases  |
+----------+-------------------+
           |
           v
+----------------------+
| Select DUT driver    |
+----------+-----------+
           |
           v
+----------------------+
| Select executor      |
+----------+-----------+
           |
           v
+----------------------+
| Run test case        |
+----------+-----------+
           |
           v
+----------------------+
| Capture actual output|
+----------+-----------+
           |
           v
+----------------------+
| Compare output       |
+----------+-----------+
           |
           v
    +------+------+
    | Match?      |
    +------+------+
           |
    +------+------+
    |             |
    v             v
+--------+   +-----------------+
| PASS   |   | VALIDATION_FAIL |
+--------+   +-----------------+
    |             |
    +------+------+
           |
           v
+----------------------+
| Record result        |
+----------+-----------+
           |
           v
+----------------------+
| Generate report      |
+----------+-----------+
           |
           v
+----------------------+
| Return exit code     |
+----------------------+
```

---

## 10. Proposed Repository Structure

```text
crypto_validation/
|
|-- main.py
|-- cli.py
|
|-- config/
|   |-- __init__.py
|   |-- config_model.py
|   |-- config_loader.py
|   |-- config_validator.py
|
|-- vectors/
|   |-- __init__.py
|   |-- vector_loader.py
|   |-- checksum.py
|
|-- parsers/
|   |-- __init__.py
|   |-- base.py
|   |-- rsp_parser.py
|   |-- json.py
|   |-- registry.py
|
|-- models/
|   |-- __init__.py
|   |-- test_case.py
|   |-- test_result.py
|   |-- validation_report.py
|
|-- dut/
|   |-- __init__.py
|   |-- base.py
|   |-- aes_python.py
|   |-- sha_python.py
|   |-- hmac_python.py
|   |-- external_command.py
|   |-- registry.py
|
|-- validation/
|   |-- __init__.py
|   |-- engine.py
|   |-- comparator.py
|   |-- exceptions.py
|   |-- executors/
|       |-- __init__.py
|       |-- base.py
|       |-- kat_executor.py
|       |-- mct_executor.py
|       |-- multiblock_executor.py
|
|-- reporting/
|   |-- __init__.py
|   |-- base.py
|   |-- console_reporter.py
|   |-- json_reporter.py
|   |-- csv_reporter.py
|   |-- html_reporter.py
|
|-- sample_vectors/
|   |-- aes/
|   |-- sha/
|   |-- hmac/
|
|-- reports/
|
|-- tests/
|   |-- test_rsp_parser.py
|   |-- test_config_validator.py
|   |-- test_comparator.py
|   |-- test_aes_dut.py
|   |-- test_engine.py
|
|-- docs/
|   |-- architecture.md
|   |-- usage.md
|   |-- extension_guide.md
|   |-- dut_contract.md
|
|-- pyproject.toml
|-- README.md
```

This structure separates responsibilities clearly and supports future growth.

---

## 11. Technical Stack

### 11.1 Programming Language

```text
Python 3.10+
```

Python is suitable because:

- Strong file parsing support.
- Good crypto libraries.
- Easy CLI development.
- Easy integration with external tools.
- Commonly used in verification automation.
- Good unit testing ecosystem.

### 11.2 Core Standard Libraries

```text
argparse
csv
dataclasses
hashlib
hmac
json
logging
pathlib
re
subprocess
typing
```

### 11.3 Recommended Third-Party Libraries

Initial:

```text
pycryptodome
pytest
```

Optional for polished CLI and reports:

```text
typer
rich
jinja2
```

### 11.4 Library Purpose

| Library | Purpose |
| --- | --- |
| pycryptodome | AES reference implementation |
| hashlib | SHA-2/SHA-3 hashing |
| hmac | HMAC implementation |
| pytest | Unit testing |
| typer | CLI framework |
| rich | Improved terminal output |
| jinja2 | HTML report generation |
| subprocess | External DUT integration |
| pathlib | File path handling |
| logging | Runtime logs |

---

## 12. Interface Choice: Terminal First

The first version should be terminal-based.

Example:

```bash
python -m crypto_validation \
  --algorithm AES \
  --mode CBC \
  --operation encrypt \
  --test-type KAT \
  --vector-file sample_vectors/aes/aes_cbc_128.rsp \
  --dut python \
  --report-format json \
  --report-dir reports/
```

### 12.1 Why Terminal First

A terminal-first framework is preferred because:

- Verification engineers commonly use CLI tools.
- It is easy to run in CI/CD.
- It is easy to run on servers.
- It does not require a browser or UI server.
- It can be scripted.
- It supports RTL and simulation workflows better.
- A UI can be added later without changing the validation engine.

### 12.2 Future UI Possibilities

Future UI layers can include:

1. **HTML static report**
   - Generated after each run.
   - Simple and useful for sharing results.

2. **FastAPI backend**
   - Exposes validation runs through REST APIs.

3. **Web dashboard**
   - View results, failures, trends, and logs.

4. **Job queue interface**
   - Useful for distributed validation later.

Recommended approach:

```text
Build CLI first.
Add HTML reports second.
Add web API only if needed.
```

---

## 13. Core Data Contracts

One of the most important design decisions is defining stable internal data contracts. These contracts allow the framework to support different algorithms, parsers, test types, and DUTs without changing the validation engine.

### 13.1 Test Case Contract

```python
from dataclasses import dataclass, field
from typing import Any

@dataclass
class TestCase:
    test_id: str
    algorithm: str
    mode: str | None
    operation: str | None
    test_type: str
    input: dict[str, Any]
    expected_output: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)
```

Example AES-CBC encryption test case:

```json
{
  "test_id": "0",
  "algorithm": "AES",
  "mode": "CBC",
  "operation": "encrypt",
  "test_type": "KAT",
  "input": {
    "key": "2b7e151628aed2a6abf7158809cf4f3c",
    "iv": "000102030405060708090a0b0c0d0e0f",
    "plaintext": "6bc1bee22e409f96e93d7e117393172a"
  },
  "expected_output": {
    "ciphertext": "7649abac8119b246cee98e9b12e9197d"
  },
  "metadata": {
    "source_file": "aes_cbc_128.rsp",
    "section": "ENCRYPT",
    "key_size": 128
  }
}
```

### 13.2 Test Result Contract

```python
from dataclasses import dataclass, field
from typing import Any

@dataclass
class TestResult:
    test_id: str
    status: str
    expected_output: dict[str, Any]
    actual_output: dict[str, Any] | None
    mismatches: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
```

Example PASS:

```json
{
  "test_id": "0",
  "status": "PASS",
  "expected_output": {
    "ciphertext": "7649abac8119b246cee98e9b12e9197d"
  },
  "actual_output": {
    "ciphertext": "7649abac8119b246cee98e9b12e9197d"
  },
  "mismatches": {},
  "error_code": null,
  "error_message": null
}
```

Example validation failure:

```json
{
  "test_id": "12",
  "status": "VALIDATION_FAIL",
  "expected_output": {
    "ciphertext": "aaaaaaaa"
  },
  "actual_output": {
    "ciphertext": "bbbbbbbb"
  },
  "mismatches": {
    "ciphertext": {
      "expected": "aaaaaaaa",
      "actual": "bbbbbbbb"
    }
  },
  "error_code": null,
  "error_message": null
}
```

### 13.3 DUT Contract

All DUT implementations should follow one interface:

```python
from abc import ABC, abstractmethod

class Dut(ABC):
    @abstractmethod
    def run(self, input_data: dict) -> dict:
        raise NotImplementedError
```

Contract rules:

1. Input is a dictionary.
2. Output is a dictionary.
3. Input and output field names must match the internal schema.
4. Values should be normalized hex strings unless explicitly documented otherwise.
5. DUT-specific errors should be raised as structured exceptions.
6. The validation engine should not know whether the DUT is Python, RTL, C, or hardware.

Example AES DUT output:

```json
{
  "ciphertext": "7649abac8119b246cee98e9b12e9197d"
}
```

Example SHA DUT output:

```json
{
  "md": "ba7816bf8f01cfea414140de5dae2223..."
}
```

Example HMAC DUT output:

```json
{
  "mac": "b0344c61d8db38535ca8afceaf0bf12b..."
}
```

---

## 14. Configuration Design

### 14.1 CLI Arguments

Suggested CLI options:

```text
--algorithm
--mode
--operation
--test-type
--vector-file
--vector-format
--dut
--report-format
--report-dir
--log-level
--fail-fast
--include-sensitive
```

### 14.2 Config File

Example JSON configuration:

```json
{
  "algorithm": "AES",
  "mode": "CBC",
  "operation": "encrypt",
  "test_type": "KAT",
  "vector_file": "sample_vectors/aes/aes_cbc_128.rsp",
  "vector_format": "rsp",
  "dut": "python",
  "report_format": "json",
  "report_dir": "reports",
  "log_level": "INFO",
  "fail_fast": false,
  "include_sensitive": false
}
```

### 14.3 Config Validation Rules

The framework should validate configuration before running tests.

Examples:

| Algorithm/Mode | Required Fields | Notes |
| --- | --- | --- |
| AES-ECB | key, plaintext or ciphertext | No IV |
| AES-CBC | key, iv, plaintext or ciphertext | IV required |
| AES-CTR | key, iv/counter, plaintext or ciphertext | Counter format must be defined |
| SHA-256 | msg | No key |
| HMAC-SHA256 | key, msg | Key required |

Invalid configuration should produce `CONFIG_ERROR`, not a confusing runtime crash.

---

## 15. Vector Loading

### 15.1 Vector Loader Responsibilities

The vector loader should:

- Locate the vector file.
- Read raw content.
- Compute checksum.
- Pass content to the selected parser.
- Preserve vector provenance metadata.

It should not:

- Interpret algorithm-specific fields.
- Compare outputs.
- Execute tests.

### 15.2 Vector Provenance

Reports should record where vectors came from.

Suggested metadata:

```json
{
  "source_file": "aes_cbc_128.rsp",
  "source_path": "sample_vectors/aes/aes_cbc_128.rsp",
  "source_format": "rsp",
  "source_standard": "NIST CAVP",
  "vector_checksum_sha256": "..."
}
```

### 15.3 Vector File Checksum

The framework should compute a SHA-256 checksum of each vector file.

Purpose:

- Traceability
- Auditability
- Reproducibility
- Proof that the tested vector file did not change

Example:

```python
import hashlib
from pathlib import Path

def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
```

---

## 16. Parser Design

### 16.1 Parser Responsibilities

The parser converts raw vector content into structured `TestCase` objects.

Responsibilities:

- Read vector records.
- Preserve section metadata.
- Separate input fields from expected output fields.
- Normalize field names.
- Normalize hex casing.
- Preserve empty messages.
- Raise clear parse errors.

### 16.2 Parser Non-Responsibilities

The parser should not:

- Run cryptographic algorithms.
- Compare expected and actual outputs.
- Decide whether a test passes.
- Know about DUT internals.

### 16.3 NIST `.rsp` Format Example

```text
[ENCRYPT]

COUNT = 0
KEY = 2b7e151628aed2a6abf7158809cf4f3c
IV = 000102030405060708090a0b0c0d0e0f
PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
CIPHERTEXT = 7649abac8119b246cee98e9b12e9197d

COUNT = 1
KEY = ...
IV = ...
PLAINTEXT = ...
CIPHERTEXT = ...
```

### 16.4 Field Mapping

AES:

```python
AES_INPUT_FIELDS = {
    "key",
    "iv",
    "plaintext",
    "ciphertext"
}

AES_OUTPUT_FIELDS = {
    "ciphertext",
    "plaintext"
}
```

The actual input/output mapping depends on operation.

AES encrypt:

```text
Inputs:
    key
    iv if mode requires it
    plaintext

Expected output:
    ciphertext
```

AES decrypt:

```text
Inputs:
    key
    iv if mode requires it
    ciphertext

Expected output:
    plaintext
```

SHA:

```text
Inputs:
    msg

Expected output:
    md
```

HMAC:

```text
Inputs:
    key
    msg

Expected output:
    mac
```

### 16.5 Empty Input Handling

Some SHA and HMAC vectors contain empty messages:

```text
Len = 0
Msg =
MD = ...
```

The parser must treat `Msg =` as an empty value, not as a missing field.

This is critical for correctness.

### 16.6 Hex Normalization

The parser should normalize:

- Uppercase hex to lowercase.
- Leading/trailing whitespace.
- Optional spaces between bytes if present.

Example:

```text
"AB CD EF" -> "abcdef"
```

However, normalization must not silently change binary meaning.

### 16.7 Streaming Parser Recommendation

For large vector files, avoid loading all test cases into memory.

Recommended approach:

```python
for test_case in parser.parse(file):
    engine.run_one(test_case)
```

Instead of:

```python
test_cases = parser.parse_all(file)
engine.run_all(test_cases)
```

This supports large vector files and future scalability.

---

## 17. Algorithm-Specific Considerations

### 17.1 AES

AES properties:

```text
Block size: 128 bits
Key sizes: 128, 192, 256 bits
Supported KAT modes: ECB, CBC, CTR, CFB1, CFB8, CFB128, OFB
```

AES input/output depends on mode and operation.

#### AES-ECB

Inputs:

```text
key
plaintext for encrypt
ciphertext for decrypt
```

No IV.

#### AES-CBC

Inputs:

```text
key
iv
plaintext for encrypt
ciphertext for decrypt
```

Important:

- IV is required.
- Test vectors are usually block-aligned.
- Do not apply automatic padding unless explicitly required.

#### AES-CTR

Inputs:

```text
key
initial counter or IV
plaintext for encrypt
ciphertext for decrypt
```

Important CTR questions:

- Is the IV treated as nonce plus counter?
- Is the counter big-endian or little-endian?
- Which bits are incremented?
- Does the vector file define counter format?

CTR mode is a common source of validation mismatch.

#### AES-CFB and AES-OFB

Supported feedback modes:

```text
CFB1, CFB8, CFB128, OFB
```

Important:

- CFB1 vectors use bit strings for plaintext and ciphertext.
- CFB8 and OFB require byte-aligned payloads.
- CFB128 requires block-aligned payloads.
- All feedback modes require a 128-bit IV.

### 17.2 Padding Rules

NIST vectors usually provide exact algorithm-level inputs. The framework should not add PKCS#7 or other application-level padding by default.

Rule:

```text
No automatic padding unless the vector specification explicitly requires it.
```

### 17.3 SHA-2 and SHA-3

SHA inputs:

```text
message -> digest
```

There is:

- No key.
- No decrypt operation.
- No IV supplied by user.

Important:

- Empty messages must be supported.
- Message length fields must be interpreted correctly.

### 17.4 HMAC

HMAC inputs:

```text
key + message -> MAC/tag
```

Important:

- Key may vary in length.
- Message may be empty.
- Hash function must be configurable.

### 17.5 RSA, ECC, and DRBG

These are more complex and should be added after AES, SHA, and HMAC.

Reasons:

- More complicated vector formats.
- More parameters.
- Probabilistic or stateful behavior in some cases.
- More involved validation methodology.

---

## 18. DUT Driver Design

### 18.1 DUT Driver Responsibilities

The DUT driver:

- Receives structured input.
- Converts input into DUT-specific format.
- Runs DUT.
- Captures output.
- Converts output back to framework output schema.

### 18.2 Python AES DUT Example

```python
from Crypto.Cipher import AES

class AesCbcPythonDut:
    def run(self, input_data: dict) -> dict:
        key = bytes.fromhex(input_data["key"])
        iv = bytes.fromhex(input_data["iv"])

        operation = input_data.get("operation", "encrypt")

        if operation == "encrypt":
            plaintext = bytes.fromhex(input_data["plaintext"])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)
            return {"ciphertext": ciphertext.hex()}

        if operation == "decrypt":
            ciphertext = bytes.fromhex(input_data["ciphertext"])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext)
            return {"plaintext": plaintext.hex()}

        raise ValueError(f"Unsupported AES-CBC operation: {operation}")
```

### 18.3 External Command DUT

Future external DUT interface:

```text
Framework input
    ->
Serialize to JSON or CLI args
    ->
Run external command using subprocess
    ->
Parse command output
    ->
Return actual output dictionary
```

Example:

```bash
./aes_model --mode CBC --key ... --iv ... --plaintext ...
```

### 18.4 RTL DUT Adapter

Future RTL adapter may:

- Generate simulator input files.
- Launch simulator.
- Wait for completion.
- Parse output waveform/log/result file.
- Return actual output.

The validation engine should not change for RTL integration because the adapter still returns:

```python
{"ciphertext": "..."}
```

---

## 19. Registry Design

Avoid hardcoding algorithm selection throughout the system.

### 19.1 DUT Registry

```python
DUT_REGISTRY = {
    ("AES", "CBC", "python"): AesCbcPythonDut,
    ("AES", "ECB", "python"): AesEcbPythonDut,
    ("AES", "CTR", "python"): AesCtrPythonDut,
    ("SHA-256", None, "python"): Sha256PythonDut,
    ("HMAC-SHA256", None, "python"): HmacSha256PythonDut,
}
```

### 19.2 Parser Registry

```python
PARSER_REGISTRY = {
    "rsp": RspParser,
    "json": JsonParser,
}
```

### 19.3 Executor Registry

```python
EXECUTOR_REGISTRY = {
    "KAT": KatExecutor,
    "MCT": MctExecutor,
    "MULTIBLOCK": MultiBlockExecutor,
}
```

This keeps the system extensible.

---

## 20. Validation Engine

### 20.1 Responsibilities

The validation engine coordinates:

- Test case iteration.
- Executor selection.
- DUT execution.
- Comparison.
- Result collection.
- Error handling.
- Report generation.

### 20.2 Pseudocode

```python
class ValidationEngine:
    def __init__(self, executor, dut, comparator, reporter):
        self.executor = executor
        self.dut = dut
        self.comparator = comparator
        self.reporter = reporter

    def run(self, test_cases):
        results = []

        for test_case in test_cases:
            try:
                actual_output = self.executor.run(test_case, self.dut)
                comparison = self.comparator.compare(
                    test_case.expected_output,
                    actual_output,
                )

                if comparison.passed:
                    result = TestResult(
                        test_id=test_case.test_id,
                        status="PASS",
                        expected_output=test_case.expected_output,
                        actual_output=actual_output,
                    )
                else:
                    result = TestResult(
                        test_id=test_case.test_id,
                        status="VALIDATION_FAIL",
                        expected_output=test_case.expected_output,
                        actual_output=actual_output,
                        mismatches=comparison.mismatches,
                    )

            except ParseError as exc:
                result = build_error_result(test_case, "PARSE_ERROR", exc)

            except DutError as exc:
                result = build_error_result(test_case, "DUT_ERROR", exc)

            except Exception as exc:
                result = build_error_result(test_case, "INTERNAL_ERROR", exc)

            results.append(result)

        return self.reporter.generate(results)
```

---

## 21. Test Executors

Different test categories require different execution logic.

### 21.1 KAT Executor

Known Answer Test logic:

```text
Input -> DUT -> Actual output -> Compare against expected output
```

Pseudocode:

```python
class KatExecutor:
    def run(self, test_case, dut):
        return dut.run(test_case.input)
```

### 21.2 MCT Executor

Monte Carlo Tests require repeated execution.

General flow:

```text
current_input = initial_input

for i in range(iteration_count):
    actual_output = dut.run(current_input)
    current_input = derive_next_input(current_input, actual_output)

return final_output
```

Important:

- Derivation logic is algorithm-specific.
- AES MCT differs from SHA MCT.
- MCT should not be forced into the same executor as KAT.

### 21.3 Multi-block Executor

Multi-block tests validate processing across longer inputs or multiple blocks.

Considerations:

- Block boundaries
- Streaming behavior
- Padding rules
- Mode-specific state updates

---

## 22. Comparator Design

### 22.1 Strict Comparison

Cryptographic validation requires bit-exact matching.

Rule:

```text
expected_output == actual_output
```

No tolerance and no approximate matching.

### 22.2 Field-Based Comparison

The comparator should report field-level mismatches.

Example:

```python
def compare(expected: dict, actual: dict) -> dict:
    mismatches = {}

    for field, expected_value in expected.items():
        actual_value = actual.get(field)
        if actual_value != expected_value:
            mismatches[field] = {
                "expected": expected_value,
                "actual": actual_value,
            }

    for field in actual:
        if field not in expected:
            mismatches[field] = {
                "expected": None,
                "actual": actual[field],
                "reason": "Unexpected output field",
            }

    return mismatches
```

### 22.3 Output Normalization

The comparator can normalize casing:

```text
ABCDEF -> abcdef
```

But it should not hide:

- Missing fields
- Extra fields
- Different lengths
- Invalid hex

---

## 23. Result Status Classification

Recommended statuses:

| Status | Meaning |
| --- | --- |
| PASS | Actual output matches expected output |
| VALIDATION_FAIL | DUT ran, but output mismatched |
| PARSE_ERROR | Test vector could not be parsed |
| CONFIG_ERROR | Configuration is invalid |
| DUT_ERROR | DUT crashed or returned invalid output |
| UNSUPPORTED_TEST | Algorithm/mode/test type is not supported |
| INTERNAL_ERROR | Unexpected framework error |

This distinction is important.

Example:

```text
VALIDATION_FAIL:
    The algorithm output is wrong.

DUT_ERROR:
    The DUT did not execute correctly.

PARSE_ERROR:
    The input vector file could not be interpreted.

CONFIG_ERROR:
    The user requested an invalid combination.
```

---

## 24. Reporting Design

### 24.1 Console Report

Example:

```text
Validation Summary
------------------
Algorithm: AES
Mode: CBC
Operation: encrypt
Test Type: KAT
DUT: python
Vector File: sample_vectors/aes/aes_cbc_128.rsp
Vector SHA256: 9a4...

Total Tests: 100
Passed: 100
Validation Failures: 0
Parse Errors: 0
DUT Errors: 0
Internal Errors: 0

Result: PASS
```

### 24.2 JSON Report

Example:

```json
{
  "run_metadata": {
    "tool_name": "crypto-validation-framework",
    "tool_version": "0.1.0",
    "timestamp_utc": "2026-06-22T00:00:00Z",
    "algorithm": "AES",
    "mode": "CBC",
    "operation": "encrypt",
    "test_type": "KAT",
    "dut": "python",
    "vector_file": "sample_vectors/aes/aes_cbc_128.rsp",
    "vector_checksum_sha256": "..."
  },
  "summary": {
    "total": 100,
    "passed": 100,
    "validation_failed": 0,
    "parse_errors": 0,
    "dut_errors": 0,
    "internal_errors": 0
  },
  "results": []
}
```

### 24.3 Failure Report Example

```text
Test Case: 45
Status: VALIDATION_FAIL
Field: ciphertext

Expected:
    7649abac8119b246cee98e9b12e9197d

Actual:
    7649abac8119b246cee98e9b12e91900
```

### 24.4 Report Metadata for Reproducibility

Each report should include:

- Tool name
- Tool version
- Run timestamp
- Git commit if available
- Config used
- DUT selected
- Vector file path
- Vector file checksum
- Algorithm
- Mode
- Operation
- Test type
- Total tests
- Result counts
- Failure details

---

## 25. Logging Strategy

### 25.1 Runtime Logs

Logs should include:

- Config loaded
- Vector file path
- Parser selected
- DUT selected
- Number of test cases parsed
- Failure IDs
- System errors
- Execution duration

### 25.2 Sensitive Data Handling

Even if NIST vector keys are public test vectors, enterprise environments may prefer not to log keys by default.

Default logging should avoid full sensitive input fields.

Recommended policy:

```text
Default:
    Log test ID, status, mismatch field, error code.

Debug mode:
    Optionally include full inputs and outputs.

Flag:
    --include-sensitive
```

---

## 26. Exit Codes

Exit codes make the tool automation-friendly.

Recommended:

| Exit Code | Meaning |
| --- | --- |
| 0 | All tests passed |
| 1 | One or more validation failures |
| 2 | Config, parser, DUT, or internal framework error |

Example:

```bash
python -m crypto_validation ...
echo $?
```

CI/CD can use the exit code to pass or fail a pipeline.

---

## 27. Error Handling Strategy

### 27.1 Principles

The framework should:

- Fail clearly.
- Preserve failure context.
- Distinguish validation failure from system failure.
- Continue running other tests unless `--fail-fast` is enabled.
- Always generate a report if possible.

### 27.2 Exception Types

Suggested exception classes:

```python
class ValidationFrameworkError(Exception):
    pass

class ConfigError(ValidationFrameworkError):
    pass

class ParseError(ValidationFrameworkError):
    pass

class DutError(ValidationFrameworkError):
    pass

class UnsupportedTestError(ValidationFrameworkError):
    pass
```

### 27.3 Error Examples

| Situation | Status |
| --- | --- |
| Expected ciphertext differs from actual ciphertext | VALIDATION_FAIL |
| Vector file missing `KEY` for AES test | PARSE_ERROR |
| User selects AES-CBC without IV | CONFIG_ERROR |
| RTL simulator crashes | DUT_ERROR |
| User selects RSA but RSA is not implemented | UNSUPPORTED_TEST |
| Unexpected Python exception | INTERNAL_ERROR |

---

## 28. Testing Strategy

### 28.1 Unit Tests

Required unit tests:

- RSP parser
- Config validator
- AES DUT
- Comparator
- Result model
- JSON reporter
- Validation engine

### 28.2 Parser Tests

Test cases:

- Valid AES-CBC vector.
- Valid AES-ECB vector without IV.
- Empty message for SHA.
- Uppercase hex.
- Lowercase hex.
- Hex values with spaces.
- Missing required field.
- Unknown field.
- Multiple sections like `[ENCRYPT]` and `[DECRYPT]`.

### 28.3 DUT Tests

Test:

- AES-CBC encrypt known vector.
- AES-CBC decrypt known vector.
- AES-ECB encrypt.
- AES-CTR if implemented.
- Invalid key length.
- Invalid input length.

### 28.4 Comparator Tests

Test:

- Exact match.
- Field mismatch.
- Missing actual field.
- Extra actual field.
- Case normalization.
- Empty expected value.

### 28.5 Integration Tests

Run:

```text
sample vector file -> parser -> DUT -> comparator -> report
```

Expected:

```text
All known good sample tests pass.
```

---

## 29. Documentation Deliverables

Documentation should include:

1. `README.md`
   - Project overview
   - Quick start
   - Example command

2. `docs/architecture.md`
   - System architecture
   - Component descriptions
   - Diagrams

3. `docs/usage.md`
   - CLI usage
   - Config file usage
   - Report examples

4. `docs/extension_guide.md`
   - How to add a new algorithm
   - How to add a new parser
   - How to add a new DUT
   - How to add a new reporter

5. `docs/dut_contract.md`
   - DUT input/output schema
   - Error behavior
   - External command expectations

6. `sample_reports/`
   - Example PASS report
   - Example FAIL report
   - Example SYSTEM_ERROR report

---

## 30. Implementation Roadmap

### Phase 1: Understanding and Requirements

Goals:

- Understand AES, SHA, HMAC basics.
- Study NIST CAVP and ACVP validation methodology.
- Understand KAT, MCT, and multi-block testing.
- Confirm manager expectations.

Questions to clarify:

- Which algorithm first?
- Which vector format first?
- Which DUT first?
- Which report format is required?
- Are MCTs required in the first version?

### Phase 2: Core Framework Design

Implement design for:

- Test case schema
- Test result schema
- DUT contract
- Parser contract
- Reporter contract
- Registry pattern

Deliverable:

```text
Architecture document and interface definitions.
```

### Phase 3: AES-CBC KAT MVP

Implement:

- CLI runner
- Config validator
- Vector loader
- RSP parser
- AES-CBC Python DUT
- KAT executor
- Comparator
- Console reporter
- JSON reporter

Deliverable:

```text
AES-CBC KAT validation from NIST `.rsp` or JSON vector file.
```

### Phase 4: AES Expansion

Add:

- AES-ECB
- AES-CBC decrypt
- AES-CTR
- AES-128, AES-192, AES-256
- More AES vector groups

### Phase 5: SHA and HMAC

Add:

- SHA-256
- SHA-512
- SHA-3 if required
- HMAC-SHA256
- HMAC-SHA512
- Empty message handling

### Phase 6: Advanced Test Categories

Add:

- MCT executor
- Algorithm-specific MCT logic
- Multi-block test support
- Edge-case support

### Phase 7: Additional DUT Support

Add:

- External command DUT
- C model adapter
- RTL simulator adapter
- Output parser for simulator logs

### Phase 8: Reporting and Integration

Add:

- CSV reports
- HTML reports
- CI/CD exit codes
- Failure artifact storage
- Report archive structure

### Phase 9: Documentation and Demo

Prepare:

- Architecture document
- Usage guide
- Extension guide
- Sample vector set
- Sample reports
- End-to-end demo

---

## 31. MVP Acceptance Criteria

The MVP is complete when:

1. Tool can be run from terminal.
2. AES-CBC KAT `.rsp` vector file can be loaded.
3. Parser creates structured test cases.
4. Inputs and expected outputs are separated correctly.
5. Python AES DUT executes each test case.
6. Comparator performs exact output comparison.
7. Console report is generated.
8. JSON report is generated.
9. Exit code is meaningful.
10. Parser unit tests pass.
11. Comparator unit tests pass.
12. AES DUT unit tests pass.
13. End-to-end integration test passes.
14. Failure cases produce clear failure details.
15. Vector checksum and run metadata are included in the report.

---

## 32. Success Criteria for Full Project

The full project is successful if:

- NIST vectors run without manual intervention.
- Expected outputs and actual outputs are compared exactly.
- Reports clearly show pass/fail/system-error status.
- Multiple algorithms can be supported through the same framework.
- New DUTs can be added without changing the validation engine.
- New parsers can be added without changing the DUT interface.
- New reporters can be added without changing validation logic.
- Results are reproducible and traceable.
- Documentation allows another engineer to use and extend the framework.

---

## 33. Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| NIST vector formats vary | Parser complexity | Support `.rsp` and JSON through parser registry |
| AES-CTR counter interpretation differs | Incorrect outputs | Document counter format and validate with known vectors |
| MCT logic is algorithm-specific | Incorrect MCT results | Use separate executor classes |
| Empty inputs mishandled | SHA/HMAC failures | Explicit parser tests for empty values |
| DUTs expose different interfaces | Integration difficulty | Define strict DUT contract |
| Reports become too large | Debugging difficulty | Summary by default, detailed failures separately |
| Sensitive test data logged | Security concern | Avoid full input logging by default |
| Large vector files consume memory | Performance issue | Use streaming parser design |
| Unsupported algorithms requested | Confusing errors | Return UNSUPPORTED_TEST clearly |
| One-off code growth | Poor maintainability | Use modular architecture and registries |

---

## 34. Key Manager Discussion Questions

These questions should be clarified before or during implementation:

1. Which algorithm should be prioritized first?
   - AES only?
   - AES plus SHA?
   - AES plus SHA plus HMAC?

2. Which AES modes are required first?
   - ECB
   - CBC
   - CTR

3. Is decrypt validation required in the first phase?

4. Which vector format should be supported first?
   - `.rsp`
   - full ACVP workflow support
   - internal CSV/TXT

5. Which DUT should be integrated first?
   - Python reference implementation
   - C reference model
   - RTL simulator
   - SoC model

6. Are Monte Carlo Tests required in the first milestone?

7. What report format is expected?
   - Console
   - JSON
   - CSV
   - HTML

8. How should failure debugging work?
   - Expected vs actual only?
   - Include input vectors?
   - Include intermediate logs?
   - Store failing test cases separately?

9. How large are the vector files expected to be?

10. How many engineers or teams are expected to use the tool initially?

11. Should this be integrated into CI/CD?

12. Are there internal coding standards or verification standards to follow?

---

## 35. Future Enhancements

### 35.1 Web Dashboard

Potential features:

- Upload vector files.
- Select algorithm and DUT.
- Start validation jobs.
- View results.
- Download reports.

Recommended stack if needed:

```text
Backend: FastAPI
Frontend: React or simple HTML templates
Database: SQLite initially, PostgreSQL later
```

### 35.2 Distributed Execution

Useful when:

- Vector sets are large.
- RTL simulations are slow.
- Many users run jobs concurrently.

Possible design:

```text
API server -> Job queue -> Worker nodes -> Result storage -> Dashboard
```

Possible technologies:

```text
Celery
Redis
RQ
PostgreSQL
Docker
Kubernetes
```

This should be future scope, not MVP.

### 35.3 AI-Assisted Debugging

Potential future feature:

- Analyze failed test cases.
- Suggest likely mismatch causes.
- Identify mode/counter/padding issues.

This should not be part of the deterministic validation core.

Rule:

```text
AI can assist debugging, but validation decisions must remain deterministic.
```

### 35.4 ACVP Server Compatibility

Future integration could:

- Consume and emit ACVP protocol payloads.
- Produce ACVP-compatible responses.
- Support automated certification workflows.

---

## 36. Business Relevance

This framework provides value by:

1. **Reducing manual effort**
   - Engineers do not manually parse and compare vectors.

2. **Improving correctness**
   - Bit-exact deterministic comparison.

3. **Standardizing validation**
   - Same flow across algorithms and DUTs.

4. **Accelerating IP sign-off**
   - Faster feedback for cryptographic IP development.

5. **Supporting certification readiness**
   - Results are traceable and aligned with NIST validation methodology.

6. **Supporting reuse**
   - One framework can support multiple SoC security IPs.

7. **Improving maintainability**
   - New algorithms and DUTs can be added through defined interfaces.

---

## 37. Final Recommended Positioning

The project should be presented as:

```text
A deterministic, modular, and NIST-aligned cryptographic validation
framework that automates vector parsing, DUT execution, output comparison,
and report generation for reusable SoC security IP validation.
```

Short version:

```text
This is not just a validation script.
It is reusable verification infrastructure for cryptographic IP correctness.
```

---

## 38. Final Implementation Recommendation

The recommended implementation path is:

1. Build the terminal-based validation backend first.
2. Define strong internal schemas and interfaces.
3. Implement AES-CBC KAT `.rsp` validation end to end.
4. Add AES-ECB and AES-CTR.
5. Add AES decrypt support.
6. Add SHA and HMAC.
7. Add MCT and multi-block support.
8. Add RTL/C/external DUT adapters.
9. Add advanced reports and CI/CD integration.
10. Add UI or distributed execution only after the core engine is reliable.

This approach balances:

- Correctness
- Practicality
- Extensibility
- Manager expectations
- Internship deliverability
- Long-term engineering value

---

## 39. One-Page Summary

### What is being built?

A Python-based automated framework to validate cryptographic algorithms using NIST test vectors.

### What does it do?

```text
Load vectors -> parse inputs/expected outputs -> run DUT -> compare -> report
```

### What is the first target?

```text
AES-CBC KAT validation using NIST `.rsp` / JSON files and Python DUT.
```

### Why terminal-first?

Because verification workflows need automation, scripting, CI/CD compatibility, and server execution.

### What makes it scalable?

Stable interfaces:

- Parser interface
- DUT interface
- Executor interface
- Reporter interface
- Internal test case schema

### What is the most important design rule?

```text
Parser parses.
DUT runs.
Comparator compares.
Reporter reports.
Validation engine coordinates.
```

### What is the main success measure?

The framework can run NIST vectors automatically and produce reliable, traceable pass/fail reports without manual intervention.

