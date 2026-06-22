# Extension Guide

This guide explains how to extend the framework without breaking the core
architecture.

## 1. Design Rule

Keep responsibilities separate:

```text
Parser parses.
DUT runs.
Executor controls test-type behavior.
Comparator compares.
Reporter reports.
Validation engine coordinates.
```

Avoid adding algorithm-specific logic to the CLI or validation engine.

## 2. Add a New AES Mode

1. Update support validation in `crypto_validation/config.py`.
2. Update or add DUT behavior in `crypto_validation/dut/aes_python.py`.
3. Add sample vectors under `sample_vectors/aes/`.
4. Add parser tests if the vector shape changes.
5. Add DUT tests.
6. Add CLI end-to-end tests.

## 3. Add a New Algorithm

Example: SHA-256.

### Step 1: Extend Config Support

Update:

```python
SUPPORTED_ALGORITHMS = {"AES", "SHA-256"}
```

If the algorithm does not use a mode, decide whether the CLI should accept
`--mode none` or whether mode should become optional.

### Step 2: Add Parser Field Mapping

Extend `RspParser` or add a dedicated parser builder.

SHA input/output shape:

```text
input:
    msg

expected_output:
    md
```

Preserve empty `Msg =` values.

### Step 3: Add DUT

Create a file such as:

```text
crypto_validation/dut/sha_python.py
```

Implement:

```python
class Sha256PythonDut(Dut):
    def run(self, input_data: dict) -> dict:
        ...
```

Return:

```python
{"md": "..."}
```

### Step 4: Register DUT

Update `crypto_validation/dut/registry.py`.

### Step 5: Add Tests

Add:

- parser tests
- DUT tests
- comparator tests if output shape is new
- CLI integration test

## 4. Add a New DUT Backend

Example: external C executable.

### Step 1: Create Adapter

Create:

```text
crypto_validation/dut/external_command.py
```

Implement:

```python
class ExternalCommandDut(Dut):
    def run(self, input_data: dict) -> dict:
        ...
```

### Step 2: Convert Framework Input

Translate:

```python
{
  "key": "...",
  "iv": "...",
  "plaintext": "..."
}
```

into the command format expected by the external DUT.

### Step 3: Parse External Output

Convert command output back into framework format:

```python
{"ciphertext": "..."}
```

### Step 4: Raise `DutError` for Failures

Examples:

- non-zero process exit
- timeout
- malformed output
- missing output field

### Step 5: Register Backend

Update `build_dut(config)`.

## 5. Add a New Vector Format

Example: ACVP JSON.

### Step 1: Create Parser

Create:

```text
crypto_validation/parsers/acvp_json.py
```

Subclass `VectorParser`.

### Step 2: Return `TestCase` Objects

Regardless of input format, output the same internal schema.

### Step 3: Register Parser

Update:

```text
crypto_validation/parsers/registry.py
```

### Step 4: Add Tests

Include:

- valid JSON vector
- missing required fields
- grouped vectors
- unsupported test groups

## 6. Add a New Test Type

Example: Monte Carlo Test.

### Step 1: Add Executor

Create:

```text
crypto_validation/validation/executors.py
```

or split executors into a package if they become large.

MCT pseudocode:

```python
class MctExecutor:
    def run(self, test_case, dut):
        current_input = test_case.input
        for _ in range(iteration_count):
            actual = dut.run(current_input)
            current_input = derive_next_input(current_input, actual)
        return actual
```

### Step 2: Keep Derivation Explicit

MCT derivation is algorithm-specific. Do not hide it in generic code.

### Step 3: Register Executor

Update `build_executor(config)`.

## 7. Add a New Reporter

Example: CSV.

Create:

```text
crypto_validation/reporting/csv_reporter.py
```

Reporter inputs should be:

```python
config
source
results
```

Do not rerun comparison or inspect raw vectors in a reporter.

## 8. Documentation Checklist for New Features

For every new feature, update:

- source docstrings
- `docs/SPECIFICATION.md`
- `docs/API_REFERENCE.md`
- this extension guide if the extension path changes
- README if user-facing commands change

## 9. Testing Checklist

For every new feature, add:

- unit tests
- error-path tests
- CLI integration test
- sample vector or fixture

Validation command:

```bash
python3 -m pytest
```
