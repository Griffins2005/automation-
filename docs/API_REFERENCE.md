# API Reference

This reference summarizes the main modules, classes, and functions in the MVP.
For full parameter descriptions, read the docstrings in the source files.

## `crypto_validation.cli`

### `main(argv: list[str] | None = None) -> int`

Runs one validation job.

Returns:

- `0` when all tests pass.
- `1` when validation mismatches occur.
- `2` when a system-level error occurs.

### `build_arg_parser() -> argparse.ArgumentParser`

Builds the command-line parser used by both `crypto-validate` and
`python -m crypto_validation`.

## `crypto_validation.config`

### `validate_config(config: ValidationConfig) -> ValidationConfig`

Normalizes and validates user configuration.

Raises:

- `ConfigError` for unsupported algorithms, modes, operations, test types,
  vector formats, DUTs, report formats, or invalid vector paths.

### `normalize_config(config: ValidationConfig) -> ValidationConfig`

Normalizes casing for registry comparisons.

## `crypto_validation.models`

### `ValidationConfig`

Run-level configuration.

### `VectorSource`

Vector file provenance:

- path
- format
- SHA-256 checksum

### `TestCase`

Parser output consumed by the validation engine.

### `ComparisonResult`

Comparator output containing:

- pass/fail boolean
- field-level mismatches

### `TestResult`

Per-test validation result.

### `ResultStatus`

Stable result status enum used in reports and exit-code decisions.

## `crypto_validation.parsers`

### `VectorParser`

Abstract parser interface.

```python
parse(content, config, source) -> Iterable[TestCase]
```

### `RspParser`

Parses CAVP-style `.rsp` vectors.

Responsibilities:

- detect sections
- parse key/value records
- normalize hex values
- separate AES inputs and expected outputs
- preserve source metadata

### `build_parser(config) -> VectorParser`

Builds a parser from normalized config.

## `crypto_validation.dut`

### `Dut`

Abstract DUT interface.

```python
run(input_data: dict[str, Any]) -> dict[str, Any]
```

### `AesPythonDut`

PyCryptodome-backed AES reference DUT.

Supported modes:

- ECB
- CBC
- CTR

Supported operations:

- encrypt
- decrypt

### `build_dut(config) -> Dut`

Builds a DUT adapter from normalized config.

## `crypto_validation.validation`

### `KatExecutor`

Runs one-shot Known Answer Tests.

### `build_executor(config)`

Builds a test executor from normalized config.

### `Comparator`

Strict field-based output comparator.

### `ValidationEngine`

Coordinates:

1. executor
2. DUT
3. comparator
4. result classification

The engine does not parse vectors, implement algorithms, or write reports.

## `crypto_validation.reporting`

### `build_summary(results) -> dict[str, int]`

Builds stable summary counts.

### `has_system_errors(summary) -> bool`

Returns whether system-level errors occurred.

### `print_console_report(config, source, results, json_report_path=None)`

Prints a concise terminal summary.

### `write_json_report(config, source, results) -> Path`

Writes a structured JSON report and returns its path.

## `crypto_validation.vectors`

### `compute_file_sha256(path: Path) -> str`

Computes a vector file checksum.

### `load_vector_text(path: Path) -> str`

Loads a vector file as UTF-8 text.

### `build_vector_source(path: Path, vector_format: str) -> VectorSource`

Creates provenance metadata for a vector file.
