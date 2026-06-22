"""Shared data contracts used across the validation framework.

The framework intentionally passes a small set of dataclasses between modules
instead of passing raw dictionaries everywhere. These models define the stable
contract between parser, DUT, comparator, validation engine, and reporters.

Keeping these contracts explicit is what allows a future SHA parser, RTL DUT,
or HTML reporter to be added without changing the engine orchestration logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ResultStatus(StrEnum):
    """Canonical result states for a single test case.

    These values appear in JSON reports and are also used to decide process exit
    codes. Keep them stable because external automation can depend on them.

    Attributes:
        PASS: The DUT output exactly matched the expected vector output.
        VALIDATION_FAIL: The DUT ran successfully, but output fields differed.
        PARSE_ERROR: Vector parsing failed before a valid test could be built.
        CONFIG_ERROR: User configuration is invalid or inconsistent.
        DUT_ERROR: The selected DUT crashed or returned unusable output.
        UNSUPPORTED_TEST: Requested algorithm/mode/test type is not implemented.
        INTERNAL_ERROR: Unexpected framework-level failure.
    """

    PASS = "PASS"
    VALIDATION_FAIL = "VALIDATION_FAIL"
    PARSE_ERROR = "PARSE_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    DUT_ERROR = "DUT_ERROR"
    UNSUPPORTED_TEST = "UNSUPPORTED_TEST"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class ValidationConfig:
    """Normalized user-selected validation configuration.

    The CLI builds this model from command-line arguments, then
    :func:`crypto_validation.config.validate_config` normalizes casing and
    verifies support before any vector file is parsed.

    Attributes:
        algorithm: Algorithm family, e.g. ``"AES"``.
        mode: Algorithm mode, e.g. ``"CBC"``. Some future algorithms may use
            ``None`` if there is no mode concept.
        operation: Operation under test, currently ``"encrypt"`` or
            ``"decrypt"`` for AES.
        test_type: Validation category, e.g. ``"KAT"``.
        vector_file: Path to the source test vector file.
        vector_format: Vector format, e.g. ``"rsp"``.
        dut: DUT backend selector, e.g. ``"python"``.
        report_format: Requested file report format. Console output is always
            printed for human readability.
        report_dir: Directory where generated report files are written.
        fail_fast: Stop after the first non-PASS result when true.
        include_sensitive: Reserved switch for future detailed logging of
            inputs such as keys. The current implementation avoids using it.
    """

    algorithm: str
    mode: str | None
    operation: str
    test_type: str
    vector_file: str
    vector_format: str
    dut: str
    report_format: str
    report_dir: str
    fail_fast: bool = False
    include_sensitive: bool = False


@dataclass(frozen=True)
class VectorSource:
    """Traceability information for an input vector file.

    Reports include this object so validation results can be tied back to the
    exact vector file used during the run. The checksum is especially important
    for reproducibility and auditability.

    Attributes:
        path: Original vector file path.
        format: Parser format selected for the file.
        checksum_sha256: SHA-256 digest of the file contents.
    """

    path: str
    format: str
    checksum_sha256: str


@dataclass(frozen=True)
class TestCase:
    """Internal schema for one parsed cryptographic test case.

    Parsers are responsible for converting raw vector formats into this schema.
    The validation engine only understands this schema; it does not know about
    raw `.rsp` syntax, AES field casing, or file section layout.

    Example:
        AES-CBC encryption test case::

            TestCase(
                test_id="0",
                algorithm="AES",
                mode="CBC",
                operation="encrypt",
                test_type="KAT",
                input={
                    "operation": "encrypt",
                    "key": "...",
                    "iv": "...",
                    "plaintext": "...",
                },
                expected_output={"ciphertext": "..."},
            )

    Attributes:
        test_id: Human-readable vector ID, usually NIST ``COUNT``.
        algorithm: Algorithm family for the test.
        mode: Algorithm mode if applicable.
        operation: Operation under test.
        test_type: Validation category.
        input: Structured DUT input fields.
        expected_output: Structured golden output fields from the vector.
        metadata: Non-comparison data such as source file, checksum, section,
            and group-level vector metadata.
    """

    test_id: str
    algorithm: str
    mode: str | None
    operation: str
    test_type: str
    input: dict[str, Any]
    expected_output: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ComparisonResult:
    """Field-level comparison result.

    Attributes:
        passed: True when all expected fields match and no unexpected actual
            fields are present.
        mismatches: Per-field mismatch details. Empty when ``passed`` is true.
    """

    passed: bool
    mismatches: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TestResult:
    """Result for one executed test case.

    A result is produced even when execution fails. This keeps reports
    deterministic and makes failures easy to inspect programmatically.

    Attributes:
        test_id: ID copied from the source test case.
        status: Canonical pass/fail/error status.
        expected_output: Golden output fields from the test vector.
        actual_output: DUT output fields, or ``None`` if the DUT did not
            produce usable output.
        mismatches: Field-level comparison differences for validation failures.
        error_code: Machine-readable error identifier for non-comparison errors.
        error_message: Human-readable error details.
        metadata: Source and group metadata copied from the test case.
    """

    test_id: str
    status: ResultStatus
    expected_output: dict[str, Any]
    actual_output: dict[str, Any] | None
    mismatches: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RunReport:
    """Full in-memory validation report.

    This model is currently reserved for future reporters that need to pass a
    complete report object instead of separate metadata, summary, and results.
    """

    metadata: dict[str, Any]
    summary: dict[str, int]
    results: list[TestResult]
