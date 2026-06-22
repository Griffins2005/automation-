"""Shared data models for validation runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ResultStatus(StrEnum):
    """Result states used by reports and exit-code handling."""

    PASS = "PASS"
    VALIDATION_FAIL = "VALIDATION_FAIL"
    PARSE_ERROR = "PARSE_ERROR"
    CONFIG_ERROR = "CONFIG_ERROR"
    DUT_ERROR = "DUT_ERROR"
    UNSUPPORTED_TEST = "UNSUPPORTED_TEST"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class ValidationConfig:
    """User-selected validation configuration."""

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
    """Traceability information for an input vector file."""

    path: str
    format: str
    checksum_sha256: str


@dataclass(frozen=True)
class TestCase:
    """Internal schema for a parsed cryptographic test case."""

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
    """Field-level comparison result."""

    passed: bool
    mismatches: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TestResult:
    """Result for one test case."""

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
    """Full validation report."""

    metadata: dict[str, Any]
    summary: dict[str, int]
    results: list[TestResult]
