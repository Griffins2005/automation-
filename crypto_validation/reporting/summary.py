"""Report summary helpers."""

from __future__ import annotations

from collections import Counter

from crypto_validation.models import ResultStatus, TestResult


def build_summary(results: list[TestResult]) -> dict[str, int]:
    """Build status counts for a validation run."""

    counts = Counter(result.status.value for result in results)
    return {
        "total": len(results),
        "passed": counts[ResultStatus.PASS.value],
        "validation_failed": counts[ResultStatus.VALIDATION_FAIL.value],
        "parse_errors": counts[ResultStatus.PARSE_ERROR.value],
        "config_errors": counts[ResultStatus.CONFIG_ERROR.value],
        "dut_errors": counts[ResultStatus.DUT_ERROR.value],
        "unsupported_tests": counts[ResultStatus.UNSUPPORTED_TEST.value],
        "internal_errors": counts[ResultStatus.INTERNAL_ERROR.value],
    }


def has_system_errors(summary: dict[str, int]) -> bool:
    """Return whether the summary contains framework/system errors."""

    return any(
        summary[key] > 0
        for key in (
            "parse_errors",
            "config_errors",
            "dut_errors",
            "unsupported_tests",
            "internal_errors",
        )
    )
