"""Strict output comparator."""

from __future__ import annotations

from typing import Any

from crypto_validation.models import ComparisonResult


class Comparator:
    """Compare expected and actual DUT outputs field by field."""

    def compare(self, expected: dict[str, Any], actual: dict[str, Any]) -> ComparisonResult:
        mismatches: dict[str, Any] = {}

        for field, expected_value in expected.items():
            actual_value = actual.get(field)
            if self._normalize(expected_value) != self._normalize(actual_value):
                mismatches[field] = {
                    "expected": expected_value,
                    "actual": actual_value,
                }

        for field, actual_value in actual.items():
            if field not in expected:
                mismatches[field] = {
                    "expected": None,
                    "actual": actual_value,
                    "reason": "Unexpected output field",
                }

        return ComparisonResult(passed=not mismatches, mismatches=mismatches)

    @staticmethod
    def _normalize(value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower()
        return value
