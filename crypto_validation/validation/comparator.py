"""Strict output comparator.

Cryptographic validation is bit-exact. The comparator therefore performs
field-by-field equality checks and reports every mismatch. It does not apply
tolerances, partial matching, or algorithm-specific interpretation.
"""

from __future__ import annotations

from typing import Any

from crypto_validation.models import ComparisonResult


class Comparator:
    """Compare expected and actual DUT outputs field by field.

    The expected output comes from the NIST vector. The actual output comes from
    the selected DUT. Both are dictionaries so algorithms with multiple outputs
    can be supported later.
    """

    def compare(self, expected: dict[str, Any], actual: dict[str, Any]) -> ComparisonResult:
        """Compare expected and actual output dictionaries.

        Args:
            expected: Golden output fields from a test vector.
            actual: Output fields returned by a DUT.

        Returns:
            ``ComparisonResult`` containing pass/fail state and mismatch detail.

        Notes:
            String values are compared case-insensitively to avoid false
            failures caused by uppercase/lowercase hex formatting differences.
        """

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
        """Normalize comparable values without changing their meaning."""

        if isinstance(value, str):
            return value.strip().lower()
        return value
