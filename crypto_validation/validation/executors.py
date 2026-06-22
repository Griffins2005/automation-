"""Test category executors."""

from __future__ import annotations

from crypto_validation.dut.base import Dut
from crypto_validation.exceptions import UnsupportedTestError
from crypto_validation.models import TestCase, ValidationConfig


class KatExecutor:
    """Known Answer Test executor."""

    def run(self, test_case: TestCase, dut: Dut) -> dict:
        return dut.run(test_case.input)


def build_executor(config: ValidationConfig) -> KatExecutor:
    """Construct the configured test executor."""

    if config.test_type == "KAT":
        return KatExecutor()

    raise UnsupportedTestError(f"Unsupported test type: {config.test_type}")
