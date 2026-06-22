"""Test category executors.

Executors define *how* a test type is run. KAT tests are one-shot, while future
MCT tests will need iterative state updates. Keeping this behavior outside the
DUT lets the same AES DUT be reused across test categories.
"""

from __future__ import annotations

from crypto_validation.dut.base import Dut
from crypto_validation.exceptions import UnsupportedTestError
from crypto_validation.models import TestCase, ValidationConfig


class KatExecutor:
    """Known Answer Test executor.

    KAT execution is intentionally simple:

    ``structured input -> DUT -> actual output``
    """

    def run(self, test_case: TestCase, dut: Dut) -> dict:
        """Run one KAT test case.

        Args:
            test_case: Parsed test case containing DUT input.
            dut: Selected DUT adapter.

        Returns:
            Structured actual output from the DUT.
        """

        return dut.run(test_case.input)


def build_executor(config: ValidationConfig) -> KatExecutor:
    """Construct the configured test executor.

    Args:
        config: Normalized validation configuration.

    Returns:
        Executor for the requested test type.

    Raises:
        UnsupportedTestError: If the requested test type is not implemented.
    """

    if config.test_type == "KAT":
        return KatExecutor()

    raise UnsupportedTestError(f"Unsupported test type: {config.test_type}")
