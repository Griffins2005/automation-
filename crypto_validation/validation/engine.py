"""Validation engine orchestration.

The engine is the framework coordinator. It does not parse vectors, implement
cryptography, or format reports. Instead, it consumes already-built components:

- an executor that knows the test category behavior,
- a DUT that produces actual outputs,
- a comparator that performs strict field comparison.

This separation is important for extensibility. Adding MCT support, an RTL DUT,
or an HTML reporter should not require rewriting the engine's core loop.
"""

from __future__ import annotations

from collections.abc import Iterable

from crypto_validation.exceptions import DutError, UnsupportedTestError, ValidationFrameworkError
from crypto_validation.models import ResultStatus, TestCase, TestResult, ValidationConfig
from crypto_validation.validation.comparator import Comparator
from crypto_validation.validation.executors import KatExecutor


class ValidationEngine:
    """Coordinate execution, comparison, and result classification.

    Args:
        config: Normalized run configuration.
        executor: Test-category executor, currently ``KatExecutor``.
        dut: Device-under-test adapter implementing ``run(input_data)``.
        comparator: Comparator used to compare expected and actual outputs.
    """

    def __init__(
        self,
        config: ValidationConfig,
        executor: KatExecutor,
        dut,
        comparator: Comparator,
    ):
        self.config = config
        self.executor = executor
        self.dut = dut
        self.comparator = comparator

    def run(self, test_cases: Iterable[TestCase]) -> list[TestResult]:
        """Run validation for a sequence of parsed test cases.

        Args:
            test_cases: Iterable of structured test cases from a parser.

        Returns:
            List of per-test results in execution order.

        Notes:
            When ``config.fail_fast`` is true, execution stops after the first
            non-PASS result. This is useful for debugging but should usually be
            disabled for full validation reports.
        """

        results: list[TestResult] = []

        for test_case in test_cases:
            result = self._run_one(test_case)
            results.append(result)

            if self.config.fail_fast and result.status != ResultStatus.PASS:
                break

        return results

    def _run_one(self, test_case: TestCase) -> TestResult:
        """Run and classify one test case.

        Args:
            test_case: Parsed test case.

        Returns:
            A ``TestResult``. DUT and framework errors are converted into error
            results instead of escaping, so reports remain complete.
        """

        try:
            actual_output = self.executor.run(test_case, self.dut)
            comparison = self.comparator.compare(test_case.expected_output, actual_output)

            if comparison.passed:
                return TestResult(
                    test_id=test_case.test_id,
                    status=ResultStatus.PASS,
                    expected_output=test_case.expected_output,
                    actual_output=actual_output,
                    metadata=test_case.metadata,
                )

            return TestResult(
                test_id=test_case.test_id,
                status=ResultStatus.VALIDATION_FAIL,
                expected_output=test_case.expected_output,
                actual_output=actual_output,
                mismatches=comparison.mismatches,
                metadata=test_case.metadata,
            )

        except DutError as exc:
            return self._error_result(test_case, ResultStatus.DUT_ERROR, exc)
        except UnsupportedTestError as exc:
            return self._error_result(test_case, ResultStatus.UNSUPPORTED_TEST, exc)
        except ValidationFrameworkError as exc:
            return self._error_result(test_case, ResultStatus.INTERNAL_ERROR, exc)
        except Exception as exc:  # pragma: no cover - defensive boundary
            return self._error_result(test_case, ResultStatus.INTERNAL_ERROR, exc)

    @staticmethod
    def _error_result(test_case: TestCase, status: ResultStatus, exc: Exception) -> TestResult:
        """Create a structured error result for one test case."""

        return TestResult(
            test_id=test_case.test_id,
            status=status,
            expected_output=test_case.expected_output,
            actual_output=None,
            error_code=status.value,
            error_message=str(exc),
            metadata=test_case.metadata,
        )
