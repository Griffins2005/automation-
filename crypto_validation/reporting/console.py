"""Console report output.

The console reporter is intentionally concise. It gives immediate feedback for
terminal users while the JSON reporter stores the full structured artifact.
"""

from __future__ import annotations

from crypto_validation.models import TestResult, ValidationConfig, VectorSource
from crypto_validation.reporting.summary import build_summary


def print_console_report(
    config: ValidationConfig,
    source: VectorSource,
    results: list[TestResult],
    json_report_path: str | None = None,
) -> None:
    """Print a concise terminal validation summary.

    Args:
        config: Normalized validation configuration.
        source: Vector file provenance metadata.
        results: Per-test validation results.
        json_report_path: Optional path to the generated JSON report.
    """

    summary = build_summary(results)
    print("Validation Summary")
    print("------------------")
    print(f"Algorithm: {config.algorithm}")
    print(f"Mode: {config.mode or '-'}")
    print(f"Operation: {config.operation}")
    print(f"Test Type: {config.test_type}")
    print(f"DUT: {config.dut}")
    print(f"Vector File: {source.path}")
    print(f"Vector SHA256: {source.checksum_sha256}")
    print()
    print(f"Total Tests: {summary['total']}")
    print(f"Passed: {summary['passed']}")
    print(f"Validation Failures: {summary['validation_failed']}")
    print(f"Parse Errors: {summary['parse_errors']}")
    print(f"Config Errors: {summary['config_errors']}")
    print(f"DUT Errors: {summary['dut_errors']}")
    print(f"Unsupported Tests: {summary['unsupported_tests']}")
    print(f"Internal Errors: {summary['internal_errors']}")

    failed = [result for result in results if result.status.value != "PASS"]
    if failed:
        print()
        print("Failures")
        print("--------")
        for result in failed[:10]:
            # Limit console failure detail to keep large validation runs usable.
            # Full detail remains available in the JSON report.
            print(f"Test {result.test_id}: {result.status.value}")
            if result.mismatches:
                for field, mismatch in result.mismatches.items():
                    print(f"  Field: {field}")
                    print(f"  Expected: {mismatch.get('expected')}")
                    print(f"  Actual:   {mismatch.get('actual')}")
            if result.error_message:
                print(f"  Error: {result.error_message}")
        if len(failed) > 10:
            print(f"... {len(failed) - 10} more failures omitted from console output")

    if json_report_path:
        print()
        print(f"JSON Report: {json_report_path}")
