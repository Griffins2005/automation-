"""Command-line entry point for the validation framework.

The CLI is intentionally thin: it translates user arguments into a
``ValidationConfig``, wires together the registered parser/DUT/executor, and
delegates the actual validation loop to :class:`ValidationEngine`.

This separation keeps the core framework usable from tests, scripts, and a
future web API without depending on terminal-specific behavior.

Example:
    Run the sample AES-CBC encryption validation::

        python3 -m crypto_validation \
          --algorithm AES \
          --mode CBC \
          --operation encrypt \
          --test-type KAT \
          --vector-file sample_vectors/aes/aes_cbc_128.rsp \
          --dut python \
          --report-format json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from crypto_validation.config import validate_config
from crypto_validation.dut.registry import build_dut
from crypto_validation.exceptions import ConfigError, ParseError, UnsupportedTestError
from crypto_validation.models import ResultStatus, ValidationConfig
from crypto_validation.parsers.registry import build_parser
from crypto_validation.reporting.console import print_console_report
from crypto_validation.reporting.json_reporter import write_json_report
from crypto_validation.reporting.summary import build_summary, has_system_errors
from crypto_validation.validation.comparator import Comparator
from crypto_validation.validation.engine import ValidationEngine
from crypto_validation.validation.executors import build_executor
from crypto_validation.vectors import build_vector_source, load_vector_text


EXIT_OK = 0
"""Process exit code used when all tests pass."""

EXIT_VALIDATION_FAIL = 1
"""Process exit code used when at least one DUT output mismatches."""

EXIT_SYSTEM_ERROR = 2
"""Process exit code used for config, parser, DUT, or framework errors."""


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Returns:
        Configured ``argparse.ArgumentParser`` instance.

    Notes:
        Supported choices are intentionally narrow for the MVP. New algorithms,
        vector formats, and report formats should be added through registries
        first, then exposed here.
    """

    parser = argparse.ArgumentParser(
        prog="crypto-validate",
        description="Validate cryptographic DUTs using NIST-style test vectors.",
    )
    parser.add_argument("--algorithm", required=True, help="Algorithm name, e.g. AES")
    parser.add_argument("--mode", required=True, help="Algorithm mode, e.g. CBC")
    parser.add_argument(
        "--operation",
        default="encrypt",
        choices=["encrypt", "decrypt"],
        help="Operation under test",
    )
    parser.add_argument("--test-type", default="KAT", help="Test category, e.g. KAT")
    parser.add_argument("--vector-file", required=True, help="Path to vector file")
    parser.add_argument(
        "--vector-format",
        default=None,
        help="Vector format. Defaults to the vector file extension.",
    )
    parser.add_argument("--dut", default="python", help="DUT backend")
    parser.add_argument(
        "--report-format",
        default="json",
        choices=["console", "json"],
        help="Report output format",
    )
    parser.add_argument("--report-dir", default="reports", help="Report output directory")
    parser.add_argument("--fail-fast", action="store_true", help="Stop after first non-pass result")
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Reserved flag for future detailed input logging",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one validation job from command-line arguments.

    Args:
        argv: Optional argument list. When ``None``, arguments are read from
            ``sys.argv``. Tests pass an explicit list to avoid spawning a
            subprocess.

    Returns:
        One of the module-level exit codes:

        - ``0`` when all tests pass.
        - ``1`` when one or more tests produce validation mismatches.
        - ``2`` when the framework cannot complete the run reliably.
    """

    args = build_arg_parser().parse_args(argv)
    vector_format = args.vector_format or Path(args.vector_file).suffix.lstrip(".")

    config = ValidationConfig(
        algorithm=args.algorithm,
        mode=args.mode,
        operation=args.operation,
        test_type=args.test_type,
        vector_file=args.vector_file,
        vector_format=vector_format,
        dut=args.dut,
        report_format=args.report_format,
        report_dir=args.report_dir,
        fail_fast=args.fail_fast,
        include_sensitive=args.include_sensitive,
    )

    try:
        # Validation happens before parsing so unsupported combinations fail
        # early with CONFIG_ERROR rather than producing confusing parser/DUT
        # failures later in the pipeline.
        config = validate_config(config)
        vector_path = Path(config.vector_file)
        source = build_vector_source(vector_path, config.vector_format)
        content = load_vector_text(vector_path)

        # Parser, DUT, and executor are selected through registries so the CLI
        # does not accumulate algorithm-specific conditionals as the framework
        # grows beyond AES.
        parser = build_parser(config)
        test_cases = list(parser.parse(content, config, source))
        if not test_cases:
            raise ParseError("No matching test cases were parsed from the vector file")

        dut = build_dut(config)
        executor = build_executor(config)
        engine = ValidationEngine(config, executor, dut, Comparator())
        results = engine.run(test_cases)

        json_report_path = None
        if config.report_format == "json":
            json_report_path = str(write_json_report(config, source, results))

        print_console_report(config, source, results, json_report_path)

        summary = build_summary(results)
        # Exit code 2 takes priority over validation failures because CI should
        # distinguish "the DUT is wrong" from "the validation run was invalid".
        if has_system_errors(summary):
            return EXIT_SYSTEM_ERROR
        if summary["validation_failed"] > 0:
            return EXIT_VALIDATION_FAIL
        return EXIT_OK

    except ConfigError as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except ParseError as exc:
        print(f"PARSE_ERROR: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR
    except UnsupportedTestError as exc:
        print(f"UNSUPPORTED_TEST: {exc}", file=sys.stderr)
        return EXIT_SYSTEM_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
