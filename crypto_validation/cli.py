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
import textwrap
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

CLI_GUIDANCE = """
Current MVP support
-------------------
Algorithm:      AES
Modes:          ECB, CBC, CTR
Operations:     encrypt, decrypt
Test type:      KAT
Vector format:  NIST-style .rsp
DUT backend:    python
Reports:        console, json

What the user provides in the terminal
--------------------------------------
The terminal arguments describe HOW to run validation:

  --algorithm     Which algorithm family to validate.
  --mode          Which AES mode the vectors are for.
  --operation     Whether to run encrypt or decrypt vectors.
  --test-type     Which validation method to use. Currently KAT.
  --vector-file   Path to the vector file containing KEY/IV/PLAINTEXT/etc.
  --dut           Which DUT backend to run. Currently python.

The user does NOT type the vector contents into the terminal. The vector
contents live inside the .rsp file passed with --vector-file.

Quick discovery commands
------------------------
Show supported algorithms, modes, formats, and examples:

  python -m crypto_validation --list-supported

Show the expected .rsp vector file structure:

  python -m crypto_validation --show-format

Currently supported .rsp record shape
-------------------------------------
AES-CBC/CTR encrypt:

  [ENCRYPT]
  COUNT = 0
  KEY = <hex>
  IV = <hex>
  PLAINTEXT = <hex>
  CIPHERTEXT = <hex>

AES-CBC/CTR decrypt:

  [DECRYPT]
  COUNT = 0
  KEY = <hex>
  IV = <hex>
  CIPHERTEXT = <hex>
  PLAINTEXT = <hex>

AES-ECB is the same but without IV.

Complete examples
-----------------
Linux/macOS:

  python3 -m crypto_validation --algorithm AES --mode CBC --operation encrypt \\
    --test-type KAT --vector-file sample_vectors/aes/aes_cbc_128.rsp \\
    --dut python --report-format json --report-dir reports

Windows PowerShell:

  python -m crypto_validation --algorithm AES --mode CBC --operation encrypt `
    --test-type KAT --vector-file sample_vectors/aes/aes_cbc_128.rsp `
    --dut python --report-format json --report-dir reports

For decrypt, change:

  --operation decrypt
"""


SUPPORTED_DETAILS = """
Supported MVP configuration
---------------------------
--algorithm:
  AES

--mode:
  ECB  - AES Electronic Codebook. Vector records must NOT include IV.
  CBC  - AES Cipher Block Chaining. Vector records must include IV.
  CTR  - AES Counter mode. Vector records must include IV.

--operation:
  encrypt - uses PLAINTEXT as DUT input and CIPHERTEXT as expected output.
  decrypt - uses CIPHERTEXT as DUT input and PLAINTEXT as expected output.

--test-type:
  KAT - Known Answer Test.

--vector-format:
  rsp - NIST CAVP-style response file.

--dut:
  python - PyCryptodome-backed reference DUT.

--report-format:
  console - terminal summary only.
  json    - terminal summary plus JSON file in --report-dir.

Important
---------
The terminal arguments describe the run configuration. The vector file contains
the test values such as KEY, IV, PLAINTEXT, and CIPHERTEXT.
"""


VECTOR_FORMAT_DETAILS = """
Supported .rsp vector format
----------------------------
Records are key/value pairs. A blank line or a new COUNT starts a new test case.
Hex values may be uppercase or lowercase. Spaces inside hex values are removed.

AES-CBC or AES-CTR encrypt:

  [ENCRYPT]
  COUNT = 0
  KEY = 2b7e151628aed2a6abf7158809cf4f3c
  IV = 000102030405060708090a0b0c0d0e0f
  PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
  CIPHERTEXT = 7649abac8119b246cee98e9b12e9197d

AES-CBC or AES-CTR decrypt:

  [DECRYPT]
  COUNT = 0
  KEY = 2b7e151628aed2a6abf7158809cf4f3c
  IV = 000102030405060708090a0b0c0d0e0f
  CIPHERTEXT = 7649abac8119b246cee98e9b12e9197d
  PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a

AES-ECB encrypt/decrypt:

  Same fields, but omit IV.

Currently not supported
-----------------------
The MVP does not yet support AES-CFB, AES-OFB, bit-level vectors such as CFB1,
Monte Carlo Tests, SHA/HMAC/RSA/ECC/DRBG, or ACVP JSON.

If your vector file is named like CFB1VarKey256.rsp, it is an AES-CFB1 vector.
That mode is not supported by the current MVP yet.
"""


class CryptoValidateArgumentParser(argparse.ArgumentParser):
    """Argument parser that prints project-specific guidance on errors."""

    def error(self, message: str) -> None:
        """Print the normal error plus MVP usage guidance, then exit.

        Args:
            message: Error message generated by ``argparse``.
        """

        self.print_usage(sys.stderr)
        self.exit(
            EXIT_SYSTEM_ERROR,
            f"{self.prog}: error: {message}\n\n"
            "Run with --help to see supported values, examples, and the expected .rsp format.\n"
            "Run --list-supported for the supported configuration matrix.\n"
            "Run --show-format for the expected .rsp file structure.\n",
        )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Returns:
        Configured ``argparse.ArgumentParser`` instance.

    Notes:
        Supported choices are intentionally narrow for the MVP. New algorithms,
        vector formats, and report formats should be added through registries
        first, then exposed here.
    """

    parser = CryptoValidateArgumentParser(
        prog="crypto-validate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Validate cryptographic DUTs using NIST-style test vectors.\n\n"
            "This tool is configuration-driven: pass the run configuration in the "
            "terminal and pass vector contents through --vector-file."
        ),
        epilog=textwrap.dedent(CLI_GUIDANCE).strip(),
    )
    parser.add_argument(
        "--list-supported",
        action="store_true",
        help="Print the currently supported algorithms, modes, formats, DUTs, and reports.",
    )
    parser.add_argument(
        "--show-format",
        action="store_true",
        help="Print the currently supported .rsp vector file structure.",
    )
    parser.add_argument(
        "--algorithm",
        type=str.upper,
        choices=["AES"],
        help="Algorithm name. Currently supported: AES.",
    )
    parser.add_argument(
        "--mode",
        type=str.upper,
        choices=["ECB", "CBC", "CTR"],
        help="AES mode. Currently supported: ECB, CBC, CTR.",
    )
    parser.add_argument(
        "--operation",
        default="encrypt",
        type=str.lower,
        choices=["encrypt", "decrypt"],
        help="Operation under test. Use encrypt for [ENCRYPT] vectors and decrypt for [DECRYPT] vectors.",
    )
    parser.add_argument(
        "--test-type",
        default="KAT",
        type=str.upper,
        choices=["KAT"],
        help="Test category. Currently supported: KAT.",
    )
    parser.add_argument(
        "--vector-file",
        help="Path to the .rsp file containing vector records such as KEY, IV, PLAINTEXT, CIPHERTEXT.",
    )
    parser.add_argument(
        "--vector-format",
        default=None,
        type=str.lower,
        choices=["rsp"],
        help="Vector format. Defaults to the vector file extension. Currently supported: rsp.",
    )
    parser.add_argument(
        "--dut",
        default="python",
        type=str.lower,
        choices=["python"],
        help="DUT backend. Currently supported: python.",
    )
    parser.add_argument(
        "--report-format",
        default="json",
        type=str.lower,
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

    if argv is None:
        argv = sys.argv[1:]

    parser = build_arg_parser()
    if not argv:
        parser.print_help(sys.stderr)
        print(
            "\nNo arguments were provided. Use the examples above and pass vector contents with --vector-file.",
            file=sys.stderr,
        )
        return EXIT_SYSTEM_ERROR

    args = parser.parse_args(argv)

    if args.list_supported:
        print(textwrap.dedent(SUPPORTED_DETAILS).strip())
        return EXIT_OK

    if args.show_format:
        print(textwrap.dedent(VECTOR_FORMAT_DETAILS).strip())
        return EXIT_OK

    missing = [
        flag
        for flag, value in (
            ("--algorithm", args.algorithm),
            ("--mode", args.mode),
            ("--vector-file", args.vector_file),
        )
        if value is None
    ]
    if missing:
        parser.print_usage(sys.stderr)
        print(
            f"{parser.prog}: error: missing required run configuration: {', '.join(missing)}\n",
            file=sys.stderr,
        )
        print(
            "The terminal must provide the run configuration, while the .rsp file provides KEY/IV/PLAINTEXT/CIPHERTEXT.",
            file=sys.stderr,
        )
        print("Run --help for complete examples or --show-format for the vector file structure.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

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
