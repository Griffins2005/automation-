"""Command-line entry point for the validation framework.

The CLI is intentionally thin: it translates user arguments into a
``ValidationConfig``, wires together the registered parser/DUT/executor, and
delegates the actual validation loop to :class:`ValidationEngine`.

This separation keeps the core framework usable from tests, scripts, and a
future web API without depending on terminal-specific behavior.

When the user runs the tool without arguments, the CLI starts an interactive
wizard. The wizard is optimized for the early framework stage: it asks only for
the information needed by the current MVP and can run either one vector file or
all supported vector files discovered under a folder.

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
import time
from dataclasses import dataclass
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

AUTO_MODE = "AUTO"
SUPPORTED_AES_MODES = ("ECB", "CBC", "CTR")
UNSUPPORTED_AES_MODE_TOKENS = ("CFB1", "CFB8", "CFB128", "CFB", "OFB")


@dataclass(frozen=True)
class CliRunOutcome:
    """CLI-level result for one validation run."""

    exit_code: int
    summary: dict[str, int]
    elapsed_seconds: float
    vector_file: str
    report_path: str | None = None

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

INTERACTIVE_INTRO = """
Interactive validation wizard
-----------------------------
Answer each prompt and the tool will build the validation command for you.

Current MVP support:
  Algorithm: AES
  Modes:     ECB, CBC, CTR
  Test type: KAT
  Format:    .rsp

Note: AES-CFB/CFB1/OFB files are not supported by this MVP yet.
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
        "--interactive",
        action="store_true",
        help="Start the step-by-step validation wizard.",
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
        return run_interactive_wizard()

    args = parser.parse_args(argv)

    if args.interactive:
        return run_interactive_wizard()

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

    return run_configs([config])


def run_configs(configs: list[ValidationConfig]) -> int:
    """Run one or more validation configurations.

    Args:
        configs: Validation runs to execute. Folder-based interactive runs
            produce one config per discovered vector file.

    Returns:
        Aggregated exit code. System errors take priority over validation
        failures, and validation failures take priority over success.
    """

    if not configs:
        print("No runnable vector files were selected.", file=sys.stderr)
        return EXIT_SYSTEM_ERROR

    outcomes: list[CliRunOutcome] = []
    exit_code = EXIT_OK
    batch_start = time.perf_counter()
    for index, config in enumerate(configs, start=1):
        if len(configs) > 1:
            print()
            print(f"=== Validation run {index}/{len(configs)}: {config.vector_file} ===")

        outcome = run_single_config(config)
        outcomes.append(outcome)
        if outcome.exit_code == EXIT_SYSTEM_ERROR:
            exit_code = EXIT_SYSTEM_ERROR
        elif outcome.exit_code == EXIT_VALIDATION_FAIL and exit_code == EXIT_OK:
            exit_code = EXIT_VALIDATION_FAIL

    if len(outcomes) > 1:
        _print_global_summary(outcomes, time.perf_counter() - batch_start)

    return exit_code


def run_single_config(config: ValidationConfig) -> CliRunOutcome:
    """Run one validation configuration and print/report its results."""

    start = time.perf_counter()
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
        elapsed_seconds = time.perf_counter() - start

        json_report_path = None
        if config.report_format == "json":
            json_report_path = str(write_json_report(config, source, results, elapsed_seconds=elapsed_seconds))

        print_console_report(config, source, results, json_report_path, elapsed_seconds=elapsed_seconds)

        summary = build_summary(results)
        # Exit code 2 takes priority over validation failures because CI should
        # distinguish "the DUT is wrong" from "the validation run was invalid".
        if has_system_errors(summary):
            exit_code = EXIT_SYSTEM_ERROR
        elif summary["validation_failed"] > 0:
            exit_code = EXIT_VALIDATION_FAIL
        else:
            exit_code = EXIT_OK

        return CliRunOutcome(
            exit_code=exit_code,
            summary=summary,
            elapsed_seconds=elapsed_seconds,
            vector_file=config.vector_file,
            report_path=json_report_path,
        )

    except ConfigError as exc:
        print(f"CONFIG_ERROR: {exc}", file=sys.stderr)
        return _error_outcome(config, "config_errors", start)
    except ParseError as exc:
        print(f"PARSE_ERROR: {exc}", file=sys.stderr)
        return _error_outcome(config, "parse_errors", start)
    except UnsupportedTestError as exc:
        print(f"UNSUPPORTED_TEST: {exc}", file=sys.stderr)
        return _error_outcome(config, "unsupported_tests", start)


def _error_outcome(config: ValidationConfig, error_key: str, start: float) -> CliRunOutcome:
    """Build a run outcome for a run that failed before producing test results."""

    summary = {
        "total": 0,
        "passed": 0,
        "validation_failed": 0,
        "parse_errors": 0,
        "config_errors": 0,
        "dut_errors": 0,
        "unsupported_tests": 0,
        "internal_errors": 0,
    }
    summary[error_key] = 1
    return CliRunOutcome(
        exit_code=EXIT_SYSTEM_ERROR,
        summary=summary,
        elapsed_seconds=time.perf_counter() - start,
        vector_file=config.vector_file,
    )


def _print_global_summary(outcomes: list[CliRunOutcome], elapsed_seconds: float) -> None:
    """Print aggregate metrics for folder or multi-file validation runs."""

    total_summary = {
        "total": 0,
        "passed": 0,
        "validation_failed": 0,
        "parse_errors": 0,
        "config_errors": 0,
        "dut_errors": 0,
        "unsupported_tests": 0,
        "internal_errors": 0,
    }
    for outcome in outcomes:
        for key in total_summary:
            total_summary[key] += outcome.summary.get(key, 0)

    throughput = total_summary["total"] / elapsed_seconds if elapsed_seconds > 0 else 0.0
    print()
    print("Global Summary")
    print("--------------")
    print(f"Files Run: {len(outcomes)}")
    print(f"Total Tests: {total_summary['total']}")
    print(f"Passed: {total_summary['passed']}")
    print(f"Validation Failures: {total_summary['validation_failed']}")
    print(f"System Errors: {sum(total_summary[key] for key in ('parse_errors', 'config_errors', 'dut_errors', 'unsupported_tests', 'internal_errors'))}")
    print(f"Elapsed Time: {elapsed_seconds:.4f}s")
    print(f"Throughput: {throughput:.2f} tests/s")


def run_interactive_wizard(input_func=None) -> int:
    """Collect validation settings step by step and run selected vectors.

    Args:
        input_func: Optional input function for tests. Defaults to ``input``.

    Returns:
        Aggregated validation exit code.
    """

    if input_func is None:
        input_func = input

    try:
        print(textwrap.dedent(INTERACTIVE_INTRO).strip())
        print()

        algorithm = _prompt_select(
            "Which algorithm are you testing?",
            ["AES"],
            default="AES",
            input_func=input_func,
        )

        test_type = _prompt_select(
            "Which test type are you running?",
            ["KAT"],
            default="KAT",
            input_func=input_func,
        )

        operation = _prompt_select(
            "Which operation should be validated?",
            ["auto-detect from file", "encrypt", "decrypt"],
            default="auto-detect from file",
            input_func=input_func,
        )

        source_kind = _prompt_select(
            "Where are the vector files?",
            ["single file", "folder of .rsp files"],
            default="single file",
            input_func=input_func,
        )

        if source_kind == "single file":
            configs = _interactive_single_file_configs(
                algorithm=algorithm,
                operation=operation,
                test_type=test_type,
                input_func=input_func,
            )
        else:
            configs = _interactive_folder_configs(
                algorithm=algorithm,
                operation=operation,
                test_type=test_type,
                input_func=input_func,
            )

        if not configs:
            return EXIT_SYSTEM_ERROR

        dut = _prompt_select(
            "Which DUT backend should be used?",
            ["python"],
            default="python",
            input_func=input_func,
        )
        report_format = _prompt_select(
            "Which report format should be generated?",
            ["json", "console"],
            default="json",
            input_func=input_func,
        )
        if report_format == "json":
            default_report_dir = "reports"
            report_dir = _prompt_text(
                f"Where should reports be written? [{default_report_dir}]",
                input_func=input_func,
                default=default_report_dir,
            )
        else:
            report_dir = "reports"
        fail_fast = _prompt_yes_no(
            "Stop after the first failing test? [y/N]",
            input_func=input_func,
            default=False,
        )

        final_configs = [
            ValidationConfig(
                algorithm=config.algorithm,
                mode=config.mode,
                operation=config.operation,
                test_type=config.test_type,
                vector_file=config.vector_file,
                vector_format=config.vector_format,
                dut=dut,
                report_format=report_format,
                report_dir=report_dir,
                fail_fast=fail_fast,
                include_sensitive=False,
            )
            for config in configs
        ]

        _print_run_plan(final_configs)
        if not _prompt_yes_no("Run validation now? [Y/n]", input_func=input_func, default=True):
            print("Validation cancelled.")
            return EXIT_SYSTEM_ERROR

    except (EOFError, KeyboardInterrupt):
        print()
        print("Interactive validation cancelled.")
        return EXIT_SYSTEM_ERROR

    return run_configs(final_configs)


def _interactive_single_file_configs(
    algorithm: str,
    operation: str,
    test_type: str,
    input_func,
) -> list[ValidationConfig]:
    """Collect settings for a single vector file."""

    while True:
        vector_file = _prompt_text("Enter the vector file path", input_func=input_func)
        path = Path(vector_file)
        if not path.exists() or not path.is_file():
            print("File not found. Try again.")
            continue
        if path.suffix.lower() != ".rsp":
            print("Use a .rsp file.")
            continue
        unsupported_reason = _unsupported_mode_reason(path)
        if unsupported_reason:
            print(f"That file looks unsupported: {unsupported_reason}")
            print("Choose ECB, CBC, or CTR.")
            continue
        break

    inferred_mode = _infer_aes_mode_from_path(path)
    if inferred_mode:
        use_inferred = _prompt_yes_no(
            f"Detected AES mode {inferred_mode} from filename. Use it? [Y/n]",
            input_func=input_func,
            default=True,
        )
        mode = inferred_mode if use_inferred else _prompt_aes_mode(input_func)
    else:
        mode = _prompt_aes_mode(input_func)

    operations = _resolve_operations_for_file(path, operation)
    if not operations:
        print("No matching operation section found. Try another file.")
        return []

    return [
        _build_config_shell(
            algorithm=algorithm,
            mode=mode,
            operation=resolved_operation,
            test_type=test_type,
            vector_file=str(path),
        )
        for resolved_operation in operations
    ]


def _interactive_folder_configs(
    algorithm: str,
    operation: str,
    test_type: str,
    input_func,
) -> list[ValidationConfig]:
    """Collect settings and discover runnable vector files from a folder."""

    while True:
        folder = Path(_prompt_text("Enter the folder path", input_func=input_func))
        if folder.exists() and folder.is_dir():
            break
        print("Folder not found. Try again.")
    mode_choice = _prompt_select(
        "How should AES mode be selected for files in this folder?",
        ["auto-detect from filename", "force ECB", "force CBC", "force CTR"],
        default="auto-detect from filename",
        input_func=input_func,
    )

    forced_mode = None
    if mode_choice.startswith("force "):
        forced_mode = mode_choice.removeprefix("force ").upper()

    files = sorted(folder.rglob("*.rsp"))
    if not files:
        print(f"No .rsp files found under: {folder}", file=sys.stderr)
        return []

    configs: list[ValidationConfig] = []
    skipped: list[tuple[Path, str]] = []

    for file_path in files:
        unsupported_reason = _unsupported_mode_reason(file_path)
        if unsupported_reason:
            skipped.append((file_path, unsupported_reason))
            continue

        inferred_mode = _infer_aes_mode_from_path(file_path)
        if forced_mode and inferred_mode and inferred_mode != forced_mode:
            skipped.append((file_path, f"filename mode {inferred_mode} does not match forced {forced_mode}"))
            continue
        mode = forced_mode or inferred_mode
        if mode is None:
            skipped.append((file_path, "could not infer ECB/CBC/CTR from filename"))
            continue

        operations = _resolve_operations_for_file(file_path, operation)
        if not operations:
            skipped.append((file_path, f"no {operation} section found"))
            continue

        for resolved_operation in operations:
            configs.append(
                _build_config_shell(
                    algorithm=algorithm,
                    mode=mode,
                    operation=resolved_operation,
                    test_type=test_type,
                    vector_file=str(file_path),
                )
            )

    print(f"Discovered {len(files)} .rsp file(s).")
    print(f"Runnable with current MVP: {len(configs)}")
    if skipped:
        print(f"Skipped unsupported/unknown files: {len(skipped)}")
        for file_path, reason in skipped[:10]:
            print(f"  - {file_path}: {reason}")
        if len(skipped) > 10:
            print(f"  ... {len(skipped) - 10} more skipped files")

    return configs


def _build_config_shell(
    algorithm: str,
    mode: str,
    operation: str,
    test_type: str,
    vector_file: str,
) -> ValidationConfig:
    """Build a partial config; wizard fills DUT/report settings later."""

    return ValidationConfig(
        algorithm=algorithm,
        mode=mode,
        operation=operation,
        test_type=test_type,
        vector_file=vector_file,
        vector_format="rsp",
        dut="python",
        report_format="json",
        report_dir="reports",
    )


def _prompt_aes_mode(input_func) -> str:
    """Prompt for an explicitly supported AES mode."""

    return _prompt_select(
        "Which AES mode does this vector file use?",
        list(SUPPORTED_AES_MODES),
        default="CBC",
        input_func=input_func,
    )


def _prompt_select(prompt: str, options: list[str], default: str, input_func) -> str:
    """Prompt for one option using numbers or names."""

    normalized_default = default.lower()
    while True:
        print(prompt)
        for index, option in enumerate(options, start=1):
            suffix = " (default)" if option.lower() == normalized_default else ""
            print(f"  {index}. {option}{suffix}")

        answer = input_func("> ").strip()
        if not answer:
            return default

        if answer.isdigit():
            index = int(answer)
            if 1 <= index <= len(options):
                return options[index - 1]

        for option in options:
            if answer.lower() == option.lower():
                return option

        print("Invalid choice. Try again.")


def _prompt_text(prompt: str, input_func, default: str | None = None) -> str:
    """Prompt for free text with optional default."""

    while True:
        print(prompt)
        answer = input_func("> ").strip()
        if answer:
            return answer
        if default is not None:
            return default
        print("Required. Try again.")


def _prompt_yes_no(prompt: str, input_func, default: bool) -> bool:
    """Prompt for a yes/no answer."""

    while True:
        print(prompt)
        answer = input_func("> ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Enter y or n.")


def _infer_aes_mode_from_path(path: Path) -> str | None:
    """Infer ECB/CBC/CTR from a vector filename."""

    name = path.name.upper()
    for mode in SUPPORTED_AES_MODES:
        if mode in name:
            return mode
    return None


def _resolve_operations_for_file(path: Path, operation_choice: str) -> list[str]:
    """Resolve wizard operation choice into runnable operations for a file."""

    detected = _detect_operations_in_file(path)
    if operation_choice == "auto-detect from file":
        return detected or ["encrypt"]

    if not detected or operation_choice in detected:
        return [operation_choice]

    return []


def _detect_operations_in_file(path: Path) -> list[str]:
    """Return ENCRYPT/DECRYPT sections present in a vector file."""

    try:
        text = path.read_text(encoding="utf-8", errors="ignore").upper()
    except OSError:
        return []

    operations: list[str] = []
    if "[ENCRYPT]" in text:
        operations.append("encrypt")
    if "[DECRYPT]" in text:
        operations.append("decrypt")
    return operations


def _unsupported_mode_reason(path: Path) -> str | None:
    """Return why a vector filename appears unsupported, if known."""

    name = path.name.upper()
    for token in UNSUPPORTED_AES_MODE_TOKENS:
        if token in name:
            return f"AES-{token} is not supported yet"
    return None


def _print_run_plan(configs: list[ValidationConfig]) -> None:
    """Print a compact summary before executing wizard-selected runs."""

    print()
    print("Run plan")
    print("--------")
    for index, config in enumerate(configs[:10], start=1):
        print(
            f"{index}. {config.algorithm}-{config.mode} {config.operation} "
            f"{config.test_type}: {config.vector_file}"
        )
    if len(configs) > 10:
        print(f"... {len(configs) - 10} more file(s)")


if __name__ == "__main__":
    raise SystemExit(main())
