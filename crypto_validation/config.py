"""Configuration construction and validation.

This module is the first gate in the validation pipeline. It normalizes user
input into canonical forms such as ``AES`` and ``KAT`` and rejects unsupported
combinations before any parsing or DUT execution happens.

The explicit support sets make current MVP boundaries visible to developers.
When adding new features, update these sets together with the corresponding
parser, DUT, executor, and tests.
"""

from __future__ import annotations

from pathlib import Path

from crypto_validation.exceptions import ConfigError
from crypto_validation.models import ValidationConfig


SUPPORTED_ALGORITHMS = {"AES"}
SUPPORTED_AES_MODES = {"ECB", "CBC", "CTR", "CFB1", "CFB8", "CFB128", "OFB"}
SUPPORTED_OPERATIONS = {"encrypt", "decrypt"}
SUPPORTED_TEST_TYPES = {"KAT"}
SUPPORTED_VECTOR_FORMATS = {"rsp"}
SUPPORTED_DUTS = {"python"}
SUPPORTED_REPORT_FORMATS = {"console", "json"}


def normalize_config(config: ValidationConfig) -> ValidationConfig:
    """Return a normalized copy of a validation config.

    Args:
        config: Raw configuration assembled from CLI arguments or future config
            file loading.

    Returns:
        A new ``ValidationConfig`` with canonical casing for fields that are
        compared against registries.
    """

    return ValidationConfig(
        algorithm=config.algorithm.upper(),
        mode=config.mode.upper() if config.mode else None,
        operation=config.operation.lower(),
        test_type=config.test_type.upper(),
        vector_file=config.vector_file,
        vector_format=config.vector_format.lower(),
        dut=config.dut.lower(),
        report_format=config.report_format.lower(),
        report_dir=config.report_dir,
        fail_fast=config.fail_fast,
        include_sensitive=config.include_sensitive,
    )


def validate_config(config: ValidationConfig) -> ValidationConfig:
    """Validate a user configuration and return a normalized version.

    Args:
        config: Raw validation configuration.

    Returns:
        Normalized and validated configuration.

    Raises:
        ConfigError: If the requested algorithm, mode, operation, vector format,
            DUT, report format, or vector file path is unsupported/invalid.
    """

    normalized = normalize_config(config)

    # These checks are deliberately explicit. They double as a compact
    # specification for what the MVP supports today.
    if normalized.algorithm not in SUPPORTED_ALGORITHMS:
        raise ConfigError(f"Unsupported algorithm: {normalized.algorithm}")

    if normalized.algorithm == "AES":
        if normalized.mode not in SUPPORTED_AES_MODES:
            raise ConfigError(f"Unsupported AES mode: {normalized.mode}")

    if normalized.operation not in SUPPORTED_OPERATIONS:
        raise ConfigError(f"Unsupported operation: {normalized.operation}")

    if normalized.test_type not in SUPPORTED_TEST_TYPES:
        raise ConfigError(f"Unsupported test type: {normalized.test_type}")

    if normalized.vector_format not in SUPPORTED_VECTOR_FORMATS:
        raise ConfigError(f"Unsupported vector format: {normalized.vector_format}")

    if normalized.dut not in SUPPORTED_DUTS:
        raise ConfigError(f"Unsupported DUT: {normalized.dut}")

    if normalized.report_format not in SUPPORTED_REPORT_FORMATS:
        raise ConfigError(f"Unsupported report format: {normalized.report_format}")

    vector_path = Path(normalized.vector_file)
    if not vector_path.exists():
        raise ConfigError(f"Vector file does not exist: {vector_path}")

    if not vector_path.is_file():
        raise ConfigError(f"Vector path is not a file: {vector_path}")

    return normalized
