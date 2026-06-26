"""Parser registry.

This module maps normalized configuration to a concrete vector parser. Add new
formats here only after implementing parser tests for that format.
"""

from __future__ import annotations

from crypto_validation.exceptions import UnsupportedTestError
from crypto_validation.models import ValidationConfig
from crypto_validation.parsers.base import VectorParser
from crypto_validation.parsers.json import JsonParser
from crypto_validation.parsers.rsp import RspParser


def build_parser(config: ValidationConfig) -> VectorParser:
    """Construct the configured vector parser.

    Args:
        config: Normalized validation configuration.

    Returns:
        Parser implementation for the selected vector format.

    Raises:
        UnsupportedTestError: If the vector format is not implemented.
    """

    if config.vector_format == "rsp":
        return RspParser()

    if config.vector_format == "json":
        return JsonParser()

    raise UnsupportedTestError(f"Unsupported vector format: {config.vector_format}")
