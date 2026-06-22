"""Parser registry."""

from __future__ import annotations

from crypto_validation.exceptions import UnsupportedTestError
from crypto_validation.models import ValidationConfig
from crypto_validation.parsers.base import VectorParser
from crypto_validation.parsers.rsp import RspParser


def build_parser(config: ValidationConfig) -> VectorParser:
    """Construct the configured vector parser."""

    if config.vector_format == "rsp":
        return RspParser()

    raise UnsupportedTestError(f"Unsupported vector format: {config.vector_format}")
