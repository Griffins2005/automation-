"""Base parser interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from crypto_validation.models import TestCase, ValidationConfig, VectorSource


class VectorParser(ABC):
    """Interface for vector parsers."""

    @abstractmethod
    def parse(
        self,
        content: str,
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        """Parse vector content into test cases."""
