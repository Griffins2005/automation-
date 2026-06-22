"""Base parser interfaces.

Every vector format adapter should implement this interface. The framework
expects parsers to produce ``TestCase`` objects and to keep algorithm execution
out of parsing logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from crypto_validation.models import TestCase, ValidationConfig, VectorSource


class VectorParser(ABC):
    """Interface for vector parsers.

    Implementations should:

    - read raw vector content,
    - preserve useful metadata,
    - separate DUT inputs from golden expected outputs,
    - raise ``ParseError`` for invalid vector syntax.
    """

    @abstractmethod
    def parse(
        self,
        content: str,
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        """Parse vector content into test cases.

        Args:
            content: Raw vector file content.
            config: Normalized validation configuration.
            source: Vector file provenance metadata.

        Yields:
            Structured ``TestCase`` objects.
        """
