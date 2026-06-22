"""Base DUT interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Dut(ABC):
    """Device-under-test interface."""

    @abstractmethod
    def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run the DUT with structured input and return structured output."""
