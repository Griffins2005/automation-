"""Base DUT interface.

A DUT adapter is the boundary between the framework and the implementation
being validated. Adapters may call Python libraries, launch C executables, run
RTL simulations, or communicate with hardware, but they must expose the same
structured ``run`` method.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Dut(ABC):
    """Device-under-test interface.

    Implementations should translate framework input dictionaries into the
    backend-specific format, execute the backend, then return framework output
    dictionaries. They should raise ``DutError`` for expected execution failures.
    """

    @abstractmethod
    def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Run the DUT with structured input and return structured output.

        Args:
            input_data: Parser-produced DUT input fields.

        Returns:
            DUT output fields using names expected by the comparator.
        """
