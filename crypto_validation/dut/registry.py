"""DUT registry.

The registry is the single place where framework configuration is mapped to a
concrete DUT adapter. This avoids scattering ``if algorithm == ...`` decisions
throughout the CLI or validation engine.
"""

from __future__ import annotations

from crypto_validation.dut.aes_python import AesPythonDut
from crypto_validation.dut.base import Dut
from crypto_validation.exceptions import UnsupportedTestError
from crypto_validation.models import ValidationConfig


def build_dut(config: ValidationConfig) -> Dut:
    """Construct the configured DUT.

    Args:
        config: Normalized validation configuration.

    Returns:
        DUT adapter matching the requested algorithm, mode, and backend.

    Raises:
        UnsupportedTestError: If no matching DUT adapter exists.
    """

    if config.algorithm == "AES" and config.dut == "python":
        if config.mode is None:
            raise UnsupportedTestError("AES requires a mode")
        return AesPythonDut(config.mode)

    raise UnsupportedTestError(
        f"Unsupported DUT selection: algorithm={config.algorithm}, mode={config.mode}, dut={config.dut}"
    )
