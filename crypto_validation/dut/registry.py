"""DUT registry."""

from __future__ import annotations

from crypto_validation.dut.aes_python import AesPythonDut
from crypto_validation.dut.base import Dut
from crypto_validation.exceptions import UnsupportedTestError
from crypto_validation.models import ValidationConfig


def build_dut(config: ValidationConfig) -> Dut:
    """Construct the configured DUT."""

    if config.algorithm == "AES" and config.dut == "python":
        if config.mode is None:
            raise UnsupportedTestError("AES requires a mode")
        return AesPythonDut(config.mode)

    raise UnsupportedTestError(
        f"Unsupported DUT selection: algorithm={config.algorithm}, mode={config.mode}, dut={config.dut}"
    )
