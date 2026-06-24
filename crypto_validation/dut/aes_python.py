"""Python AES DUT adapters backed by PyCryptodome.

This module provides the reference software DUT used by the MVP. It follows the
same dictionary-in/dictionary-out contract that future RTL, C-model, or hardware
adapters should implement.

Important crypto assumptions:

- Inputs and outputs are hex strings.
- CBC/ECB payloads must already be block-aligned.
- No automatic padding is applied. NIST algorithm vectors generally operate on
  exact algorithm-level inputs, not application-level padded messages.
- CTR mode treats the provided ``iv`` field as a full 128-bit big-endian initial
  counter value with an empty nonce. If production vectors use a nonce/counter
  split, this adapter should be extended with explicit metadata instead of
  guessing.
"""

from __future__ import annotations

from Crypto.Cipher import AES

from crypto_validation.dut.base import Dut
from crypto_validation.exceptions import DutError


class AesPythonDut(Dut):
    """AES DUT supporting ECB, CBC, and CTR modes.

    Args:
        mode: AES mode name. Supported values are ``ECB``, ``CBC``, and
            ``CTR``.
    """

    def __init__(self, mode: str):
        self.mode = mode.upper()

    def run(self, input_data: dict) -> dict:
        """Execute AES using structured framework input.

        Args:
            input_data: Dictionary produced by a parser. Required fields depend
                on operation and mode:

                - ``operation``: ``encrypt`` or ``decrypt``
                - ``key``: AES key as a hex string
                - ``iv``: required for CBC and CTR
                - ``plaintext``: required for encryption
                - ``ciphertext``: required for decryption

        Returns:
            ``{"ciphertext": hex}`` for encryption or ``{"plaintext": hex}``
            for decryption.

        Raises:
            DutError: If inputs are missing, malformed, unsupported, or rejected
                by PyCryptodome.
        """

        try:
            key = bytes.fromhex(input_data["key"])
            operation = input_data["operation"]

            if operation == "encrypt":
                input_field = "plaintext"
                output_field = "ciphertext"
                payload = bytes.fromhex(input_data[input_field])
            elif operation == "decrypt":
                input_field = "ciphertext"
                output_field = "plaintext"
                payload = bytes.fromhex(input_data[input_field])
            else:
                raise DutError(f"Unsupported AES operation: {operation}")

            cipher = self._build_cipher(key, input_data)
            if operation == "encrypt":
                output = cipher.encrypt(payload)
            else:
                output = cipher.decrypt(payload)

            return {output_field: output.hex()}

        except DutError:
            raise
        except KeyError as exc:
            raise DutError(f"Missing DUT input field: {exc.args[0]}") from exc
        except ValueError as exc:
            raise DutError(f"Invalid AES DUT input: {exc}") from exc

    def _build_cipher(self, key: bytes, input_data: dict):
        """Create a PyCryptodome AES cipher for the configured mode.

        Args:
            key: Raw AES key bytes.
            input_data: Structured test input containing IV/counter when needed.

        Returns:
            PyCryptodome cipher object.

        Raises:
            DutError: If the configured mode is unsupported.
            KeyError: If a required IV field is missing. The public ``run``
                method converts this into ``DutError``.
        """

        if self.mode == "ECB":
            return AES.new(key, AES.MODE_ECB)

        if self.mode == "CBC":
            iv = bytes.fromhex(input_data["iv"])
            return AES.new(key, AES.MODE_CBC, iv)

        if self.mode == "CTR":
            iv = bytes.fromhex(input_data["iv"])
            # MVP convention: treat IV as the full AES block-sized initial
            # counter. This is deterministic and easy to validate, but ACVP CTR
            # vectors may need richer nonce/counter metadata later.
            initial_value = int.from_bytes(iv, byteorder="big")
            return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=initial_value)

        raise DutError(f"Unsupported AES mode: {self.mode}")
