"""Python AES DUT adapters backed by PyCryptodome."""

from __future__ import annotations

from Crypto.Cipher import AES

from crypto_validation.dut.base import Dut
from crypto_validation.exceptions import DutError


class AesPythonDut(Dut):
    """AES DUT supporting ECB, CBC, and CTR modes."""

    def __init__(self, mode: str):
        self.mode = mode.upper()

    def run(self, input_data: dict) -> dict:
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
        if self.mode == "ECB":
            return AES.new(key, AES.MODE_ECB)

        if self.mode == "CBC":
            iv = bytes.fromhex(input_data["iv"])
            return AES.new(key, AES.MODE_CBC, iv)

        if self.mode == "CTR":
            iv = bytes.fromhex(input_data["iv"])
            initial_value = int.from_bytes(iv, byteorder="big")
            return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=initial_value)

        raise DutError(f"Unsupported AES mode: {self.mode}")
