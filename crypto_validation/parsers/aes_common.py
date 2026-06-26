"""Shared AES parser helpers.

Both `.rsp` and JSON parsers normalize raw vector fields into the same internal
`TestCase` shape. This module keeps AES field aliases and mode validation in
one place so supported formats cannot drift apart.
"""

from __future__ import annotations

from typing import Any

from crypto_validation.exceptions import ParseError
from crypto_validation.models import TestCase, ValidationConfig, VectorSource


AES_BLOCK_BYTES = 16
AES_KEY_BYTE_LENGTHS = {16, 24, 32}
AES_IV_MODES = {"CBC", "CTR", "CFB1", "CFB8", "CFB128", "OFB"}
AES_BLOCK_ALIGNED_MODES = {"ECB", "CBC", "CFB128"}

AES_FIELD_ALIASES = {
    "count": "count",
    "id": "count",
    "tcid": "count",
    "testid": "count",
    "key": "key",
    "iv": "iv",
    "initialcounter": "iv",
    "counter": "iv",
    "plaintext": "plaintext",
    "plainText": "plaintext",
    "pt": "plaintext",
    "ciphertext": "ciphertext",
    "cipherText": "ciphertext",
    "ct": "ciphertext",
}


def canonicalize_aes_record(raw_record: dict[str, Any]) -> dict[str, str]:
    """Normalize known AES field names and values from a parsed record."""

    record: dict[str, str] = {}
    for raw_key, raw_value in raw_record.items():
        alias_key = str(raw_key).replace("_", "").replace("-", "").lower()
        field = AES_FIELD_ALIASES.get(alias_key, str(raw_key).strip().lower())
        if raw_value is None:
            value = ""
        else:
            value = str(raw_value).strip()
        record[field] = value.replace(" ", "").lower() if field in {"key", "iv", "plaintext", "ciphertext"} else value
    return record


def build_aes_test_case(
    record: dict[str, str],
    config: ValidationConfig,
    source: VectorSource,
    operation: str,
    metadata: dict[str, Any] | None = None,
) -> TestCase:
    """Build an AES `TestCase` from canonicalized vector fields."""

    test_id = record.get("count")
    if test_id is None:
        raise ParseError("AES record is missing COUNT/tcId/id")

    input_data: dict[str, str] = {
        "operation": operation,
        "key": require_field(record, "key", test_id),
    }

    if config.mode in AES_IV_MODES:
        input_data["iv"] = require_field(record, "iv", test_id)

    if operation == "encrypt":
        input_data["plaintext"] = require_field(record, "plaintext", test_id)
        expected_output = {
            "ciphertext": require_field(record, "ciphertext", test_id),
        }
    elif operation == "decrypt":
        input_data["ciphertext"] = require_field(record, "ciphertext", test_id)
        expected_output = {
            "plaintext": require_field(record, "plaintext", test_id),
        }
    else:
        raise ParseError(f"Unsupported AES operation for COUNT {test_id}: {operation}")

    validate_aes_fields(config, test_id, input_data, expected_output, record)

    return TestCase(
        test_id=test_id,
        algorithm=config.algorithm,
        mode=config.mode,
        operation=operation,
        test_type=config.test_type,
        input=input_data,
        expected_output=expected_output,
        metadata={
            "source_file": source.path,
            "source_format": source.format,
            "source_checksum_sha256": source.checksum_sha256,
            "section_operation": operation,
            **(metadata or {}),
        },
    )


def require_field(record: dict[str, str], field: str, test_id: str) -> str:
    """Return a required AES field or raise a parser-level error."""

    if field not in record:
        raise ParseError(f"Record COUNT {test_id} is missing required field: {field.upper()}")
    return record[field]


def validate_aes_fields(
    config: ValidationConfig,
    test_id: str,
    input_data: dict[str, str],
    expected_output: dict[str, str],
    record: dict[str, str],
) -> None:
    """Validate AES field requirements before DUT execution."""

    key = _bytes_from_hex(input_data["key"], f"COUNT {test_id}: invalid AES key")
    if len(key) not in AES_KEY_BYTE_LENGTHS:
        raise ParseError(f"COUNT {test_id}: AES key must be 128, 192, or 256 bits")

    if config.mode == "ECB" and "iv" in record:
        raise ParseError(f"COUNT {test_id}: AES-ECB vectors must not include IV")

    if config.mode in AES_IV_MODES:
        iv = _bytes_from_hex(input_data["iv"], f"COUNT {test_id}: invalid AES-{config.mode} IV/counter")
        if len(iv) != AES_BLOCK_BYTES:
            raise ParseError(f"COUNT {test_id}: AES-{config.mode} IV/counter must be 128 bits")

    payload_values = [
        value
        for field_map in (input_data, expected_output)
        for field, value in field_map.items()
        if field in {"plaintext", "ciphertext"}
    ]

    if config.mode == "CFB1":
        for value in payload_values:
            if not value or any(bit not in {"0", "1"} for bit in value):
                raise ParseError(f"COUNT {test_id}: AES-CFB1 data must be a bit string")
        return

    for value in payload_values:
        if len(value) % 2 != 0:
            raise ParseError(f"COUNT {test_id}: AES-{config.mode} data must be byte-aligned")
        _bytes_from_hex(value, f"COUNT {test_id}: invalid AES-{config.mode} data")

    if config.mode in AES_BLOCK_ALIGNED_MODES:
        for value in payload_values:
            if len(bytes.fromhex(value)) % AES_BLOCK_BYTES != 0:
                raise ParseError(f"COUNT {test_id}: AES-{config.mode} data must be block-aligned")


def _bytes_from_hex(value: str, message: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ParseError(message) from exc
