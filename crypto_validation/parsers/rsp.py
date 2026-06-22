"""Parser for NIST CAVP-style .rsp vector files."""

from __future__ import annotations

import re
from collections.abc import Iterable

from crypto_validation.exceptions import ParseError
from crypto_validation.models import TestCase, ValidationConfig, VectorSource
from crypto_validation.parsers.base import VectorParser


SECTION_RE = re.compile(r"^\[(?P<body>.+)]$")
HEX_FIELDS = {
    "key",
    "iv",
    "plaintext",
    "ciphertext",
    "msg",
    "md",
    "mac",
}


class RspParser(VectorParser):
    """Parse simple NIST .rsp records into framework test cases."""

    def parse(
        self,
        content: str,
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        group_metadata: dict[str, str] = {}
        section_operation: str | None = None
        record: dict[str, str] = {}

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                if record:
                    yield from self._build_case(record, config, source, group_metadata, section_operation)
                    record = {}
                continue

            section_match = SECTION_RE.match(line)
            if section_match:
                if record:
                    yield from self._build_case(record, config, source, group_metadata, section_operation)
                    record = {}
                body = section_match.group("body").strip()
                if body.upper() in {"ENCRYPT", "DECRYPT"}:
                    section_operation = body.lower()
                elif "=" in body:
                    key, value = body.split("=", 1)
                    group_metadata[key.strip().lower()] = value.strip()
                else:
                    group_metadata["section"] = body
                continue

            if "=" not in line:
                raise ParseError(f"Invalid .rsp line {line_number}: {raw_line}")

            key, value = line.split("=", 1)
            field = key.strip().lower()
            parsed_value = value.strip()

            if field == "count" and record:
                yield from self._build_case(record, config, source, group_metadata, section_operation)
                record = {}

            record[field] = self._normalize_field_value(field, parsed_value, line_number)

        if record:
            yield from self._build_case(record, config, source, group_metadata, section_operation)

    def _build_case(
        self,
        record: dict[str, str],
        config: ValidationConfig,
        source: VectorSource,
        group_metadata: dict[str, str],
        section_operation: str | None,
    ) -> Iterable[TestCase]:
        operation = section_operation or config.operation

        if operation != config.operation:
            return

        if config.algorithm == "AES":
            yield self._build_aes_case(record, config, source, group_metadata, operation)
            return

        raise ParseError(f"Unsupported parser algorithm: {config.algorithm}")

    def _build_aes_case(
        self,
        record: dict[str, str],
        config: ValidationConfig,
        source: VectorSource,
        group_metadata: dict[str, str],
        operation: str,
    ) -> TestCase:
        test_id = record.get("count")
        if test_id is None:
            raise ParseError("AES .rsp record is missing COUNT")

        input_data: dict[str, str] = {
            "operation": operation,
            "key": self._require(record, "key", test_id),
        }

        if config.mode != "ECB":
            input_data["iv"] = self._require(record, "iv", test_id)

        if operation == "encrypt":
            input_data["plaintext"] = self._require(record, "plaintext", test_id)
            expected_output = {
                "ciphertext": self._require(record, "ciphertext", test_id),
            }
        elif operation == "decrypt":
            input_data["ciphertext"] = self._require(record, "ciphertext", test_id)
            expected_output = {
                "plaintext": self._require(record, "plaintext", test_id),
            }
        else:
            raise ParseError(f"Unsupported AES operation for COUNT {test_id}: {operation}")

        metadata = {
            "source_file": source.path,
            "source_format": source.format,
            "source_checksum_sha256": source.checksum_sha256,
            "section_operation": operation,
            **group_metadata,
        }

        return TestCase(
            test_id=test_id,
            algorithm=config.algorithm,
            mode=config.mode,
            operation=operation,
            test_type=config.test_type,
            input=input_data,
            expected_output=expected_output,
            metadata=metadata,
        )

    @staticmethod
    def _require(record: dict[str, str], field: str, test_id: str) -> str:
        if field not in record:
            raise ParseError(f"Record COUNT {test_id} is missing required field: {field.upper()}")
        return record[field]

    @staticmethod
    def _normalize_field_value(field: str, value: str, line_number: int) -> str:
        if field not in HEX_FIELDS:
            return value

        normalized = value.replace(" ", "").lower()
        if normalized == "":
            return normalized

        if len(normalized) % 2 != 0:
            raise ParseError(f"Invalid odd-length hex value at line {line_number}")

        try:
            bytes.fromhex(normalized)
        except ValueError as exc:
            raise ParseError(f"Invalid hex value at line {line_number}") from exc

        return normalized
