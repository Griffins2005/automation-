"""Parser for NIST CAVP-style `.rsp` vector files.

The parser converts line-oriented CAVP records into ``TestCase`` objects and
separates DUT inputs from golden expected outputs. For AES KAT records it also
enforces mode-level requirements before DUT execution, including key size,
IV/counter size, ECB IV absence, byte/bit alignment, and block alignment where
the mode requires full blocks.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from crypto_validation.exceptions import ParseError
from crypto_validation.models import TestCase, ValidationConfig, VectorSource
from crypto_validation.parsers.aes_common import build_aes_test_case, canonicalize_aes_record
from crypto_validation.parsers.base import VectorParser


SECTION_RE = re.compile(r"^\[(?P<body>.+)]$")
"""Regex used to detect bracketed `.rsp` section headers."""

HEX_FIELDS = {
    "key",
    "iv",
    "plaintext",
    "ciphertext",
    "msg",
    "md",
    "mac",
}
"""Fields that should be treated as hexadecimal values when parsing."""

class RspParser(VectorParser):
    """Parse NIST-style `.rsp` text into ``TestCase`` objects.

    The parser is currently scoped to AES KAT records. Future algorithms should
    add their own record builder while keeping the same ``TestCase`` contract.
    """

    def parse(
        self,
        content: str,
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        """Parse raw `.rsp` text.

        Args:
            content: Full text content of a vector file.
            config: Normalized validation configuration.
            source: Vector file provenance and checksum metadata.

        Yields:
            Parsed ``TestCase`` objects matching the requested operation.

        Raises:
            ParseError: If syntax, required fields, or AES mode requirements are
                invalid.

        Notes:
            The implementation yields cases as it parses so it can evolve into a
            true streaming parser later. The current CLI materializes the cases
            into a list only because the MVP reports total counts after parsing.
        """

        group_metadata: dict[str, str] = {}
        section_operation: str | None = None
        record: dict[str, str] = {}

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                # Blank lines commonly separate records in CAVP files. When a
                # record is active, a blank line commits it.
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
                    # Operation sections select whether PLAINTEXT or CIPHERTEXT
                    # is the DUT input for AES records.
                    section_operation = body.lower()
                elif "=" in body:
                    # Some files use bracketed group metadata such as
                    # [KEYSIZE = 128]. Preserve it for report traceability.
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
                # Some `.rsp` files omit blank separators. A new COUNT starts a
                # new test record, so commit the previous one first.
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
        """Build a framework test case from one raw `.rsp` record.

        Args:
            record: Raw lower-cased field/value map for a single vector record.
            config: Normalized validation configuration.
            source: Vector file provenance metadata.
            group_metadata: Current section/group metadata.
            section_operation: Operation implied by `[ENCRYPT]` or `[DECRYPT]`.

        Yields:
            One test case if the record matches the requested operation.
            Nothing when the record is for the opposite operation.
        """

        operation = section_operation or config.operation

        if operation != config.operation:
            return

        if config.algorithm == "AES":
            yield build_aes_test_case(
                record=canonicalize_aes_record(record),
                config=config,
                source=source,
                operation=operation,
                metadata={**group_metadata},
            )
            return

        raise ParseError(f"Unsupported parser algorithm: {config.algorithm}")

    @staticmethod
    def _normalize_field_value(field: str, value: str, line_number: int) -> str:
        """Normalize and validate a single `.rsp` field value.

        Args:
            field: Lower-cased `.rsp` field name.
            value: Raw string value after the equals sign.
            line_number: Source line number for useful error messages.

        Returns:
            Normalized field value. Hex values are lower-cased and stripped of
            internal spaces.

        Raises:
            ParseError: If a hex field has invalid syntax.

        Notes:
            Empty hex values are preserved. This matters for future SHA/HMAC
            vectors where an empty message is a valid test input.
        """

        if field not in HEX_FIELDS:
            return value

        normalized = value.replace(" ", "").lower()
        if normalized == "":
            return normalized

        if field in {"plaintext", "ciphertext"} and len(normalized) % 2 != 0:
            if all(character in "0123456789abcdef" for character in normalized):
                return normalized
            raise ParseError(f"Invalid hex value at line {line_number}")

        if len(normalized) % 2 != 0:
            raise ParseError(f"Invalid odd-length hex value at line {line_number}")

        try:
            bytes.fromhex(normalized)
        except ValueError as exc:
            raise ParseError(f"Invalid hex value at line {line_number}") from exc

        return normalized
