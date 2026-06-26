"""Parser for JSON AES vector files.

Supported shapes:

- Framework-native JSON with a top-level `tests` list.
- ACVP-like JSON with `testGroups` containing `tests`.

Both shapes are normalized into the same AES `TestCase` contract used by the
`.rsp` parser.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from crypto_validation.exceptions import ParseError
from crypto_validation.models import TestCase, ValidationConfig, VectorSource
from crypto_validation.parsers.aes_common import build_aes_test_case, canonicalize_aes_record
from crypto_validation.parsers.base import VectorParser


class JsonParser(VectorParser):
    """Parse framework-native or ACVP-like JSON vector files."""

    def parse(
        self,
        content: str,
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON vector file: {exc.msg}") from exc

        if not isinstance(payload, dict):
            raise ParseError("JSON vector file must contain an object at the top level")

        self._validate_declared_mode(payload, config)

        if "testGroups" in payload:
            yield from self._parse_acvp_like(payload, config, source)
            return

        if "tests" in payload:
            yield from self._parse_native_tests(payload, config, source)
            return

        raise ParseError("JSON vector file must contain 'tests' or 'testGroups'")

    def _parse_native_tests(
        self,
        payload: dict[str, Any],
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        tests = payload.get("tests")
        if not isinstance(tests, list):
            raise ParseError("JSON 'tests' must be a list")

        for index, item in enumerate(tests):
            if not isinstance(item, dict):
                raise ParseError(f"JSON test at index {index} must be an object")

            operation = str(item.get("operation") or payload.get("operation") or config.operation).lower()
            if operation != config.operation:
                continue

            record = self._merge_native_record(item, index)
            yield build_aes_test_case(
                record=canonicalize_aes_record(record),
                config=config,
                source=source,
                operation=operation,
                metadata={"json_index": index},
            )

    def _parse_acvp_like(
        self,
        payload: dict[str, Any],
        config: ValidationConfig,
        source: VectorSource,
    ) -> Iterable[TestCase]:
        groups = payload.get("testGroups")
        if not isinstance(groups, list):
            raise ParseError("JSON 'testGroups' must be a list")

        for group_index, group in enumerate(groups):
            if not isinstance(group, dict):
                raise ParseError(f"JSON test group at index {group_index} must be an object")

            group_operation = str(group.get("direction") or group.get("operation") or config.operation).lower()
            tests = group.get("tests")
            if not isinstance(tests, list):
                raise ParseError(f"JSON test group {group_index} is missing a tests list")

            for test_index, test in enumerate(tests):
                if not isinstance(test, dict):
                    raise ParseError(f"JSON test {test_index} in group {group_index} must be an object")

                operation = str(test.get("direction") or test.get("operation") or group_operation).lower()
                if operation != config.operation:
                    continue

                record = {
                    **{key: value for key, value in group.items() if key != "tests"},
                    **test,
                }
                yield build_aes_test_case(
                    record=canonicalize_aes_record(record),
                    config=config,
                    source=source,
                    operation=operation,
                    metadata={
                        "group_index": group_index,
                        "test_index": test_index,
                        "tg_id": group.get("tgId"),
                    },
                )

    @staticmethod
    def _merge_native_record(item: dict[str, Any], index: int) -> dict[str, Any]:
        record = {
            "id": item.get("id", item.get("tcId", item.get("count", index))),
            **item,
        }
        input_data = item.get("input")
        expected = item.get("expected_output", item.get("expectedOutput"))
        if isinstance(input_data, dict):
            record.update(input_data)
        if isinstance(expected, dict):
            record.update(expected)
        return record

    @staticmethod
    def _validate_declared_mode(payload: dict[str, Any], config: ValidationConfig) -> None:
        declared_mode = _extract_declared_aes_mode(payload)
        if declared_mode and declared_mode != config.mode:
            raise ParseError(f"JSON declares AES-{declared_mode}, but config selected AES-{config.mode}")


def _extract_declared_aes_mode(payload: dict[str, Any]) -> str | None:
    for key in ("mode", "algorithm", "alg"):
        value = payload.get(key)
        if value is None:
            continue
        text = str(value).upper()
        for mode in ("CFB128", "CFB8", "CFB1", "ECB", "CBC", "CTR", "OFB"):
            if mode in text:
                return mode
    return None
