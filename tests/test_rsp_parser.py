from pathlib import Path

from crypto_validation.config import validate_config
from crypto_validation.exceptions import ParseError
from crypto_validation.models import ValidationConfig
from crypto_validation.parsers.rsp import RspParser
from crypto_validation.vectors import build_vector_source, load_vector_text


def _config(operation: str = "encrypt", mode: str = "CBC") -> ValidationConfig:
    return validate_config(
        ValidationConfig(
            algorithm="AES",
            mode=mode,
            operation=operation,
            test_type="KAT",
            vector_file="sample_vectors/aes/aes_cbc_128.rsp",
            vector_format="rsp",
            dut="python",
            report_format="json",
            report_dir="reports",
        )
    )


def test_rsp_parser_separates_encrypt_inputs_and_expected_outputs():
    config = _config("encrypt")
    path = Path(config.vector_file)
    source = build_vector_source(path, config.vector_format)
    content = load_vector_text(path)

    cases = list(RspParser().parse(content, config, source))

    assert len(cases) == 2
    assert cases[0].input["plaintext"] == "6bc1bee22e409f96e93d7e117393172a"
    assert cases[0].expected_output == {
        "ciphertext": "7649abac8119b246cee98e9b12e9197d"
    }
    assert "source_checksum_sha256" in cases[0].metadata


def test_rsp_parser_separates_decrypt_inputs_and_expected_outputs():
    config = _config("decrypt")
    path = Path(config.vector_file)
    source = build_vector_source(path, config.vector_format)
    content = load_vector_text(path)

    cases = list(RspParser().parse(content, config, source))

    assert len(cases) == 2
    assert cases[0].input["ciphertext"] == "7649abac8119b246cee98e9b12e9197d"
    assert cases[0].expected_output == {
        "plaintext": "6bc1bee22e409f96e93d7e117393172a"
    }


def test_rsp_parser_preserves_empty_hex_values():
    assert RspParser._normalize_field_value("msg", "", 1) == ""


def test_rsp_parser_rejects_ecb_vectors_with_iv():
    config = validate_config(
        ValidationConfig(
            algorithm="AES",
            mode="ECB",
            operation="encrypt",
            test_type="KAT",
            vector_file="sample_vectors/aes/aes_cbc_128.rsp",
            vector_format="rsp",
            dut="python",
            report_format="json",
            report_dir="reports",
        )
    )
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 2b7e151628aed2a6abf7158809cf4f3c
IV = 000102030405060708090a0b0c0d0e0f
PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
CIPHERTEXT = 7649abac8119b246cee98e9b12e9197d
"""

    try:
        list(RspParser().parse(content, config, source))
    except ParseError as exc:
        assert "must not include IV" in str(exc)
    else:
        raise AssertionError("Expected ParseError")


def test_rsp_parser_rejects_invalid_aes_key_size():
    config = _config("encrypt")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 00
IV = 000102030405060708090a0b0c0d0e0f
PLAINTEXT = 6bc1bee22e409f96e93d7e117393172a
CIPHERTEXT = 7649abac8119b246cee98e9b12e9197d
"""

    try:
        list(RspParser().parse(content, config, source))
    except ParseError as exc:
        assert "AES key must be" in str(exc)
    else:
        raise AssertionError("Expected ParseError")


def test_rsp_parser_rejects_unaligned_cbc_payload():
    config = _config("encrypt")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 2b7e151628aed2a6abf7158809cf4f3c
IV = 000102030405060708090a0b0c0d0e0f
PLAINTEXT = 00
CIPHERTEXT = 00
"""

    try:
        list(RspParser().parse(content, config, source))
    except ParseError as exc:
        assert "block-aligned" in str(exc)
    else:
        raise AssertionError("Expected ParseError")


def test_rsp_parser_accepts_cfb1_bit_string_payload():
    config = _config("encrypt", mode="CFB1")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 8000000000000000000000000000000000000000000000000000000000000000
IV = 00000000000000000000000000000000
PLAINTEXT = 0
CIPHERTEXT = 1
"""

    cases = list(RspParser().parse(content, config, source))

    assert cases[0].input["plaintext"] == "0"
    assert cases[0].expected_output == {"ciphertext": "1"}


def test_rsp_parser_rejects_non_bit_cfb1_payload():
    config = _config("encrypt", mode="CFB1")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 8000000000000000000000000000000000000000000000000000000000000000
IV = 00000000000000000000000000000000
PLAINTEXT = 2
CIPHERTEXT = 1
"""

    try:
        list(RspParser().parse(content, config, source))
    except ParseError as exc:
        assert "bit string" in str(exc)
    else:
        raise AssertionError("Expected ParseError")


def test_rsp_parser_rejects_unaligned_cfb8_payload():
    config = _config("encrypt", mode="CFB8")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 2b7e151628aed2a6abf7158809cf4f3c
IV = 000102030405060708090a0b0c0d0e0f
PLAINTEXT = f
CIPHERTEXT = a
"""

    try:
        list(RspParser().parse(content, config, source))
    except ParseError as exc:
        assert "byte-aligned" in str(exc)
    else:
        raise AssertionError("Expected ParseError")


def test_rsp_parser_rejects_unaligned_cfb128_payload():
    config = _config("encrypt", mode="CFB128")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY = 2b7e151628aed2a6abf7158809cf4f3c
IV = 000102030405060708090a0b0c0d0e0f
PLAINTEXT = 00
CIPHERTEXT = 00
"""

    try:
        list(RspParser().parse(content, config, source))
    except ParseError as exc:
        assert "block-aligned" in str(exc)
    else:
        raise AssertionError("Expected ParseError")
