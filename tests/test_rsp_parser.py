from pathlib import Path

from crypto_validation.config import validate_config
from crypto_validation.models import ValidationConfig
from crypto_validation.parsers.rsp import RspParser
from crypto_validation.vectors import build_vector_source, load_vector_text


def _config(operation: str = "encrypt") -> ValidationConfig:
    return validate_config(
        ValidationConfig(
            algorithm="AES",
            mode="CBC",
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
    config = _config("encrypt")
    source = build_vector_source(Path(config.vector_file), config.vector_format)
    content = """
[ENCRYPT]
COUNT = 0
KEY =
IV = 00
PLAINTEXT = 00
CIPHERTEXT = 00
"""

    cases = list(RspParser().parse(content, config, source))

    assert cases[0].input["key"] == ""
