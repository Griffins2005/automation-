from pathlib import Path

from crypto_validation.config import validate_config
from crypto_validation.models import ValidationConfig
from crypto_validation.parsers.json import JsonParser
from crypto_validation.vectors import build_vector_source, load_vector_text


def _config(vector_file: str, mode: str, operation: str) -> ValidationConfig:
    return validate_config(
        ValidationConfig(
            algorithm="AES",
            mode=mode,
            operation=operation,
            test_type="KAT",
            vector_file=vector_file,
            vector_format="json",
            dut="python",
            report_format="json",
            report_dir="reports",
        )
    )


def test_json_parser_reads_native_framework_shape():
    config = _config("sample_vectors/aes/aes_cbc_128.json", "CBC", "encrypt")
    path = Path(config.vector_file)
    source = build_vector_source(path, config.vector_format)

    cases = list(JsonParser().parse(load_vector_text(path), config, source))

    assert len(cases) == 1
    assert cases[0].test_id == "0"
    assert cases[0].input["plaintext"] == "6bc1bee22e409f96e93d7e117393172a"
    assert cases[0].expected_output == {"ciphertext": "7649abac8119b246cee98e9b12e9197d"}


def test_json_parser_reads_acvp_like_shape_with_aliases():
    config = _config("sample_vectors/aes/aes_ctr_128_acvp.json", "CTR", "encrypt")
    path = Path(config.vector_file)
    source = build_vector_source(path, config.vector_format)

    cases = list(JsonParser().parse(load_vector_text(path), config, source))

    assert len(cases) == 1
    assert cases[0].test_id == "1"
    assert cases[0].input["plaintext"] == "6bc1bee22e409f96e93d7e117393172a"
    assert cases[0].expected_output == {"ciphertext": "874d6191b620e3261bef6864990db6ce"}
    assert cases[0].metadata["tg_id"] == 1


def test_json_parser_filters_by_operation():
    config = _config("sample_vectors/aes/aes_cbc_128.json", "CBC", "decrypt")
    path = Path(config.vector_file)
    source = build_vector_source(path, config.vector_format)

    cases = list(JsonParser().parse(load_vector_text(path), config, source))

    assert len(cases) == 1
    assert cases[0].test_id == "1"
    assert cases[0].input["ciphertext"] == "7649abac8119b246cee98e9b12e9197d"
    assert cases[0].expected_output == {"plaintext": "6bc1bee22e409f96e93d7e117393172a"}
