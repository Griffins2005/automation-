from crypto_validation.validation.comparator import Comparator


def test_comparator_passes_exact_match_with_case_normalization():
    result = Comparator().compare({"ciphertext": "ABCD"}, {"ciphertext": "abcd"})

    assert result.passed is True
    assert result.mismatches == {}


def test_comparator_reports_field_mismatch():
    result = Comparator().compare({"ciphertext": "aaaa"}, {"ciphertext": "bbbb"})

    assert result.passed is False
    assert result.mismatches["ciphertext"] == {
        "expected": "aaaa",
        "actual": "bbbb",
    }


def test_comparator_reports_unexpected_output_field():
    result = Comparator().compare({"ciphertext": "aaaa"}, {"ciphertext": "aaaa", "tag": "00"})

    assert result.passed is False
    assert result.mismatches["tag"]["reason"] == "Unexpected output field"
