from crypto_validation.dut.aes_python import AesPythonDut


def test_aes_cbc_python_dut_encrypts_known_vector():
    dut = AesPythonDut("CBC")

    actual = dut.run(
        {
            "operation": "encrypt",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
        }
    )

    assert actual == {"ciphertext": "7649abac8119b246cee98e9b12e9197d"}


def test_aes_cbc_python_dut_decrypts_known_vector():
    dut = AesPythonDut("CBC")

    actual = dut.run(
        {
            "operation": "decrypt",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "ciphertext": "7649abac8119b246cee98e9b12e9197d",
        }
    )

    assert actual == {"plaintext": "6bc1bee22e409f96e93d7e117393172a"}
