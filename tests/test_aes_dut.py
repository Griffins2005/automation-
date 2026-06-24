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


def test_aes_ctr_python_dut_encrypts_sp800_38a_vector():
    dut = AesPythonDut("CTR")

    actual = dut.run(
        {
            "operation": "encrypt",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
        }
    )

    assert actual == {"ciphertext": "874d6191b620e3261bef6864990db6ce"}


def test_aes_cfb128_python_dut_encrypts_known_vector():
    dut = AesPythonDut("CFB128")

    actual = dut.run(
        {
            "operation": "encrypt",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
        }
    )

    assert actual == {"ciphertext": "3b3fd92eb72dad20333449f8e83cfb4a"}


def test_aes_cfb8_python_dut_encrypts_known_vector():
    dut = AesPythonDut("CFB8")

    actual = dut.run(
        {
            "operation": "encrypt",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
        }
    )

    assert actual == {"ciphertext": "3b79424c9c0dd436bace9e0ed4586a4f"}


def test_aes_ofb_python_dut_encrypts_known_vector():
    dut = AesPythonDut("OFB")

    actual = dut.run(
        {
            "operation": "encrypt",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "iv": "000102030405060708090a0b0c0d0e0f",
            "plaintext": "6bc1bee22e409f96e93d7e117393172a",
        }
    )

    assert actual == {"ciphertext": "3b3fd92eb72dad20333449f8e83cfb4a"}


def test_aes_cfb1_python_dut_encrypts_and_decrypts_bit_vector():
    dut = AesPythonDut("CFB1")
    base_input = {
        "key": "8000000000000000000000000000000000000000000000000000000000000000",
        "iv": "00000000000000000000000000000000",
    }

    encrypted = dut.run({**base_input, "operation": "encrypt", "plaintext": "0"})
    decrypted = dut.run({**base_input, "operation": "decrypt", "ciphertext": encrypted["ciphertext"]})

    assert encrypted == {"ciphertext": "1"}
    assert decrypted == {"plaintext": "0"}
