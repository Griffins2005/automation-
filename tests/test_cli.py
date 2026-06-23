import json

from crypto_validation.cli import EXIT_OK, EXIT_SYSTEM_ERROR, main


def test_cli_runs_aes_cbc_encrypt_end_to_end(tmp_path):
    exit_code = main(
        [
            "--algorithm",
            "AES",
            "--mode",
            "CBC",
            "--operation",
            "encrypt",
            "--test-type",
            "KAT",
            "--vector-file",
            "sample_vectors/aes/aes_cbc_128.rsp",
            "--dut",
            "python",
            "--report-format",
            "json",
            "--report-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == EXIT_OK
    reports = list(tmp_path.glob("*.json"))
    assert len(reports) == 1

    payload = json.loads(reports[0].read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["passed"] == 2
    assert payload["summary"]["validation_failed"] == 0


def test_cli_without_arguments_prints_guidance(capsys):
    exit_code = main([])

    captured = capsys.readouterr()
    assert exit_code == EXIT_SYSTEM_ERROR
    assert "Current MVP support" in captured.err
    assert "--vector-file" in captured.err
    assert "No arguments were provided" in captured.err


def test_cli_list_supported_prints_supported_matrix(capsys):
    exit_code = main(["--list-supported"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert "Supported MVP configuration" in captured.out
    assert "AES" in captured.out
    assert "CBC" in captured.out


def test_cli_show_format_prints_rsp_structure(capsys):
    exit_code = main(["--show-format"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert "Supported .rsp vector format" in captured.out
    assert "COUNT = 0" in captured.out
    assert "KEY =" in captured.out
    assert "CFB1" in captured.out


def test_cli_accepts_lowercase_supported_values(tmp_path):
    exit_code = main(
        [
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--operation",
            "encrypt",
            "--test-type",
            "kat",
            "--vector-file",
            "sample_vectors/aes/aes_cbc_128.rsp",
            "--vector-format",
            "rsp",
            "--dut",
            "python",
            "--report-format",
            "json",
            "--report-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == EXIT_OK
