import json
import shutil

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


def test_cli_without_arguments_starts_interactive_single_file_wizard(monkeypatch, capsys):
    answers = iter(
        [
            "",  # algorithm: AES
            "",  # test type: KAT
            "",  # operation: encrypt
            "",  # source kind: single file
            "sample_vectors/aes/aes_cbc_128.rsp",
            "",  # use detected CBC mode
            "",  # DUT: python
            "2",  # report format: console
            "",  # report dir: reports
            "",  # fail fast: no
            "",  # run now: yes
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    exit_code = main([])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert "Interactive validation wizard" in captured.out
    assert "AES-CBC encrypt KAT" in captured.out
    assert "Total Tests: 2" in captured.out


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


def test_interactive_folder_wizard_skips_unsupported_cfb_files(tmp_path, monkeypatch, capsys):
    vector_dir = tmp_path / "vectors"
    vector_dir.mkdir()
    shutil.copy("sample_vectors/aes/aes_cbc_128.rsp", vector_dir / "CBCVarKey128.rsp")
    (vector_dir / "CFB1VarKey256.rsp").write_text(
        "[ENCRYPT]\nCOUNT = 0\nKEY = 00\nIV = 00\nPLAINTEXT = 0\nCIPHERTEXT = 1\n",
        encoding="utf-8",
    )

    answers = iter(
        [
            "",  # algorithm: AES
            "",  # test type: KAT
            "",  # operation: encrypt
            "2",  # source kind: folder
            str(vector_dir),
            "",  # mode handling: auto-detect
            "",  # DUT: python
            "2",  # report format: console
            "",  # report dir: reports
            "",  # fail fast: no
            "",  # run now: yes
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    exit_code = main(["--interactive"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert "Runnable with current MVP: 1" in captured.out
    assert "Skipped unsupported/unknown files: 1" in captured.out
    assert "AES-CFB1 is not supported yet" in captured.out
