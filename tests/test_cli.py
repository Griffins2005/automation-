import json
import shutil
from pathlib import Path

from crypto_validation.cli import EXIT_OK, EXIT_SYSTEM_ERROR, EXIT_VALIDATION_FAIL, main


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
    assert payload["run_metadata"]["elapsed_seconds"] is not None
    assert payload["run_metadata"]["throughput_tests_per_second"] is not None


def test_cli_without_arguments_starts_interactive_single_file_wizard(monkeypatch, capsys):
    answers = iter(
        [
            "",  # algorithm: AES
            "",  # test type: KAT
            "2",  # operation: encrypt
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
    assert "Where should reports be written" not in captured.out


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
            "2",  # operation: encrypt
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


def test_interactive_folder_wizard_skips_forced_mode_mismatches(tmp_path, monkeypatch, capsys):
    vector_dir = tmp_path / "vectors"
    vector_dir.mkdir()
    shutil.copy("sample_vectors/aes/aes_cbc_128.rsp", vector_dir / "CBCVarKey128.rsp")
    shutil.copy("sample_vectors/aes/aes_ctr_128.rsp", vector_dir / "CTRVarKey128.rsp")

    answers = iter(
        [
            "",  # algorithm: AES
            "",  # test type: KAT
            "2",  # operation: encrypt
            "2",  # source kind: folder
            str(vector_dir),
            "3",  # force CBC
            "",  # DUT: python
            "2",  # report format: console
            "",  # fail fast: no
            "",  # run now: yes
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    exit_code = main(["--interactive"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert "Runnable with current MVP: 1" in captured.out
    assert "filename mode CTR does not match forced CBC" in captured.out
    assert "Global Summary" not in captured.out


def test_folder_wizard_prints_global_summary(tmp_path, monkeypatch, capsys):
    vector_dir = tmp_path / "vectors"
    vector_dir.mkdir()
    shutil.copy("sample_vectors/aes/aes_cbc_128.rsp", vector_dir / "CBCVarKey128.rsp")
    shutil.copy("sample_vectors/aes/aes_ctr_128.rsp", vector_dir / "CTRVarKey128.rsp")

    answers = iter(
        [
            "",  # algorithm: AES
            "",  # test type: KAT
            "2",  # operation: encrypt
            "2",  # source kind: folder
            str(vector_dir),
            "",  # auto-detect
            "",  # DUT: python
            "2",  # report format: console
            "",  # fail fast: no
            "",  # run now: yes
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    exit_code = main(["--interactive"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OK
    assert "Global Summary" in captured.out
    assert "Files Run: 2" in captured.out
    assert "Throughput:" in captured.out


def test_failure_injection_modified_ciphertext_is_detected(tmp_path):
    bad_vector = tmp_path / "bad_cbc.rsp"
    original = Path("sample_vectors/aes/aes_cbc_128.rsp").read_text(encoding="utf-8")
    bad_vector.write_text(
        original.replace("7649abac8119b246cee98e9b12e9197d", "7649abac8119b246cee98e9b12e9197e", 1),
        encoding="utf-8",
    )

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
            str(bad_vector),
            "--dut",
            "python",
            "--report-format",
            "json",
            "--report-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == EXIT_VALIDATION_FAIL
    reports = list(tmp_path.glob("*.json"))
    assert len(reports) == 1
    payload = json.loads(reports[0].read_text(encoding="utf-8"))
    assert payload["summary"]["validation_failed"] == 1


def test_json_report_names_are_unique(tmp_path):
    args = [
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

    assert main(args) == EXIT_OK
    assert main(args) == EXIT_OK

    assert len(list(tmp_path.glob("*.json"))) == 2


def test_cli_runs_aes_ctr_encrypt_end_to_end(tmp_path):
    exit_code = main(
        [
            "--algorithm",
            "AES",
            "--mode",
            "CTR",
            "--operation",
            "encrypt",
            "--test-type",
            "KAT",
            "--vector-file",
            "sample_vectors/aes/aes_ctr_128.rsp",
            "--dut",
            "python",
            "--report-format",
            "json",
            "--report-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == EXIT_OK
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["summary"]["passed"] == 2


def test_folder_wizard_auto_detects_mixed_encrypt_decrypt_files(tmp_path, monkeypatch, capsys):
    vector_dir = tmp_path / "failure_injection"
    vector_dir.mkdir()
    shutil.copy(
        "sample_vectors/aes/failure_injection/cbc_encrypt_bad_ciphertext.rsp",
        vector_dir / "cbc_encrypt_bad_ciphertext.rsp",
    )
    shutil.copy(
        "sample_vectors/aes/failure_injection/cbc_decrypt_bad_plaintext.rsp",
        vector_dir / "cbc_decrypt_bad_plaintext.rsp",
    )

    answers = iter(
        [
            "",  # algorithm: AES
            "",  # test type: KAT
            "",  # operation: auto-detect from file
            "2",  # source kind: folder
            str(vector_dir),
            "",  # mode handling: auto-detect
            "",  # DUT: python
            "2",  # report format: console
            "",  # fail fast: no
            "",  # run now: yes
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    exit_code = main(["--interactive"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_VALIDATION_FAIL
    assert "AES-CBC encrypt KAT" in captured.out
    assert "AES-CBC decrypt KAT" in captured.out
    assert "PARSE_ERROR" not in captured.err
    assert "System Errors: 0" in captured.out
