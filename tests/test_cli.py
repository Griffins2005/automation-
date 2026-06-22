import json

from crypto_validation.cli import EXIT_OK, main


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
