"""JSON report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from crypto_validation import __version__
from crypto_validation.models import TestResult, ValidationConfig, VectorSource
from crypto_validation.reporting.summary import build_summary


def write_json_report(
    config: ValidationConfig,
    source: VectorSource,
    results: list[TestResult],
) -> Path:
    """Write a JSON validation report and return its path."""

    report_dir = Path(config.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    mode = config.mode.lower() if config.mode else "none"
    filename = f"{config.algorithm.lower()}_{mode}_{config.operation}_{config.test_type.lower()}_{timestamp}.json"
    report_path = report_dir / filename

    payload = {
        "run_metadata": {
            "tool_name": "crypto-validation",
            "tool_version": __version__,
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "algorithm": config.algorithm,
            "mode": config.mode,
            "operation": config.operation,
            "test_type": config.test_type,
            "dut": config.dut,
            "vector_file": source.path,
            "vector_format": source.format,
            "vector_checksum_sha256": source.checksum_sha256,
        },
        "summary": build_summary(results),
        "results": [asdict(result) for result in results],
    }

    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return report_path
