"""JSON report generation.

JSON reports are intended for both humans and automation. The report includes
run metadata, summary counts, and per-test results so CI systems or dashboards
can consume validation output without scraping terminal text.
"""

from __future__ import annotations

import json
import re
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
    elapsed_seconds: float | None = None,
) -> Path:
    """Write a JSON validation report and return its path.

    Args:
        config: Normalized validation configuration.
        source: Vector file provenance metadata.
        results: Per-test validation results.
        elapsed_seconds: Optional measured execution time.

    Returns:
        Path to the generated JSON report.

    Report schema:
        ``run_metadata`` contains reproducibility information, ``summary``
        contains status counts, and ``results`` contains serialized
        ``TestResult`` objects.
    """

    report_dir = Path(config.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    mode = config.mode.lower() if config.mode else "none"
    vector_stem = _safe_filename_part(Path(source.path).stem)
    # Include the run configuration in the filename so multiple algorithm/mode
    # runs can share one report directory without overwriting each other.
    filename = (
        f"{config.algorithm.lower()}_{mode}_{config.operation}_"
        f"{config.test_type.lower()}_{vector_stem}_{timestamp}.json"
    )
    report_path = _unique_report_path(report_dir / filename)
    summary = build_summary(results)
    throughput = None
    if elapsed_seconds is not None:
        throughput = summary["total"] / elapsed_seconds if elapsed_seconds > 0 else 0.0

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
            "elapsed_seconds": elapsed_seconds,
            "throughput_tests_per_second": throughput,
        },
        "summary": summary,
        "results": [asdict(result) for result in results],
    }

    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return report_path


def _safe_filename_part(value: str) -> str:
    """Return a filesystem-friendly filename component."""

    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "vector"


def _unique_report_path(path: Path) -> Path:
    """Return a non-existing report path by appending a suffix if needed."""

    if not path.exists():
        return path

    for index in range(1, 1000):
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate

    raise FileExistsError(f"Could not create a unique report filename for {path}")
