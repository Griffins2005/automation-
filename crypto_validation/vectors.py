"""Vector file loading and provenance helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

from crypto_validation.models import VectorSource


def compute_file_sha256(path: Path) -> str:
    """Compute the SHA-256 checksum for a vector file."""

    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_vector_text(path: Path) -> str:
    """Load a text vector file."""

    return path.read_text(encoding="utf-8")


def build_vector_source(path: Path, vector_format: str) -> VectorSource:
    """Build provenance metadata for a vector file."""

    return VectorSource(
        path=str(path),
        format=vector_format,
        checksum_sha256=compute_file_sha256(path),
    )
