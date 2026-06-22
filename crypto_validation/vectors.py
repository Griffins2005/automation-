"""Vector file loading and provenance helpers.

Vector provenance is part of validation credibility. Every report includes a
SHA-256 checksum of the vector file so a result can be reproduced against the
same input data later.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from crypto_validation.models import VectorSource


def compute_file_sha256(path: Path) -> str:
    """Compute the SHA-256 checksum for a vector file.

    Args:
        path: File path to hash.

    Returns:
        Hex-encoded SHA-256 digest.

    Notes:
        The file is read in chunks so the helper remains safe for large NIST
        vector files.
    """

    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_vector_text(path: Path) -> str:
    """Load a UTF-8 text vector file.

    Args:
        path: Path to the vector file.

    Returns:
        Full file contents as text.
    """

    return path.read_text(encoding="utf-8")


def build_vector_source(path: Path, vector_format: str) -> VectorSource:
    """Build provenance metadata for a vector file.

    Args:
        path: Vector file path.
        vector_format: Parser format selected for the file.

    Returns:
        ``VectorSource`` containing path, format, and checksum.
    """

    return VectorSource(
        path=str(path),
        format=vector_format,
        checksum_sha256=compute_file_sha256(path),
    )
