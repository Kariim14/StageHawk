"""Hashing helpers for samples and extracted artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_metadata(path: str | Path) -> dict[str, object]:
    p = Path(path)
    stat = p.stat()
    return {
        "path": str(p),
        "name": p.name,
        "size": stat.st_size,
        "sha256": sha256_file(p),
    }
