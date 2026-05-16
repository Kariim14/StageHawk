"""Basic artifact classification for safe evidence handling."""

from __future__ import annotations

import re
from pathlib import Path


MARKER_RE = re.compile(r"^(hit_\d+_[A-Za-z0-9_]+|autorun_marker)\.bin$")
STAGE_DROP_RE = re.compile(r"^dropped_stage(\d+)\.bin$", re.IGNORECASE)


def classify_artifact(path: str | Path) -> dict[str, object]:
    p = Path(path)
    size = p.stat().st_size if p.exists() else 0
    name = p.name
    lowered = name.lower()

    if MARKER_RE.match(name) and size <= 16:
        return {
            "artifact_kind": "api_hit_marker",
            "file_type": "x64dbg_marker",
            "is_stage_artifact": False,
            "stage_number": None,
            "confidence": 0.95,
        }

    stage_match = STAGE_DROP_RE.match(name)
    if stage_match:
        return {
            "artifact_kind": "dropped_file",
            "file_type": "stage_blob",
            "is_stage_artifact": True,
            "stage_number": int(stage_match.group(1)),
            "confidence": 0.9,
        }

    header = b""
    if p.exists() and p.is_file():
        with p.open("rb") as f:
            header = f.read(64)

    if "memory" in str(p.parent).lower() or lowered.startswith(("memdump", "dump_")):
        file_type = "memory_dump"
        artifact_kind = "memory_dump"
    elif "cape" in str(p).lower() and p.parent.name in {"dropped_files", "selfextracted", "files"}:
        file_type = "cape_artifact"
        artifact_kind = "cape_dropped_file"
    elif lowered.endswith((".png", ".jpg", ".jpeg", ".bmp")):
        file_type = "image"
        artifact_kind = "screenshot"
    elif header.startswith(b"MZ"):
        file_type = "pe_or_mz_like"
        artifact_kind = "runtime_artifact"
    elif header.startswith(b"MZ_FAKE_EDU"):
        file_type = "stage_blob"
        artifact_kind = "runtime_artifact"
    elif lowered.endswith((".log", ".txt", ".md", ".json")):
        file_type = "text_or_report"
        artifact_kind = "runtime_artifact"
    else:
        file_type = "unknown_binary"
        artifact_kind = "runtime_artifact"

    return {
        "artifact_kind": artifact_kind,
        "file_type": file_type,
        "is_stage_artifact": False,
        "stage_number": None,
        "confidence": 0.4,
    }
