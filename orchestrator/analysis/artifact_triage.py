from __future__ import annotations

from pathlib import Path
from typing import Any


PE_MAGIC = b"MZ"
ZIP_MAGIC = b"PK\x03\x04"

SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
    ".sh", ".py", ".psm1", ".lnk",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
}

LOW_VALUE_EXTENSIONS = {
    ".log", ".txt", ".tmp", ".temp", ".xml", ".json", ".ini", ".cfg",
    ".dat", ".pf", ".etl", ".evtx", ".png", ".jpg", ".jpeg", ".bmp",
    ".gif", ".ico", ".manifest", ".cat", ".inf",
}


def _artifact_path(artifact: dict[str, Any]) -> Path | None:
    for key in ("case_path", "destination_path", "path"):
        value = artifact.get(key)
        if value:
            p = Path(str(value))
            if p.exists() and p.is_file():
                return p
    return None


def _read_head(path: Path | None, size: int = 4096) -> bytes:
    if not path:
        return b""
    try:
        return path.read_bytes()[:size]
    except OSError:
        return b""


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if b in b"\r\n\t" or 32 <= b <= 126)
    return printable / max(1, len(data)) > 0.85


def triage_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    """Classify an artifact for analyst value and graph inclusion.

    This does not delete evidence. It only separates raw copied artifacts from
    stage-like/high-value artifacts.
    """
    item = dict(artifact)
    path = _artifact_path(item)
    head = _read_head(path)
    suffix = path.suffix.lower() if path else Path(str(item.get("name") or "")).suffix.lower()
    size = int(item.get("size") or (path.stat().st_size if path else 0) or 0)

    original_kind = str(item.get("artifact_kind") or "")
    source_backend = str(item.get("source_backend") or "")

    role = "runtime_artifact"
    reason = "Generic runtime artifact"
    high_value = False
    recursive_candidate = False
    graph_include = False
    stage_like = False

    if head.startswith(PE_MAGIC) or suffix in EXECUTABLE_EXTENSIONS:
        role = "pe_or_executable_artifact"
        reason = "PE/executable-like artifact"
        high_value = True
        recursive_candidate = True
        graph_include = True
        stage_like = True

    elif suffix in SCRIPT_EXTENSIONS or head.startswith(b"#!"):
        role = "script_artifact"
        reason = "Script-like artifact"
        high_value = True
        recursive_candidate = False
        graph_include = True
        stage_like = True

    elif head.startswith(ZIP_MAGIC):
        role = "archive_or_installer_container"
        reason = "Archive/container artifact"
        high_value = False
        recursive_candidate = False
        graph_include = False
        stage_like = False

    elif original_kind == "memory_dump":
        role = "memory_dump"
        reason = "Memory dump kept as evidence, not a dropped stage"
        high_value = True
        recursive_candidate = False
        graph_include = False
        stage_like = False

    elif suffix in LOW_VALUE_EXTENSIONS or _looks_text(head):
        role = "log_config_or_text_artifact"
        reason = "Text/config/log-style artifact"
        high_value = False
        recursive_candidate = False
        graph_include = False
        stage_like = False

    elif original_kind == "cape_dropped_file" or source_backend == "cape":
        role = "cape_runtime_artifact"
        reason = "CAPE copied artifact without PE/script evidence"
        high_value = False
        recursive_candidate = False
        graph_include = False
        stage_like = False

    if size <= 128 and not high_value:
        role = "small_runtime_artifact"
        reason = "Very small runtime artifact; not enough evidence to treat as stage"
        graph_include = False
        stage_like = False

    item["artifact_role"] = role
    item["artifact_triage_reason"] = reason
    item["high_value_artifact"] = high_value
    item["recursive_candidate"] = recursive_candidate
    item["graph_include"] = graph_include
    item["is_stage_artifact"] = stage_like
    item["artifact_triage_version"] = "1.0"

    if stage_like and not item.get("confidence"):
        item["confidence"] = 0.8
    elif not stage_like:
        item["confidence"] = min(float(item.get("confidence") or 0.25), 0.4)

    return item


def triage_artifacts(artifacts: list[dict[str, Any]], max_graph_artifacts: int = 12) -> list[dict[str, Any]]:
    """Triage artifacts and select only high-value unique artifacts for the main graph.

    All artifacts remain in JSON/report evidence. graph_include controls what appears
    in the main stage graph.
    """
    triaged = [triage_artifact(a) for a in artifacts]

    graph_candidates = [
        (idx, item)
        for idx, item in enumerate(triaged)
        if item.get("graph_include")
    ]

    # Noisy installer/admin-tool runs can produce many PE-like files. Keep evidence,
    # but avoid turning every copied file into a main graph stage.
    if len(triaged) >= 80 and len(graph_candidates) >= 20:
        max_graph_artifacts = min(max_graph_artifacts, 12)

    graph_candidates = sorted(
        graph_candidates,
        key=lambda pair: (
            0 if pair[1].get("recursive_candidate") else 1,
            0 if pair[1].get("high_value_artifact") else 1,
            -int(pair[1].get("size") or 0),
            str(pair[1].get("sha256") or ""),
        ),
    )

    selected_indices: set[int] = set()
    selected_keys: set[str] = set()

    for idx, item in graph_candidates:
        sha = str(item.get("sha256") or "").strip()
        path = str(item.get("destination_path") or item.get("case_path") or item.get("path") or "").strip()
        key = f"sha256:{sha}" if sha else f"path:{path}" if path else f"idx:{idx}"

        if key in selected_keys:
            item["graph_include"] = False
            item["is_stage_artifact"] = False
            item["artifact_triage_reason"] = "Duplicate artifact omitted from main graph"
            continue

        if len(selected_indices) >= max_graph_artifacts:
            item["graph_include"] = False
            item["is_stage_artifact"] = False
            item["artifact_triage_reason"] = "High-value artifact omitted from main graph due to graph-size limit"
            continue

        selected_indices.add(idx)
        selected_keys.add(key)

    for idx, item in enumerate(triaged):
        if item.get("graph_include") and idx not in selected_indices:
            item["graph_include"] = False
            item["is_stage_artifact"] = False
            item["artifact_triage_reason"] = "Artifact omitted from main graph after deduplication/limit"

    return triaged

