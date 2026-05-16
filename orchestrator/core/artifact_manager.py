"""Collection and metadata for runtime artifacts and extracted stages."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterable

from orchestrator.analysis.artifact_classifier import classify_artifact
from orchestrator.core.case_manager import CaseContext
from orchestrator.core.hashing import file_metadata


def _metadata_for(path: Path, source_path: Path, evidence_reference: str | None = None) -> dict[str, object]:
    metadata = file_metadata(path)
    classification = classify_artifact(path)
    metadata.update(classification)
    metadata.update(
        {
            "source_path": str(source_path),
            "evidence_reference": evidence_reference,
            "source_api_or_event": None,
            "parent_stage": "root",
        }
    )
    return metadata


def copy_api_markers(case: CaseContext, marker_paths: Iterable[Path]) -> list[dict[str, object]]:
    output_dir = case.root / "dynamic" / "evidence" / "api_hit_markers"
    records: list[dict[str, object]] = []
    for src in marker_paths:
        if not src.exists() or not src.is_file():
            continue
        dst = output_dir / src.name
        shutil.copy2(src, dst)
        meta = _metadata_for(dst, src, evidence_reference="x64dbg_api_hit_marker")
        records.append(meta)

    (output_dir / "metadata.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    return records


def collect_dropped_files(case: CaseContext, search_paths: Iterable[str | Path]) -> list[dict[str, object]]:
    """Collect real dropped stage files if they exist.

    This function never fabricates stage payloads. If no dropped files are found,
    it returns an empty list and the report states that extraction was not
    observed.
    """
    dropped_dir = case.root / "dynamic" / "evidence" / "dropped_files"
    extracted_root = case.root / "extracted"
    seen_hashes: set[str] = set()
    records: list[dict[str, object]] = []

    for raw_path in search_paths:
        base = Path(raw_path).expanduser()
        if not base.exists():
            continue
        candidates = [base] if base.is_file() else sorted(base.glob("dropped_stage*.bin"))
        for src in candidates:
            if not src.is_file():
                continue
            tmp_dst = dropped_dir / src.name
            shutil.copy2(src, tmp_dst)
            meta = _metadata_for(tmp_dst, src, evidence_reference="runtime_dropped_file")
            if not meta.get("is_stage_artifact"):
                continue
            if str(meta["sha256"]) in seen_hashes:
                continue
            seen_hashes.add(str(meta["sha256"]))

            stage_number = int(meta.get("stage_number") or (len(records) + 1))
            stage_dir = extracted_root / f"stage_{stage_number:03d}"
            stage_dir.mkdir(parents=True, exist_ok=True)
            artifact_dst = stage_dir / "artifact.bin"
            shutil.copy2(tmp_dst, artifact_dst)
            stage_meta = _metadata_for(artifact_dst, src, evidence_reference="runtime_dropped_file")
            stage_meta.update(
                {
                    "artifact_kind": meta.get("artifact_kind"),
                    "file_type": meta.get("file_type"),
                    "is_stage_artifact": meta.get("is_stage_artifact"),
                    "stage_number": meta.get("stage_number"),
                }
            )
            stage_meta.update(
                {
                    "stage_id": f"stage_{stage_number:03d}",
                    "destination_path": str(artifact_dst),
                    "source_path": str(src),
                    "confidence": meta.get("confidence", 0.8),
                    "relationship_basis": "observed_file_name_from_runtime_output",
                }
            )
            (stage_dir / "metadata.json").write_text(
                json.dumps(stage_meta, indent=2),
                encoding="utf-8",
            )
            records.append(stage_meta)

    (dropped_dir / "metadata.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    return records
