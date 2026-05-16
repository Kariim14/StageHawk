"""Case creation, output layout, and manifest updates."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from orchestrator.core.hashing import file_metadata


STEP_NAMES = [
    "case_created",
    "static_analysis",
    "stage_candidate_detection",
    "dynamic_plan_generation",
    "dynamic_analysis",
    "runtime_evidence_collection",
    "cape_analysis",
    "artifact_extraction",
    "recursive_analysis",
    "stage_graph_generation",
    "report_generation",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slugify(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "_" for ch in value)
    cleaned = "_".join(part for part in cleaned.split("_") if part)
    return cleaned[:80] or "case"


@dataclass
class CaseContext:
    case_id: str
    case_name: str
    root: Path
    manifest_path: Path
    input_sample: Path


def ensure_case_layout(root: Path) -> None:
    for rel in [
        "input",
        "static",
        "dynamic/raw_logs",
        "dynamic/evidence/api_hit_markers",
        "dynamic/evidence/dropped_files",
        "dynamic/evidence/memory_dumps",
        "dynamic/evidence/process_events",
        "dynamic/evidence/network_events",
        "dynamic/evidence/registry_events",
        "extracted",
        "graph",
        "reports",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)


def create_case(sample_path: str | Path, case_name: str | None, results_root: str | Path) -> CaseContext:
    sample = Path(sample_path).expanduser().resolve()
    if not sample.exists():
        raise FileNotFoundError(f"sample does not exist: {sample}")
    if not sample.is_file():
        raise ValueError(f"sample is not a file: {sample}")

    name = case_name or sample.stem
    case_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{slugify(name)}"
    root = Path(results_root).expanduser().resolve() / case_id
    ensure_case_layout(root)

    input_sample = root / "input" / sample.name
    shutil.copy2(sample, input_sample)

    metadata = file_metadata(input_sample)
    metadata.update(
        {
            "original_path": str(sample),
            "safety_mode": "static_or_sandbox_only",
        }
    )
    (root / "input" / "original_sample_metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    manifest = {
        "case_id": case_id,
        "case_name": name,
        "sample_path": str(input_sample),
        "original_sample_path": str(sample),
        "current_status": "pending",
        "analysis_mode": "static",
        "selected_backends": {
            "static": True,
            "cape": False,
            "x64dbg": False,
            "ghidra": False,
        },
        "required_steps": [],
        "completed_steps": [],
        "failed_steps": [],
        "skipped_steps": [],
        "step_status": {step: "pending" for step in STEP_NAMES},
        "output_paths": {
            "case_root": str(root),
            "input_metadata": str(root / "input" / "original_sample_metadata.json"),
        },
        "timestamps": {"created_at": utc_now(), "updated_at": utc_now()},
        "errors": [],
        "warnings": [],
        "analysis_depth": 0,
        "parent_case_or_stage_if_any": None,
    }
    manifest_path = root / "case_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ctx = CaseContext(
        case_id=case_id,
        case_name=name,
        root=root,
        manifest_path=manifest_path,
        input_sample=input_sample,
    )
    update_step(ctx, "case_created", "completed")
    return ctx


def read_manifest(ctx: CaseContext) -> dict[str, object]:
    return json.loads(ctx.manifest_path.read_text(encoding="utf-8"))


def write_manifest(ctx: CaseContext, manifest: dict[str, object]) -> None:
    timestamps = manifest.setdefault("timestamps", {})
    if isinstance(timestamps, dict):
        timestamps["updated_at"] = utc_now()
    ctx.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def list_cases(results_root: str | Path = "results/cases") -> list[dict[str, object]]:
    root = Path(results_root).expanduser().resolve()
    cases: list[dict[str, object]] = []
    if not root.exists():
        return cases
    for manifest_path in sorted(root.glob("*/case_manifest.json"), reverse=True):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["_manifest_path"] = str(manifest_path)
            manifest["_case_root"] = str(manifest_path.parent)
            cases.append(manifest)
        except Exception:
            continue
    return cases


def get_case(case_id: str, results_root: str | Path = "results/cases") -> dict[str, object] | None:
    for case in list_cases(results_root):
        if str(case.get("case_id")) == case_id:
            return case
    return None


def update_step(
    ctx: CaseContext,
    step: str,
    status: str,
    *,
    error: str | None = None,
    warning: str | None = None,
    output_paths: dict[str, str] | None = None,
) -> None:
    if status not in {"pending", "running", "completed", "failed", "skipped"}:
        raise ValueError(f"invalid step status: {status}")

    manifest = read_manifest(ctx)
    step_status = manifest.setdefault("step_status", {})
    if isinstance(step_status, dict):
        step_status[step] = status

    for bucket in ("completed_steps", "failed_steps", "skipped_steps"):
        values = manifest.setdefault(bucket, [])
        if isinstance(values, list) and step in values:
            values.remove(step)

    if status == "completed":
        manifest["completed_steps"].append(step)
    elif status == "failed":
        manifest["failed_steps"].append(step)
    elif status == "skipped":
        manifest["skipped_steps"].append(step)

    if error:
        manifest.setdefault("errors", []).append({"step": step, "message": error, "time": utc_now()})
    if warning:
        manifest.setdefault("warnings", []).append({"step": step, "message": warning, "time": utc_now()})
    if output_paths:
        manifest.setdefault("output_paths", {}).update(output_paths)

    if status == "running":
        manifest["current_status"] = "running"
    else:
        manifest["current_status"] = compute_case_status(manifest)

    write_manifest(ctx, manifest)


def compute_case_status(manifest: dict[str, object]) -> str:
    required_steps = set(manifest.get("required_steps") or [])
    failed_required = required_steps.intersection(set(manifest.get("failed_steps") or []))
    skipped_required = required_steps.intersection(set(manifest.get("skipped_steps") or []))

    if failed_required or skipped_required:
        return "completed_with_errors"
    if manifest.get("failed_steps"):
        return "completed_with_errors"
    if all(
        manifest.get("step_status", {}).get(s) in {"completed", "skipped"}
        for s in STEP_NAMES
    ):
        # Optional skipped steps are normal mode behavior.
        # Example: Static Only skips CAPE/x64dbg; Full Analysis may skip x64dbg
        # until that backend is explicitly enabled and validated.
        return "completed_with_warnings" if manifest.get("warnings") else "completed"
    return "queued"


def configure_case_execution(
    ctx: CaseContext,
    *,
    analysis_mode: str,
    selected_backends: dict[str, bool],
    required_steps: list[str],
) -> None:
    manifest = read_manifest(ctx)
    manifest["analysis_mode"] = analysis_mode
    manifest["selected_backends"] = selected_backends
    manifest["required_steps"] = required_steps
    if manifest.get("current_status") == "pending":
        manifest["current_status"] = "queued"
    write_manifest(ctx, manifest)


def finalize_case_status(ctx: CaseContext) -> None:
    manifest = read_manifest(ctx)
    manifest["current_status"] = compute_case_status(manifest)
    write_manifest(ctx, manifest)
