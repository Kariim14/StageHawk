"""Reusable high-level automation pipeline.

Future GUI/web/chatbot integrations should call ``run_full_pipeline`` rather
than shelling out to individual CLI scripts.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from orchestrator.analysis.ioc_extractor import extract_iocs
from orchestrator.analysis.mitre_mapper import map_behaviors
from orchestrator.analysis.stage_detector import detect_stage_candidates
from orchestrator.analysis.signature_scanner import run_signature_scan
from orchestrator.analysis.artifact_triage import triage_artifacts
from orchestrator.core.artifact_manager import collect_dropped_files
from orchestrator.core.case_manager import (
    CaseContext,
    compute_case_status,
    configure_case_execution,
    create_case,
    finalize_case_status,
    read_manifest,
    update_step,
    utc_now,
    write_manifest,
)
from orchestrator.core.config_loader import load_config
from orchestrator.core.graph_builder import build_stage_graph, write_graph_outputs
from orchestrator.core.report_builder import build_final_report, write_final_report
from orchestrator.core.timing import record_step_timing, start_case_timing, start_step_timing
from orchestrator.integrations.ghidra_runner import GhidraRunnerError, run_ghidra
from orchestrator.integrations.cape_client import CapeClient, SUCCESS_STATUSES
from orchestrator.integrations.memory_dump_collector import collect_memory_dumps
from orchestrator.integrations.vm_manager import check_vm_status


SECRET_KEY_NAMES = {"api_key", "api_token", "token", "secret", "password"}
SECRET_KEY_SUFFIXES = ("_api_key", "_api_token", "_token", "_secret", "_password")


def redact_secret(value: Any) -> str:
    if value in {None, "", "***missing***"}:
        return "***missing***"
    return "***configured***" if value else "***missing***"


def _redact_config_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_name = str(key).lower()
            if key_name in SECRET_KEY_NAMES or key_name.endswith(SECRET_KEY_SUFFIXES):
                redacted[key] = redact_secret(item)
            else:
                redacted[key] = _redact_config_secrets(item)
        return redacted
    if isinstance(value, list):
        return [_redact_config_secrets(item) for item in value]
    return value


def create_backend_case(sample_path: str | Path, case_name: str | None = None, config_path: str | Path | None = None) -> CaseContext:
    config = load_config(config_path)
    return create_case(sample_path, case_name, config["results_root"])


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]



def _load_input_metadata(ctx: CaseContext) -> dict[str, Any]:
    return json.loads((ctx.root / "input" / "original_sample_metadata.json").read_text(encoding="utf-8"))



def _minimal_static_data(ctx: CaseContext) -> dict[str, Any]:
    """Return safe metadata-only static data without disassembling/executing the sample."""
    return {
        "program_name": ctx.input_sample.name,
        "image_base": None,
        "function_count": 0,
        "imported_dlls": [],
        "imported_symbols": [],
        "all_strings": [],
        "memory_sections": [],
        "functions": [],
        "suspicious_addresses": [],
        "_summary": {"analysis_source": "metadata_only_no_static_engine"},
    }


def _empty_runtime_events() -> dict[str, Any]:
    """Return an empty runtime evidence structure when no debugger runtime backend is active."""
    return {
        "input_log": None,
        "event_count": 0,
        "message_count": 0,
        "api_counts": {},
        "stage_counts": {},
        "category_counts": {},
        "messages": [],
        "events": [],
    }


def _normalize_mode(mode: str | None) -> str:
    raw = (mode or "full").strip().lower().replace("-", "_")
    aliases = {
        "full": "full",
        "full_analysis": "full",
        "static": "static",
        "static_only": "static",
        "dynamic": "dynamic",
        "dynamic_only": "dynamic",
    }
    if raw not in aliases:
        raise ValueError("Invalid analysis mode. Use full, static, or dynamic.")
    return aliases[raw]


def _is_x64dbg_legacy_request(mode: str | None) -> bool:
    return False



def _static_summary(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("_summary") or {}
    useful_hits = [
        hit
        for hit in data.get("suspicious_addresses", [])
        if hit.get("containing_function") not in ("UNKNOWN", hit.get("api"))
        and hit.get("from_address") != "NO_REFERENCE_FOUND"
    ]
    return {
        "program_name": data.get("program_name"),
        "image_base": data.get("image_base"),
        "function_count": data.get("function_count"),
        "imported_dll_count": len(data.get("imported_dlls", [])),
        "imported_symbol_count": len(data.get("imported_symbols", [])),
        "string_count": len(data.get("all_strings", [])),
        "memory_section_count": len(data.get("memory_sections", [])),
        "suspicious_hit_count": len(data.get("suspicious_addresses", [])),
        "useful_suspicious_hit_count": summary.get("useful_suspicious_hit_count", len(useful_hits)),
    }



def run_signature_analysis(ctx: CaseContext, config: dict[str, Any]) -> dict[str, Any]:
    """Run real known-malware signature engines without executing the sample.

    This is an evidence-producing step:
    - YARA uses configured local rules.
    - ClamAV uses local antivirus signatures if installed.
    Missing engines are reported as unavailable, never as clean.
    """
    static_dir = ctx.root / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    output_json = static_dir / "signature_scan.json"

    if not config.get("signature_scan_enabled", True):
        result = {
            "schema_version": "1.0",
            "sample_path": str(ctx.input_sample),
            "verdict": "disabled",
            "engines": {},
            "summary": {
                "matched_engine_count": 0,
                "unavailable_engine_count": 0,
                "error_engine_count": 0,
                "total_match_count": 0,
            },
        }
        output_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        result = run_signature_scan(ctx.input_sample, output_json, config)

    manifest = read_manifest(ctx)
    manifest.setdefault("output_paths", {})["signature_scan"] = str(output_json)
    write_manifest(ctx, manifest)
    return result


def run_static_analysis(case_id: str | CaseContext, config: dict[str, Any] | None = None) -> dict[str, Any]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id, config)
    config = config or load_config()
    out = ctx.root / "static" / "ghidra_out.json"
    update_step(ctx, "static_analysis", "running")

    try:
        if config.get("run_ghidra"):
            run_ghidra(
                sample_path=ctx.input_sample,
                output_json=out,
                ghidra_headless=config.get("ghidra_headless_path"),
                script_dir=config.get("ghidra_script_dir"),
                timeout=int(config.get("ghidra_timeout_seconds", 300)),
            )
            update_step(ctx, "static_analysis", "completed", output_paths={"ghidra_out": str(out)})
        else:
            minimal = _minimal_static_data(ctx)
            out.write_text(json.dumps(minimal, indent=2), encoding="utf-8")
            update_step(
                ctx,
                "static_analysis",
                "completed",
                warning="Ghidra static analysis disabled; metadata-only static output generated.",
                output_paths={"ghidra_out": str(out)},
            )
    except (GhidraRunnerError, OSError, ValueError) as exc:
        update_step(ctx, "static_analysis", "failed", error=str(exc), output_paths={"ghidra_out": str(out)})
        raise

    return json.loads(out.read_text(encoding="utf-8"))


def detect_stage_boundaries(case_id: str | CaseContext, ghidra_data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id)
    update_step(ctx, "stage_candidate_detection", "running")
    if ghidra_data is None:
        ghidra_data = json.loads((ctx.root / "static" / "ghidra_out.json").read_text(encoding="utf-8"))
    candidates = detect_stage_candidates(ghidra_data)
    out = ctx.root / "static" / "stage_candidates.json"
    out.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    update_step(ctx, "stage_candidate_detection", "completed", output_paths={"stage_candidates": str(out)})
    return candidates


def generate_dynamic_plan(case_id: str | CaseContext, ghidra_data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id)
    update_step(ctx, "dynamic_plan_generation", "skipped")
    return []


def run_dynamic_analysis(case_id: str | CaseContext, config: dict[str, Any] | None = None) -> None:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id, config)
    update_step(ctx, "dynamic_analysis", "skipped")


def collect_runtime_evidence(case_id: str | CaseContext, config: dict[str, Any] | None = None) -> dict[str, Any]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id, config)
    update_step(ctx, "runtime_evidence_collection", "skipped")
    return _empty_runtime_events()


def run_cape_analysis(
    case_id: str | CaseContext,
    config: dict[str, Any] | None = None,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id, config)
    config = config or load_config()
    cape_config = config.get("cape", {})
    cape_dir = ctx.root / "cape"
    cape_dir.mkdir(parents=True, exist_ok=True)
    update_step(ctx, "cape_analysis", "running")
    client = CapeClient(cape_config)
    status = client.availability().as_dict()
    (cape_dir / "cape_status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")

    if not cape_config.get("enabled"):
        result = {"status": "skipped", "reason": "CAPE disabled by config", "availability": status}
        (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        update_step(ctx, "cape_analysis", "skipped", warning="CAPE disabled by config", output_paths={"cape_status": str(cape_dir / "cape_status.json")})
        return result

    try:
        task_id = None
        if cape_config.get("mode") == "api" and cape_config.get("submit_sample"):
            if progress_callback:
                progress_callback("submitting_to_cape", {})
            machine = cape_config.get("machine") or ((status.get("vm_names") or [None])[0])
            submission_started = start_step_timing(ctx, "cape_submission", extra={"boundary": "CAPE API task submission"})
            try:
                submission = client.submit_sample(
                    ctx.input_sample,
                    machine=machine,
                    timeout=int(cape_config.get("analysis_timeout_seconds") or config.get("analysis_timeout_seconds") or 120),
                    options=cape_config.get("options"),
                )
                (cape_dir / "cape_submission.json").write_text(json.dumps(submission, indent=2), encoding="utf-8")
                task_id = client.extract_task_id(submission)
                record_step_timing(ctx, "cape_submission", submission_started, status="completed", extra={"task_id": task_id})
            except Exception as exc:
                record_step_timing(ctx, "cape_submission", submission_started, status="failed", extra={"error": str(exc)})
                raise
            if task_id:
                if progress_callback:
                    progress_callback("cape_task_created", {"task_id": task_id})

                def on_poll(update: dict[str, Any]) -> None:
                    (cape_dir / "cape_progress.json").write_text(json.dumps(update, indent=2), encoding="utf-8")
                    if progress_callback:
                        progress_callback("waiting_for_cape", {"task_id": task_id, "cape_status": update.get("status")})

                wait_started = start_step_timing(
                    ctx,
                    "cape_sandbox_wait",
                    extra={"task_id": task_id, "boundary": "CAPE task polling until final task status"},
                )
                try:
                    task = client.poll_task(task_id, progress_callback=on_poll)
                    (cape_dir / "cape_task.json").write_text(json.dumps(task, indent=2), encoding="utf-8")
                except Exception as exc:
                    record_step_timing(ctx, "cape_sandbox_wait", wait_started, status="failed", extra={"task_id": task_id, "error": str(exc)})
                    raise
                task_status = str((task.get("data") or {}).get("status") or "")
                record_step_timing(
                    ctx,
                    "cape_sandbox_wait",
                    wait_started,
                    status="completed" if task_status in SUCCESS_STATUSES else "failed",
                    extra={"task_id": task_id, "cape_task_status": task_status or "unknown"},
                )
                if task_status not in SUCCESS_STATUSES:
                    reason = f"CAPE task ended with status {task_status or 'unknown'}"
                    result = {"status": "failed", "mode": "api", "task_id": task_id, "reason": reason, "task": task, "availability": status}
                    (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
                    update_step(ctx, "cape_analysis", "failed", error=reason, output_paths={"cape_task": str(cape_dir / "cape_task.json")})
                    return result

                if progress_callback:
                    progress_callback("importing_cape_report", {"task_id": task_id})
                local_report = client.report_path_for_task(task_id)
                if local_report.exists():
                    summary = client.import_report(local_report, cape_dir, timing_context=ctx)
                    result = {"status": "completed", "mode": "api", "task_id": task_id, "summary": summary, "availability": status}
                    (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
                    update_step(
                        ctx,
                        "cape_analysis",
                        "completed",
                        output_paths={
                            "cape_status": str(cape_dir / "cape_status.json"),
                            "cape_submission": str(cape_dir / "cape_submission.json"),
                            "cape_task": str(cape_dir / "cape_task.json"),
                            "cape_progress": str(cape_dir / "cape_progress.json"),
                            "cape_result": str(cape_dir / "cape_result.json"),
                            "cape_report": str(cape_dir / "cape_report.json"),
                            "cape_summary": str(cape_dir / "cape_summary.md"),
                            "cape_artifacts": str(cape_dir / "cape_artifacts.json"),
                        },
                    )
                    return result
                reason = f"CAPE task {task_id} reported but no local report was found at {local_report}"
                result = {"status": "failed", "mode": "api", "task_id": task_id, "reason": reason, "availability": status}
                (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
                update_step(ctx, "cape_analysis", "failed", error=reason, output_paths={"cape_task": str(cape_dir / "cape_task.json")})
                return result
            reason = "CAPE submission response did not include a task ID"
            result = {"status": "failed", "mode": "api", "reason": reason, "submission": submission, "availability": status}
            (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            update_step(ctx, "cape_analysis", "failed", error=reason, output_paths={"cape_status": str(cape_dir / "cape_status.json")})
            return result

        report_path = None
        sample_sha = _load_input_metadata(ctx).get("sha256")
        if cape_config.get("import_latest_matching_report") and sample_sha:
            report_path = client.find_local_report_by_sha256(str(sample_sha))
        if report_path is None and cape_config.get("mode") == "file":
            report_path = client.latest_local_report()
        if report_path:
            summary = client.import_report(report_path, cape_dir, timing_context=ctx)
            result = {"status": "completed", "mode": "file_import", "summary": summary, "availability": status}
            (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            update_step(
                ctx,
                "cape_analysis",
                "completed",
                output_paths={
                    "cape_status": str(cape_dir / "cape_status.json"),
                    "cape_result": str(cape_dir / "cape_result.json"),
                    "cape_report": str(cape_dir / "cape_report.json"),
                    "cape_summary": str(cape_dir / "cape_summary.md"),
                    "cape_artifacts": str(cape_dir / "cape_artifacts.json"),
                },
            )
            return result

        result = {"status": "skipped", "reason": "No matching CAPE report found and submission disabled or unavailable", "availability": status}
        (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        update_step(ctx, "cape_analysis", "skipped", warning=result["reason"], output_paths={"cape_status": str(cape_dir / "cape_status.json")})
        return result
    except Exception as exc:
        result = {"status": "failed", "reason": str(exc), "availability": status}
        (cape_dir / "cape_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        update_step(ctx, "cape_analysis", "failed", error=str(exc), output_paths={"cape_status": str(cape_dir / "cape_status.json")})
        return result


def extract_stage_artifacts(case_id: str | CaseContext, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id, config)
    config = config or load_config()
    update_step(ctx, "artifact_extraction", "running")

    search_paths: list[str | Path] = [
        ctx.root / "dynamic" / "evidence" / "dropped_files",
        ctx.root / "dynamic" / "raw_logs",
        ctx.root / "dynamic",
    ]
    search_paths.extend(config.get("local_artifact_collection_paths", []))
    marker_metadata = ctx.root / "dynamic" / "evidence" / "api_hit_markers" / "metadata.json"
    markers: list[dict[str, Any]] = []
    if marker_metadata.exists():
        markers = json.loads(marker_metadata.read_text(encoding="utf-8"))

    dropped = collect_dropped_files(ctx, search_paths)
    memory_dumps = collect_memory_dumps(ctx.root)
    cape_artifacts_path = ctx.root / "cape" / "cape_artifacts.json"
    cape_artifacts = json.loads(cape_artifacts_path.read_text(encoding="utf-8")) if cape_artifacts_path.exists() else []
    cape_artifacts = triage_artifacts(cape_artifacts, max_graph_artifacts=int(config.get("max_graph_artifacts", 40)))
    for idx, artifact in enumerate(cape_artifacts, start=1):
        if not artifact.get("is_stage_artifact"):
            continue
        stage_id = artifact.get("stage_id") or f"cape_artifact_{idx:03d}"
        stage_dir = ctx.root / "extracted" / str(stage_id)
        stage_dir.mkdir(parents=True, exist_ok=True)
        src = Path(str(artifact.get("path") or artifact.get("destination_path")))
        if src.exists():
            dst = stage_dir / src.name
            if src.resolve() != dst.resolve():
                shutil.copy2(src, dst)
            artifact["case_path"] = str(dst)
            artifact["destination_path"] = str(dst)
        (stage_dir / "metadata.json").write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    artifacts = markers + dropped + memory_dumps + cape_artifacts

    stage_like_cape = [a for a in cape_artifacts if a.get("is_stage_artifact")]
    if dropped or stage_like_cape:
        status = "completed"
        warning = None
    elif cape_artifacts:
        status = "completed"
        warning = "CAPE completed and artifacts were copied, but no stage-like dropped payloads were identified."
    else:
        status = "skipped"
        warning = "No real dropped stage artifacts were found. API marker files were labeled as markers only."
    update_step(ctx, "artifact_extraction", status, warning=warning, output_paths={"extracted_dir": str(ctx.root / "extracted")})
    return artifacts


def _recursive_analysis(
    ctx: CaseContext,
    artifacts: list[dict[str, Any]],
    max_depth: int,
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Recursively run safe static analysis on supported extracted payloads.

    This function intentionally performs static recursion only. It does not
    execute child artifacts or resubmit them to CAPE. Dynamic child detonation
    should remain an explicit future/optional feature because real malware may
    drop many children and recursive execution can be expensive and noisy.
    """
    config = config or load_config()
    update_step(ctx, "recursive_analysis", "running")

    recursive_root = ctx.root / "recursive"
    recursive_root.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "mode": "static_only",
        "max_depth": max_depth,
        "total_artifacts_seen": len(artifacts),
        "analyzed_count": 0,
        "skipped_count": 0,
        "failed_count": 0,
        "children": [],
    }

    recursive_enabled = bool(config.get("recursive_static_analysis_enabled", True))

    for index, artifact in enumerate(artifacts, start=1):
        file_type = artifact.get("file_type")
        artifact_path = (
            artifact.get("destination_path")
            or artifact.get("case_path")
            or artifact.get("path")
        )

        artifact["recursive_analysis_depth"] = 1
        artifact["recursive_analysis_engine"] = "ghidra_static"

        if not artifact_path:
            artifact["analysis_status"] = "skipped"
            artifact["analysis_skip_reason"] = "artifact path unavailable"
        elif max_depth <= 0:
            artifact["analysis_status"] = "skipped"
            artifact["analysis_skip_reason"] = "max_depth reached"
        elif file_type not in {"pe_or_mz_like"}:
            artifact["analysis_status"] = "skipped"
            artifact["analysis_skip_reason"] = "not a supported PE for recursive static analysis"
        elif not recursive_enabled:
            artifact["analysis_status"] = "skipped"
            artifact["analysis_skip_reason"] = "recursive static analysis disabled by config"
        else:
            child_path = Path(str(artifact_path))
            stage_id = str(artifact.get("stage_id") or f"artifact_{index:03d}")
            child_dir = recursive_root / stage_id
            child_dir.mkdir(parents=True, exist_ok=True)

            ghidra_out = child_dir / "ghidra_out.json"
            candidates_out = child_dir / "stage_candidates.json"
            iocs_out = child_dir / "recursive_iocs.json"

            try:
                child_ghidra = run_ghidra(
                    sample_path=child_path,
                    output_json=ghidra_out,
                    ghidra_headless=config.get("ghidra_headless_path"),
                    script_dir=config.get("ghidra_script_dir"),
                    timeout=int(config.get("recursive_static_timeout_seconds", config.get("ghidra_timeout_seconds", 300))),
                )

                child_candidates = detect_stage_candidates(child_ghidra)
                candidates_out.write_text(json.dumps(child_candidates, indent=2), encoding="utf-8")

                child_iocs = extract_iocs(child_ghidra, {}, [], {})
                iocs_out.write_text(json.dumps(child_iocs, indent=2), encoding="utf-8")

                artifact["analysis_status"] = "completed"
                artifact["analysis_skip_reason"] = None
                artifact["recursive_static_summary"] = _static_summary(child_ghidra)
                artifact["recursive_stage_candidate_count"] = len(child_candidates)
                artifact["recursive_ioc_count"] = sum(len(v) for v in child_iocs.values())
                artifact["recursive_output_paths"] = {
                    "ghidra_out": str(ghidra_out),
                    "stage_candidates": str(candidates_out),
                    "iocs": str(iocs_out),
                }
                summary["analyzed_count"] += 1

            except (GhidraRunnerError, OSError, ValueError) as exc:
                artifact["analysis_status"] = "failed"
                artifact["analysis_skip_reason"] = f"recursive static analysis failed: {exc}"
                artifact["recursive_output_paths"] = {
                    "ghidra_out": str(ghidra_out),
                    "stage_candidates": str(candidates_out),
                    "iocs": str(iocs_out),
                }
                summary["failed_count"] += 1

        if artifact.get("analysis_status") == "skipped":
            summary["skipped_count"] += 1

        summary["children"].append(
            {
                "artifact": artifact_path,
                "stage_id": artifact.get("stage_id"),
                "file_type": file_type,
                "status": artifact.get("analysis_status"),
                "reason": artifact.get("analysis_skip_reason"),
                "recursive_ioc_count": artifact.get("recursive_ioc_count"),
                "recursive_stage_candidate_count": artifact.get("recursive_stage_candidate_count"),
                "output_paths": artifact.get("recursive_output_paths", {}),
            }
        )

        if artifact_path:
            meta_path = Path(str(artifact_path)).parent / "metadata.json"
            if meta_path.parent.exists():
                meta_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    summary_path = recursive_root / "recursive_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    update_step(
        ctx,
        "recursive_analysis",
        "completed" if artifacts else "skipped",
        output_paths={"recursive_summary": str(summary_path)},
    )
    return artifacts


def build_stage_graph_for_case(
    case_id: str | CaseContext,
    artifacts: list[dict[str, Any]],
    iocs: dict[str, list[str]],
    mitre_mappings: list[dict[str, str]],
) -> dict[str, Any]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id)
    update_step(ctx, "stage_graph_generation", "running")
    cape_result_path = ctx.root / "cape" / "cape_result.json"
    cape_result = json.loads(cape_result_path.read_text(encoding="utf-8")) if cape_result_path.exists() else {}
    graph = build_stage_graph(_load_input_metadata(ctx), artifacts, iocs, mitre_mappings, cape_result=cape_result)
    paths = write_graph_outputs(graph, ctx.root / "graph")
    update_step(ctx, "stage_graph_generation", "completed", output_paths=paths)
    return graph


def generate_report(
    case_id: str | CaseContext,
    ghidra_data: dict[str, Any],
    stage_candidates: list[dict[str, Any]],
    runtime_events: dict[str, Any],
    artifacts: list[dict[str, Any]],
    graph: dict[str, Any],
    iocs: dict[str, list[str]],
    mitre_mappings: list[dict[str, str]],
) -> dict[str, Any]:
    ctx = case_id if isinstance(case_id, CaseContext) else _context_from_case_id(case_id)
    update_step(ctx, "report_generation", "running")
    manifest = read_manifest(ctx)
    manifest_for_report = json.loads(json.dumps(manifest))
    manifest_for_report.setdefault("step_status", {})["report_generation"] = "completed"
    if "report_generation" not in manifest_for_report.setdefault("completed_steps", []):
        manifest_for_report["completed_steps"].append("report_generation")
    manifest_for_report["current_status"] = compute_case_status(manifest_for_report)
    cape_result_path = ctx.root / "cape" / "cape_result.json"
    cape_result = json.loads(cape_result_path.read_text(encoding="utf-8")) if cape_result_path.exists() else {}
    x64_result_path = ctx.root / "dynamic" / "x64dbg_live_result.json"
    x64_result = json.loads(x64_result_path.read_text(encoding="utf-8")) if x64_result_path.exists() else {}
    report = build_final_report(
        manifest=manifest_for_report,
        input_metadata=_load_input_metadata(ctx),
        static_summary=_static_summary(ghidra_data),
        stage_candidates=stage_candidates,
        runtime_events=runtime_events,
        artifacts=artifacts,
        graph=graph,
        iocs=iocs,
        mitre_mappings=mitre_mappings,
        backend_status={
            "ghidra": manifest.get("step_status", {}).get("static_analysis"),
            "x64dbg": manifest.get("step_status", {}).get("dynamic_analysis"),
            "cape": manifest.get("step_status", {}).get("cape_analysis"),
            "x64dbg_result": x64_result,
            "cape_result": cape_result,
        },
    )
    paths = write_final_report(report, ctx.root / "reports")
    update_step(ctx, "report_generation", "completed", output_paths=paths)
    manifest = read_manifest(ctx)
    manifest["current_status"] = compute_case_status(manifest)
    write_manifest(ctx, manifest)
    return report



def _mode_to_overrides(mode: str, config: dict[str, Any]) -> dict[str, Any]:
    """Convert public analysis modes into backend configuration.

    Accepted modes:
    - full: Ghidra/static + CAPE sandbox dynamic analysis.
    - static: static analysis only; no sample execution.
    - dynamic: CAPE sandbox dynamic analysis only.
    """
    canonical = _normalize_mode(mode)

    if canonical == "static":
        return {
            "cape": {"enabled": False, "submit_sample": False},
            "run_windows_dynamic": False,
            "vm": {"enabled": False},
            "use_fake_fixture_static": False,
            "use_fake_fixture_dynamic": False,
            "allow_test_fixtures": False,
        }

    if canonical == "dynamic":
        return {
            "cape": {"enabled": True, "mode": "api", "submit_sample": True},
            "run_windows_dynamic": False,
            "vm": {"enabled": False},
            "use_fake_fixture_static": False,
            "use_fake_fixture_dynamic": False,
            "allow_test_fixtures": False,
        }

    return {
        "cape": {"enabled": True, "mode": "api", "submit_sample": True},
        "run_windows_dynamic": False,
        "vm": {"enabled": False},
        "use_fake_fixture_static": False,
        "use_fake_fixture_dynamic": False,
        "allow_test_fixtures": False,
    }


def _selected_backends(config: dict[str, Any], mode: str) -> tuple[dict[str, bool], list[str]]:
    canonical = _normalize_mode(mode)

    static_selected = canonical in {"static", "full"}
    cape_selected = canonical in {"dynamic", "full"} and bool(config.get("cape", {}).get("enabled"))

    selected = {
        "static": static_selected,
        "ghidra": static_selected and bool(config.get("run_ghidra")),
        "cape": cape_selected,
        "x64dbg": False,
    }

    required = ["stage_graph_generation", "report_generation"]

    if static_selected:
        required.extend(["static_analysis", "stage_candidate_detection"])

    if cape_selected:
        required.append("cape_analysis")

    return selected, required


def _skip_step(ctx: CaseContext, step: str, message: str) -> None:
    """Mark an expected, mode-driven skip without treating it as a warning.

    These notices explain why a step did not run, but they should not make a
    successful Static/Dynamic/Full run look degraded.
    """
    update_step(ctx, step, "skipped")
    manifest = read_manifest(ctx)
    manifest.setdefault("notices", []).append({"step": step, "message": message, "time": utc_now()})
    write_manifest(ctx, manifest)


def run_full_pipeline(
    sample_path: str | Path,
    case_name: str | None = None,
    config_path: str | Path | None = None,
    max_depth: int = 2,
    config_overrides: dict[str, Any] | None = None,
    mode: str = "static",
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    config = load_config(config_path)
    from orchestrator.core.config_loader import _merge_dict

    canonical_mode = _normalize_mode(mode)

    config = _merge_dict(config, _mode_to_overrides(mode, config))
    if config_overrides:
        config = _merge_dict(config, config_overrides)

    config["max_recursion_depth"] = max_depth

    ctx = create_case(sample_path, case_name, config["results_root"])
    start_case_timing(ctx)
    selected, required = _selected_backends(config, canonical_mode)
    configure_case_execution(
        ctx,
        analysis_mode=canonical_mode,
        selected_backends=selected,
        required_steps=required,
    )

    ghidra_data = _minimal_static_data(ctx)
    stage_candidates: list[dict[str, Any]] = []
    runtime_events = _empty_runtime_events()
    cape_result: dict[str, Any] = {"status": "skipped", "reason": "CAPE not selected for this mode"}
    artifacts: list[dict[str, Any]] = []

    if progress_callback:
        progress_callback("running_signature_scan", {"case_id": ctx.case_id})

    signature_result = run_signature_analysis(ctx, config)

    if selected["static"]:
        if progress_callback:
            progress_callback("running_static", {"case_id": ctx.case_id})

        ghidra_data = run_static_analysis(ctx, config)
        stage_candidates = detect_stage_boundaries(ctx, ghidra_data)
    else:
        _skip_step(ctx, "static_analysis", "Static analysis disabled by Dynamic Only mode.")
        _skip_step(ctx, "stage_candidate_detection", "Static stage candidate detection disabled by Dynamic Only mode.")

    if selected["x64dbg"]:
        generate_dynamic_plan(ctx, ghidra_data)

        if progress_callback:
            progress_callback("running_x64dbg_dynamic", {"case_id": ctx.case_id})

        run_dynamic_analysis(ctx, config)
        runtime_events = collect_runtime_evidence(ctx, config)
    else:
        # Debugger-assisted x64dbg tracing is not part of the active product flow.
        # It remains a planned reverse-engineering enhancement, so these internal
        # steps are marked skipped silently and do not appear as user-facing notices.
        update_step(ctx, "dynamic_plan_generation", "skipped")
        update_step(ctx, "dynamic_analysis", "skipped")
        update_step(ctx, "runtime_evidence_collection", "skipped")

    if selected["cape"]:
        if progress_callback:
            progress_callback("running_cape_dynamic", {"case_id": ctx.case_id})

        cape_result = run_cape_analysis(ctx, config, progress_callback=progress_callback)
    else:
        cape_dir = ctx.root / "cape"
        cape_dir.mkdir(parents=True, exist_ok=True)
        (cape_dir / "cape_result.json").write_text(json.dumps(cape_result, indent=2), encoding="utf-8")
        _skip_step(ctx, "cape_analysis", "CAPE sandbox backend not selected for this mode.")

    if selected["cape"] or selected["x64dbg"]:
        if progress_callback:
            progress_callback("collecting_artifacts", {"case_id": ctx.case_id})

        artifacts = extract_stage_artifacts(ctx, config)
        artifacts = _recursive_analysis(ctx, artifacts, max_depth=max_depth, config=config)
    else:
        _skip_step(ctx, "artifact_extraction", "No dynamic backend selected, so no runtime artifacts were collected.")
        _skip_step(ctx, "recursive_analysis", "No extracted runtime artifacts available for recursive analysis.")

    iocs = extract_iocs(ghidra_data, runtime_events, artifacts, (cape_result.get("summary") or {}))
    mitre_mappings = map_behaviors(ghidra_data, runtime_events, (cape_result.get("summary") or {}))

    if progress_callback:
        progress_callback("building_graph", {"case_id": ctx.case_id})

    graph = build_stage_graph_for_case(ctx, artifacts, iocs, mitre_mappings)

    if progress_callback:
        progress_callback("generating_report", {"case_id": ctx.case_id})

    generate_report(ctx, ghidra_data, stage_candidates, runtime_events, artifacts, graph, iocs, mitre_mappings)
    finalize_case_status(ctx)

    manifest = read_manifest(ctx)
    return {
        "case_id": manifest["case_id"],
        "case_name": manifest["case_name"],
        "current_status": manifest["current_status"],
        "case_root": str(ctx.root),
        "manifest_path": str(ctx.manifest_path),
        "output_paths": manifest.get("output_paths", {}),
        "warnings": manifest.get("warnings", []),
        "errors": manifest.get("errors", []),
    }

def _context_from_case_id(case_id: str, config: dict[str, Any] | None = None) -> CaseContext:
    config = config or load_config()
    root_base = Path(config["results_root"]).expanduser().resolve()
    matches = list(root_base.glob(f"{case_id}*"))
    root = matches[0] if matches else root_base / case_id
    manifest_path = root / "case_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return CaseContext(
        case_id=str(manifest["case_id"]),
        case_name=str(manifest["case_name"]),
        root=root,
        manifest_path=manifest_path,
        input_sample=Path(str(manifest["sample_path"])),
    )


def get_config_status(config_path: str | Path | None = None) -> dict[str, Any]:
    config = load_config(config_path)
    redaction_enabled = bool(config.get("web_secret_redaction_enabled", True))
    cape_status = CapeClient(config.get("cape", {})).availability().as_dict()
    vm_status = check_vm_status(config.get("vm", {})).as_dict()
    ghidra_path = Path(str(config.get("ghidra_headless_path")))
    cape_services_active = all(v == "active" for v in cape_status.get("services", {}).values())
    cape_ready = bool(cape_status.get("installed") and cape_status.get("reachable") and cape_services_active)
    vm_running = str(vm_status.get("state") or "").lower() == "running"
    default_mode = "full" if cape_ready else "static"
    recommended = (
        "Use Full Analysis for the complete Ghidra + CAPE pipeline."
        if cape_ready
        else "Use Static Only until CAPE service/API availability is repaired."
    )
    security = {
        "upload_max_bytes": int(config.get("web_upload_max_bytes", 104857600)),
        "allowed_upload_extensions": list(config.get("web_allowed_upload_extensions", []) or []),
        "rate_limit_enabled": bool(config.get("web_rate_limit_enabled", True)),
        "rate_limit_window_seconds": int(config.get("web_rate_limit_window_seconds", 60)),
        "rate_limit_max_requests": int(config.get("web_rate_limit_max_requests", 30)),
        "max_concurrent_jobs": int(config.get("web_job_max_concurrent", 2)),
        "secret_values_redacted": redaction_enabled,
        "secrets": {
            "cape_api_token": redact_secret(config.get("cape", {}).get("api_token")),
            "virustotal_api_key": redact_secret(
                config.get("virustotal", {}).get("api_key")
                or os.environ.get("VT_API_KEY")
                or os.environ.get("VIRUSTOTAL_API_KEY")
            ),
            "malwarebazaar_api_key": redact_secret(
                config.get("malwarebazaar", {}).get("api_key")
                or os.environ.get("MALWAREBAZAAR_API_KEY")
            ),
            "urlhaus_auth_key": redact_secret(os.environ.get("URLHAUS_AUTH_KEY")),
        },
    }

    status = {
        "ghidra": {"configured": ghidra_path.exists(), "path": str(ghidra_path), "enabled": bool(config.get("run_ghidra"))},
        "x64dbg": {"configured": bool(config.get("vm", {}).get("x64dbg_path")), "path": config.get("vm", {}).get("x64dbg_path"), "enabled": bool(config.get("run_windows_dynamic"))},
        "windows_vm": vm_status | {"provider": config.get("vm", {}).get("provider") or config.get("vm", {}).get("machinery"), "running": vm_running, "auto_start_allowed": bool(config.get("vm", {}).get("auto_start"))},
        "cape": cape_status | {
            "enabled": bool(config.get("cape", {}).get("enabled")),
            "mode": config.get("cape", {}).get("mode"),
            "services_active": cape_services_active,
            "submission_available": cape_ready,
            "storage_path": config.get("cape", {}).get("storage_path"),
            "vm_name": (cape_status.get("vm_names") or [None])[0],
        },
        "real_malware_mode": bool(config.get("real_malware_mode")),
        "results_root": config.get("results_root"),
        "web_security": security,
        "default_analysis_mode": default_mode,
        "recommended_next_action": recommended,
        "warnings": cape_status.get("warnings", []) + vm_status.get("warnings", []),
    }
    if redaction_enabled:
        status = _redact_config_secrets(status)
    return status

# === StageHawk case timing wrappers v1 ===
from orchestrator.core.timing import (
    finish_case_timing as _timing_finish_case,
    start_case_timing as _timing_start_case,
    timed_case_step_from_args as _timing_step_from_args,
)

_run_signature_analysis_raw_timing = run_signature_analysis
_run_static_analysis_raw_timing = run_static_analysis
_detect_stage_boundaries_raw_timing = detect_stage_boundaries
_run_cape_analysis_raw_timing = run_cape_analysis
_extract_stage_artifacts_raw_timing = extract_stage_artifacts
_recursive_analysis_raw_timing = _recursive_analysis
_build_stage_graph_for_case_raw_timing = build_stage_graph_for_case
_generate_report_raw_timing = generate_report
_run_full_pipeline_raw_timing = run_full_pipeline


def run_signature_analysis(*args, **kwargs):
    return _timing_step_from_args("signature_scan", _run_signature_analysis_raw_timing, *args, **kwargs)


def run_static_analysis(*args, **kwargs):
    return _timing_step_from_args("ghidra_static_analysis", _run_static_analysis_raw_timing, *args, **kwargs)


def detect_stage_boundaries(*args, **kwargs):
    return _timing_step_from_args("stage_candidate_detection", _detect_stage_boundaries_raw_timing, *args, **kwargs)


def run_cape_analysis(*args, **kwargs):
    return _timing_step_from_args("cape_total", _run_cape_analysis_raw_timing, *args, **kwargs)


def extract_stage_artifacts(*args, **kwargs):
    return _timing_step_from_args("artifact_extraction", _extract_stage_artifacts_raw_timing, *args, **kwargs)


def _recursive_analysis(*args, **kwargs):
    return _timing_step_from_args("recursive_analysis", _recursive_analysis_raw_timing, *args, **kwargs)


def build_stage_graph_for_case(*args, **kwargs):
    return _timing_step_from_args("stage_graph_generation", _build_stage_graph_for_case_raw_timing, *args, **kwargs)


def generate_report(*args, **kwargs):
    return _timing_step_from_args("report_generation", _generate_report_raw_timing, *args, **kwargs)


def run_full_pipeline(*args, **kwargs):
    result = None
    ctx_root = None
    try:
        result = _run_full_pipeline_raw_timing(*args, **kwargs)
        ctx_root = result.get("case_root") if isinstance(result, dict) else None
        if ctx_root:
            _timing_finish_case(ctx_root, status=result.get("current_status", "completed"))
        return result
    except Exception:
        # If the case was created before failure, the manifest still captures the error.
        raise
