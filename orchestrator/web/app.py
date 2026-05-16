"""FastAPI web/API layer for the orchestrator backend."""

from __future__ import annotations

import json
import shutil
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from orchestrator.core.case_manager import get_case, list_cases
from orchestrator.core.config_loader import load_config
from orchestrator.core.pipeline import get_config_status, run_full_pipeline
from orchestrator.analysis.reputation_lookup import lookup_hash_reputation
from orchestrator.analysis.url_reputation import lookup_url_reputation
from orchestrator.analysis.verdict_engine import build_report_verdict_context
from jinja2 import ChainableUndefined


APP_ROOT = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_ROOT / "templates"))
templates.env.undefined = ChainableUndefined  # tolerate legacy case manifests
app = FastAPI(title="Malware Analysis Orchestrator", version="1.0")
static_dir = APP_ROOT / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
RATE_LIMIT_BUCKETS: dict[tuple[str, str], deque[float]] = defaultdict(deque)
RATE_LIMIT_LOCK = threading.Lock()
RISKY_POST_ENDPOINTS = {"/api/analyze", "/api/reputation/hash", "/api/reputation/url"}


def _config() -> dict[str, Any]:
    return load_config()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(request: Request, config: dict[str, Any]) -> None:
    if not config.get("web_rate_limit_enabled", True):
        return
    if request.url.path not in RISKY_POST_ENDPOINTS:
        return

    window = int(config.get("web_rate_limit_window_seconds", 60))
    max_requests = int(config.get("web_rate_limit_max_requests", 30))
    now = time.monotonic()
    key = (_client_ip(request), request.url.path)

    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS[key]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= max_requests:
            raise HTTPException(status_code=429, detail="rate_limit_exceeded")
        bucket.append(now)


def _allowed_upload_extensions(config: dict[str, Any]) -> set[str]:
    return {
        str(item).lower()
        for item in config.get("web_allowed_upload_extensions", []) or []
    }


def _validate_upload_extension(filename: str, config: dict[str, Any]) -> None:
    allowed = _allowed_upload_extensions(config)
    suffix = Path(filename).suffix.lower()
    if allowed and suffix not in allowed:
        raise HTTPException(
            status_code=400,
            detail="unsupported_file_type_by_current_upload_policy",
        )


def _active_job_count() -> int:
    with JOBS_LOCK:
        return sum(1 for job in JOBS.values() if job.get("status") in {"queued", "running"})


def _check_concurrent_job_limit(config: dict[str, Any]) -> None:
    max_jobs = int(config.get("web_job_max_concurrent", 2))
    if max_jobs > 0 and _active_job_count() >= max_jobs:
        raise HTTPException(status_code=429, detail="too_many_active_jobs")


async def _read_upload_bytes(sample: UploadFile, config: dict[str, Any]) -> bytes:
    max_bytes = int(config.get("web_upload_max_bytes", 104857600))
    declared_size = getattr(sample, "size", None)
    if declared_size is not None and int(declared_size) > max_bytes:
        raise HTTPException(status_code=413, detail="upload_too_large")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await sample.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail="upload_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _case_root(case_id: str) -> Path:
    case = get_case(case_id, _config()["results_root"])
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return Path(str(case["_case_root"]))


def _read_json(path: Path) -> Any:
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"file not found: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _run_job(job_id: str, sample_path: str, case_name: str, mode: str, overrides: dict[str, Any]) -> None:
    started_monotonic = time.monotonic()
    with JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["progress"] = "creating_case"
        JOBS[job_id]["started_at_monotonic"] = started_monotonic
        JOBS[job_id]["elapsed_seconds"] = 0.0

    def progress(state: str, details: dict[str, Any]) -> None:
        with JOBS_LOCK:
            JOBS[job_id]["progress"] = state
            JOBS[job_id]["details"] = details
            JOBS[job_id]["elapsed_seconds"] = round(time.monotonic() - started_monotonic, 1)
            if details.get("task_id"):
                JOBS[job_id]["cape_task_id"] = details.get("task_id")
            if details.get("cape_status"):
                JOBS[job_id]["cape_status"] = details.get("cape_status")
    try:
        result = run_full_pipeline(sample_path, case_name=case_name, mode=mode, config_overrides=overrides, progress_callback=progress)
        with JOBS_LOCK:
            JOBS[job_id].update({
                "status": "completed",
                "result": result,
                "case_id": result["case_id"],
                "elapsed_seconds": round(time.monotonic() - started_monotonic, 1),
            })
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id].update({
                "status": "failed",
                "error": str(exc),
                "elapsed_seconds": round(time.monotonic() - started_monotonic, 1),
            })


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    cases = list_cases(_config()["results_root"])
    return templates.TemplateResponse("dashboard.html", {"request": request, "cases": cases})




@app.get("/url-scan")
def url_scan_page() -> RedirectResponse:
    return RedirectResponse(url="/reputation", status_code=307)


@app.post("/api/reputation/url")
async def api_url_reputation(request: Request) -> JSONResponse:
    _check_rate_limit(request, _config())
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    raw_url = str(payload.get("url") or "").strip()

    try:
        result = lookup_url_reputation(raw_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return JSONResponse(result)


@app.get("/reputation", response_class=HTMLResponse)
def reputation_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("reputation.html", {"request": request})


@app.get("/new", response_class=HTMLResponse)
def new_analysis(request: Request) -> HTMLResponse:
    config_status = get_config_status()
    return templates.TemplateResponse("new_analysis.html", {"request": request, "config_status": config_status, "default_mode": config_status.get("default_analysis_mode", "static")})



@app.get("/system-status", response_class=HTMLResponse)
def system_status(request: Request) -> HTMLResponse:
    status = get_config_status()

    raw_warnings = status.get("warnings", []) or []
    active_warnings = [
        w for w in raw_warnings
        if "x64dbg" not in str(w).lower() and "ssh" not in str(w).lower()
    ]

    return templates.TemplateResponse(
        "system_status.html",
        {
            "request": request,
            "status": status,
            "active_warnings": active_warnings,
            "developer_warnings": raw_warnings,
        },
    )


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: str) -> HTMLResponse:
    root = _case_root(case_id)
    manifest = _read_json(root / "case_manifest.json")
    report = _read_json(root / "reports" / "final_report.json") if (root / "reports" / "final_report.json").exists() else None
    signature_path = root / "static" / "signature_scan.json"
    signature_scan = _read_json(signature_path) if signature_path.exists() else {}
    timing_path = root / "case_timing.json"
    timing = _read_json(timing_path) if timing_path.exists() else {}

    return templates.TemplateResponse(
        "case_detail.html",
        {
            "request": request,
            "manifest": manifest,
            "report": report,
            "signature_scan": signature_scan,
            "timing": timing,
        },
    )


@app.get("/cases/{case_id}/graph", response_class=HTMLResponse)
def graph_view(request: Request, case_id: str) -> HTMLResponse:
    root = _case_root(case_id)
    graph_md = (root / "graph" / "stage_graph.md").read_text(encoding="utf-8") if (root / "graph" / "stage_graph.md").exists() else ""
    graph_dot = (root / "graph" / "stage_graph.dot").read_text(encoding="utf-8") if (root / "graph" / "stage_graph.dot").exists() else ""
    graph = _read_json(root / "graph" / "stage_graph.json")

    report_path = root / "reports" / "final_report.json"
    report = _read_json(report_path) if report_path.exists() else {}
    report_summary = report.get("summary", {}) if isinstance(report, dict) else {}
    backend_summary = report.get("backend_summary", {}) if isinstance(report, dict) else {}

    return templates.TemplateResponse(
        "graph.html",
        {
            "request": request,
            "case_id": case_id,
            "graph": graph,
            "graph_md": graph_md,
            "graph_dot": graph_dot,
            "report_summary": report_summary,
            "backend_summary": backend_summary,
        },
    )


@app.get("/cases/{case_id}/report", response_class=HTMLResponse)
def report_view(request: Request, case_id: str) -> HTMLResponse:
    root = _case_root(case_id)

    report_json_path = root / "reports" / "final_report.json"
    report_md_path = root / "reports" / "final_report.md"

    report = _read_json(report_json_path) if report_json_path.exists() else {}
    report_md = report_md_path.read_text(encoding="utf-8") if report_md_path.exists() else ""
    timing_path = root / "case_timing.json"
    timing = _read_json(timing_path) if timing_path.exists() else report.get("timing", {})
    if timing:
        report["timing"] = timing

    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    cape = report.get("cape_analysis_summary", {}) if isinstance(report, dict) else {}
    signature = report.get("signature_scan", {}) if isinstance(report, dict) else {}
    assessment = report.get("analysis_assessment", {}) if isinstance(report, dict) else {}

    score = 0
    breakdown: list[str] = []

    if cape.get("status") == "completed":
        score += 15
        breakdown.append("CAPE completed")

    cape_score = cape.get("score") or 0
    try:
        cape_score_value = float(cape_score)
    except (TypeError, ValueError):
        cape_score_value = 0.0

    if cape_score_value > 0:
        added = min(30, int(cape_score_value * 3))
        score += added
        breakdown.append(f"CAPE score contributed {added}")

    cape_signatures = int(cape.get("signature_count") or 0)
    if cape_signatures:
        added = min(15, cape_signatures)
        score += added
        breakdown.append(f"CAPE signatures contributed {added}")

    signature_verdict = signature.get("verdict")
    signature_matches = int((signature.get("summary") or {}).get("total_match_count") or 0)
    if signature_verdict == "matched_known_signature" or signature_matches:
        score += 20
        breakdown.append("Local signature match")

    stage_artifacts = int(summary.get("stage_artifact_count") or 0)
    if stage_artifacts:
        added = min(10, stage_artifacts * 2)
        score += added
        breakdown.append(f"Stage artifacts contributed {added}")

    ioc_count = int(summary.get("ioc_count") or 0)
    if ioc_count:
        added = min(10, max(1, ioc_count // 5))
        score += added
        breakdown.append(f"IOCs contributed {added}")

    mitre_count = int(summary.get("mitre_mapping_count") or 0)
    if mitre_count:
        added = min(10, max(1, mitre_count // 2))
        score += added
        breakdown.append(f"Behavior mappings contributed {added}")

    score = min(100, score)

    if score >= 75:
        score_label = "High evidence"
    elif score >= 45:
        score_label = "Medium evidence"
    elif score > 0:
        score_label = "Low evidence"
    else:
        score_label = "No scored evidence"

    stagehawk_score = {
        "score": score,
        "label": score_label,
        "breakdown": breakdown,
        "note": "This is an internal weighted evidence score, not a probability of maliciousness.",
    }

    # Heuristic maliciousness likelihood.
    # This is NOT a calibrated ML probability. It is a transparent scoring model
    # based only on evidence collected by configured local/sandbox/signature sources.
    malicious_score = 0
    malicious_drivers: list[str] = []

    if signature_verdict == "matched_known_signature" or signature_matches:
        malicious_score += 30
        malicious_drivers.append("Local known-malware signature match")

    if cape.get("status") == "completed":
        malicious_score += 5
        malicious_drivers.append("Sandbox execution completed")

    if cape_score_value > 0:
        added = min(35, int(cape_score_value * 4))
        malicious_score += added
        malicious_drivers.append(f"CAPE behavior score contributed {added}")

    if cape_signatures:
        added = min(20, cape_signatures)
        malicious_score += added
        malicious_drivers.append(f"CAPE signatures contributed {added}")

    if stage_artifacts:
        added = min(10, stage_artifacts * 2)
        malicious_score += added
        malicious_drivers.append(f"Dropped/stage-like artifacts contributed {added}")

    useful_suspicious_hits = 0
    try:
        useful_suspicious_hits = int((report.get("static_analysis_summary") or {}).get("useful_suspicious_hit_count") or 0)
    except (TypeError, ValueError):
        useful_suspicious_hits = 0

    if useful_suspicious_hits:
        added = min(10, max(1, useful_suspicious_hits // 3))
        malicious_score += added
        malicious_drivers.append(f"Suspicious static indicators contributed {added}")

    if mitre_count:
        added = min(10, max(1, mitre_count // 2))
        malicious_score += added
        malicious_drivers.append(f"Behavior mappings contributed {added}")

    malicious_score = min(100, malicious_score)

    dynamic_selected = (report.get("selected_backends") or {}).get("cape") or (report.get("case", {}).get("analysis_mode") in {"full", "dynamic"})
    static_only = report.get("case", {}).get("analysis_mode") == "static"

    if malicious_score >= 85:
        malicious_label = "Likely malicious"
        malicious_explanation = "Multiple strong evidence sources indicate malicious or highly suspicious behavior."
    elif malicious_score >= 60:
        malicious_label = "Highly suspicious"
        malicious_explanation = "Sandbox/static evidence shows strong suspicious behavior. Analyst review is recommended."
    elif malicious_score >= 35:
        malicious_label = "Suspicious"
        malicious_explanation = "Some suspicious evidence was collected, but the result should be confirmed with more context."
    elif static_only:
        malicious_label = "Inconclusive static-only result"
        malicious_explanation = "Only static evidence was collected. A low score does not prove the file is safe."
    elif dynamic_selected and cape.get("status") == "completed":
        malicious_label = "No strong malicious evidence observed"
        malicious_explanation = "Configured analysis completed but did not collect strong malicious evidence. This does not guarantee the file is safe."
    else:
        malicious_label = "Inconclusive"
        malicious_explanation = "Configured evidence sources were not sufficient to estimate maliciousness."

    maliciousness = {
        "score": malicious_score,
        "label": malicious_label,
        "drivers": malicious_drivers,
        "explanation": malicious_explanation,
        "note": "This is a heuristic likelihood indicator, not a calibrated mathematical probability.",
    }

    if not assessment:
        assessment = {
            "assessment": "Evidence collected; review required",
            "confidence": "unknown",
            "note": "No assessment block was found in final_report.json.",
        }

    verdict_context = build_report_verdict_context(report, root=root)

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "case_id": case_id,
            "report": report,
            "report_md": report_md,
            "stagehawk_score": verdict_context["stagehawk_score"],
            "maliciousness": verdict_context["maliciousness"],
            "assessment": verdict_context["assessment"],
            "behavior_classification": verdict_context["behavior_classification"],
            "reputation": verdict_context["reputation"],
        },
    )



@app.post("/api/reputation/hash")
async def api_hash_reputation(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    _check_rate_limit(request, _config())
    value = str(payload.get("hash") or payload.get("query") or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="hash is required")

    result = lookup_hash_reputation(value, _config())

    if result.get("status") == "invalid":
        raise HTTPException(status_code=400, detail=result.get("reason"))

    return result


@app.get("/api/cases")
def api_cases() -> list[dict[str, Any]]:
    return list_cases(_config()["results_root"])


@app.post("/api/cases")
def api_create_case() -> dict[str, str]:
    raise HTTPException(status_code=501, detail="Use /api/analyze to create and run a case")


@app.post("/api/analyze")
async def api_analyze(
    request: Request,
    background_tasks: BackgroundTasks,
    sample: UploadFile | None = File(default=None),
    sample_path: str | None = Form(default=None),
    case_name: str = Form(default=""),
    analysis_mode: str = Form(default="full"),
) -> dict[str, Any]:
    config = _config()
    _check_rate_limit(request, config)
    _check_concurrent_job_limit(config)
    upload_dir = Path(str(config.get("web", {}).get("upload_dir", "results/uploads"))).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)

    if sample is not None and sample.filename:
        safe_name = Path(sample.filename).name
        _validate_upload_extension(safe_name, config)
        upload_bytes = await _read_upload_bytes(sample, config)
        dst = upload_dir / safe_name
        dst.write_bytes(upload_bytes)
        selected_sample = dst
    elif sample_path and sample_path.strip():
        selected_sample = Path(sample_path).expanduser().resolve()
        _validate_upload_extension(selected_sample.name, config)
    else:
        raise HTTPException(
            status_code=400,
            detail="No sample provided. Upload a file or enter an explicit sample path.",
        )

    raw_mode = str(analysis_mode or "static").strip().lower().replace("-", "_")
    mode_aliases = {
        "full": "full",
        "full_analysis": "full",
        "static": "static",
        "static_only": "static",
        "dynamic": "dynamic",
        "dynamic_only": "dynamic",
    }
    if raw_mode not in mode_aliases:
        raise HTTPException(status_code=400, detail="invalid analysis mode. Use full, static, or dynamic.")

    analysis_mode = mode_aliases[raw_mode]

    case_name = case_name.strip() or selected_sample.stem

    ghidra_path = Path(str(config.get("ghidra_headless_path", "")))
    ghidra_available = ghidra_path.exists()
    run_live_ghidra = analysis_mode in {"full", "static"} and ghidra_available
    run_cape = analysis_mode in {"full", "dynamic"}

    if analysis_mode in {"full", "static"} and not ghidra_available:
        raise HTTPException(
            status_code=503,
            detail="Ghidra headless is not available. Static analysis cannot run honestly without the configured Ghidra backend.",
        )

    overrides = {
        "run_ghidra": run_live_ghidra,
        "run_windows_dynamic": False,
        "use_fake_fixture_static": False,
        "use_fake_fixture_dynamic": False,
        "allow_test_fixtures": False,
        "cape": {"enabled": run_cape, "mode": "api", "submit_sample": run_cape},
        "vm": {"enabled": False, "auto_start": False},
    }
    job_id = f"job_{len(JOBS) + 1:06d}"
    with JOBS_LOCK:
        JOBS[job_id] = {"job_id": job_id, "status": "queued", "case_name": case_name}
    background_tasks.add_task(_run_job, job_id, str(selected_sample), case_name, analysis_mode, overrides)
    return {"job_id": job_id, "status": "queued"}


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        if job_id not in JOBS:
            raise HTTPException(status_code=404, detail="job not found")
        return dict(JOBS[job_id])


@app.get("/api/cases/{case_id}")
def api_case(case_id: str) -> dict[str, Any]:
    return _read_json(_case_root(case_id) / "case_manifest.json")


@app.get("/api/cases/{case_id}/status")
def api_case_status(case_id: str) -> dict[str, Any]:
    manifest = _read_json(_case_root(case_id) / "case_manifest.json")
    return {
        "case_id": manifest.get("case_id"),
        "current_status": manifest.get("current_status"),
        "step_status": manifest.get("step_status"),
        "completed_steps": manifest.get("completed_steps"),
        "failed_steps": manifest.get("failed_steps"),
        "skipped_steps": manifest.get("skipped_steps"),
        "warnings": manifest.get("warnings"),
        "errors": manifest.get("errors"),
    }


@app.get("/api/cases/{case_id}/report")
def api_case_report(case_id: str) -> Any:
    return _read_json(_case_root(case_id) / "reports" / "final_report.json")


@app.get("/api/cases/{case_id}/graph")
def api_case_graph(case_id: str) -> Any:
    return _read_json(_case_root(case_id) / "graph" / "stage_graph.json")


@app.get("/api/cases/{case_id}/artifacts")
def api_case_artifacts(case_id: str) -> dict[str, Any]:
    root = _case_root(case_id)
    artifacts = []
    for metadata in root.glob("**/metadata.json"):
        try:
            loaded = json.loads(metadata.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                artifacts.extend(loaded)
            else:
                artifacts.append(loaded)
        except Exception:
            continue
    cape_artifacts = root / "cape" / "cape_artifacts.json"
    if cape_artifacts.exists():
        artifacts.extend(json.loads(cape_artifacts.read_text(encoding="utf-8")))
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for artifact in artifacts:
        sha256 = str(artifact.get("sha256") or "")
        location = str(artifact.get("destination_path") or artifact.get("case_path") or artifact.get("path") or artifact.get("name") or "")
        key = ("sha256", sha256) if sha256 else ("location", location)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(artifact)
    return {"case_id": case_id, "artifacts": deduped}


@app.get("/api/config/status")
def api_config_status() -> dict[str, Any]:
    return get_config_status()


@app.get("/api/cases/{case_id}/download/{kind}")
def api_download(case_id: str, kind: str) -> FileResponse:
    root = _case_root(case_id)
    mapping = {
        "report_json": root / "reports" / "final_report.json",
        "report_md": root / "reports" / "final_report.md",
        "graph_json": root / "graph" / "stage_graph.json",
        "graph_dot": root / "graph" / "stage_graph.dot",
    }
    if kind not in mapping or not mapping[kind].exists():
        raise HTTPException(status_code=404, detail="download not found")
    return FileResponse(mapping[kind])
