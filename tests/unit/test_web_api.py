import json

import pytest
from fastapi.testclient import TestClient

from orchestrator.web.app import app


@pytest.fixture(autouse=True)
def clear_web_state():
    from orchestrator.web import app as web_app

    with web_app.JOBS_LOCK:
        web_app.JOBS.clear()
    with web_app.RATE_LIMIT_LOCK:
        web_app.RATE_LIMIT_BUCKETS.clear()
    yield
    with web_app.JOBS_LOCK:
        web_app.JOBS.clear()
    with web_app.RATE_LIMIT_LOCK:
        web_app.RATE_LIMIT_BUCKETS.clear()


def _test_config(tmp_path, **overrides):
    config = {
        "results_root": str(tmp_path / "cases"),
        "ghidra_headless_path": "/does/not/exist/analyzeHeadless",
        "run_ghidra": False,
        "run_windows_dynamic": False,
        "web": {"upload_dir": str(tmp_path / "uploads")},
        "web_upload_max_bytes": 1024,
        "web_allowed_upload_extensions": [".exe", ".dll", ".bin"],
        "web_job_max_concurrent": 2,
        "web_rate_limit_enabled": False,
        "web_rate_limit_window_seconds": 60,
        "web_rate_limit_max_requests": 30,
        "web_secret_redaction_enabled": True,
        "cape": {"enabled": False, "mode": "api", "submit_sample": False},
        "vm": {"enabled": False, "auto_start": False},
    }
    config.update(overrides)
    return config


def test_web_health_and_config_status():
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    config = client.get("/api/config/status").json()
    assert "cape" in config
    assert "windows_vm" in config
    assert "web_security" in config
    assert config["web_security"]["secret_values_redacted"] is True


def test_web_layout_contains_theme_toggle_and_dashboard_filters():
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert "StageHawk" in response.text
    assert 'href="/static/favicon.svg"' in response.text
    assert "brand-falcon" in response.text
    assert 'id="themeToggle"' in response.text
    assert "data-theme-toggle" in response.text
    assert "stagehawk-theme" in response.text
    assert 'aria-label="Switch to dark mode"' in response.text
    assert 'id="caseSearch"' in response.text
    assert 'id="modeFilter"' in response.text
    assert 'id="statusFilter"' in response.text
    assert 'id="showMoreCases"' in response.text


def test_web_case_listing_report_graph_after_pipeline():
    client = TestClient(app)
    cases = client.get("/api/cases").json()
    assert isinstance(cases, list)
    if not cases:
        return
    case_id = cases[0]["case_id"]
    assert client.get(f"/api/cases/{case_id}/status").status_code == 200
    report_response = client.get(f"/api/cases/{case_id}/report")
    graph_response = client.get(f"/api/cases/{case_id}/graph")
    assert report_response.status_code in {200, 404}
    assert graph_response.status_code in {200, 404}


def test_web_analyze_dynamic_mode_enables_cape(monkeypatch):
    from orchestrator.web import app as web_app

    captured = {}

    def fake_run(sample_path, case_name=None, mode="static", config_overrides=None, progress_callback=None, **_kwargs):
        captured["mode"] = mode
        captured["config_overrides"] = config_overrides
        if progress_callback:
            progress_callback("submitting_to_cape", {"task_id": 123})
        return {
            "case_id": "case_web_test",
            "case_name": case_name,
            "current_status": "completed",
            "case_root": "/tmp/case_web_test",
            "manifest_path": "/tmp/case_web_test/case_manifest.json",
            "output_paths": {},
            "warnings": [],
            "errors": [],
        }

    monkeypatch.setattr(web_app, "run_full_pipeline", fake_run)
    client = TestClient(web_app.app)
    response = client.post(
        "/api/analyze",
        data={
            "sample_path": "samples/fake/fake_dropper_sample.exe",
            "case_name": "web_dynamic",
            "analysis_mode": "dynamic",
        },
    )
    job = response.json()
    status = client.get(f"/api/jobs/{job['job_id']}").json()
    assert status["status"] == "completed"
    assert captured["mode"] == "dynamic"
    assert captured["config_overrides"]["cape"]["enabled"] is True
    assert captured["config_overrides"]["cape"]["submit_sample"] is True
    assert captured["config_overrides"]["run_windows_dynamic"] is False
    assert captured["config_overrides"]["vm"]["enabled"] is False


def test_web_analyze_requires_sample_input():
    from orchestrator.web import app as web_app

    client = TestClient(web_app.app)
    response = client.post(
        "/api/analyze",
        data={
            "case_name": "missing_input",
            "analysis_mode": "static",
        },
    )

    assert response.status_code == 400
    assert "No sample provided" in response.json()["detail"]


def test_web_upload_rejects_oversized_file_without_saving(monkeypatch, tmp_path):
    from orchestrator.web import app as web_app

    monkeypatch.setattr(
        web_app,
        "_config",
        lambda: _test_config(tmp_path, web_upload_max_bytes=4),
    )
    client = TestClient(web_app.app)

    response = client.post(
        "/api/analyze",
        data={"case_name": "oversized", "analysis_mode": "dynamic"},
        files={"sample": ("big.exe", b"12345", "application/octet-stream")},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "upload_too_large"
    assert not (tmp_path / "uploads" / "big.exe").exists()


def test_web_upload_rejects_unsupported_extension(monkeypatch, tmp_path):
    from orchestrator.web import app as web_app

    monkeypatch.setattr(web_app, "_config", lambda: _test_config(tmp_path))
    client = TestClient(web_app.app)

    response = client.post(
        "/api/analyze",
        data={"case_name": "unsupported", "analysis_mode": "dynamic"},
        files={"sample": ("note.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "unsupported_file_type_by_current_upload_policy"
    assert not (tmp_path / "uploads" / "note.txt").exists()


def test_web_upload_allowed_extension_reaches_job_start(monkeypatch, tmp_path):
    from orchestrator.web import app as web_app

    captured = {}

    def fake_run(sample_path, case_name=None, mode="static", config_overrides=None, progress_callback=None, **_kwargs):
        captured["sample_path"] = sample_path
        captured["case_name"] = case_name
        captured["mode"] = mode
        return {
            "case_id": "case_allowed_upload",
            "case_name": case_name,
            "current_status": "completed",
            "case_root": str(tmp_path / "case_allowed_upload"),
            "manifest_path": str(tmp_path / "case_allowed_upload" / "case_manifest.json"),
            "output_paths": {},
            "warnings": [],
            "errors": [],
        }

    monkeypatch.setattr(web_app, "_config", lambda: _test_config(tmp_path))
    monkeypatch.setattr(web_app, "run_full_pipeline", fake_run)
    client = TestClient(web_app.app)

    response = client.post(
        "/api/analyze",
        data={"case_name": "allowed", "analysis_mode": "dynamic"},
        files={"sample": ("allowed.bin", b"abc", "application/octet-stream")},
    )

    assert response.status_code == 200
    job = response.json()
    status = client.get(f"/api/jobs/{job['job_id']}").json()
    assert status["status"] == "completed"
    assert captured["mode"] == "dynamic"
    assert captured["case_name"] == "allowed"
    assert captured["sample_path"].endswith("allowed.bin")
    assert (tmp_path / "uploads" / "allowed.bin").read_bytes() == b"abc"


def test_rate_limit_returns_429_when_exceeded(monkeypatch, tmp_path):
    from orchestrator.web import app as web_app

    monkeypatch.setattr(
        web_app,
        "_config",
        lambda: _test_config(
            tmp_path,
            web_rate_limit_enabled=True,
            web_rate_limit_window_seconds=60,
            web_rate_limit_max_requests=1,
        ),
    )
    monkeypatch.setattr(
        web_app,
        "lookup_hash_reputation",
        lambda value, config: {"status": "completed", "query": value},
    )
    client = TestClient(web_app.app)

    first = client.post("/api/reputation/hash", json={"hash": "a" * 64})
    second = client.post("/api/reputation/hash", json={"hash": "b" * 64})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"] == "rate_limit_exceeded"


def test_config_status_redacts_secret_values(monkeypatch):
    from orchestrator.web import app as web_app

    secret = "stagehawk-test-secret-value"
    monkeypatch.setenv("VT_API_KEY", secret)
    client = TestClient(web_app.app)

    response = client.get("/api/config/status")
    body = response.json()
    rendered = json.dumps(body)

    assert response.status_code == 200
    assert secret not in rendered
    assert body["web_security"]["secrets"]["virustotal_api_key"] == "***configured***"
    assert body["web_security"]["secret_values_redacted"] is True


def test_analyze_rejects_when_too_many_active_jobs(monkeypatch, tmp_path):
    from orchestrator.web import app as web_app

    monkeypatch.setattr(
        web_app,
        "_config",
        lambda: _test_config(tmp_path, web_job_max_concurrent=1),
    )
    with web_app.JOBS_LOCK:
        web_app.JOBS["job_existing"] = {"job_id": "job_existing", "status": "queued"}

    client = TestClient(web_app.app)
    response = client.post(
        "/api/analyze",
        data={
            "sample_path": "samples/fake/fake_dropper_sample.exe",
            "case_name": "blocked",
            "analysis_mode": "dynamic",
        },
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "too_many_active_jobs"


def test_report_and_case_views_render_without_cape_substep_timing(monkeypatch, tmp_path):
    from orchestrator.web import app as web_app

    case_root = tmp_path / "case_missing_cape_timing"
    (case_root / "reports").mkdir(parents=True)
    (case_root / "graph").mkdir()
    (case_root / "static").mkdir()
    (case_root / "case_manifest.json").write_text(
        json.dumps(
            {
                "case_id": "case_missing_cape_timing",
                "case_name": "missing cape timing",
                "current_status": "completed",
                "analysis_mode": "static",
                "selected_backends": {"static": True, "cape": False, "x64dbg": False},
                "completed_steps": [],
                "failed_steps": [],
                "skipped_steps": [],
                "step_status": {},
            }
        ),
        encoding="utf-8",
    )
    report = {
        "case": {
            "case_id": "case_missing_cape_timing",
            "case_name": "missing cape timing",
            "current_status": "completed",
            "analysis_mode": "static",
            "selected_backends": {"static": True, "cape": False},
        },
        "input_sample": {"name": "sample.exe", "size": 1},
        "summary": {},
        "backend_summary": {"static": "Basic static analysis", "dynamic": "Not selected"},
        "static_analysis_summary": {},
        "signature_scan": {},
        "cape_analysis_summary": {"status": "skipped"},
        "runtime_evidence_summary": {},
        "stage_graph": {"nodes": [], "edges": []},
        "extracted_artifacts": [],
        "recursive_analysis_results": [],
        "iocs": {},
        "mitre_style_mapping": [],
        "limitations": [],
        "timing": {"steps": {"signature_scan": {"status": "completed", "duration_seconds": 0.1}}},
    }
    (case_root / "reports" / "final_report.json").write_text(json.dumps(report), encoding="utf-8")
    (case_root / "reports" / "final_report.md").write_text("# Report\n", encoding="utf-8")
    (case_root / "case_timing.json").write_text(json.dumps(report["timing"]), encoding="utf-8")

    monkeypatch.setattr(web_app, "_case_root", lambda case_id: case_root)
    client = TestClient(web_app.app)

    assert client.get("/cases/case_missing_cape_timing").status_code == 200
    assert client.get("/cases/case_missing_cape_timing/report").status_code == 200
