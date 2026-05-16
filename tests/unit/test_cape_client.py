import json

from orchestrator.integrations.cape_client import CapeClient, summarize_cape_report


def test_cape_report_summary_and_import(tmp_path):
    analysis = tmp_path / "analyses" / "42"
    report_dir = analysis / "reports"
    dropped_dir = analysis / "selfextracted"
    report_dir.mkdir(parents=True)
    dropped_dir.mkdir()
    dropped = dropped_dir / "payload.bin"
    dropped.write_bytes(b"MZ_FAKE_EDU_STAGE")
    report = {
        "info": {"id": 42, "machine": {"name": "win10"}, "duration": 12},
        "target": {"file": {"sha256": "a" * 64, "name": "sample.exe"}},
        "malscore": 3.0,
        "malstatus": "suspicious",
        "signatures": [{"name": "demo", "severity": 1, "description": "demo sig", "ttps": ["T1055"]}],
        "behavior": {"processes": [1], "processtree": [], "summary": {}},
        "CAPE": {"payloads": [{}], "configs": []},
        "network": {},
    }
    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    summary = summarize_cape_report(report)
    assert summary["task_id"] == 42
    assert summary["signature_count"] == 1

    client = CapeClient({"storage_path": str(tmp_path / "analyses")})
    found = client.find_local_report_by_sha256("a" * 64)
    assert found == report_path
    imported = client.import_report(report_path, tmp_path / "case" / "cape")
    assert imported["copied_artifacts"][0]["artifact_kind"] == "cape_dropped_file"


def test_cape_unavailable_status(tmp_path):
    client = CapeClient(
        {
            "api_base_url": "http://127.0.0.1:9",
            "install_path": str(tmp_path / "missing"),
            "storage_path": str(tmp_path / "missing_storage"),
        }
    )
    status = client.availability().as_dict()
    assert status["installed"] is False
    assert status["reachable"] is False
    assert status["warnings"]
