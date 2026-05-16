import json
from pathlib import Path

from orchestrator.core.hashing import sha256_file
from orchestrator.core.pipeline import run_full_pipeline


def test_pipeline_with_cape_report_import(tmp_path):
    sample = Path("samples/fake/fake_dropper_sample.exe")
    storage = tmp_path / "cape_storage"
    report_dir = storage / "7" / "reports"
    report_dir.mkdir(parents=True)
    (storage / "7" / "selfextracted").mkdir()
    (storage / "7" / "selfextracted" / "payload.bin").write_bytes(b"MZ_TEST_STAGE")
    report = {
        "info": {"id": 7, "machine": {"name": "win10"}, "duration": 5},
        "target": {"file": {"sha256": sha256_file(sample), "name": sample.name}},
        "malscore": 1.0,
        "malstatus": "test_report",
        "signatures": [{"name": "test_signature", "severity": 1, "ttps": ["T1055"]}],
        "behavior": {"processes": [], "processtree": [], "summary": {}},
        "CAPE": {"payloads": [{}], "configs": []},
        "network": {},
    }
    (report_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(
        f"results_root: {tmp_path / 'cases'}\n"
        "run_ghidra: false\n"
        "run_windows_dynamic: false\n"
        "use_fake_fixture_static: true\n"
        "allow_test_fixtures: true\n"
        "use_fake_fixture_dynamic: true\n"
        "cape:\n"
        "  enabled: true\n"
        "  mode: file\n"
        f"  storage_path: {storage}\n",
        encoding="utf-8",
    )

    result = run_full_pipeline(
        sample,
        case_name="cape_import",
        config_path=config,
        mode="dynamic",
        config_overrides={"cape": {"enabled": True, "mode": "file", "submit_sample": False, "storage_path": str(storage)}},
    )

    assert result["current_status"] in {"completed", "completed_with_warnings"}
    assert Path(result["case_root"], "cape", "cape_report.json").exists()
    assert Path(result["case_root"], "cape", "cape_artifacts.json").exists()
    timing = json.loads(Path(result["case_root"], "case_timing.json").read_text(encoding="utf-8"))
    assert "cape_import" in timing["steps"]
    assert "cape_artifact_copy" in timing["steps"]
    assert "cape_total" in timing["steps"]
