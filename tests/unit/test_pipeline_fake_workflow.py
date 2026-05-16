import json
from pathlib import Path

from orchestrator.core.pipeline import run_full_pipeline


def test_fake_sample_pipeline_creates_static_case_outputs(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        f"results_root: {tmp_path / 'cases'}\n"
        "run_ghidra: false\n"
        "run_windows_dynamic: false\n"
        "use_fake_fixture_static: true\n"
        "allow_test_fixtures: true\n"
        "use_fake_fixture_dynamic: true\n",
        encoding="utf-8",
    )

    result = run_full_pipeline(
        Path("samples/fake/fake_dropper_sample.exe"),
        case_name="fake_unit",
        config_path=config,
        mode="static",
    )

    root = Path(result["case_root"])
    manifest = json.loads((root / "case_manifest.json").read_text(encoding="utf-8"))
    report = json.loads((root / "reports" / "final_report.json").read_text(encoding="utf-8"))

    # This test intentionally uses the bundled static fixture, so a fixture
    # warning is expected. Dynamic execution is not expected in Static Only mode.
    assert result["current_status"] == "completed_with_warnings"
    assert any(w["step"] == "static_analysis" for w in result["warnings"])

    assert (root / "case_manifest.json").exists()
    assert (root / "static" / "ghidra_out.json").exists()
    assert (root / "static" / "stage_candidates.json").exists()
    assert (root / "graph" / "stage_graph.json").exists()
    assert (root / "reports" / "final_report.json").exists()
    assert (root / "reports" / "final_report.md").exists()

    # Static Only must not create x64dbg/dynamic plan files.
    assert not (root / "dynamic" / "breakpoint_plan.json").exists()

    assert manifest["analysis_mode"] == "static"
    assert manifest["selected_backends"]["static"] is True
    assert manifest["selected_backends"]["cape"] is False
    assert manifest["selected_backends"]["x64dbg"] is False
    assert manifest["step_status"]["static_analysis"] == "completed"
    assert manifest["step_status"]["stage_candidate_detection"] == "completed"
    assert manifest["step_status"]["dynamic_plan_generation"] == "skipped"
    assert manifest["step_status"]["cape_analysis"] == "skipped"

    assert report["analysis_mode"] == "static"
    assert report["backend_summary"]["dynamic"] == "Not selected"
    assert report["summary"]["artifact_count"] == 0
    assert result["errors"] == []
