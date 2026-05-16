import json
from pathlib import Path

from orchestrator.core.pipeline import run_full_pipeline


def test_pipeline_with_cape_disabled(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        f"results_root: {tmp_path / 'cases'}\n"
        "run_ghidra: false\n"
        "run_windows_dynamic: false\n"
        "use_fake_fixture_static: true\n"
        "allow_test_fixtures: true\n"
        "use_fake_fixture_dynamic: true\n"
        "cape:\n"
        "  enabled: false\n",
        encoding="utf-8",
    )

    result = run_full_pipeline(
        Path("samples/fake/fake_dropper_sample.exe"),
        case_name="cape_disabled",
        config_path=config,
        mode="static",
    )

    root = Path(result["case_root"])
    manifest = json.loads((root / "case_manifest.json").read_text(encoding="utf-8"))

    # Static fixture usage is still a real warning in this test config.
    assert result["current_status"] == "completed_with_warnings"
    assert any(w["step"] == "static_analysis" for w in result["warnings"])

    # CAPE is not selected in Static Only mode, so it should be skipped cleanly,
    # not treated as a warning/error.
    assert not any(w["step"] == "cape_analysis" for w in result["warnings"])
    assert manifest["selected_backends"]["cape"] is False
    assert manifest["step_status"]["cape_analysis"] == "skipped"
    assert any(n["step"] == "cape_analysis" for n in manifest.get("notices", []))
    assert result["errors"] == []
