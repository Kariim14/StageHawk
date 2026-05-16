import json

from orchestrator.core.case_manager import create_case, update_step


def test_case_manifest_step_updates(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    ctx = create_case(sample, "manifest_case", tmp_path / "cases")

    update_step(ctx, "static_analysis", "completed", output_paths={"ghidra_out": "x"})

    manifest = json.loads(ctx.manifest_path.read_text())
    assert "static_analysis" in manifest["completed_steps"]
    assert manifest["output_paths"]["ghidra_out"] == "x"
