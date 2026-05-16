import json

from orchestrator.core.artifact_manager import collect_dropped_files, copy_api_markers
from orchestrator.core.case_manager import create_case


def test_artifact_manager_separates_markers_and_dropped_files(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ fake")
    ctx = create_case(sample, "unit_case", tmp_path / "cases")

    marker = tmp_path / "hit_01_VirtualAlloc.bin"
    marker.write_bytes(b"\x90")
    dropped = tmp_path / "dropped_stage2.bin"
    dropped.write_bytes(b"MZ_FAKE_EDU_STAGE2")

    markers = copy_api_markers(ctx, [marker])
    dropped_records = collect_dropped_files(ctx, [tmp_path])

    assert markers[0]["artifact_kind"] == "api_hit_marker"
    assert dropped_records[0]["is_stage_artifact"] is True
    assert (ctx.root / "extracted" / "stage_002" / "metadata.json").exists()

    metadata = json.loads((ctx.root / "dynamic" / "evidence" / "dropped_files" / "metadata.json").read_text())
    assert metadata[0]["stage_id"] == "stage_002"
