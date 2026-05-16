from orchestrator.analysis.artifact_classifier import classify_artifact


def test_marker_file_is_not_stage_artifact(tmp_path):
    marker = tmp_path / "hit_01_VirtualAlloc.bin"
    marker.write_bytes(b"\x90")

    result = classify_artifact(marker)

    assert result["artifact_kind"] == "api_hit_marker"
    assert result["is_stage_artifact"] is False


def test_dropped_stage_file_is_stage_artifact(tmp_path):
    dropped = tmp_path / "dropped_stage2.bin"
    dropped.write_bytes(b"MZ_FAKE_EDU_STAGE2")

    result = classify_artifact(dropped)

    assert result["artifact_kind"] == "dropped_file"
    assert result["is_stage_artifact"] is True
    assert result["stage_number"] == 2
