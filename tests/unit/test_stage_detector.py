from orchestrator.analysis.stage_detector import detect_stage_candidates


def test_stage_detector_finds_api_and_fake_stage_strings():
    data = {
        "suspicious_addresses": [
            {
                "api": "WriteProcessMemory",
                "from_address": "140001000",
                "containing_function": "s2_process_hollow_sim",
            }
        ],
        "all_strings": ["dropped_stage2.bin"],
    }

    candidates = detect_stage_candidates(data)

    assert len(candidates) == 2
    assert candidates[0]["confidence"] >= candidates[1]["confidence"]
    assert any(c["related_api"] == "WriteProcessMemory" for c in candidates)
