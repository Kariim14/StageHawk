from orchestrator.analysis.runtime_log_parser import parse_runtime_log


def test_runtime_log_parser_extracts_api_hits(tmp_path):
    log = tmp_path / "x64dbg.log"
    log.write_text(
        "[MALPROJ] HIT WriteProcessMemory | base=1000 | buffer=2000 | size=28\n"
        "[MALPROJ] HIT connect | sockaddr=3000 | len=10\n",
        encoding="utf-8",
    )

    result = parse_runtime_log(log)

    assert result["event_count"] == 2
    assert result["api_counts"]["WriteProcessMemory"] == 1
    assert result["events"][0]["arguments"]["size"] == "28"
