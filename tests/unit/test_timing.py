import time
from types import SimpleNamespace

from orchestrator.core.timing import finish_case_timing, read_case_timing, record_step_timing, start_case_timing, start_step_timing


def test_timing_helper_records_multiple_named_steps(tmp_path):
    ctx = SimpleNamespace(case_id="case_timing", case_name="timing", root=tmp_path)

    start_case_timing(ctx)
    first = start_step_timing(ctx, "cape_submission")
    time.sleep(0.001)
    record_step_timing(ctx, "cape_submission", first, status="completed")

    second = start_step_timing(ctx, "cape_sandbox_wait")
    time.sleep(0.001)
    record_step_timing(ctx, "cape_sandbox_wait", second, status="completed", extra={"task_id": 7})
    finish_case_timing(ctx)

    timing = read_case_timing(tmp_path)

    assert "cape_submission" in timing["steps"]
    assert "cape_sandbox_wait" in timing["steps"]
    assert timing["steps"]["cape_sandbox_wait"]["task_id"] == 7
    assert timing["steps"]["cape_submission"]["duration_seconds"] >= 0
    assert timing["total_duration_seconds"] >= 0

