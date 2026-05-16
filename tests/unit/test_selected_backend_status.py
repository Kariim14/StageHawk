from pathlib import Path

import pytest

from orchestrator.core.pipeline import run_full_pipeline


def test_x64dbg_mode_is_rejected_in_production(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        f"results_root: {tmp_path / 'cases'}\n"
        "run_ghidra: false\n"
        "use_fake_fixture_static: true\n"
        "allow_test_fixtures: true\n"
        "use_fake_fixture_dynamic: false\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid analysis mode"):
        run_full_pipeline(
            Path("samples/fake/fake_dropper_sample.exe"),
            case_name="x64_rejected",
            config_path=config,
            mode="x64dbg",
            config_overrides={"vm": {"auto_start": False}},
        )


def test_cape_selected_but_unavailable_is_not_clean_completed(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        f"results_root: {tmp_path / 'cases'}\n"
        "run_ghidra: false\n"
        "use_fake_fixture_static: true\n"
        "allow_test_fixtures: true\n"
        "use_fake_fixture_dynamic: false\n",
        encoding="utf-8",
    )

    result = run_full_pipeline(
        Path("samples/fake/fake_dropper_sample.exe"),
        case_name="cape_unavailable",
        config_path=config,
        mode="dynamic",
        config_overrides={
            "cape": {
                "enabled": True,
                "mode": "api",
                "submit_sample": True,
                "api_base_url": "http://127.0.0.1:9",
                "timeout_seconds": 1,
            }
        },
    )

    assert result["current_status"] != "completed"
    assert result["errors"]
