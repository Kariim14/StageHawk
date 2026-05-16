"""Configuration loading with safe defaults.

The loader intentionally supports a tiny YAML subset so the project does not
need an extra dependency just to read ``config/default.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "results_root": "results/cases",
    "ghidra_headless_path": "/opt/ghidra/support/analyzeHeadless",
    "ghidra_script_dir": "ghidra_scripts",
    "ghidra_timeout_seconds": 180,
    "x64dbg_path": r"C:\Tools\x64dbg_new\release\x64\x64dbg.exe",
    "windows_ssh_host": "malproj-win10",
    "windows_runtime_base": r"C:\malproj_runtime",
    "analysis_timeout_seconds": 60,
    "max_recursion_depth": 2,
    "fake_sample_mode": False,
    "real_malware_mode": False,
    "run_ghidra": True,
    "run_windows_dynamic": False,
    "use_fake_fixture_static": False,
    "use_fake_fixture_dynamic": False,
    "allow_test_fixtures": False,
    "artifact_collection_paths": [
        r"C:\malproj_runtime\logs",
        r"C:\malproj_runtime\output",
        r"C:\malproj_runtime\drops",
        r"C:\malproj_runtime",
    ],
    "cape": {
        "enabled": False,
        "mode": "api",
        "api_base_url": "http://127.0.0.1:8000",
        "api_token": None,
        "install_path": "/opt/CAPEv2",
        "storage_path": "/opt/CAPEv2/storage/analyses",
        "timeout_seconds": 900,
        "poll_interval_seconds": 10,
        "collect_dropped_files": True,
        "collect_reports": True,
        "submit_sample": False,
        "import_latest_matching_report": True,
        "machine": "win10",
        "analysis_timeout_seconds": 120,
        "options": "",
    },
    "vm": {
        "enabled": False,
        "provider": "kvm",
        "machinery": "kvm",
        "name": "win10",
        "auto_start": True,
        "wait_for_ssh_seconds": 180,
        "ssh_host": "malproj-win10",
        "ssh_user": "kareem",
        "runtime_base": r"C:\malproj_runtime",
        "x64dbg_path": r"C:\Tools\x64dbg_new\release\x64\x64dbg.exe",
        "restore_snapshot_before_run": False,
        "snapshot_name": "x64dbg_ready",
        "shutdown_after_run": False,
    },
    "web": {"host": "127.0.0.1", "port": 8088, "upload_dir": "results/uploads"},
    "web_upload_max_bytes": 104857600,
    "web_allowed_upload_extensions": [
        ".exe",
        ".dll",
        ".bin",
        ".dat",
        ".scr",
        ".ps1",
        ".vbs",
        ".js",
        ".zip",
    ],
    "web_job_max_concurrent": 2,
    "web_rate_limit_enabled": True,
    "web_rate_limit_window_seconds": 60,
    "web_rate_limit_max_requests": 30,
    "web_secret_redaction_enabled": True,
}


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"none", "null"}:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _merge_dict(dict(base[key]), value)
        else:
            base[key] = value
    return base


def _read_simple_yaml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_list_key: str | None = None
    current_section: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line:
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        target = data
        if indent >= 2 and current_section:
            target = data.setdefault(current_section, {})

        if stripped.startswith("- ") and current_list_key:
            target.setdefault(current_list_key, []).append(_parse_scalar(stripped[2:]))
            continue

        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            target[key] = _parse_scalar(value)
            current_list_key = None
        else:
            if indent == 0:
                data[key] = {}
                current_section = key
            else:
                target[key] = []
                current_list_key = key

    return data


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    default_path = Path("config/default.yaml")
    path = Path(config_path) if config_path else default_path

    if path.exists():
        try:
            import yaml  # type: ignore

            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            loaded = _read_simple_yaml(path)
        config = _merge_dict(config, loaded)

    return config
