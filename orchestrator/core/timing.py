from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timing_path(ctx_or_root: Any) -> Path:
    if hasattr(ctx_or_root, "root"):
        return Path(ctx_or_root.root) / "case_timing.json"
    return Path(ctx_or_root) / "case_timing.json"


def _read_timing(path: Path) -> dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _write_timing(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def start_case_timing(ctx: Any) -> None:
    path = _timing_path(ctx)
    data = _read_timing(path)
    data.setdefault("schema_version", "1.0")
    data.setdefault("case_id", getattr(ctx, "case_id", None))
    data.setdefault("case_name", getattr(ctx, "case_name", None))
    data.setdefault("steps", {})
    data["started_at"] = data.get("started_at") or _now_iso()
    data["_started_monotonic"] = data.get("_started_monotonic") or time.monotonic()
    _write_timing(path, data)


def finish_case_timing(ctx_or_root: Any, status: str = "completed") -> dict[str, Any]:
    path = _timing_path(ctx_or_root)
    data = _read_timing(path)
    started = data.get("_started_monotonic")
    data["finished_at"] = _now_iso()
    data["status"] = status
    if isinstance(started, (int, float)):
        duration = round(time.monotonic() - float(started), 3)
        data["duration_seconds"] = duration
        data["total_duration_seconds"] = duration
    data.pop("_started_monotonic", None)
    _write_timing(path, data)
    return data


def start_step_timing(
    ctx: Any,
    step: str,
    status: str = "running",
    extra: dict[str, Any] | None = None,
) -> float:
    started = time.monotonic()
    path = _timing_path(ctx)
    data = _read_timing(path)
    data.setdefault("schema_version", "1.0")
    data.setdefault("case_id", getattr(ctx, "case_id", None))
    data.setdefault("case_name", getattr(ctx, "case_name", None))
    steps = data.setdefault("steps", {})
    entry = steps.setdefault(step, {})
    entry["status"] = status
    entry["started_at"] = _now_iso()
    if extra:
        entry.update(extra)
    _write_timing(path, data)
    return started


def record_step_timing(
    ctx: Any,
    step: str,
    started_monotonic: float,
    status: str = "completed",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path = _timing_path(ctx)
    data = _read_timing(path)
    data.setdefault("schema_version", "1.0")
    data.setdefault("case_id", getattr(ctx, "case_id", None))
    data.setdefault("case_name", getattr(ctx, "case_name", None))
    steps = data.setdefault("steps", {})

    entry = steps.setdefault(step, {})
    entry["status"] = status
    entry["finished_at"] = _now_iso()
    entry["duration_seconds"] = round(time.monotonic() - started_monotonic, 3)
    if extra:
        entry.update(extra)

    _write_timing(path, data)
    return entry


def timed_case_step(ctx: Any, step: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    started = time.monotonic()
    path = _timing_path(ctx)
    data = _read_timing(path)
    data.setdefault("schema_version", "1.0")
    data.setdefault("case_id", getattr(ctx, "case_id", None))
    data.setdefault("case_name", getattr(ctx, "case_name", None))
    data.setdefault("steps", {}).setdefault(step, {})["started_at"] = _now_iso()
    _write_timing(path, data)

    try:
        result = func(*args, **kwargs)
    except Exception as exc:
        record_step_timing(ctx, step, started, status="failed", extra={"error": str(exc)})
        raise

    record_step_timing(ctx, step, started, status="completed")
    return result


def timed_case_step_from_args(step: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    ctx = args[0] if args and hasattr(args[0], "root") else None
    if ctx is None:
        return func(*args, **kwargs)
    return timed_case_step(ctx, step, func, *args, **kwargs)


def read_case_timing(root: Path) -> dict[str, Any]:
    return _read_timing(Path(root) / "case_timing.json")


def format_duration(seconds: Any) -> str:
    try:
        value = float(seconds)
    except (TypeError, ValueError):
        return "-"
    if value < 60:
        return f"{value:.1f}s"
    minutes = int(value // 60)
    secs = int(value % 60)
    return f"{minutes}m {secs}s"
