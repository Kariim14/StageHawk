"""Small status helper used by future GUI/web/chatbot adapters."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from orchestrator.core.case_manager import CaseContext, update_step


@contextmanager
def tracked_step(ctx: CaseContext, step: str) -> Iterator[None]:
    update_step(ctx, step, "running")
    try:
        yield
    except Exception as exc:
        update_step(ctx, step, "failed", error=str(exc))
        raise
    else:
        update_step(ctx, step, "completed")
