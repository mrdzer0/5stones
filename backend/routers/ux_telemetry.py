"""Minimal, anonymous task-completion telemetry; deliberately separate from audit logs."""
from __future__ import annotations

import json
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, conlist

from backend.utils.storage import DATA_DIR

router = APIRouter(prefix="/api/ux-telemetry", tags=["ux-telemetry"])
_directory = DATA_DIR / "ux_telemetry"
_write_lock = threading.Lock()
_MAX_DAILY_BYTES = 5 * 1024 * 1024


class TaskEvent(BaseModel):
    event: Literal["task.completed"]
    task: Literal["analysis_run", "finding_review", "boundary_review", "dfd_edit", "report_export", "evidence_review"]
    surface: Literal["analysis", "model", "findings", "action-plan", "evidence", "report"]
    outcome: Literal["success", "partial", "failed"]
    phase: Literal["context", "model", "findings", "action-plan", "evidence", "signoff"] | None = None
    duration_bucket: Literal["lt_5s", "5_30s", "30_120s", "gt_120s"] | None = None
    format: Literal["markdown", "csv", "json"] | None = None

    class Config:
        extra = "forbid"


class EventBatch(BaseModel):
    events: conlist(TaskEvent, min_length=1, max_length=25)

    class Config:
        extra = "forbid"


class BatchAccepted(BaseModel):
    accepted: int


def _prune_old_files(today: date) -> None:
    cutoff = today - timedelta(days=30)
    for path in _directory.glob("*.jsonl"):
        try:
            if date.fromisoformat(path.stem) < cutoff:
                path.unlink(missing_ok=True)
        except ValueError:
            continue


@router.post("/events", response_model=BatchAccepted)
def record_events(batch: EventBatch) -> BatchAccepted:
    """Accept only coarse task metadata; no IDs, URLs, request headers, or free text."""
    now = datetime.now(timezone.utc)
    day = now.date()
    _directory.mkdir(parents=True, exist_ok=True)
    path = _directory / f"{day.isoformat()}.jsonl"
    rows = [json.dumps({"schema_version": 1, "recorded_at": now.isoformat(), **event.dict(exclude_none=True)}, separators=(",", ":")) for event in batch.events]
    payload = "\n".join(rows) + "\n"
    encoded = payload.encode("utf-8")
    with _write_lock:
        _prune_old_files(day)
        current_size = path.stat().st_size if path.exists() else 0
        if current_size + len(encoded) > _MAX_DAILY_BYTES:
            raise HTTPException(status_code=429, detail="Daily anonymous telemetry limit reached")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(payload)
    return BatchAccepted(accepted=len(batch.events))
