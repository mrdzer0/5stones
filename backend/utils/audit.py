"""Audit logging for ThreatModelz."""
from __future__ import annotations
import json
import os
from pathlib import Path
from datetime import datetime

AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "./backend/data/audit.log"))


def _ensure_log_dir():
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


_ensure_log_dir()


def log_event(event_type: str, user: str = "system", details: dict = None):
    """Append an audit event to the log file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "user": user,
        "details": details or {}
    }
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def get_recent_events(limit: int = 100) -> list:
    """Return the last N audit events."""
    if not AUDIT_LOG_PATH.exists():
        return []
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").strip().splitlines()
    events = []
    for line in lines[-limit:]:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return list(reversed(events))
