"""Workspace-aware audit events with a locally verifiable append chain.

The hash chain detects accidental edits, insertions, and interior deletions. It
is not a substitute for a remote/WORM sink: a host administrator can rewrite
the whole file or truncate its tail unless an external checkpoint is retained.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "./backend/data/audit.log"))
_audit_actor: ContextVar[str] = ContextVar("5stones_audit_actor", default="system")
_audit_workspace: ContextVar[str | None] = ContextVar("5stones_audit_workspace", default=None)
AUDIT_CHAIN_VERSION = 1
AUDIT_GENESIS_HASH = "0" * 64


class AuditIntegrityError(RuntimeError):
    """Raised when persisted audit history cannot be verified."""


def set_audit_actor(actor: str):
    """Set the verified request actor for audit events in this request context."""
    return _audit_actor.set(str(actor or "system"))


def reset_audit_actor(token) -> None:
    _audit_actor.reset(token)


def set_audit_workspace(workspace_id: str | None):
    return _audit_workspace.set(str(workspace_id).strip() if workspace_id else None)


def reset_audit_workspace(token) -> None:
    _audit_workspace.reset(token)


def _ensure_log_dir():
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


_ensure_log_dir()


def _canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _event_hash(event: dict) -> str:
    unsigned = {key: value for key, value in event.items() if key != "event_hash"}
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def _read_verified_log(raw: bytes) -> tuple[list[dict], int, int, str]:
    """Parse complete lines and verify the chained suffix without rewriting history."""
    events: list[dict] = []
    legacy_lines: list[bytes] = []
    legacy_count = 0
    chain_count = 0
    previous_hash: str | None = None
    chain_started = False
    lines = raw.splitlines(keepends=True)

    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.endswith(b"\n"):
            raise AuditIntegrityError(f"Audit log has an incomplete record at line {line_number}.")
        payload = raw_line[:-1]
        if payload.endswith(b"\r"):
            payload = payload[:-1]
        try:
            event = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError(f"Audit log has an invalid record at line {line_number}.") from exc
        if not isinstance(event, dict):
            raise AuditIntegrityError(f"Audit log record {line_number} is not an object.")

        chain_version = event.get("audit_chain_version")
        if chain_version is None:
            if chain_started:
                raise AuditIntegrityError(f"Unchained record appears after the hash chain at line {line_number}.")
            legacy_lines.append(raw_line)
            legacy_count += 1
            event["_integrity_status"] = "legacy_unverified"
            events.append(event)
            continue

        if type(chain_version) is not int or chain_version != AUDIT_CHAIN_VERSION:
            raise AuditIntegrityError(f"Unsupported audit chain version at line {line_number}.")
        if not chain_started:
            legacy_anchor = hashlib.sha256(b"".join(legacy_lines)).hexdigest() if legacy_lines else AUDIT_GENESIS_HASH
            expected_previous = legacy_anchor
            expected_sequence = legacy_count + 1
        else:
            expected_previous = str(previous_hash)
            expected_sequence = legacy_count + chain_count + 1
        if event.get("previous_hash") != expected_previous:
            raise AuditIntegrityError(f"Audit chain predecessor mismatch at line {line_number}.")
        if type(event.get("sequence")) is not int or event.get("sequence") != expected_sequence:
            raise AuditIntegrityError(f"Audit chain sequence mismatch at line {line_number}.")
        supplied_hash = str(event.get("event_hash") or "")
        if len(supplied_hash) != 64 or supplied_hash != _event_hash(event):
            raise AuditIntegrityError(f"Audit event hash mismatch at line {line_number}.")

        chain_started = True
        chain_count += 1
        previous_hash = supplied_hash
        event["_integrity_status"] = "verified"
        events.append(event)

    if not chain_started:
        head = hashlib.sha256(b"".join(legacy_lines)).hexdigest() if legacy_lines else AUDIT_GENESIS_HASH
    else:
        head = str(previous_hash)
    return events, legacy_count, chain_count, head


def log_event(event_type: str, user: str = "system", details: dict = None):
    """Append a hash-chained event under a single-host file lock.

    Existing unchained history is retained as a legacy prefix and anchored by
    the first chained event. Writes fail closed when any existing record fails
    verification.
    """
    if user == "system":
        user = _audit_actor.get()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user": user,
        "workspace_id": _audit_workspace.get(),
        "details": details or {}
    }
    _ensure_log_dir()
    with open(AUDIT_LOG_PATH, "a+b") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            stream.seek(0)
            raw = stream.read()
            _events, legacy_count, chain_count, previous_hash = _read_verified_log(raw)
            entry.update({
                "audit_chain_version": AUDIT_CHAIN_VERSION,
                "sequence": legacy_count + chain_count + 1,
                "previous_hash": previous_hash,
            })
            entry["event_hash"] = _event_hash(entry)
            stream.seek(0, os.SEEK_END)
            stream.write((json.dumps(entry, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def get_recent_events(limit: int = 100, workspace_id: str | None = None) -> list:
    """Return the last N events only after verifying the complete audit chain."""
    if not AUDIT_LOG_PATH.exists():
        return []
    with open(AUDIT_LOG_PATH, "rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        try:
            raw = stream.read()
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    all_events, _legacy_count, _chain_count, _head = _read_verified_log(raw)
    events = []
    workspace_id = workspace_id or _audit_workspace.get()
    for event in reversed(all_events):
        if workspace_id and event.get("workspace_id") != workspace_id:
            continue
        events.append(event)
        if len(events) >= max(int(limit), 1):
            break
    return events
