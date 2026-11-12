from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from backend.routers.settings import get_audit_log
from backend.utils import audit


@contextmanager
def temporary_audit_log():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "audit.log"
        with patch.object(audit, "AUDIT_LOG_PATH", path):
            yield path


class AuditIntegrityTests(unittest.TestCase):
    def test_appends_a_sequential_hash_chain_and_marks_events_verified(self):
        with temporary_audit_log() as path:
            audit.log_event("project.created", user="actor-1", details={"project_id": "p1"})
            audit.log_event("project.updated", user="actor-1", details={"project_id": "p1"})

            stored = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            recent = audit.get_recent_events(limit=10)

        self.assertEqual([item["sequence"] for item in stored], [1, 2])
        self.assertEqual(stored[0]["previous_hash"], audit.AUDIT_GENESIS_HASH)
        self.assertEqual(stored[1]["previous_hash"], stored[0]["event_hash"])
        self.assertEqual([item["_integrity_status"] for item in recent], ["verified", "verified"])
        self.assertEqual([item["event_type"] for item in recent], ["project.updated", "project.created"])

    def test_editing_existing_event_blocks_reads_and_future_appends(self):
        with temporary_audit_log() as path:
            audit.log_event("project.created", details={"project_id": "p1"})
            audit.log_event("project.updated", details={"project_id": "p1"})
            first, second = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            first["details"]["project_id"] = "forged-project"
            path.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")
            tampered_bytes = path.read_bytes()

            with self.assertRaises(audit.AuditIntegrityError):
                audit.get_recent_events()
            with self.assertRaises(audit.AuditIntegrityError):
                audit.log_event("project.deleted", details={"project_id": "p1"})

            self.assertEqual(path.read_bytes(), tampered_bytes)

    def test_legacy_history_is_preserved_and_anchored_by_first_chained_event(self):
        legacy_event = {"timestamp": "2026-10-01T00:00:00Z", "event_type": "legacy.event", "user": "legacy", "workspace_id": "team-a", "details": {}}
        legacy_line = (json.dumps(legacy_event, separators=(",", ":")) + "\n").encode("utf-8")
        with temporary_audit_log() as path:
            path.write_bytes(legacy_line)
            audit.log_event("project.created", user="actor-1", details={"project_id": "p1"})
            recent = audit.get_recent_events(limit=10)
            stored = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            preserved_legacy_line = path.read_bytes().splitlines(keepends=True)[0]

        self.assertEqual(preserved_legacy_line, legacy_line)
        self.assertEqual(stored[1]["sequence"], 2)
        self.assertEqual(stored[1]["previous_hash"], hashlib.sha256(legacy_line).hexdigest())
        self.assertEqual(recent[0]["_integrity_status"], "verified")
        self.assertEqual(recent[1]["_integrity_status"], "legacy_unverified")

    def test_concurrent_appends_keep_a_single_ordered_chain(self):
        with temporary_audit_log() as path:
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(lambda index: audit.log_event("concurrent.event", details={"index": index}), range(32)))
            stored = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            recent = audit.get_recent_events(limit=40)

        self.assertEqual(len(stored), 32)
        self.assertEqual([item["sequence"] for item in stored], list(range(1, 33)))
        self.assertTrue(all(item["_integrity_status"] == "verified" for item in recent))

    def test_corrupt_audit_api_fails_closed_without_returning_partial_events(self):
        with patch("backend.routers.settings.workspace_id_for_request", return_value="team-a"), patch(
            "backend.routers.settings.get_recent_events", side_effect=audit.AuditIntegrityError("private file detail")
        ):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(get_audit_log(100, object()))

        self.assertEqual(raised.exception.status_code, 503)
        self.assertNotIn("private file detail", raised.exception.detail)
        self.assertIn("integrity verification failed", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
