import copy
import asyncio
import csv
import io
import os
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from starlette.requests import Request

from backend.services.formal_report_service import (
    project_context_fingerprint,
    report_snapshot_fingerprint,
    source_manifest,
)
from backend.services.release_decision_service import build_release_decision
from backend.main import app
from backend.utils.access_control import AuthPrincipal
from backend.routers.analysis import update_threat_review
from backend.routers.export import _to_csv, _to_markdown, export_report


def make_current_evidence():
    project = {
        "project_id": "project-p0-test",
        "name": "Synthetic example",
        "description": "Synthetic architecture evidence",
        "environment": "test",
        "data_policy": "local_only",
        "actors": ["Synthetic user"],
        "manual_context": {"owner": "synthetic"},
        "artifact_sources": [],
    }
    dfd = {"revision": 3, "semantic_hash": "e" * 64}
    formal = {
        "schema_version": "formal-report-v1",
        "status": "signed",
        "revision": 7,
        "signed_by": "reviewer-subject-1",
        "signed_at": "2026-10-04T10:00:00+00:00",
        "signed_deployment_profile": "enterprise",
        "signed_identity_mode": "oidc_jwt",
        "analysis_run_id": "analysis-run-7",
        "dfd_revision": dfd["revision"],
        "dfd_semantic_hash": dfd["semantic_hash"],
        "project_context_sha256": project_context_fingerprint(project),
        "source_manifest": source_manifest(project),
    }
    report = {
        "report_revision": 7,
        "analysis_run": {"run_id": "analysis-run-7"},
        "dfd_model": copy.deepcopy(dfd),
        "formal_report": copy.deepcopy(formal),
    }
    snapshot = {
        "revision_id": "report-r7-signed",
        "status": "signed",
        "created_at": formal["signed_at"],
        "formal_report": copy.deepcopy(formal),
        "report": copy.deepcopy(report),
    }
    snapshot["snapshot_sha256"] = report_snapshot_fingerprint(snapshot)
    return project, report, dfd, snapshot, formal


class ReleaseDecisionServiceTests(unittest.TestCase):
    def test_project_release_decision_api_returns_not_ready_for_missing_report(self):
        project = {"project_id": "project-api-test", "name": "Synthetic project", "artifact_sources": []}
        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "disabled"}, clear=False), \
                patch("backend.main.local_development_request_allowed", return_value=True), \
                patch("backend.utils.storage.get_project", return_value=project), \
                patch("backend.routers.analysis.get_report", return_value=None), \
                patch("backend.routers.analysis.get_dfd_model", return_value=None):
            with TestClient(app) as client:
                response = client.get("/api/projects/project-api-test/release-decision")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "project-release-decision-v1")
        self.assertEqual(payload["status"], "not_ready")
        self.assertIn("enterprise_release_authority", {item["code"] for item in payload["blockers"]})
        self.assertIn("report_missing", {item["code"] for item in payload["blockers"]})

    def test_project_release_decision_api_returns_signed_current_snapshot(self):
        project, report, dfd, snapshot, _formal = make_current_evidence()
        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "disabled"}, clear=False), \
                patch("backend.main.local_development_request_allowed", return_value=True), \
                patch("backend.utils.storage.get_project", return_value=project), \
                patch("backend.routers.analysis.get_report", return_value=report), \
                patch("backend.routers.analysis.get_dfd_model", return_value=dfd), \
                patch("backend.routers.analysis.get_report_revision", return_value=snapshot), \
                patch("backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value), \
                patch("backend.routers.analysis.compute_signoff_readiness", return_value={"signoff_ready": True, "blocking_reasons": []}):
            with TestClient(app) as client:
                response = client.get("/api/projects/project-p0-test/release-decision")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["status"], "not_ready")
        self.assertIn("enterprise_release_authority", {item["code"] for item in payload["blockers"]})
        self.assertEqual(payload["approval_actor"], "reviewer-subject-1")
        self.assertEqual(payload["signed_snapshot_sha256"], snapshot["snapshot_sha256"])

    def test_report_api_exposes_enterprise_release_decision_for_report_ui(self):
        project, report, dfd, snapshot, _formal = make_current_evidence()
        dfd_model = MagicMock()
        dfd_model.model_dump.return_value = copy.deepcopy(dfd)
        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "disabled"}, clear=False), \
                patch("backend.main.local_development_request_allowed", return_value=True), \
                patch("backend.routers.analysis.get_authorized_project", return_value=project), \
                patch("backend.routers.analysis.get_report", return_value=report), \
                patch("backend.routers.analysis.get_dfd_model", return_value=dfd), \
                patch("backend.routers.analysis.get_report_revision", return_value=snapshot), \
                patch("backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value), \
                patch("backend.routers.analysis.compute_completeness", return_value={"score": 100, "level": "High"}), \
                patch("backend.routers.analysis.compute_signoff_readiness", return_value={
                    "signoff_ready": True, "blocking_reasons": [], "review_required": False,
                }), \
                patch("backend.routers.analysis.load_dfd_model", return_value=(dfd_model, False)), \
                patch("backend.routers.analysis.recalculate_boundary_crossings"), \
                patch("backend.routers.analysis.validate_dfd_model", return_value={}), \
                patch("backend.routers.analysis.get_analysis_progress", return_value=None), \
                patch("backend.routers.analysis.attach_analysis_state", side_effect=lambda value, _project, _progress: value), \
                patch("backend.services.release_decision_service.release_authority_context", return_value=("local_dev", "disabled")):
            with TestClient(app) as client:
                response = client.get("/api/projects/project-p0-test/report")

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["formal_report"]["status"], "signed")
        self.assertEqual(payload["formal_report"]["release_decision_status"], "not_ready")
        self.assertEqual(payload["release_decision"]["status"], "not_ready")
        self.assertIn("enterprise_release_authority", {
            item["code"] for item in payload["release_decision"]["blockers"]
        })

    def test_enterprise_oidc_release_api_accepts_current_enterprise_signed_snapshot(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from types import SimpleNamespace
        from tests.test_enterprise_api_access import signed_token

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class Jwks:
            def get_signing_key_from_jwt(self, _token):
                return SimpleNamespace(key=key.public_key())

        project, report, dfd, snapshot, _formal = make_current_evidence()
        project["workspace_id"] = "team-a"
        token = signed_token(key, roles=["Reviewer"], workspace="team-a", subject="reviewer-subject-1")
        enterprise_env = {
            "APP_ENV": "enterprise",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
            "CORS_ALLOWED_ORIGINS": "https://5stones.example.test",
            "APP_SECRET_KEY": "enterprise-test-secret-value-32-characters-long",
        }
        with patch.dict(os.environ, enterprise_env, clear=False), \
                patch("backend.utils.access_control._jwks_client", return_value=Jwks()), \
                patch("backend.utils.storage.get_project", return_value=project), \
                patch("backend.routers.analysis.get_report", return_value=report), \
                patch("backend.routers.analysis.get_dfd_model", return_value=dfd), \
                patch("backend.routers.analysis.get_report_revision", return_value=snapshot), \
                patch("backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value), \
                patch("backend.routers.analysis.compute_signoff_readiness", return_value={"signoff_ready": True, "blocking_reasons": []}):
            with TestClient(app) as client:
                response = client.get(
                    "/api/projects/project-p0-test/release-decision",
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["deployment_profile"], "enterprise")
        self.assertEqual(payload["identity_mode"], "oidc_jwt")
        self.assertEqual(payload["signer_deployment_profile"], "enterprise")
        self.assertEqual(payload["signer_identity_mode"], "oidc_jwt")
        self.assertEqual(payload["approval_actor"], "reviewer-subject-1")

    def test_signoff_route_seals_snapshot_and_release_api_accepts_current_revision(self):
        project, report, dfd, _snapshot, _formal = make_current_evidence()
        project["workspace_id"] = None
        report["report_revision"] = 0
        report["formal_report"]["status"] = "draft"
        report["formal_report"]["revision"] = 0
        report["formal_report"]["signed_by"] = None
        report["formal_report"]["signed_at"] = None
        report["dfd_model"] = copy.deepcopy(dfd)
        report_store = {"value": report}
        revision_store = {}

        def save_report(_project_id, value):
            value["report_revision"] = 1
            report_store["value"] = copy.deepcopy(value)
            return value

        def save_revision(_project_id, snapshot):
            revision_store[snapshot["revision_id"]] = copy.deepcopy(snapshot)
            return snapshot

        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "disabled"}, clear=False), \
                patch("backend.main.local_development_request_allowed", return_value=True), \
                patch("backend.routers.analysis.principal_for_request", return_value=AuthPrincipal("verified-reviewer-7", "team-a", frozenset({"reviewer"}), "oidc_jwt")), \
                patch("backend.utils.storage.get_project", return_value=project), \
                patch("backend.routers.analysis.get_report", side_effect=lambda _project_id: copy.deepcopy(report_store["value"])), \
                patch("backend.routers.analysis.save_report", side_effect=save_report), \
                patch("backend.routers.analysis.save_report_revision", side_effect=save_revision), \
                patch("backend.routers.analysis.get_report_revision", side_effect=lambda _project_id, revision_id: copy.deepcopy(revision_store.get(revision_id))), \
                patch("backend.routers.analysis.get_dfd_model", return_value=dfd), \
                patch("backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value), \
                patch("backend.routers.analysis._refresh_quality_gate", side_effect=lambda value: {"signoff_ready": True, "blocking_reasons": []}), \
                patch("backend.routers.analysis.compute_signoff_readiness", return_value={"signoff_ready": True, "blocking_reasons": []}), \
                patch("backend.services.formal_report_service.get_settings", return_value={}), \
                patch("backend.routers.analysis.log_event"):
            with TestClient(app) as client:
                signed = client.post("/api/projects/project-p0-test/report/signoff", json={"reviewer": "attacker-supplied-reviewer"})
                self.assertEqual(signed.status_code, 200, signed.text)
                revision = signed.json()["revision"]
                self.assertEqual(len(revision["snapshot_sha256"]), 64)
                self.assertEqual(signed.json()["formal_report"]["signed_deployment_profile"], "local_dev")
                self.assertEqual(signed.json()["formal_report"]["signed_identity_mode"], "disabled")
                self.assertEqual(signed.json()["formal_report"]["signed_by"], "verified-reviewer-7")
                self.assertNotEqual(signed.json()["formal_report"]["signed_by"], "attacker-supplied-reviewer")

                decision = client.get("/api/projects/project-p0-test/release-decision")

        self.assertEqual(decision.status_code, 200, decision.text)
        self.assertEqual(decision.json()["status"], "not_ready")
        self.assertIn("enterprise_release_authority", {item["code"] for item in decision.json()["blockers"]})
        self.assertIn("signer_enterprise_identity", {item["code"] for item in decision.json()["blockers"]})
        self.assertEqual(decision.json()["approval_actor"], "verified-reviewer-7")

    def test_risk_override_audit_actor_comes_from_principal_not_payload(self):
        project = {"project_id": "project-p0-test", "artifact_sources": []}
        report = {
            "threats": [{
                "threat_id": "threat-1",
                "finding_state": "grounded",
                "risk_override_history": [],
            }],
            "dfd_model": {"flows": [{"id": "flow-1"}], "nodes": [], "data_objects": [], "boundaries": []},
            "trust_boundaries": [],
        }
        request = Request({
            "type": "http", "method": "PATCH", "path": "/api/projects/project-p0-test/threats/threat-1",
            "headers": [], "client": ("127.0.0.1", 50000),
        })
        request.state.principal = AuthPrincipal(
            "verified-appsec-reviewer", "team-a", frozenset({"reviewer"}), "oidc_jwt"
        )
        payload = {
            "risk_override_level": "High",
            "risk_override_reason": "Evidence supports a higher business impact",
            "risk_override_by": "attacker-controlled-actor",
            "risk_override_at": "2000-01-01T00:00:00Z",
            "risk_override_history": [{"reviewer": "attacker-controlled-actor"}],
        }
        with patch("backend.routers.analysis.get_authorized_project", return_value=project), \
                patch("backend.routers.analysis.get_report", return_value=report), \
                patch("backend.routers.analysis.build_project_evidence_catalog", return_value=[]), \
                patch("backend.routers.analysis.normalize_report_evidence", side_effect=lambda value, _project: value), \
                patch("backend.routers.analysis.attach_target_refs"), \
                patch("backend.routers.analysis.propagate_target_refs"), \
                patch("backend.routers.analysis._refresh_quality_gate", return_value={"signoff_ready": False}), \
                patch("backend.routers.analysis.save_report", side_effect=lambda _project_id, value: value), \
                patch("backend.routers.analysis.log_event"):
            result = asyncio.run(update_threat_review("project-p0-test", "threat-1", payload, request))

        threat = result["threat"]
        self.assertEqual(threat["risk_override_by"], "verified-appsec-reviewer")
        self.assertEqual(threat["risk_override_history"][0]["reviewer"], "verified-appsec-reviewer")

    def test_current_signed_report_with_matching_snapshot_is_ready(self):
        project, report, dfd, snapshot, formal = make_current_evidence()

        with patch("backend.services.release_decision_service.release_authority_context", return_value=("enterprise", "oidc_jwt")):
            decision = build_release_decision(
                project, report, dfd, snapshot, {"signoff_ready": True}, signed_metadata=formal
            )

        self.assertEqual(decision["status"], "ready")
        self.assertEqual(decision["approval_actor"], "reviewer-subject-1")
        self.assertEqual(decision["revision_id"], "report-r7-signed")
        self.assertEqual(decision["signed_snapshot_sha256"], snapshot["snapshot_sha256"])
        self.assertEqual(decision["deployment_profile"], "enterprise")
        self.assertEqual(len(decision["decision_fingerprint"]), 64)

    def test_local_development_or_legacy_signer_cannot_be_enterprise_ready(self):
        project, report, dfd, snapshot, formal = make_current_evidence()
        with patch("backend.services.release_decision_service.release_authority_context", return_value=("local_dev", "disabled")):
            local_decision = build_release_decision(project, report, dfd, snapshot, {"signoff_ready": True}, signed_metadata=formal)
        self.assertEqual(local_decision["status"], "not_ready")
        self.assertIn("enterprise_release_authority", {item["code"] for item in local_decision["blockers"]})

        local_signer = {**formal, "signed_deployment_profile": "local_dev", "signed_identity_mode": "disabled"}
        local_snapshot = copy.deepcopy(snapshot)
        local_snapshot["formal_report"] = copy.deepcopy(local_signer)
        local_snapshot["report"]["formal_report"] = copy.deepcopy(local_signer)
        local_snapshot["snapshot_sha256"] = report_snapshot_fingerprint(local_snapshot)
        with patch("backend.services.release_decision_service.release_authority_context", return_value=("enterprise", "oidc_jwt")):
            migrated_decision = build_release_decision(project, report, dfd, local_snapshot, {"signoff_ready": True}, signed_metadata=local_signer)
        self.assertEqual(migrated_decision["status"], "not_ready")
        self.assertIn("signer_enterprise_identity", {item["code"] for item in migrated_decision["blockers"]})

        tampered_signer = {**formal, "signed_by": "payload-injected-reviewer"}
        with patch("backend.services.release_decision_service.release_authority_context", return_value=("enterprise", "oidc_jwt")):
            tampered_decision = build_release_decision(project, report, dfd, snapshot, {"signoff_ready": True}, signed_metadata=tampered_signer)
        self.assertEqual(tampered_decision["status"], "not_ready")
        self.assertIn("signed_approval_metadata_mismatch", {item["code"] for item in tampered_decision["blockers"]})
        self.assertEqual(tampered_decision["approval_actor"], "reviewer-subject-1")

    def test_export_distinguishes_local_signed_history_from_enterprise_release_verdict(self):
        project, report, dfd, snapshot, formal = make_current_evidence()
        formal["signed_deployment_profile"] = "local_dev"
        formal["signed_identity_mode"] = "disabled"
        report["formal_report"] = copy.deepcopy(formal)
        snapshot["formal_report"] = copy.deepcopy(formal)
        snapshot["report"]["formal_report"] = copy.deepcopy(formal)
        snapshot["snapshot_sha256"] = report_snapshot_fingerprint(snapshot)
        dfd_model = MagicMock()
        dfd_model.model_dump.return_value = copy.deepcopy(dfd)

        with patch("backend.routers.export.get_authorized_project", return_value=project), \
                patch("backend.routers.export.get_report", return_value=report), \
                patch("backend.routers.export.get_report_revision", return_value=snapshot), \
                patch("backend.routers.export.get_dfd_model", return_value=dfd), \
                patch("backend.routers.export.get_analysis_progress", return_value=None), \
                patch("backend.routers.export.load_dfd_model", return_value=(dfd_model, False)), \
                patch("backend.routers.export.recalculate_boundary_crossings"), \
                patch("backend.routers.export.validate_dfd_model", return_value={}), \
                patch("backend.routers.export.normalize_report_evidence", side_effect=lambda value, _project: value), \
                patch("backend.routers.export.compute_completeness", return_value={"score": 100, "level": "High"}), \
                patch("backend.routers.export.compute_signoff_readiness", return_value={"signoff_ready": True, "blocking_reasons": []}), \
                patch("backend.routers.export.attach_analysis_state", side_effect=lambda value, _project, _progress: value), \
                patch("backend.routers.export.log_event"), \
                patch("backend.services.release_decision_service.release_authority_context", return_value=("local_dev", "disabled")):
            exported = asyncio.run(export_report("project-p0-test", format="json"))

        self.assertEqual(exported["formal_report"]["status"], "signed")
        self.assertEqual(exported["release_decision"]["status"], "not_ready")
        self.assertEqual(exported["formal_report"]["release_decision_status"], "not_ready")
        self.assertIn("enterprise_release_authority", {
            item["code"] for item in exported["release_decision"]["blockers"]
        })
        markdown = _to_markdown(project, exported)
        self.assertIn("**Formal Report Status:** signed", markdown)
        self.assertIn("**Enterprise Release Decision:** NOT_READY", markdown)
        self.assertIn("`enterprise_release_authority`", markdown)

        rows = list(csv.reader(io.StringIO(_to_csv(exported))))
        header, data = rows
        self.assertEqual(data[header.index("Formal Report Status")], "signed")
        self.assertEqual(data[header.index("Enterprise Release Decision")], "not_ready")
        self.assertIn("enterprise_release_authority", data[header.index("Release Blocker Codes")])
        self.assertEqual(len(data), len(header))

    def test_unsigned_or_unready_report_fails_closed(self):
        project, report, dfd, snapshot, formal = make_current_evidence()
        unsigned = copy.deepcopy(formal)
        unsigned["status"] = "draft"
        result = build_release_decision(project, report, dfd, snapshot, {"signoff_ready": True}, signed_metadata=unsigned)
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("report_unsigned", {item["code"] for item in result["blockers"]})

        result = build_release_decision(project, report, dfd, snapshot, {"signoff_ready": False, "blocking_reasons": ["DFD needs review"]}, signed_metadata=formal)
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("quality_gate", {item["code"] for item in result["blockers"]})

    def test_missing_report_is_not_ready(self):
        result = build_release_decision({}, {}, {}, None, {"signoff_ready": False})
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("report_missing", {item["code"] for item in result["blockers"]})

    def test_context_source_and_dfd_changes_supersede_signed_snapshot(self):
        project, report, dfd, snapshot, formal = make_current_evidence()
        changed_project = copy.deepcopy(project)
        changed_project["auth_method"] = "mTLS"
        result = build_release_decision(changed_project, report, dfd, snapshot, {"signoff_ready": True}, signed_metadata=formal)
        self.assertEqual(result["status"], "superseded")
        self.assertTrue(any("context changed" in item["message"] for item in result["blockers"]))

        changed_dfd = {**dfd, "revision": 4, "semantic_hash": "f" * 64}
        result = build_release_decision(project, report, changed_dfd, snapshot, {"signoff_ready": True}, signed_metadata=formal)
        self.assertEqual(result["status"], "superseded")
        self.assertTrue(any("DFD changed" in item["message"] for item in result["blockers"]))

    def test_missing_or_tampered_snapshot_cannot_be_ready(self):
        project, report, dfd, snapshot, formal = make_current_evidence()
        result = build_release_decision(project, report, dfd, None, {"signoff_ready": True}, signed_metadata=formal)
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("signed_snapshot_missing", {item["code"] for item in result["blockers"]})

        tampered = copy.deepcopy(snapshot)
        tampered["report"]["analysis_run"]["run_id"] = "forged-run"
        result = build_release_decision(project, report, dfd, tampered, {"signoff_ready": True}, signed_metadata=formal)
        self.assertIn(result["status"], {"not_ready", "superseded"})
        self.assertIn("signed_snapshot_integrity", {item["code"] for item in result["blockers"]})

    def test_superseded_status_is_never_reported_ready(self):
        project, report, dfd, snapshot, formal = make_current_evidence()
        superseded = {**formal, "status": "superseded"}
        result = build_release_decision(project, report, dfd, snapshot, {"signoff_ready": True}, signed_metadata=superseded)
        self.assertEqual(result["status"], "superseded")


if __name__ == "__main__":
    unittest.main()
