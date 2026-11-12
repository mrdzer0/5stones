import asyncio
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from backend.main import app, audit_request_actor
from backend.utils import audit, storage


def signed_token(private_key, *, roles, workspace="team-a", subject="user-1"):
    return jwt.encode({
        "iss": "https://idp.example.test/",
        "aud": "5stones-api",
        "sub": subject,
        "workspace_id": workspace,
        "roles": roles,
        "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
    }, private_key, algorithm="RS256", headers={"kid": "api-test-key"})


class EnterpriseApiAccessTests(unittest.TestCase):
    def test_unauthenticated_local_dev_middleware_rejects_remote_client(self):
        remote = Request({
            "type": "http", "method": "GET", "path": "/api/health", "headers": [],
            "client": ("203.0.113.25", 50000),
        })
        loopback = Request({
            "type": "http", "method": "GET", "path": "/api/health", "headers": [],
            "client": ("127.0.0.1", 50000),
        })
        async def endpoint(_request):
            return Response("ok", status_code=200)

        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "disabled", "HOST": "127.0.0.1"}, clear=False):
            denied = asyncio.run(audit_request_actor(remote, endpoint))
            allowed = asyncio.run(audit_request_actor(loopback, endpoint))
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(allowed.status_code, 200)

    def test_api_route_inventory_has_no_unclassified_public_routes(self):
        public_routes = {
            "/api/health",
            "/api/ux-telemetry/events",
            "/api/auth/config",
            "/api/auth/register",
            "/api/auth/login",
        }
        developer_docs_routes = {path for path in (app.docs_url, app.redoc_url, app.openapi_url) if path}
        observed_public = set()
        observed_developer_docs = set()

        def walk(dependency):
            yield dependency.call
            for child in dependency.dependencies:
                yield from walk(child)

        for route in app.routes:
            path = getattr(route, "path", "")
            if not path.startswith("/api"):
                continue
            if path in public_routes:
                observed_public.add(path)
                continue
            if path in developer_docs_routes:
                observed_developer_docs.add(path)
                continue
            self.assertTrue(hasattr(route, "dependant"), f"Unclassified API route type: {type(route).__name__} {path}")
            calls = {
                getattr(call, "__name__", "")
                for call in walk(route.dependant)
                if call is not None
            }
            self.assertIn("_require_workspace_access_dependency", calls, f"Unprotected API route: {sorted(route.methods or [])} {path}")

        self.assertEqual(observed_public, public_routes)
        self.assertEqual(observed_developer_docs, developer_docs_routes)

    def test_enterprise_profile_disables_openapi_and_api_docs_routes(self):
        environment = os.environ.copy()
        environment.update({"APP_ENV": "enterprise", "AUTH_MODE": "oidc_jwt"})
        check = subprocess.run(
            [sys.executable, "-c", "from backend.main import app; assert app.docs_url is None; assert app.redoc_url is None; assert app.openapi_url is None; assert not any(getattr(route, 'path', '').startswith('/api/docs') or getattr(route, 'path', '') == '/api/openapi.json' for route in app.routes)"],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(check.returncode, 0, check.stderr[:500])

    def test_health_is_public_but_settings_and_projects_require_identity(self):
        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "oidc_jwt"}, clear=False):
            with TestClient(app) as client:
                self.assertEqual(client.get("/api/health").status_code, 200)
                self.assertEqual(client.get("/api/settings").status_code, 401)
                self.assertEqual(client.get("/api/projects").status_code, 401)
                self.assertEqual(client.get("/api/projects/missing/release-decision").status_code, 401)

    def test_admin_only_settings_and_reviewer_only_signoff(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class Jwks:
            def get_signing_key_from_jwt(self, token):
                return SimpleNamespace(key=key.public_key())

        env = {
            "APP_ENV": "local_dev",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with patch.dict(os.environ, env, clear=False), patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
            with TestClient(app) as client:
                analyst = signed_token(key, roles=["Analyst"])
                headers = {"Authorization": f"Bearer {analyst}"}
                self.assertEqual(client.get("/api/settings", headers=headers).status_code, 403)
                self.assertEqual(client.post("/api/projects/missing/report/signoff", headers=headers, json={}).status_code, 403)

                reviewer = signed_token(key, roles=["Reviewer"], subject="reviewer-1")
                reviewer_headers = {"Authorization": f"Bearer {reviewer}"}
                # Reviewer passes the route role check and reaches resource lookup.
                self.assertEqual(client.post("/api/projects/missing/report/signoff", headers=reviewer_headers, json={}).status_code, 404)
                self.assertEqual(client.get("/api/projects/missing/release-decision", headers=reviewer_headers).status_code, 404)

                admin = signed_token(key, roles=["Admin"], subject="admin-1")
                admin_headers = {"Authorization": f"Bearer {admin}"}
                self.assertEqual(client.get("/api/settings", headers=admin_headers).status_code, 200)
                self.assertEqual(client.post("/api/projects/missing/report/signoff", headers=admin_headers, json={}).status_code, 403)

    def test_provider_settings_and_audit_are_workspace_scoped(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class Jwks:
            def get_signing_key_from_jwt(self, token):
                return SimpleNamespace(key=key.public_key())

        env = {
            "APP_ENV": "local_dev",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            with patch.object(storage, "WORKSPACE_SETTINGS_DIR", temp_path / "workspace_settings"), \
                    patch.object(audit, "AUDIT_LOG_PATH", temp_path / "audit.log"), \
                    patch.dict(os.environ, env, clear=False), \
                    patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
                with TestClient(app) as client:
                    team_a = signed_token(key, roles=["Admin"], workspace="team-a", subject="admin-a")
                    team_a_headers = {"Authorization": f"Bearer {team_a}"}
                    created = client.post("/api/settings/providers", headers=team_a_headers, json={
                        "name": "Team A provider",
                        "provider_type": "openai",
                        "base_url": "https://api.openai.com/v1",
                        "model": "gpt-4o-mini",
                        "api_key": "team-a-secret-key",
                    })
                    self.assertEqual(created.status_code, 200)
                    team_a_settings = client.get("/api/settings", headers=team_a_headers).json()
                    self.assertEqual(len(team_a_settings["providers"]), 1, team_a_settings)
                    team_a_events = client.get("/api/settings/audit", headers=team_a_headers).json()
                    self.assertEqual(len(team_a_events), 1)
                    self.assertEqual(team_a_events[0]["user"], "admin-a")
                    self.assertEqual(team_a_events[0]["workspace_id"], "team-a")

                    team_b = signed_token(key, roles=["Admin"], workspace="team-b", subject="admin-b")
                    team_b_headers = {"Authorization": f"Bearer {team_b}"}
                    self.assertEqual(client.get("/api/settings", headers=team_b_headers).json()["providers"], [])
                    self.assertEqual(client.get("/api/settings/audit", headers=team_b_headers).json(), [])

    def test_project_update_rejects_server_owned_fields_and_preserves_revision(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class Jwks:
            def get_signing_key_from_jwt(self, token):
                return SimpleNamespace(key=key.public_key())

        env = {
            "APP_ENV": "local_dev",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            with patch.object(storage, "PROJECTS_DIR", temp_path / "projects"), \
                    patch.object(storage, "REPORTS_DIR", temp_path / "reports"), \
                    patch.object(storage, "DFD_MODELS_DIR", temp_path / "dfd_models"), \
                    patch.object(storage, "ANALYSIS_RUNS_DIR", temp_path / "analysis_runs"), \
                    patch.object(storage, "REPORT_REVISIONS_DIR", temp_path / "report_revisions"), \
                    patch.object(audit, "AUDIT_LOG_PATH", temp_path / "audit.log"), \
                    patch.dict(os.environ, env, clear=False), \
                    patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
                with TestClient(app) as client:
                    analyst = signed_token(key, roles=["Analyst"], workspace="team-a")
                    headers = {"Authorization": f"Bearer {analyst}"}
                    created = client.post("/api/projects", headers=headers, json={"name": "Scoped project"})
                    self.assertEqual(created.status_code, 200, created.text)
                    project_id = created.json()["project_id"]
                    self.assertEqual(created.json()["workspace_id"], "team-a")

                    malicious_update = client.put(f"/api/projects/{project_id}", headers=headers, json={
                        "description": "should not persist",
                        "workspace_id": "team-b",
                        "project_revision": 999,
                    })
                    self.assertEqual(malicious_update.status_code, 422, malicious_update.text)

                    unchanged = client.get(f"/api/projects/{project_id}", headers=headers)
                    self.assertEqual(unchanged.status_code, 200, unchanged.text)
                    self.assertEqual(unchanged.json()["workspace_id"], "team-a")
                    self.assertEqual(unchanged.json()["project_revision"], 1)
                    self.assertIsNone(unchanged.json().get("description"))

                    updated = client.put(f"/api/projects/{project_id}", headers=headers, json={
                        "description": "approved editable field",
                    })
                    self.assertEqual(updated.status_code, 200, updated.text)
                    self.assertEqual(updated.json()["description"], "approved editable field")
                    self.assertEqual(updated.json()["workspace_id"], "team-a")
                    self.assertEqual(updated.json()["project_revision"], 2)

    def test_artifact_parse_race_returns_conflict_without_losing_concurrent_project_edit(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class Jwks:
            def get_signing_key_from_jwt(self, token):
                return SimpleNamespace(key=key.public_key())

        env = {
            "APP_ENV": "local_dev",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            with patch.object(storage, "PROJECTS_DIR", temp_path / "projects"), \
                    patch.object(storage, "REPORTS_DIR", temp_path / "reports"), \
                    patch.object(storage, "DFD_MODELS_DIR", temp_path / "dfd_models"), \
                    patch.object(storage, "ANALYSIS_RUNS_DIR", temp_path / "analysis_runs"), \
                    patch.object(storage, "REPORT_REVISIONS_DIR", temp_path / "report_revisions"), \
                    patch.object(audit, "AUDIT_LOG_PATH", temp_path / "audit.log"), \
                    patch.dict(os.environ, env, clear=False), \
                    patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
                with TestClient(app) as client:
                    token = signed_token(key, roles=["Analyst"], workspace="team-a")
                    headers = {"Authorization": f"Bearer {token}"}
                    created = client.post("/api/projects", headers=headers, json={"name": "Artifact race project"})
                    self.assertEqual(created.status_code, 200, created.text)
                    project_id = created.json()["project_id"]

                    async def parse_after_concurrent_edit(*_args, **_kwargs):
                        latest = storage.get_project(project_id)
                        latest["description"] = "concurrent edit wins"
                        storage.save_project(latest, expected_revision=latest["project_revision"])
                        return {
                            "actors": [], "components": [], "data_flows": [], "endpoints": [],
                            "data_fields": [], "external_systems": [], "auth_methods": [],
                            "critical_actions": [], "existing_controls": [], "operations": [],
                            "use_cases": [], "evidence_items": [], "warnings": [], "stats": {},
                            "parser": {"version": "test-parser"},
                            "coverage_manifest": {"status": "complete"},
                        }

                    with patch("backend.routers.artifacts.parse_artifact", new=AsyncMock(side_effect=parse_after_concurrent_edit)), \
                            patch("backend.routers.artifacts.capture_manual_context", return_value={}), \
                            patch("backend.routers.artifacts.rebuild_project_from_artifacts", side_effect=lambda value: value), \
                            patch("backend.routers.artifacts.compute_completeness", return_value={"score": 0, "level": "unknown"}):
                        response = client.post(f"/api/projects/{project_id}/artifact", headers=headers, json={
                            "artifact_type": "prd",
                            "content": "Synthetic project requirement for revision conflict regression.",
                            "filename": "race.md",
                        })

                    self.assertEqual(response.status_code, 409, response.text)
                    self.assertEqual(response.json()["detail"]["resource"], "project")
                    self.assertEqual(response.json()["detail"]["expected_revision"], 1)
                    self.assertEqual(response.json()["detail"]["current_revision"], 2)
                    current = storage.get_project(project_id)
                    self.assertEqual(current["description"], "concurrent edit wins")
                    self.assertFalse(current.get("artifact_sources"))

    def test_json_artifact_upload_uses_flat_payload_and_rejects_client_upload_metadata(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        class Jwks:
            def get_signing_key_from_jwt(self, token):
                return SimpleNamespace(key=key.public_key())

        env = {
            "APP_ENV": "local_dev",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            with patch.object(storage, "PROJECTS_DIR", temp_path / "projects"), \
                    patch.object(storage, "REPORTS_DIR", temp_path / "reports"), \
                    patch.object(storage, "DFD_MODELS_DIR", temp_path / "dfd_models"), \
                    patch.object(storage, "ANALYSIS_RUNS_DIR", temp_path / "analysis_runs"), \
                    patch.object(storage, "REPORT_REVISIONS_DIR", temp_path / "report_revisions"), \
                    patch.object(audit, "AUDIT_LOG_PATH", temp_path / "audit.log"), \
                    patch.dict(os.environ, env, clear=False), \
                    patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
                with TestClient(app) as client:
                    token = signed_token(key, roles=["Analyst"], workspace="team-a")
                    headers = {"Authorization": f"Bearer {token}"}
                    created = client.post("/api/projects", headers=headers, json={"name": "JSON artifact project"})
                    self.assertEqual(created.status_code, 200, created.text)
                    project_id = created.json()["project_id"]
                    content = "Synthetic product requirement with a sufficient amount of text."
                    parsed = {
                        "actors": [], "components": [], "data_flows": [], "endpoints": [],
                        "data_fields": [], "external_systems": [], "auth_methods": [],
                        "critical_actions": [], "existing_controls": [], "operations": [],
                        "use_cases": [], "evidence_items": [], "warnings": [], "stats": {},
                        "parser": {"version": "test-parser"},
                        "coverage_manifest": {"status": "complete"},
                    }
                    parser_mock = AsyncMock(return_value=parsed)
                    with patch("backend.routers.artifacts.parse_artifact", new=parser_mock), \
                            patch("backend.routers.artifacts.capture_manual_context", return_value={}), \
                            patch("backend.routers.artifacts.rebuild_project_from_artifacts", side_effect=lambda value: value), \
                            patch("backend.routers.artifacts.compute_completeness", return_value={"score": 0, "level": "unknown"}):
                        forged = client.post(f"/api/projects/{project_id}/artifact", headers=headers, json={
                            "artifact_type": "prd",
                            "content": content,
                            "filename": "safe.md",
                            "upload_meta": {"source_hash": "f" * 64, "size_bytes": 1, "truncated": False},
                        })
                        self.assertEqual(forged.status_code, 422, forged.text)
                        parser_mock.assert_not_awaited()

                        response = client.post(f"/api/projects/{project_id}/artifact", headers=headers, json={
                            "artifact_type": "prd", "content": content, "filename": "safe.md",
                        })

                    self.assertEqual(response.status_code, 200, response.text)
                    source = storage.get_project(project_id)["artifact_sources"][0]
                    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    self.assertEqual(source["content_hash"], expected_hash)
                    self.assertEqual(source["source_kind"], "api_payload")
                    self.assertIsNone(source["size_bytes"])
                    self.assertFalse(source["truncated"])


if __name__ == "__main__":
    unittest.main()
