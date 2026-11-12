import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.utils.access_control import (
    _oidc_principal,
    authorize_project,
    local_development_request_allowed,
    require_roles,
    require_workspace_access,
    validate_enterprise_security_config,
    workspace_id_for_request,
    reset_workspace_context,
    set_workspace_context,
)
from backend.utils import audit, storage


def request_with_headers(**headers) -> Request:
    encoded = [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/projects/project-1",
        "headers": encoded,
    })


class AccessControlTests(unittest.TestCase):
    def tearDown(self):
        set_workspace_context(None)
        audit.set_audit_workspace(None)
        audit.set_audit_actor("system")

    def test_local_mode_keeps_existing_mvp_access(self):
        request = request_with_headers()
        with patch.dict(os.environ, {"AUTH_MODE": "disabled", "WORKSPACE_AUTH_REQUIRED": "false"}, clear=False):
            self.assertIsNone(require_workspace_access(request))
            self.assertEqual(workspace_id_for_request(request), None)
            self.assertEqual(authorize_project(request, {"project_id": "project-1"})["project_id"], "project-1")

    def test_enabled_mode_requires_matching_workspace_token(self):
        request = request_with_headers(
            x_workspace_id="team-a",
            authorization="Bearer token-a",
        )
        env = {
            "WORKSPACE_AUTH_REQUIRED": "true",
            "WORKSPACE_AUTH_TOKENS_JSON": '{"team-a":"token-a","team-b":"token-b"}',
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(require_workspace_access(request), "team-a")
            self.assertEqual(workspace_id_for_request(request), "team-a")
            project = {"project_id": "project-1", "workspace_id": "team-a"}
            self.assertIs(authorize_project(request, project), project)

    def test_cross_workspace_project_is_hidden(self):
        request = request_with_headers(
            x_workspace_id="team-a",
            authorization="Bearer token-a",
        )
        env = {
            "WORKSPACE_AUTH_REQUIRED": "true",
            "WORKSPACE_AUTH_TOKENS_JSON": '{"team-a":"token-a"}',
        }
        with patch.dict(os.environ, env, clear=False):
            require_workspace_access(request)
            with self.assertRaisesRegex(HTTPException, "Project not found") as raised:
                authorize_project(request, {"project_id": "project-2", "workspace_id": "team-b"})
            self.assertEqual(raised.exception.status_code, 404)

    def test_enabled_mode_fails_closed_without_token_configuration(self):
        request = request_with_headers(
            x_workspace_id="team-a",
            authorization="Bearer token-a",
        )
        env = {
            "WORKSPACE_AUTH_REQUIRED": "true",
            "WORKSPACE_AUTH_TOKENS_JSON": "",
        }
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaisesRegex(HTTPException, "no tokens are configured") as raised:
                require_workspace_access(request)
            self.assertEqual(raised.exception.status_code, 503)

    def test_oidc_claims_supply_workspace_and_roles_not_request_headers(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        claims = {
            "iss": "https://idp.example.test/",
            "aud": "5stones-api",
            "sub": "security-reviewer-17",
            "workspace_id": "team-a",
            "roles": ["Reviewer"],
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})

        class Jwks:
            def get_signing_key_from_jwt(self, supplied):
                self.asserted_token = supplied
                return SimpleNamespace(key=key.public_key())

        request = request_with_headers(x_workspace_id="team-b", authorization=f"Bearer {token}")
        env = {
            "APP_ENV": "enterprise",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with patch.dict(os.environ, env, clear=True), patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
            self.assertEqual(require_workspace_access(request), "team-a")
            self.assertEqual(workspace_id_for_request(request), "team-a")
            reviewer = require_roles("reviewer").dependency(request)
            self.assertEqual(reviewer.subject, "security-reviewer-17")
            with self.assertRaisesRegex(HTTPException, "Insufficient role"):
                require_roles("admin").dependency(request)

    def test_oidc_rejects_expired_token(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        token = jwt.encode({
            "iss": "https://idp.example.test/",
            "aud": "5stones-api",
            "sub": "user-1",
            "workspace_id": "team-a",
            "roles": ["Analyst"],
            "exp": int((now - timedelta(minutes=1)).timestamp()),
        }, key, algorithm="RS256", headers={"kid": "test-key"})
        request = request_with_headers(authorization=f"Bearer {token}")

        class Jwks:
            def get_signing_key_from_jwt(self, supplied):
                return SimpleNamespace(key=key.public_key())

        env = {
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/.well-known/jwks.json",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
        }
        with patch.dict(os.environ, env, clear=True), patch("backend.utils.access_control._jwks_client", return_value=Jwks()):
            with self.assertRaisesRegex(HTTPException, "invalid or expired") as raised:
                require_workspace_access(request)
            self.assertEqual(raised.exception.status_code, 401)

    def test_enterprise_startup_rejects_static_token_auth_and_missing_origin(self):
        with patch.dict(os.environ, {"APP_ENV": "enterprise", "AUTH_MODE": "workspace_tokens"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "AUTH_MODE=oidc_jwt"):
                validate_enterprise_security_config()

        valid_auth_but_missing_origin = {
            "APP_ENV": "enterprise",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/jwks",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
            "APP_SECRET_KEY": "s" * 40,
            "CORS_ALLOWED_ORIGINS": "*",
        }
        with patch.dict(os.environ, valid_auth_but_missing_origin, clear=True):
            with self.assertRaisesRegex(RuntimeError, "CORS_ALLOWED_ORIGINS"):
                validate_enterprise_security_config()

    def test_enterprise_startup_rejects_invalid_or_excessive_jwt_clock_skew(self):
        base = {
            "APP_ENV": "enterprise",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/jwks",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
            "APP_SECRET_KEY": "s" * 40,
            "CORS_ALLOWED_ORIGINS": "https://app.example.test",
        }
        for value in ("", "not-an-integer", "1.5", "-1", "61"):
            with self.subTest(leeway=value), patch.dict(
                os.environ, {**base, "AUTH_JWT_LEEWAY_SECONDS": value}, clear=True
            ):
                with self.assertRaisesRegex(RuntimeError, "AUTH_JWT_LEEWAY_SECONDS"):
                    validate_enterprise_security_config()

    def test_enterprise_startup_accepts_jwt_clock_skew_boundaries(self):
        base = {
            "APP_ENV": "enterprise",
            "AUTH_MODE": "oidc_jwt",
            "AUTH_JWKS_URL": "https://idp.example.test/jwks",
            "AUTH_ISSUER": "https://idp.example.test/",
            "AUTH_AUDIENCE": "5stones-api",
            "APP_SECRET_KEY": "s" * 40,
            "CORS_ALLOWED_ORIGINS": "https://app.example.test",
        }
        for value in ("0", "60"):
            with self.subTest(leeway=value), patch.dict(
                os.environ, {**base, "AUTH_JWT_LEEWAY_SECONDS": value}, clear=True
            ):
                validate_enterprise_security_config()

    def test_unknown_deployment_profile_fails_closed(self):
        with patch.dict(os.environ, {"APP_ENV": "production"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "APP_ENV must be local_dev or enterprise"):
                validate_enterprise_security_config()

    def test_local_development_must_bind_to_loopback(self):
        with patch.dict(os.environ, {"APP_ENV": "local_dev", "HOST": "0.0.0.0"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "requires HOST to be a loopback address"):
                validate_enterprise_security_config()

        with patch.dict(os.environ, {"APP_ENV": "local_dev", "HOST": "::1"}, clear=True):
            validate_enterprise_security_config()

    def test_unauthenticated_local_profile_allows_only_loopback_clients(self):
        loopback = Request({
            "type": "http", "method": "GET", "path": "/", "headers": [],
            "client": ("127.0.0.1", 50000),
        })
        remote = Request({
            "type": "http", "method": "GET", "path": "/", "headers": [],
            "client": ("203.0.113.12", 50000),
        })
        with patch.dict(os.environ, {"APP_ENV": "local_dev", "AUTH_MODE": "disabled"}, clear=True):
            self.assertTrue(local_development_request_allowed(loopback))
            self.assertFalse(local_development_request_allowed(remote))

    def test_workspace_provider_settings_and_audit_are_isolated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            settings_dir = temp_path / "workspace_settings"
            audit_path = temp_path / "audit.log"
            with patch.object(storage, "WORKSPACE_SETTINGS_DIR", settings_dir), patch.object(audit, "AUDIT_LOG_PATH", audit_path):
                team_a_token = set_workspace_context("team-a")
                team_a_audit_token = audit.set_audit_workspace("team-a")
                try:
                    storage.save_settings({"providers": [{"provider_id": "provider-a"}]})
                    audit.log_event("settings.provider_added", details={"provider_id": "provider-a"})
                finally:
                    reset_workspace_context(team_a_token)
                    audit.reset_audit_workspace(team_a_audit_token)

                team_b_token = set_workspace_context("team-b")
                team_b_audit_token = audit.set_audit_workspace("team-b")
                try:
                    self.assertEqual(storage.get_settings()["providers"], [])
                    audit.log_event("settings.provider_added", details={"provider_id": "provider-b"})
                    self.assertEqual([item["details"]["provider_id"] for item in audit.get_recent_events()], ["provider-b"])
                finally:
                    reset_workspace_context(team_b_token)
                    audit.reset_audit_workspace(team_b_audit_token)

                team_a_token = set_workspace_context("team-a")
                team_a_audit_token = audit.set_audit_workspace("team-a")
                try:
                    self.assertEqual(storage.get_settings()["providers"][0]["provider_id"], "provider-a")
                    self.assertEqual([item["details"]["provider_id"] for item in audit.get_recent_events()], ["provider-a"])
                finally:
                    reset_workspace_context(team_a_token)
                    audit.reset_audit_workspace(team_a_audit_token)


if __name__ == "__main__":
    unittest.main()
