"""Authentication and workspace authorization for project-scoped APIs.

Local development defaults to SQLite-backed user sessions; the legacy
workspace-token adapter remains available only when explicitly enabled.
Enterprise deployments must use an OIDC/JWT issuer and receive identity,
workspace, and roles from validated token claims. A caller-supplied workspace
header is never the source of identity in OIDC mode.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional
from urllib.parse import urlsplit

import jwt
from fastapi import Depends, HTTPException, Request

_workspace_context: ContextVar[str | None] = ContextVar("5stones_workspace_id", default=None)
MAX_JWT_CLOCK_SKEW_SECONDS = 60


def _configured_jwt_leeway_seconds() -> int:
    raw = os.getenv("AUTH_JWT_LEEWAY_SECONDS", "30").strip()
    try:
        leeway = int(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "AUTH_JWT_LEEWAY_SECONDS must be an integer between 0 and 60"
        ) from exc
    if not 0 <= leeway <= MAX_JWT_CLOCK_SKEW_SECONDS:
        raise RuntimeError(
            "AUTH_JWT_LEEWAY_SECONDS must be an integer between 0 and 60"
        )
    return leeway


def set_workspace_context(workspace_id: str | None):
    return _workspace_context.set(str(workspace_id).strip() if workspace_id else None)


def reset_workspace_context(token) -> None:
    _workspace_context.reset(token)


def current_workspace_context() -> str | None:
    return _workspace_context.get()


@dataclass(frozen=True)
class AuthPrincipal:
    subject: str
    workspace_id: str | None
    roles: frozenset[str]
    auth_mode: str


def auth_mode() -> str:
    configured = os.getenv("AUTH_MODE", "").strip().casefold()
    if configured:
        return configured
    if os.getenv("APP_ENV", "").strip().casefold() == "enterprise":
        return "oidc_jwt"
    if os.getenv("WORKSPACE_AUTH_REQUIRED", "false").strip().casefold() in {"1", "true", "yes", "on"}:
        return "workspace_tokens"
    return "local_users"


def _app_environment() -> str:
    return os.getenv("APP_ENV", "local_dev").strip().casefold() or "local_dev"


def release_authority_context() -> tuple[str, str]:
    """Return the deployment and identity modes used to qualify release decisions."""
    return _app_environment(), auth_mode()


def _is_loopback_host(host: str) -> bool:
    candidate = str(host or "").strip()
    if candidate.casefold() == "localhost":
        return True
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def local_development_request_allowed(request: Request) -> bool:
    """Keep local-only account and unauthenticated modes on loopback."""
    if _app_environment() != "local_dev" or auth_mode() not in {"disabled", "local_users"}:
        return True
    client = getattr(request, "client", None)
    return bool(client and _is_loopback_host(client.host))


def workspace_auth_required() -> bool:
    return auth_mode() != "disabled"


def validate_enterprise_security_config() -> None:
    """Fail startup for unknown deployment profiles or incomplete security."""
    environment = _app_environment()
    if environment not in {"local_dev", "enterprise"}:
        raise RuntimeError("APP_ENV must be local_dev or enterprise; unknown profiles are not allowed")
    if environment == "local_dev":
        host = os.getenv("HOST", "127.0.0.1").strip()
        if not _is_loopback_host(host):
            raise RuntimeError("APP_ENV=local_dev requires HOST to be a loopback address; use APP_ENV=enterprise for shared deployments")
        mode = auth_mode()
        if mode not in {"disabled", "workspace_tokens", "local_users", "oidc_jwt"}:
            raise RuntimeError("AUTH_MODE must be disabled, workspace_tokens, local_users, or oidc_jwt")
        if mode == "local_users":
            registration_enabled = os.getenv("AUTH_REGISTRATION_ENABLED", "false").strip().casefold() in {"1", "true", "yes", "on"}
            registration_key = os.getenv("AUTH_REGISTRATION_KEY", "")
            if registration_enabled and len(registration_key) < 32:
                raise RuntimeError("Local self-registration requires AUTH_REGISTRATION_KEY with at least 32 characters")
            from backend.services.local_auth_service import initialize_database
            initialize_database()
        return
    if auth_mode() != "oidc_jwt":
        raise RuntimeError("Enterprise mode requires AUTH_MODE=oidc_jwt")
    jwks_url = os.getenv("AUTH_JWKS_URL", "").strip()
    issuer = os.getenv("AUTH_ISSUER", "").strip()
    audience = os.getenv("AUTH_AUDIENCE", "").strip()
    origins = _configured_origins()
    if not jwks_url or urlsplit(jwks_url).scheme != "https" or not issuer or not audience:
        raise RuntimeError("Enterprise mode requires HTTPS AUTH_JWKS_URL, AUTH_ISSUER, and AUTH_AUDIENCE")
    _configured_jwt_leeway_seconds()
    if not origins or "*" in origins or any(not item.startswith("https://") for item in origins):
        raise RuntimeError("Enterprise mode requires explicit CORS_ALLOWED_ORIGINS without wildcard")
    secret = os.getenv("APP_SECRET_KEY", "")
    if len(secret) < 32 or secret == "change-this-to-a-random-secret-key-32chars":
        raise RuntimeError("Enterprise mode requires a unique APP_SECRET_KEY of at least 32 characters")


def _configured_origins() -> list[str]:
    return [item.strip().rstrip("/") for item in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",") if item.strip()]


def _configured_tokens() -> dict[str, str]:
    raw = os.getenv("WORKSPACE_AUTH_TOKENS_JSON", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail="Workspace auth token configuration is invalid") from exc
    if not isinstance(parsed, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in parsed.items()):
        raise HTTPException(status_code=503, detail="Workspace auth token configuration is invalid")
    return parsed


def _bearer_token(request: Request) -> Optional[str]:
    value = request.headers.get("authorization", "")
    scheme, _, token = value.partition(" ")
    if scheme.casefold() != "bearer" or not token.strip():
        return None
    return token.strip()


@lru_cache(maxsize=8)
def _jwks_client(jwks_url: str):
    return jwt.PyJWKClient(jwks_url, timeout=5, cache_jwk_set=True, lifespan=300)


def _oidc_principal(token: str) -> AuthPrincipal:
    jwks_url = os.getenv("AUTH_JWKS_URL", "").strip()
    issuer = os.getenv("AUTH_ISSUER", "").strip()
    audience = os.getenv("AUTH_AUDIENCE", "").strip()
    if not jwks_url or not issuer or not audience:
        raise HTTPException(status_code=503, detail="OIDC authentication is not configured")
    algorithms = [item.strip() for item in os.getenv("AUTH_JWT_ALGORITHMS", "RS256,ES256,EdDSA").split(",") if item.strip()]
    if not algorithms or any(item.casefold() == "none" or item.startswith("HS") for item in algorithms):
        raise HTTPException(status_code=503, detail="OIDC JWT algorithms must use configured asymmetric keys")
    try:
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=algorithms,
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iss", "sub", "aud"]},
            leeway=_configured_jwt_leeway_seconds(),
        )
    except Exception as exc:
        # Provider/JWKS details can contain deployment information; return a
        # stable authentication error and keep details out of the response.
        raise HTTPException(status_code=401, detail="Bearer token is invalid or expired") from exc

    subject = str(claims.get("sub") or "").strip()
    workspace_claim = os.getenv("AUTH_WORKSPACE_CLAIM", "workspace_id").strip() or "workspace_id"
    roles_claim = os.getenv("AUTH_ROLES_CLAIM", "roles").strip() or "roles"
    workspace_id = str(claims.get(workspace_claim) or "").strip()
    roles_value = claims.get(roles_claim) or []
    if not subject or not workspace_id or not isinstance(roles_value, list):
        raise HTTPException(status_code=403, detail="Identity token is missing required workspace or role claims")
    roles = frozenset(str(role).strip().casefold() for role in roles_value if str(role).strip())
    return AuthPrincipal(subject, workspace_id, roles, "oidc_jwt")


def authenticate_request(request: Request) -> AuthPrincipal:
    mode = auth_mode()
    if mode == "disabled":
        if os.getenv("APP_ENV", "").strip().casefold() == "enterprise":
            raise HTTPException(status_code=503, detail="Authentication is disabled in enterprise mode")
        principal = AuthPrincipal("local-developer", None, frozenset({"analyst", "reviewer", "admin"}), mode)
        request.state.principal = principal
        request.state.workspace_id = None
        request.state.user_id = principal.subject
        request.state.roles = principal.roles
        return principal

    if mode == "local_users":
        if os.getenv("APP_ENV", "local_dev").strip().casefold() != "local_dev":
            raise HTTPException(status_code=503, detail="Local user authentication is unavailable in this deployment")
        raw_session = request.cookies.get("5stones_session", "")
        from backend.services import local_auth_service
        user = local_auth_service.authenticate_session(raw_session)
        if not user:
            raise HTTPException(status_code=401, detail="A valid local user session is required")
        if request.method.upper() not in {"GET", "HEAD", "OPTIONS", "TRACE"}:
            valid_csrf = local_auth_service.validate_session_csrf(
                raw_session,
                request.cookies.get("5stones_csrf"),
                request.headers.get("x-csrf-token"),
            )
            if not valid_csrf:
                raise HTTPException(status_code=403, detail="CSRF validation failed")
        principal = AuthPrincipal(
            user["user_id"],
            user["workspace_id"],
            frozenset({user["role"]}),
            mode,
        )
        request.state.local_auth_user = user
    else:
        token = _bearer_token(request)
        if not token:
            raise HTTPException(status_code=401, detail="Bearer token is required")

        if mode == "oidc_jwt":
            principal = _oidc_principal(token)
        elif mode == "workspace_tokens":
            workspace_id = request.headers.get("x-workspace-id", "").strip()
            configured = _configured_tokens()
            if not configured:
                raise HTTPException(status_code=503, detail="Workspace auth is enabled but no tokens are configured")
            expected = configured.get(workspace_id)
            if not workspace_id or expected is None or not hmac.compare_digest(expected, token):
                raise HTTPException(status_code=403, detail="Workspace access denied")
            # This compatibility adapter is for a single trusted development
            # workspace. Enterprise mode rejects it during startup validation.
            principal = AuthPrincipal(f"workspace:{workspace_id}", workspace_id,
                                      frozenset({"analyst", "reviewer", "admin"}), mode)
        else:
            raise HTTPException(status_code=503, detail="Configured authentication mode is unsupported")

    request.state.principal = principal
    request.state.workspace_id = principal.workspace_id
    request.state.user_id = principal.subject
    request.state.roles = principal.roles
    set_workspace_context(principal.workspace_id)
    try:
        from backend.utils.audit import set_audit_actor, set_audit_workspace
        set_audit_actor(principal.subject)
        set_audit_workspace(principal.workspace_id)
    except Exception:
        pass
    return principal


def require_workspace_access(request: Request) -> Optional[str]:
    """Authenticate the caller and set its verified workspace on request state."""
    principal = authenticate_request(request)
    return principal.workspace_id


async def _require_workspace_access_dependency(request: Request) -> Optional[str]:
    # Keep authentication/context binding on the request's async execution
    # context. A sync FastAPI dependency may run in a worker thread and lose
    # ContextVar values before endpoint audit/provider calls execute.
    return require_workspace_access(request)


workspace_access_dependency = Depends(_require_workspace_access_dependency)


def require_roles(*allowed_roles: str):
    """Return a route dependency that checks roles from verified identity claims."""
    allowed = {str(role).strip().casefold() for role in allowed_roles}

    def dependency(request: Request) -> AuthPrincipal:
        principal = getattr(request.state, "principal", None) or authenticate_request(request)
        if principal.auth_mode != "disabled" and not principal.roles.intersection(allowed):
            raise HTTPException(status_code=403, detail="Insufficient role for this operation")
        return principal

    return Depends(dependency)


def principal_for_request(request: Request | None) -> AuthPrincipal | None:
    if request is None:
        return None
    return getattr(request.state, "principal", None)


def authorize_project(request: Request | None, project: dict) -> dict:
    """Verify that a loaded project belongs to the authenticated workspace."""
    if request is None or not workspace_auth_required():
        return project
    workspace_id = getattr(request.state, "workspace_id", None)
    if not workspace_id or project.get("workspace_id") != workspace_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def get_authorized_project(project_id: str, request: Request | None = None) -> dict | None:
    """Load a project and apply the workspace resource check."""
    from backend.utils.storage import get_project

    project = get_project(project_id)
    if not project:
        return None
    return authorize_project(request, project)


def workspace_id_for_request(request: Request | None) -> str | None:
    if request is None or not workspace_auth_required():
        return None
    return getattr(request.state, "workspace_id", None)
