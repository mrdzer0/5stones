"""Configurable workspace access guard for project-scoped APIs.

The MVP can run without an identity provider for local development. When
``WORKSPACE_AUTH_REQUIRED=true`` is set, every project-scoped router requires
an ``X-Workspace-ID`` header and a bearer token whose value is configured in
``WORKSPACE_AUTH_TOKENS_JSON``. Resource checks return 404 for a project in a
different workspace to avoid leaking whether the ID exists.
"""
from __future__ import annotations

import hmac
import json
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request


def workspace_auth_required() -> bool:
    return os.getenv("WORKSPACE_AUTH_REQUIRED", "false").strip().casefold() in {
        "1", "true", "yes", "on"
    }


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


def require_workspace_access(request: Request) -> Optional[str]:
    """Authenticate the request when workspace auth is enabled.

    The dependency is intentionally shared by all project-scoped routers. It
    stores the authenticated workspace on ``request.state`` so endpoint
    handlers can apply the resource-level check without duplicating token
    parsing.
    """
    if not workspace_auth_required():
        request.state.workspace_id = None
        return None

    workspace_id = request.headers.get("x-workspace-id", "").strip()
    token = _bearer_token(request)
    configured = _configured_tokens()
    if not configured:
        raise HTTPException(status_code=503, detail="Workspace auth is enabled but no tokens are configured")
    if not workspace_id or not token:
        raise HTTPException(status_code=401, detail="Workspace ID and bearer token are required")

    expected = configured.get(workspace_id)
    if expected is None or not hmac.compare_digest(expected, token):
        raise HTTPException(status_code=403, detail="Workspace access denied")

    request.state.workspace_id = workspace_id
    return workspace_id


workspace_access_dependency = Depends(require_workspace_access)


def authorize_project(request: Request | None, project: dict) -> dict:
    """Verify that a loaded project belongs to the authenticated workspace."""
    if request is None or not workspace_auth_required():
        return project
    workspace_id = getattr(request.state, "workspace_id", None)
    if not workspace_id or project.get("workspace_id") != workspace_id:
        # Do not reveal whether a project exists in another workspace.
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
