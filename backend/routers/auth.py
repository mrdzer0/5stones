"""Local user registration and cookie-session endpoints.

This router is deliberately separate from the OIDC enterprise identity flow.
Local accounts are available only when APP_ENV=local_dev and AUTH_MODE is
explicitly set to local_users.
"""
from __future__ import annotations

import hmac
import os
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from backend.services import local_auth_service as auth_store
from backend.utils.access_control import (
    AuthPrincipal,
    auth_mode,
    principal_for_request,
    workspace_access_dependency,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])
SESSION_COOKIE_NAME = "5stones_session"
CSRF_COOKIE_NAME = "5stones_csrf"


def _enabled(value: str | None) -> bool:
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}


def registration_enabled() -> bool:
    return _enabled(os.getenv("AUTH_REGISTRATION_ENABLED", "false"))


def _require_local_user_mode() -> None:
    if os.getenv("APP_ENV", "local_dev").strip().casefold() != "local_dev" or auth_mode() != "local_users":
        raise HTTPException(status_code=404, detail="Not found")


def _same_origin_request(request: Request) -> None:
    fetch_site = request.headers.get("sec-fetch-site", "").casefold()
    if fetch_site == "cross-site":
        raise HTTPException(status_code=403, detail="Cross-site request rejected")
    origin = request.headers.get("origin")
    if not origin:
        return
    try:
        origin_parts = urlsplit(origin)
        request_parts = urlsplit(str(request.base_url))
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Request origin is invalid") from exc
    if (origin_parts.scheme, origin_parts.netloc) != (request_parts.scheme, request_parts.netloc):
        raise HTTPException(status_code=403, detail="Request origin is not allowed")


def _cookie_options(request: Request, path: str = "/") -> dict:
    return {
        "secure": request.url.scheme == "https",
        "samesite": "strict",
        "path": path,
    }


def _set_session_cookies(response: Response, request: Request, session: str, csrf: str, expires_at: int) -> None:
    session_options = _cookie_options(request, "/api")
    csrf_options = _cookie_options(request, "/")
    max_age = max(0, expires_at - int(time.time()))
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session,
        max_age=max_age,
        expires=max_age,
        httponly=True,
        **session_options,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf,
        max_age=max_age,
        expires=max_age,
        httponly=False,
        **csrf_options,
    )


def _clear_session_cookies(response: Response, request: Request) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, httponly=True, **_cookie_options(request, "/api"))
    response.delete_cookie(CSRF_COOKIE_NAME, httponly=False, **_cookie_options(request, "/"))


def _user_view(user: dict) -> dict:
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "workspace_id": user["workspace_id"],
        "role": user["role"],
    }


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)
    display_name: str = Field(default="", max_length=120)
    registration_key: str = Field(min_length=1, max_length=512)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=256)


@router.get("/config")
async def auth_configuration():
    mode = auth_mode()
    return {
        "auth_mode": mode,
        "registration_enabled": mode == "local_users" and registration_enabled(),
    }


@router.post("/register", status_code=201)
async def register_user(data: RegisterRequest, request: Request, response: Response):
    _require_local_user_mode()
    _same_origin_request(request)
    if not registration_enabled():
        raise HTTPException(status_code=403, detail="Account registration is disabled")
    configured_key = os.getenv("AUTH_REGISTRATION_KEY", "")
    if len(configured_key) < 32 or not hmac.compare_digest(configured_key.encode(), data.registration_key.encode()):
        raise HTTPException(status_code=403, detail="Registration key is invalid")
    # Local accounts own separate data scopes. Never reuse a deployment-wide
    # default workspace for self-registration.
    workspace_id = auth_store.new_account_workspace_id()
    try:
        user = auth_store.create_user(
            data.email,
            data.password,
            workspace_id=workspace_id,
            role="analyst",
            display_name=data.display_name,
        )
        _user, session, csrf, expires_at = auth_store.create_session_for_user(user["user_id"])
    except auth_store.DuplicateUserError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except auth_store.InvalidUserInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except auth_store.InvalidCredentialsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _set_session_cookies(response, request, session, csrf, expires_at)
    return {"user": _user_view(user), "expires_at": expires_at}


@router.post("/login")
async def login_user(data: LoginRequest, request: Request, response: Response):
    _require_local_user_mode()
    _same_origin_request(request)
    try:
        user, session, csrf, expires_at = auth_store.login(
            data.email,
            data.password,
            request.client.host if request.client else "unknown",
        )
    except auth_store.LoginRateLimitedError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except auth_store.InvalidCredentialsError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except auth_store.InvalidUserInputError:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    _set_session_cookies(response, request, session, csrf, expires_at)
    return {"user": _user_view(user), "expires_at": expires_at}


@router.get("/me", dependencies=[workspace_access_dependency])
async def current_user(request: Request):
    principal: AuthPrincipal | None = principal_for_request(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    user = getattr(request.state, "local_auth_user", None)
    return {
        "user": _user_view(user) if user else {
            "user_id": principal.subject,
            "email": None,
            "display_name": principal.subject,
            "workspace_id": principal.workspace_id,
            "role": sorted(principal.roles),
        },
        "auth_mode": principal.auth_mode,
    }


@router.post("/logout", dependencies=[workspace_access_dependency])
async def logout_user(request: Request, response: Response):
    _same_origin_request(request)
    _require_local_user_mode()
    auth_store.revoke_session(request.cookies.get(SESSION_COOKIE_NAME, ""))
    _clear_session_cookies(response, request)
    return {"success": True}
