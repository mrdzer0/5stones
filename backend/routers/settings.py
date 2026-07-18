"""Settings router — BYOK, LLM, MCP configuration."""
from __future__ import annotations
import os
import uuid
from fastapi import APIRouter, HTTPException
from backend.utils.storage import get_settings, save_settings
from backend.utils.audit import log_event, get_recent_events
from cryptography.fernet import Fernet
import base64

router = APIRouter(prefix="/api/settings", tags=["settings"])

# Derive a Fernet key from APP_SECRET_KEY env var
def _get_fernet() -> Fernet:
    secret = os.getenv("APP_SECRET_KEY", "threatmodelz-default-insecure-key-32c")
    key = base64.urlsafe_b64encode(secret[:32].encode().ljust(32, b'0'))
    return Fernet(key)


def _encrypt(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode()


def _decrypt(value: str) -> str:
    try:
        return _get_fernet().decrypt(value.encode()).decode()
    except Exception:
        return ""


def _mask(value: str) -> str:
    if not value:
        return ""
    return value[:4] + "****" + value[-4:] if len(value) > 8 else "****"


@router.get("")
async def get_app_settings():
    settings = get_settings()
    # Mask API keys before returning
    safe = dict(settings)
    safe["providers"] = []
    for p in settings.get("providers", []):
        p_safe = dict(p)
        p_safe.pop("_api_key", None)
        p_safe["api_key_masked"] = p.get("api_key_masked", "****")
        safe["providers"].append(p_safe)
    return safe


@router.put("")
async def update_app_settings(data: dict):
    settings = get_settings()
    allowed = ["active_provider_id", "default_data_policy",
               "local_llm_endpoint", "local_llm_model", "mcp_servers"]
    for key in allowed:
        if key in data:
            settings[key] = data[key]
    save_settings(settings)
    return {"success": True}


@router.post("/providers")
async def add_provider(data: dict):
    """Add a new LLM provider (BYOK)."""
    api_key = data.get("api_key", "")
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key is required")

    settings = get_settings()
    provider = {
        "provider_id": str(uuid.uuid4()),
        "name": data.get("name", "Custom Provider"),
        "provider_type": data.get("provider_type", "openai"),
        "base_url": data.get("base_url", "https://api.openai.com/v1"),
        "model": data.get("model", "gpt-4o"),
        "max_tokens": data.get("max_tokens", 4096),
        "is_active": False,
        "is_local": data.get("is_local", False),
        "api_key_masked": _mask(api_key),
        "_api_key": _encrypt(api_key),  # stored encrypted
    }
    settings.setdefault("providers", []).append(provider)
    save_settings(settings)

    log_event("settings.provider_added", details={
        "provider_id": provider["provider_id"],
        "name": provider["name"]
    })

    safe = dict(provider)
    safe.pop("_api_key", None)
    return safe


@router.put("/providers/{provider_id}/activate")
async def activate_provider(provider_id: str):
    settings = get_settings()
    found = False
    for p in settings.get("providers", []):
        p["is_active"] = (p["provider_id"] == provider_id)
        if p["provider_id"] == provider_id:
            found = True
    if not found:
        raise HTTPException(status_code=404, detail="Provider not found")
    settings["active_provider_id"] = provider_id
    save_settings(settings)
    log_event("settings.provider_activated", details={"provider_id": provider_id})
    return {"success": True}


@router.delete("/providers/{provider_id}")
async def delete_provider(provider_id: str):
    settings = get_settings()
    settings["providers"] = [p for p in settings.get("providers", []) if p["provider_id"] != provider_id]
    if settings.get("active_provider_id") == provider_id:
        settings["active_provider_id"] = None
    save_settings(settings)
    log_event("settings.provider_deleted", details={"provider_id": provider_id})
    return {"success": True}


@router.get("/audit")
async def get_audit_log(limit: int = 100):
    return get_recent_events(limit)
