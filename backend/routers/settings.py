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

    # Compute active_source so the UI always knows what's in use
    active_id = settings.get("active_provider_id")
    has_local = bool(settings.get("local_llm_endpoint") and settings.get("local_llm_model"))
    if active_id and any(p["provider_id"] == active_id for p in settings.get("providers", [])):
        safe["active_source"] = "byok"
    elif has_local:
        safe["active_source"] = "local"
    else:
        safe["active_source"] = "none"

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


@router.put("/active-source")
async def set_active_source(data: dict):
    """Switch the active LLM source. source='byok' requires provider_id; source='local' clears active_provider_id."""
    source = data.get("source")
    settings = get_settings()

    if source == "byok":
        provider_id = data.get("provider_id")
        if not provider_id:
            # Use the currently active BYOK or first available
            provider_id = settings.get("active_provider_id")
            if not provider_id:
                providers = settings.get("providers", [])
                if providers:
                    provider_id = providers[0]["provider_id"]
        if not provider_id:
            raise HTTPException(status_code=400, detail="No BYOK provider configured. Add one first.")
        # Verify provider exists
        found = any(p["provider_id"] == provider_id for p in settings.get("providers", []))
        if not found:
            raise HTTPException(status_code=404, detail="Provider not found")
        for p in settings.get("providers", []):
            p["is_active"] = (p["provider_id"] == provider_id)
        settings["active_provider_id"] = provider_id
        log_event("settings.active_source_changed", details={"source": "byok", "provider_id": provider_id})

    elif source == "local":
        if not (settings.get("local_llm_endpoint") and settings.get("local_llm_model")):
            raise HTTPException(status_code=400, detail="Local LLM not configured. Set endpoint and model first.")
        # Deactivate all BYOK providers
        for p in settings.get("providers", []):
            p["is_active"] = False
        settings["active_provider_id"] = None
        log_event("settings.active_source_changed", details={"source": "local"})

    else:
        raise HTTPException(status_code=400, detail="source must be 'byok' or 'local'")

    save_settings(settings)
    return {"success": True, "active_source": source}


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


@router.put("/providers/{provider_id}")
async def update_provider(provider_id: str, data: dict):
    """Update details of an existing BYOK provider."""
    settings = get_settings()
    provider = None
    for p in settings.get("providers", []):
        if p["provider_id"] == provider_id:
            provider = p
            break

    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    if "name" in data:
        provider["name"] = data["name"]
    if "base_url" in data:
        provider["base_url"] = data["base_url"]
    if "model" in data:
        provider["model"] = data["model"]
    if "max_tokens" in data:
        provider["max_tokens"] = int(data["max_tokens"])
    if "api_key" in data and data["api_key"].strip() != "":
        api_key = data["api_key"]
        provider["api_key_masked"] = _mask(api_key)
        provider["_api_key"] = _encrypt(api_key)

    save_settings(settings)
    log_event("settings.provider_updated", details={"provider_id": provider_id, "model": provider.get("model")})

    safe = dict(provider)
    safe.pop("_api_key", None)
    return safe


@router.delete("/providers/{provider_id}")
async def delete_provider(provider_id: str):
    settings = get_settings()
    settings["providers"] = [p for p in settings.get("providers", []) if p["provider_id"] != provider_id]
    if settings.get("active_provider_id") == provider_id:
        settings["active_provider_id"] = None
    save_settings(settings)
    log_event("settings.provider_deleted", details={"provider_id": provider_id})
    return {"success": True}


@router.get("/list-models")
async def list_models(base_url: str, api_key: str = "ollama", provider_id: Optional[str] = None):
    """Fetch available models from a local or remote LLM endpoint. Supports stored provider key fallback."""
    try:
        if provider_id and (not api_key or api_key == "ollama" or api_key.startswith("***") or api_key == ""):
            settings = get_settings()
            for p in settings.get("providers", []):
                if p.get("provider_id") == provider_id:
                    decrypted = _decrypt(p.get("_api_key", ""))
                    if decrypted:
                        api_key = decrypted
                    else:
                        raise ValueError("Stored API key could not be decrypted (Fernet decryption failed). Please re-add the provider or re-enter the key.")
                    if not base_url:
                        base_url = p.get("base_url")
                    break

        if not api_key:
            raise ValueError("API key is empty or not provided.")

        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        models = await client.models.list()
        return {
            "ok": True,
            "models": [m.id for m in models.data],
        }
    except Exception as exc:
        return {"ok": False, "models": [], "error": str(exc)}


@router.post("/check-connection")
async def check_connection(data: dict):
    """Test LLM connectivity. First lists available models, then does a chat completion. Supports stored provider decryption."""
    import time
    from openai import AsyncOpenAI

    try:
        provider_id = data.get("provider_id")
        base_url = data.get("base_url")
        api_key = data.get("api_key")
        model = data.get("model")

        if provider_id:
            settings = get_settings()
            for p in settings.get("providers", []):
                if p.get("provider_id") == provider_id:
                    if not api_key or api_key.strip() == "":
                        decrypted = _decrypt(p.get("_api_key", ""))
                        if decrypted:
                            api_key = decrypted
                        else:
                            raise ValueError("Stored API key could not be decrypted.")
                    if not base_url:
                        base_url = p.get("base_url")
                    if not model:
                        model = p.get("model")
                    break

        if not base_url:
            base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not api_key:
            api_key = os.getenv("OPENAI_API_KEY", "ollama")
        if not model:
            model = os.getenv("OPENAI_MODEL", "gpt-4o")

        if data.get("encrypted_api_key"):
            try:
                decrypted = _decrypt(data["encrypted_api_key"])
                if decrypted:
                    api_key = decrypted
            except Exception:
                pass

        if not api_key:
            raise ValueError("API key is empty.")

        client = AsyncOpenAI(api_key=api_key, base_url=base_url)

        # Step 1: fetch available models
        available_models: list[str] = []
        try:
            models_resp = await client.models.list()
            available_models = [m.id for m in models_resp.data]
        except Exception:
            pass

        # Step 2: attempt minimal chat completion
        start = time.time()
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with the single word: OK"}],
            max_tokens=5,
            temperature=0,
        )
        elapsed_ms = int((time.time() - start) * 1000)
        reply = (resp.choices[0].message.content or "").strip()
        return {
            "ok": True,
            "model": resp.model or model,
            "reply": reply,
            "latency_ms": elapsed_ms,
            "available_models": available_models,
        }
    except Exception as exc:
        error_msg = str(exc)
        # Helpful hint when no model is loaded in LM Studio
        hint = None
        if "No models loaded" in error_msg:
                hint = "No model is loaded in LM Studio. Open LM Studio → Developer tab → load a model, then retry."
        return {
            "ok": False,
            "error": error_msg,
            "hint": hint,
            "latency_ms": elapsed_ms,
            "available_models": available_models,
        }


@router.get("/audit")
async def get_audit_log(limit: int = 100):
    return get_recent_events(limit)
