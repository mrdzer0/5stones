#!/usr/bin/env python3
"""Authenticate the saved live provider with a minimal non-PRD JSON prompt.

The command never prints the credential, provider response body, or exception
message. It is intended to run before spending time on a full CR8 corpus pass.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass

os.environ.setdefault("LLM_TIMEOUT_SECONDS", "30")
os.environ.setdefault("LLM_MAX_RETRIES", "1")

from backend.services.ai_service import StructuredJSONResult, chat_complete_json, get_active_provider_config
from backend.utils.storage import get_settings


def _safe_status_code(exc: Exception) -> int | None:
    value = getattr(exc, "status_code", None)
    return value if isinstance(value, int) and 100 <= value <= 599 else None


async def check_provider(provider_name: str, provider: dict, model: str, *, timeout_seconds: float = 75,
                         complete_json=chat_complete_json) -> dict:
    """Make one bounded synthetic request and return redacted status metadata."""
    endpoint = urlsplit(str(provider.get("base_url") or ""))
    started = time.monotonic()
    try:
        response = await asyncio.wait_for(complete_json(
            system_prompt="Return only a JSON object. This is a provider connectivity check, not application data.",
            user_prompt='Return exactly {"ok":true}.',
            model=model,
            base_url=provider.get("base_url"),
            api_key=provider.get("api_key"),
            max_tokens=64,
            return_metadata=True,
            max_format_retries=0,
        ), timeout=timeout_seconds)
    except Exception as exc:
        return {
            "status": "failed",
            "provider_name": provider_name,
            "configured_model": model,
            "endpoint_hostname": endpoint.hostname,
            "error_type": type(exc).__name__,
            "http_status": _safe_status_code(exc),
            "latency_ms": round((time.monotonic() - started) * 1000),
        }

    payload = response.payload if isinstance(response, StructuredJSONResult) else response
    metadata = response.metadata if isinstance(response, StructuredJSONResult) else {}
    response_model = metadata.get("response_model") if isinstance(metadata, dict) else None
    reasons = []
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        reasons.append("minimal_json_contract_failed")
    if not isinstance(response_model, str) or not response_model.strip():
        reasons.append("response_model_missing")
    elif response_model.strip().casefold() != model.strip().casefold():
        reasons.append("response_model_mismatch")
    return {
        "status": "qualified" if not reasons else "failed",
        "provider_name": provider_name,
        "configured_model": model,
        "response_model": response_model,
        "endpoint_hostname": endpoint.hostname,
        "provider_attempts": metadata.get("provider_attempts") if isinstance(metadata, dict) else None,
        "latency_ms": round((time.monotonic() - started) * 1000),
        "reasons": reasons,
    }


def _active_provider(provider_name: str) -> tuple[dict, dict]:
    settings = get_settings()
    providers = settings.get("providers") if isinstance(settings, dict) else []
    active_id = settings.get("active_provider_id") if isinstance(settings, dict) else None
    matches = [item for item in providers or [] if item.get("provider_id") == active_id]
    if len(matches) != 1 or str(matches[0].get("name") or "").casefold() != provider_name.casefold():
        raise ValueError("active_provider_mismatch")
    config = get_active_provider_config()
    if not config.get("api_key"):
        raise ValueError("credential_unavailable")
    return matches[0], config


async def _main(args) -> dict:
    try:
        selected, config = _active_provider(args.provider_name)
    except Exception as exc:
        return {
            "status": "failed",
            "provider_name": args.provider_name,
            "configured_model": args.model,
            "error_type": type(exc).__name__,
            "reasons": [str(exc) if str(exc) in {"active_provider_mismatch", "credential_unavailable"} else "provider_configuration_invalid"],
        }
    model = args.model or str(config.get("model") or "")
    if not model:
        return {"status": "failed", "provider_name": args.provider_name, "reasons": ["model_missing"]}
    return await check_provider(args.provider_name, config, model, timeout_seconds=args.timeout_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-name", default="sumopod")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--timeout-seconds", type=float, default=75)
    parser.add_argument("--output")
    args = parser.parse_args()
    result = asyncio.run(_main(args))
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if result.get("status") == "qualified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
