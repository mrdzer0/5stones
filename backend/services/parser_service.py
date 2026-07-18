"""Artifact parser — extracts entities from PRD text, OpenAPI, Postman, Markdown."""
from __future__ import annotations
import json
import re
from typing import List, Dict
from backend.services.ai_service import chat_complete_json, get_active_provider_config


SYSTEM_PROMPT = """You are a security analyst specialized in extracting threat modeling context from technical documents.
Extract only what is explicitly stated or strongly implied. Do NOT hallucinate. Return strict JSON."""


async def parse_artifact(artifact_type: str, content: str) -> dict:
    """Parse an artifact and extract relevant security context."""
    cfg = get_active_provider_config()

    user_prompt = f"""Analyze this {artifact_type} artifact and extract security-relevant information.

ARTIFACT CONTENT:
{content[:8000]}

Return a JSON object with these exact keys:
{{
  "actors": ["list of actors/users/roles mentioned"],
  "components": ["list of system components, services, APIs, DBs"],
  "data_flows": [
    {{"source": "...", "destination": "...", "data": ["..."], "protocol": "..."}}
  ],
  "endpoints": ["list of API endpoints or entry points"],
  "data_fields": ["list of data fields, especially PII or sensitive data"],
  "external_systems": ["third-party services, partner systems"],
  "auth_methods": ["authentication methods mentioned"],
  "critical_actions": ["high-risk actions like payment, delete, admin functions"],
  "existing_controls": ["security controls already mentioned"],
  "has_pii": true or false,
  "summary": "2-3 sentence summary of what this artifact describes"
}}"""

    try:
        result = await chat_complete_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            base_url=cfg.get("base_url"),
            api_key=cfg.get("api_key"),
            model=cfg.get("model"),
        )
        if isinstance(result, dict):
            return result
    except Exception as e:
        pass

    # Fallback: basic regex extraction
    return _basic_extract(content)


def _basic_extract(content: str) -> dict:
    """Simple regex-based fallback extractor."""
    endpoints = re.findall(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)', content)
    pii_patterns = ["email", "phone", "password", "ssn", "nama", "address", "dob", "ktp"]
    has_pii = any(p in content.lower() for p in pii_patterns)

    return {
        "actors": [],
        "components": [],
        "data_flows": [],
        "endpoints": list(set(endpoints)),
        "data_fields": [],
        "external_systems": [],
        "auth_methods": [],
        "critical_actions": [],
        "existing_controls": [],
        "has_pii": has_pii,
        "summary": "Artifact parsed with basic extraction (AI not available)."
    }
