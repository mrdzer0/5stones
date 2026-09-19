"""AI Service — wraps OpenAI-compatible LLM client (BYOK + local LLM)."""
from __future__ import annotations
import os
import json
from typing import Optional
from urllib.parse import urlparse
from openai import AsyncOpenAI
from cryptography.fernet import Fernet
import base64
from backend.services.provider_policy import (
    validate_provider_url,
    normalize_max_tokens,
    normalize_timeout_seconds,
    normalize_max_retries,
)


def _get_client(base_url: Optional[str] = None, api_key: Optional[str] = None) -> AsyncOpenAI:
    timeout_seconds = normalize_timeout_seconds(os.getenv("LLM_TIMEOUT_SECONDS", "180"))
    max_retries = normalize_max_retries(os.getenv("LLM_MAX_RETRIES", "0"))
    resolved_base_url = base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    validate_provider_url(resolved_base_url)
    return AsyncOpenAI(
        api_key=api_key or os.getenv("OPENAI_API_KEY", "ollama"),
        base_url=resolved_base_url,
        timeout=timeout_seconds,
        max_retries=max_retries,
    )


def _get_model() -> str:
    return os.getenv("OPENAI_MODEL", "gpt-4o")


class AnalysisResponseError(ValueError):
    """Raised when an analysis provider responds without usable structured data."""


def _get_fernet() -> Fernet:
    secret = os.getenv("APP_SECRET_KEY", "threatmodelz-default-insecure-key-32c")
    key = base64.urlsafe_b64encode(secret[:32].encode().ljust(32, b'0'))
    return Fernet(key)


def _decrypt(value: str) -> str:
    try:
        return _get_fernet().decrypt(value.encode()).decode()
    except Exception:
        return value or ""


async def chat_complete(
    system_prompt: str,
    user_prompt: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    max_tokens: int = 4096,
    response_format: Optional[str] = None,
    use_json_format: bool = False,
) -> str:
    """Send a chat completion request and return the response text."""
    client = _get_client(base_url=base_url, api_key=api_key)
    resolved_model = model or _get_model()
    kwargs = dict(
        model=resolved_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    # Ask remote OpenAI-compatible providers for structured JSON. If a provider
    # rejects the option, retry once without it as a fast compatibility fallback.
    if use_json_format and _is_cloud_provider(base_url):
        kwargs["response_format"] = {"type": "json_object"}

    # DeepSeek V4 defaults to thinking mode, and reasoning tokens count against
    # max_tokens. Structured analysis needs the final JSON, so disable thinking.
    if "deepseek" in resolved_model.lower():
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}

    while True:
        try:
            response = await client.chat.completions.create(**kwargs)
            break
        except Exception as exc:
            if getattr(exc, "status_code", None) not in (400, 422):
                raise
            if "extra_body" in kwargs:
                kwargs.pop("extra_body", None)
                continue
            if "response_format" in kwargs:
                kwargs.pop("response_format", None)
                continue
            raise

    if not response.choices:
        raise AnalysisResponseError("Analysis engine returned no completion choices")

    message = response.choices[0].message
    content = message.content
    candidates = []
    if isinstance(content, str) and content.strip():
        candidates.append(content.strip())
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
            elif isinstance(getattr(part, "text", None), str):
                parts.append(part.text)
        joined = "\n".join(parts).strip()
        if joined:
            candidates.append(joined)

    # Several DeepSeek-compatible gateways place the response in an extension
    # field when the standard content field is empty.
    extra = getattr(message, "model_extra", None) or {}
    for key in ("reasoning_content", "reasoning", "text"):
        value = extra.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())

    # Prefer a field that actually contains structured data. Some compatible
    # gateways return prose in `content` and the useful payload in an extension.
    for candidate in candidates:
        if "{" in candidate or "[" in candidate:
            return candidate
    if candidates:
        return candidates[0]

    raise AnalysisResponseError("Analysis engine returned an empty response")


def _is_cloud_provider(base_url: Optional[str]) -> bool:
    """Return True for remote endpoints; local gateways commonly reject response_format."""
    if not base_url:
        url = os.getenv("OPENAI_BASE_URL", "")
    else:
        url = base_url
    normalized = url if "://" in url else f"http://{url}"
    hostname = (urlparse(normalized).hostname or "").lower()
    local_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "::1"}
    return bool(hostname) and hostname not in local_hosts


def clean_and_repair_json(raw_text: str) -> str:
    """Extract the first JSON block (array or object) from a string and repair any truncation or trailing commas."""
    if not raw_text:
        return ""
    text = raw_text.strip()

    # Step 1: Find the first JSON start character
    start_idx = -1
    for i, c in enumerate(text):
        if c in ('[', '{'):
            start_idx = i
            break

    if start_idx == -1:
        return text

    start_char = text[start_idx]
    end_char = ']' if start_char == '[' else '}'

    # Step 2: Track balance to find matching end character
    stack = []
    in_quote = False
    escaped = False
    matched_end_idx = -1

    for i in range(start_idx, len(text)):
        char = text[i]

        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue

        if not in_quote:
            if char == start_char:
                stack.append(char)
            elif char == end_char:
                if stack:
                    stack.pop()
                    if not stack:
                        matched_end_idx = i
                        break

    # Extract the candidate substring
    if matched_end_idx != -1:
        json_str = text[start_idx:matched_end_idx + 1]
    else:
        # Truncated JSON
        json_str = text[start_idx:]

    # Step 3: Repair trailing commas and unclosed structures
    import re
    json_str = re.sub(r',\s*([\]}])', r'\1', json_str)

    # If the JSON was truncated (no matched end), repair it
    if matched_end_idx == -1:
        in_quote = False
        escaped = False
        repair_stack = []

        for c in json_str:
            if escaped:
                escaped = False
                continue
            if c == '\\':
                escaped = True
                continue
            if c == '"':
                in_quote = not in_quote
                continue
            if not in_quote:
                if c in ('{', '['):
                    repair_stack.append(c)
                elif c in ('}', ']'):
                    if repair_stack:
                        repair_stack.pop()

        if in_quote:
            json_str += '"'

        json_str = json_str.strip()
        if json_str.endswith(',') or json_str.endswith(':'):
            json_str = json_str[:-1].strip()

        while repair_stack:
            open_c = repair_stack.pop()
            json_str += '}' if open_c == '{' else ']'

    return json_str


async def chat_complete_json(
    system_prompt: str,
    user_prompt: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    max_tokens: int = 4096,
) -> dict | list:
    """Chat complete and parse JSON from response. Works with local and cloud LLMs."""
    last_error = None
    retry_context = ""
    for attempt in range(2):
        attempt_system = system_prompt
        attempt_user = user_prompt
        if attempt:
            attempt_system = (
                f"{system_prompt}\nYour previous response was not valid JSON. "
                "Return exactly one valid JSON object, with no markdown, reasoning, commentary, or code fences."
            )
            attempt_user = (
                f"{user_prompt}\n\nThe previous response could not be parsed. "
                f"Correct it and return only the required JSON object. Previous response excerpt:\n{retry_context}"
            )

        try:
            raw = await chat_complete(
                system_prompt=attempt_system,
                user_prompt=attempt_user,
                model=model,
                base_url=base_url,
                api_key=api_key,
                max_tokens=max_tokens,
                use_json_format=True,
            )
        except AnalysisResponseError as exc:
            last_error = exc
            retry_context = "(empty response)"
            continue
        repaired = clean_and_repair_json(raw)
        retry_context = raw[:3000]
        if not repaired or repaired[0] not in ("{", "["):
            last_error = AnalysisResponseError("Analysis engine returned text instead of structured JSON")
            continue
        try:
            return json.loads(repaired)
        except json.JSONDecodeError as exc:
            last_error = exc

    raise AnalysisResponseError(
        "Analysis engine could not produce valid structured data after one formatting retry. Baseline results are available."
    ) from last_error


def get_active_provider_config(data_policy: str | None = None) -> dict:
    """Read active provider from settings or env vars."""
    from backend.utils.storage import get_settings
    settings = get_settings()
    if data_policy == "local_only":
        if settings.get("local_llm_endpoint") and settings.get("local_llm_model"):
            config = {
                "base_url": settings.get("local_llm_endpoint"),
                "model": settings.get("local_llm_model"),
                "api_key": os.getenv("LOCAL_LLM_API_KEY", "ollama"),
                "is_local": True,
                "max_tokens": normalize_max_tokens(os.getenv("LLM_MAX_TOKENS", "4096")),
            }
            validate_provider_url(config["base_url"], is_local=True, data_policy=data_policy)
            return config
        raise ValueError("local_only project requires a configured local LLM provider")
    active_id = settings.get("active_provider_id")
    if active_id:
        for p in settings.get("providers", []):
            if p.get("provider_id") == active_id:
                config = {
                    "base_url": p.get("base_url"),
                    "model": p.get("model"),
                    "api_key": _decrypt(p.get("_api_key", "")),
                    "is_local": bool(p.get("is_local") or p.get("provider_type") == "local"),
                    "max_tokens": normalize_max_tokens(p.get("max_tokens", 4096)),
                }
                validate_provider_url(config["base_url"], is_local=config["is_local"], data_policy=data_policy)
                return config
    if settings.get("local_llm_endpoint") and settings.get("local_llm_model"):
        config = {
            "base_url": settings.get("local_llm_endpoint"),
            "model": settings.get("local_llm_model"),
            "api_key": os.getenv("LOCAL_LLM_API_KEY", "ollama"),
            "is_local": True,
            "max_tokens": normalize_max_tokens(os.getenv("LLM_MAX_TOKENS", "4096")),
        }
        validate_provider_url(config["base_url"], is_local=True, data_policy=data_policy)
        return config
    config = {
        "base_url": os.getenv("OPENAI_BASE_URL"),
        "model": os.getenv("OPENAI_MODEL", "gpt-4o"),
        "api_key": os.getenv("OPENAI_API_KEY"),
        "is_local": False,
        "max_tokens": normalize_max_tokens(os.getenv("LLM_MAX_TOKENS", "4096")),
    }
    validate_provider_url(config["base_url"] or "https://api.openai.com/v1", data_policy=data_policy)
    return config
