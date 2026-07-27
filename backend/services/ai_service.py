"""AI Service — wraps OpenAI-compatible LLM client (BYOK + local LLM)."""
from __future__ import annotations
import os
import json
from typing import Optional
from openai import AsyncOpenAI
from cryptography.fernet import Fernet
import base64


def _get_client(base_url: Optional[str] = None, api_key: Optional[str] = None) -> AsyncOpenAI:
    return AsyncOpenAI(
        api_key=api_key or os.getenv("OPENAI_API_KEY", "ollama"),
        base_url=base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )


def _get_model() -> str:
    return os.getenv("OPENAI_MODEL", "gpt-4o")


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
    kwargs = dict(
        model=model or _get_model(),
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    # Only pass response_format for cloud providers (OpenAI, Azure, OpenRouter).
    # Local LLMs (Ollama, LM Studio, vLLM) often don't support it and will 400.
    if use_json_format and _is_cloud_provider(base_url):
        kwargs["response_format"] = {"type": "json_object"}

    response = await client.chat.completions.create(**kwargs)
    return response.choices[0].message.content


def _is_cloud_provider(base_url: Optional[str]) -> bool:
    """Return True if the base_url points to a known cloud provider that supports response_format."""
    if not base_url:
        url = os.getenv("OPENAI_BASE_URL", "")
    else:
        url = base_url
    cloud_hosts = ("openai.com", "azure.com", "openrouter.ai", "googleapis.com")
    return any(h in url for h in cloud_hosts)


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
    raw = await chat_complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        model=model,
        base_url=base_url,
        api_key=api_key,
        max_tokens=max_tokens,
        use_json_format=True,  # only applied for cloud providers
    )
    repaired = clean_and_repair_json(raw)
    return json.loads(repaired)


def get_active_provider_config() -> dict:
    """Read active provider from settings or env vars."""
    from backend.utils.storage import get_settings
    settings = get_settings()
    active_id = settings.get("active_provider_id")
    if active_id:
        for p in settings.get("providers", []):
            if p.get("provider_id") == active_id:
                return {
                    "base_url": p.get("base_url"),
                    "model": p.get("model"),
                    "api_key": _decrypt(p.get("_api_key", "")),
                }
    if settings.get("local_llm_endpoint") and settings.get("local_llm_model"):
        return {
            "base_url": settings.get("local_llm_endpoint"),
            "model": settings.get("local_llm_model"),
            "api_key": os.getenv("LOCAL_LLM_API_KEY", "ollama"),
        }
    return {
        "base_url": os.getenv("OPENAI_BASE_URL"),
        "model": os.getenv("OPENAI_MODEL", "gpt-4o"),
        "api_key": os.getenv("OPENAI_API_KEY"),
    }
