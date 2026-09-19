"""Best-effort secret redaction for untrusted artifact content.

The original artifact hash is still calculated by the upload route, while the
redacted representation is the only representation sent to an AI provider or
stored as an evidence excerpt.
"""
from __future__ import annotations

import json
import re


SENSITIVE_KEYS = {
    "api_key", "apikey", "api-key", "access_token", "access-token", "refresh_token",
    "client_secret", "client-secret", "password", "passwd", "secret", "token",
    "authorization", "cookie", "set-cookie", "private_key", "private-key",
}


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key or "").casefold().replace(" ", "_")
    return normalized in SENSITIVE_KEYS or any(
        marker in normalized for marker in ("api_key", "access_token", "refresh_token", "client_secret", "private_key")
    )


def _redact_json(value, parents: tuple[str, ...] = ()):
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            key_text = str(key)
            # Redact the value of a sensitive field, but do not redact every
            # nested metadata field under an object such as an OpenAPI
            # security-scheme declaration.
            sensitive_context = _is_sensitive_key(key_text)
            if sensitive_context and isinstance(child, (str, int, float, bool)):
                result[key] = "[REDACTED]"
            elif key_text.casefold() in {"raw", "example", "default"} and isinstance(child, str):
                result[key] = redact_text(child)
            else:
                result[key] = _redact_json(child, (*parents, key_text))
        return result
    if isinstance(value, list):
        return [_redact_json(item, parents) for item in value[:500]]
    return value


_KEY_VALUE_RE = re.compile(
    r"(?:"
    r"(?P<quoted_prefix>(?:\"|')?(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|secret|token|authorization|cookie|private[_ -]?key)(?:\"|')?\s*[:=]\s*)"
    r"(?P<quote>[\"'])(?P<quoted_value>.*?)(?P=quote)"
    r"|"
    r"(?P<bare_prefix>(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|passwd|secret|token|authorization|cookie|private[_ -]?key)\s*[:=]\s*)"
    r"(?P<bare_value>[^,};\s]+)"
    r")",
    re.IGNORECASE,
)


def redact_text(content: str) -> str:
    """Redact scalar secret values while preserving structure and field names."""
    text = str(content or "")
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        def replace(match):
            prefix = match.group("quoted_prefix") or match.group("bare_prefix")
            quote = match.group("quote") or ""
            return f"{prefix}{quote}[REDACTED]{quote}"

        return _KEY_VALUE_RE.sub(replace, text)
    return json.dumps(_redact_json(parsed), indent=2, ensure_ascii=False)
