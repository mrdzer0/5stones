"""Provider endpoint and resource policy for analysis integrations.

Documents and project data are untrusted inputs. Provider URLs therefore need
an explicit allowlist and local-only projects must never silently fall back to
a cloud endpoint.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
DEFAULT_CLOUD_HOSTS = {
    "api.openai.com",
    "api.openrouter.ai",
    "openrouter.ai",
}


class ProviderPolicyError(ValueError):
    """Raised when a provider violates endpoint or data-policy rules."""


def _configured_hosts() -> set[str]:
    raw = os.getenv("LLM_PROVIDER_ALLOWLIST", "").strip()
    return {
        item.strip().casefold().lstrip(".")
        for item in raw.split(",")
        if item.strip()
    }


def hostname_for_url(base_url: str) -> str:
    value = str(base_url or "").strip()
    if not value:
        raise ProviderPolicyError("Provider URL is required")
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ProviderPolicyError("Provider URL must use http or https and include a hostname")
    if parsed.username or parsed.password:
        raise ProviderPolicyError("Provider URL must not contain embedded credentials")
    if parsed.fragment:
        raise ProviderPolicyError("Provider URL must not contain a fragment")
    return parsed.hostname.casefold().rstrip(".")


def is_local_provider_url(base_url: str) -> bool:
    hostname = hostname_for_url(base_url)
    if hostname in LOCAL_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def _host_matches(hostname: str, allowed: set[str]) -> bool:
    return any(hostname == value or hostname.endswith(f".{value}") for value in allowed)


def validate_provider_url(
    base_url: str,
    *,
    is_local: bool | None = None,
    data_policy: str | None = None,
) -> dict:
    """Validate and classify a provider endpoint without making a request."""
    hostname = hostname_for_url(base_url)
    local = is_local_provider_url(base_url) if is_local is None else bool(is_local)

    if data_policy == "local_only" and not local:
        raise ProviderPolicyError("local_only projects require a local provider endpoint")

    if local:
        local_allowlist = _configured_hosts() | LOCAL_HOSTS
        if not _host_matches(hostname, local_allowlist):
            raise ProviderPolicyError("Local provider hostname is not allowlisted")
    else:
        allowed = DEFAULT_CLOUD_HOSTS | _configured_hosts()
        if not _host_matches(hostname, allowed):
            raise ProviderPolicyError(
                "Provider hostname is not allowlisted; configure LLM_PROVIDER_ALLOWLIST for a custom endpoint"
            )

    return {"hostname": hostname, "is_local": local}


def normalize_max_tokens(value, *, default: int = 4096) -> int:
    """Clamp provider token budgets to a safe, explicit resource range."""
    try:
        tokens = int(value)
    except (TypeError, ValueError) as exc:
        raise ProviderPolicyError("max_tokens must be an integer") from exc
    ceiling = int(os.getenv("LLM_MAX_TOKENS_LIMIT", "128000"))
    ceiling = max(256, min(128000, ceiling))
    if tokens < 256 or tokens > ceiling:
        raise ProviderPolicyError(f"max_tokens must be between 256 and {ceiling}")
    return tokens


def normalize_timeout_seconds(value, *, default: float = 180.0) -> float:
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ProviderPolicyError("LLM timeout must be a number") from exc
    ceiling = float(os.getenv("LLM_TIMEOUT_MAX_SECONDS", "1800"))
    ceiling = max(1.0, min(3600.0, ceiling))
    if seconds < 1.0 or seconds > ceiling:
        raise ProviderPolicyError(f"LLM timeout must be between 1 and {ceiling:g} seconds")
    return seconds


def normalize_max_retries(value, *, default: int = 0) -> int:
    try:
        retries = int(value)
    except (TypeError, ValueError) as exc:
        raise ProviderPolicyError("LLM max retries must be an integer") from exc
    if retries < 0 or retries > 3:
        raise ProviderPolicyError("LLM max retries must be between 0 and 3")
    return retries
