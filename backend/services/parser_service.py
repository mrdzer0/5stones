"""Artifact parsing with deterministic support for structured API artifacts."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from backend.services.ai_service import chat_complete_json, get_active_provider_config
from backend.utils.redaction import redact_text


SYSTEM_PROMPT = """You are a security analyst specialized in extracting threat modeling context from technical documents.
Extract only what is explicitly stated or strongly implied. Do NOT hallucinate. Return strict JSON."""

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
PARSER_VERSION = "structured-api-v2"
GENERIC_CHUNK_MAX_CHARS = 6000
SENSITIVE_FIELD_TOKENS = {
    "address", "authorization", "birth", "card", "cookie", "credential", "dob", "email",
    "jwt", "ktp", "location", "name", "password", "phone", "secret", "ssn", "token",
}
_POSTMAN_VARIABLE_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


async def parse_artifact(artifact_type: str, content: str, data_policy: str | None = None) -> dict:
    """Parse an artifact without using AI for schema-defined API formats."""
    safe_content = redact_text(content)
    if artifact_type == "openapi":
        document = _load_structured_document(safe_content, allow_yaml=True)
        return parse_openapi_document(document)
    if artifact_type == "postman":
        document = _load_structured_document(safe_content, allow_yaml=False)
        return parse_postman_document(document)

    cfg = get_active_provider_config(data_policy)
    chunks = _document_chunks(safe_content)
    if not chunks:
        return _basic_extract(safe_content)

    chunk_results = []
    for chunk in chunks:
        user_prompt = f"""Analyze chunk {chunk['index']} of {chunk['total_chunks']} from this {artifact_type} artifact and extract security-relevant information.

SOURCE LOCATOR: {chunk['locator']}
ARTIFACT CONTENT CHUNK:
{chunk['content']}

Return a JSON object with these exact keys:
{{
  "actors": ["list of actors/users/roles mentioned"],
  "components": ["list of system components, services, APIs, DBs"],
  "data_flows": [{{"source": "...", "destination": "...", "data": ["..."], "protocol": "..."}}],
  "endpoints": ["list of API endpoints or entry points"],
  "data_fields": ["list of data fields, especially PII or sensitive data"],
  "external_systems": ["third-party services, partner systems"],
  "auth_methods": ["authentication methods mentioned"],
  "critical_actions": ["high-risk actions like payment, delete, admin functions"],
  "existing_controls": ["security controls already mentioned"],
  "use_cases": [{{
    "name": "business use-case name",
    "actor": "actor performing the use case",
    "trigger": "explicit trigger if stated",
    "preconditions": ["explicit precondition"],
    "steps": [
      {{"type": "action", "label": "actor or system action", "target": "component if stated", "data": ["data touched"]}},
      {{"type": "decision", "label": "decision or validation condition"}},
      {{"type": "data_store", "label": "explicit storage interaction"}},
      {{"type": "external_system", "label": "explicit third-party interaction"}}
    ],
    "data": ["data involved across the use case"],
    "evidence_snippet": "exact supporting excerpt from the artifact",
    "evidence_locator": "heading or section if available"
  }}],
  "evidence_items": [{{"snippet": "exact short excerpt", "locator": "source location", "topics": ["supported topic"]}}],
  "has_pii": true or false,
  "summary": "2-3 sentence summary"
}}

Return at most 12 evidence_items for this chunk. Each snippet must be copied verbatim from ARTIFACT CONTENT CHUNK,
must be understandable on its own, and must be no longer than 320 characters."""
        try:
            result = await chat_complete_json(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                base_url=cfg.get("base_url"),
                api_key=cfg.get("api_key"),
                model=cfg.get("model"),
                max_tokens=2500,
            )
            if isinstance(result, dict):
                chunk_results.append((chunk, result, "processed", None))
                continue
            raise ValueError("AI parser returned a non-object response")
        except Exception as exc:
            # Keep the deterministic fallback on the same redacted representation
            # as the AI path. A provider outage must not silently discard a tail
            # section; when deterministic extraction has no signal, the section
            # is explicitly marked deferred in the coverage manifest.
            fallback = _basic_extract(chunk["content"])
            has_signal = bool(
                fallback.get("evidence_items")
                or fallback.get("endpoints")
                or fallback.get("has_pii")
            )
            status = "processed_fallback" if has_signal else "deferred"
            reason = None if has_signal else f"AI extraction unavailable: {type(exc).__name__}"
            chunk_results.append((chunk, fallback, status, reason))

    return _merge_generic_results(safe_content, chunk_results)


def _document_chunks(content: str, max_chars: int = GENERIC_CHUNK_MAX_CHARS) -> list[dict]:
    """Split a redacted document on headings and line boundaries without gaps."""
    if not content:
        return []
    headings = list(re.finditer(r"(?m)^\s{0,3}(#{1,6})\s+(.+?)\s*$", content))
    sections = []
    if headings:
        if headings[0].start() > 0:
            sections.append((0, headings[0].start(), "Document preface"))
        for index, heading in enumerate(headings):
            end = headings[index + 1].start() if index + 1 < len(headings) else len(content)
            label = " ".join(heading.group(2).split())[:160] or "Untitled section"
            sections.append((heading.start(), end, label))
    else:
        sections.append((0, len(content), "Document"))

    chunks = []
    for section_start, section_end, label in sections:
        cursor = section_start
        while cursor < section_end:
            target = min(cursor + max_chars, section_end)
            end = target
            if target < section_end:
                boundary = content.rfind("\n", cursor + max_chars // 2, target)
                if boundary > cursor:
                    end = boundary + 1
            chunk_content = content[cursor:end]
            if not chunk_content:
                break
            chunks.append({
                "content": chunk_content,
                "start_char": cursor,
                "end_char": end,
                "section": label,
            })
            cursor = end

    total = len(chunks)
    for index, chunk in enumerate(chunks, start=1):
        chunk["index"] = index
        chunk["total_chunks"] = total
        chunk["chunk_id"] = f"chunk-{index:03d}"
        chunk["locator"] = (
            f"{chunk['section']} · characters {chunk['start_char'] + 1}-{chunk['end_char']}"
        )
    return chunks


def _merge_generic_results(content: str, chunk_results: list[tuple[dict, dict, str, str | None]]) -> dict:
    """Merge per-section AI/fallback results and make unread coverage explicit."""
    list_fields = (
        "actors", "components", "endpoints", "data_fields", "external_systems",
        "auth_methods", "critical_actions", "existing_controls", "operations", "warnings",
    )
    merged = {field: [] for field in list_fields}
    merged.update({"data_flows": [], "use_cases": [], "evidence_items": []})
    summaries = []
    coverage_chunks = []

    def append_unique(field: str, values: Any):
        if values is None:
            return
        if not isinstance(values, list):
            values = [values]
        for value in values or []:
            if isinstance(value, (dict, list)):
                key = json.dumps(value, sort_keys=True, ensure_ascii=False)
                existing = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in merged[field]}
            else:
                key = " ".join(str(value).split()).casefold()
                existing = {" ".join(str(item).split()).casefold() for item in merged[field]}
            if value and key not in existing:
                merged[field].append(value)

    for chunk, result, status, reason in chunk_results:
        for field in list_fields:
            append_unique(field, result.get(field))
        append_unique("data_flows", result.get("data_flows"))
        append_unique("use_cases", result.get("use_cases"))
        for item in result.get("evidence_items") or []:
            if not isinstance(item, dict):
                continue
            evidence = dict(item)
            evidence["chunk_id"] = chunk["chunk_id"]
            evidence["chunk_locator"] = chunk["locator"]
            if not evidence.get("locator"):
                evidence["locator"] = chunk["locator"]
            merged["evidence_items"].append(evidence)
        summary = " ".join(str(result.get("summary") or "").split())
        if summary:
            summaries.append(summary)
        coverage_chunks.append({
            "chunk_id": chunk["chunk_id"],
            "section": chunk["section"],
            "locator": chunk["locator"],
            "start_char": chunk["start_char"],
            "end_char": chunk["end_char"],
            "char_count": len(chunk["content"]),
            "status": status,
            **({"reason": reason} if reason else {}),
        })

    processed = [item for item in coverage_chunks if item["status"] != "deferred"]
    deferred = [item for item in coverage_chunks if item["status"] == "deferred"]
    coverage_status = "complete" if not deferred else "partial" if processed else "deferred"
    coverage = {
        "status": coverage_status,
        "source_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "total_characters": len(content),
        "chunk_count": len(coverage_chunks),
        "processed_chunk_count": len(processed),
        "deferred_chunk_count": len(deferred),
        "chunks": coverage_chunks,
        "unread_sections": [
            {"chunk_id": item["chunk_id"], "section": item["section"], "locator": item["locator"], "reason": item.get("reason")}
            for item in deferred
        ],
    }
    merged["has_pii"] = any(bool(result.get("has_pii")) for _, result, _, _ in chunk_results)
    merged["summary"] = " ".join(dict.fromkeys(summaries))[:2000] or "Artifact parsed with section coverage tracking."
    merged["stats"] = {
        "document_characters": len(content),
        "chunk_count": len(coverage_chunks),
        "processed_chunk_count": len(processed),
        "deferred_chunk_count": len(deferred),
        "evidence_candidate_count": len(merged["evidence_items"]),
    }
    merged["coverage_manifest"] = coverage
    merged["parser"] = {
        "kind": "ai_enrichment" if any(status == "processed" for _, _, status, _ in chunk_results) else "basic",
        "version": PARSER_VERSION,
        "chunked": True,
    }
    if deferred:
        merged["warnings"].append(
            f"{len(deferred)} document section(s) were deferred; review the ingestion coverage manifest."
        )
    return merged


def _load_structured_document(content: str, *, allow_yaml: bool) -> dict:
    try:
        value = json.loads(content)
    except json.JSONDecodeError as json_error:
        if not allow_yaml:
            raise ValueError(f"Invalid JSON: line {json_error.lineno}, column {json_error.colno}") from json_error
        try:
            import yaml

            value = yaml.safe_load(content)
        except Exception as yaml_error:
            raise ValueError("Invalid OpenAPI JSON/YAML document") from yaml_error
    if not isinstance(value, dict):
        raise ValueError("Artifact root must be an object")
    return value


def canonicalize_api_path(value: Any) -> str:
    """Return an environment-independent path while preserving parameter names."""
    raw = str(value or "").strip()
    raw = re.sub(r"^\{\{[^{}]+\}\}(?=/)", "", raw)
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = urlsplit(raw).path
    raw = raw.split("?", 1)[0].split("#", 1)[0]
    raw = re.sub(r"\{\{\s*([^{}]+?)\s*\}\}", r"{\1}", raw)
    raw = re.sub(r"(?<=/)\:([A-Za-z_][A-Za-z0-9_-]*)", r"{\1}", raw)
    raw = re.sub(r"/{2,}", "/", raw)
    if not raw.startswith("/"):
        raw = f"/{raw}"
    if len(raw) > 1:
        raw = raw.rstrip("/")
    return raw or "/"


def operation_match_key(method: str, path: str) -> str:
    generic_path = re.sub(r"\{[^{}]+\}", "{param}", canonicalize_api_path(path))
    return f"{method.upper()} {generic_path}"


def _unique_strings(values) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        text = " ".join(str(value or "").split())
        if not text or text.casefold() in seen:
            continue
        seen.add(text.casefold())
        result.append(text)
    return result


def _service_from_path(path: str, tags: list[str] | None = None) -> str:
    if tags:
        leading = str(tags[0]).split("/")[0].strip()
        if leading:
            return f"{leading} API"
    segments = [part for part in canonicalize_api_path(path).split("/") if part and not part.startswith("{")]
    leading = segments[0] if segments else "Application"
    if leading.casefold() in {"api", ".well-known", "well-known", ".well known", "well known"}:
        return "Application API"
    return f"{leading.replace('-', ' ').replace('_', ' ').title()} API"


def _classify_openapi_security(requirements: Any) -> str:
    if not requirements:
        return "public"
    if isinstance(requirements, list) and any(isinstance(item, dict) and not item for item in requirements):
        return "optional"
    return "secured"


def _security_names(requirements: Any) -> list[str]:
    if not isinstance(requirements, list):
        return []
    return _unique_strings(key for item in requirements if isinstance(item, dict) for key in item)


def _resolve_ref(document: dict, value: Any, seen: set[str] | None = None) -> Any:
    if not isinstance(value, dict) or not isinstance(value.get("$ref"), str):
        return value
    ref = value["$ref"]
    if not ref.startswith("#/"):
        return value
    seen = set(seen or ())
    if ref in seen:
        return value
    seen.add(ref)
    target: Any = document
    try:
        for token in ref[2:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            target = target[token]
    except (KeyError, TypeError):
        return value
    return _resolve_ref(document, target, seen)


def _schema_fields(document: dict, schema: Any, depth: int = 0, prefix: str = "") -> list[str]:
    if depth > 5 or not isinstance(schema, dict):
        return []
    schema = _resolve_ref(document, schema)
    if not isinstance(schema, dict):
        return []
    fields: list[str] = []
    for name, child in (schema.get("properties") or {}).items():
        field = f"{prefix}.{name}" if prefix else str(name)
        fields.append(field)
        fields.extend(_schema_fields(document, child, depth + 1, field))
    if isinstance(schema.get("items"), dict):
        fields.extend(_schema_fields(document, schema["items"], depth + 1, prefix))
    for keyword in ("allOf", "oneOf", "anyOf"):
        for child in schema.get(keyword) or []:
            fields.extend(_schema_fields(document, child, depth + 1, prefix))
    return _unique_strings(fields)


def _media_schema_fields(document: dict, content: Any) -> tuple[list[str], list[str]]:
    fields: list[str] = []
    media_types: list[str] = []
    if not isinstance(content, dict):
        return fields, media_types
    for media_type, media in content.items():
        media_types.append(str(media_type))
        if isinstance(media, dict):
            fields.extend(_schema_fields(document, media.get("schema")))
    return _unique_strings(fields), _unique_strings(media_types)


def _openapi_auth_methods(document: dict, names: list[str]) -> list[str]:
    definitions = ((document.get("components") or {}).get("securitySchemes") or {})
    if document.get("swagger"):
        definitions = document.get("securityDefinitions") or {}
    methods: list[str] = []
    for name in names:
        scheme = _resolve_ref(document, definitions.get(name, {}))
        if not isinstance(scheme, dict):
            methods.append(name)
            continue
        scheme_type = scheme.get("type")
        detail = scheme.get("scheme") or scheme.get("in")
        methods.append(f"{scheme_type} {detail}".strip() if scheme_type else name)
    return _unique_strings(methods)


def parse_openapi_document(document: dict) -> dict:
    version = document.get("openapi") or document.get("swagger")
    if not version or not isinstance(document.get("paths"), dict):
        candidate = document.get("collection") if isinstance(document.get("collection"), dict) else document
        if isinstance(candidate.get("info"), dict) and isinstance(candidate.get("item"), list):
            raise ValueError("This looks like a Postman Collection. Select Postman Collection and retry.")
        raise ValueError("The file is not a valid OpenAPI/Swagger document: missing version or paths")

    operations: list[dict] = []
    evidence_items: list[dict] = []
    global_security = document.get("security", [])
    for raw_path, path_item in document["paths"].items():
        if not isinstance(path_item, dict):
            continue
        inherited_parameters = path_item.get("parameters") or []
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            method_upper = method.upper()
            path = canonicalize_api_path(raw_path)
            tags = _unique_strings(operation.get("tags") or [])
            service = _service_from_path(path, tags)
            requirements = operation["security"] if "security" in operation else global_security
            security_names = _security_names(requirements)
            parameters: list[dict] = []
            request_fields: list[str] = []
            content_types: list[str] = []

            for parameter in [*inherited_parameters, *(operation.get("parameters") or [])]:
                parameter = _resolve_ref(document, parameter)
                if not isinstance(parameter, dict):
                    continue
                name = str(parameter.get("name") or "").strip()
                location = str(parameter.get("in") or "").strip()
                if name:
                    parameters.append({
                        "name": name,
                        "in": location,
                        "required": bool(parameter.get("required")),
                    })
                    if location != "header":
                        request_fields.append(name)
                request_fields.extend(_schema_fields(document, parameter.get("schema")))

            request_body = _resolve_ref(document, operation.get("requestBody"))
            if isinstance(request_body, dict):
                body_fields, body_media = _media_schema_fields(document, request_body.get("content"))
                request_fields.extend(body_fields)
                content_types.extend(body_media)

            # Swagger 2.0 body and form parameters.
            for parameter in operation.get("parameters") or []:
                parameter = _resolve_ref(document, parameter)
                if not isinstance(parameter, dict):
                    continue
                if parameter.get("in") == "body":
                    request_fields.extend(_schema_fields(document, parameter.get("schema")))
                elif parameter.get("in") == "formData" and parameter.get("name"):
                    request_fields.append(str(parameter["name"]))

            response_fields: list[str] = []
            response_types: list[str] = []
            for response in (operation.get("responses") or {}).values():
                response = _resolve_ref(document, response)
                if not isinstance(response, dict):
                    continue
                fields, media = _media_schema_fields(document, response.get("content"))
                response_fields.extend(fields)
                response_types.extend(media)
                response_fields.extend(_schema_fields(document, response.get("schema")))

            summary = " ".join(str(operation.get("summary") or operation.get("description") or "").split())[:320]
            locator = f"paths.{raw_path}.{method.lower()}"
            operation_record = {
                "key": f"{method_upper} {path}",
                "match_key": operation_match_key(method_upper, path),
                "method": method_upper,
                "path": path,
                "service": service,
                "operation_id": operation.get("operationId"),
                "summary": summary,
                "tags": tags,
                "security_status": _classify_openapi_security(requirements),
                "auth_methods": _openapi_auth_methods(document, security_names),
                "parameters": parameters,
                "request_fields": _unique_strings(request_fields),
                "response_fields": _unique_strings(response_fields),
                "content_types": _unique_strings([*content_types, *response_types]),
                "scenarios": [],
                "locator": locator,
            }
            operations.append(operation_record)
            if len(summary) >= 20 and len(evidence_items) < 12:
                evidence_items.append({"snippet": summary, "locator": locator, "topics": [operation_record["key"], service]})

    if not operations:
        raise ValueError("OpenAPI document contains no supported HTTP operations")

    services = _unique_strings(operation["service"] for operation in operations)
    data_fields = _unique_strings(
        field for operation in operations for field in [*operation["request_fields"], *operation["response_fields"]]
    )
    auth_methods = _unique_strings(method for operation in operations for method in operation["auth_methods"])
    info = document.get("info") or {}
    title = str(info.get("title") or "OpenAPI specification")
    return {
        "actors": [],
        "components": services,
        "data_flows": _flows_from_operations(operations),
        "endpoints": [operation["key"] for operation in operations],
        "data_fields": data_fields,
        "external_systems": [],
        "auth_methods": auth_methods,
        "critical_actions": _critical_actions(operations),
        "existing_controls": auth_methods,
        "evidence_items": evidence_items,
        "has_pii": _has_sensitive_fields(data_fields),
        "summary": f"{title}: {len(operations)} API operations across {len(services)} service groups.",
        "operations": operations,
        "warnings": [],
        "stats": {
            "path_count": len(document["paths"]),
            "operation_count": len(operations),
            "service_count": len(services),
        },
        "parser": {"kind": "openapi", "version": PARSER_VERSION, "document_version": str(version)},
    }


def _postman_url_path(url: Any) -> str:
    if isinstance(url, str):
        return canonicalize_api_path(url)
    if not isinstance(url, dict):
        return "/"
    path_parts = url.get("path")
    if isinstance(path_parts, list) and path_parts:
        return canonicalize_api_path("/" + "/".join(str(part) for part in path_parts))
    return canonicalize_api_path(url.get("raw") or "/")


def _postman_auth(auth: Any) -> tuple[str, list[str]]:
    if not isinstance(auth, dict):
        return "unknown", []
    auth_type = str(auth.get("type") or "").strip()
    if not auth_type:
        return "unknown", []
    if auth_type == "noauth":
        return "public", []
    return "secured", [auth_type]


def _json_field_names(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
    if depth > 5:
        return []
    fields: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            field = f"{prefix}.{key}" if prefix else str(key)
            fields.append(field)
            fields.extend(_json_field_names(child, field, depth + 1))
    elif isinstance(value, list) and value:
        fields.extend(_json_field_names(value[0], prefix, depth + 1))
    return _unique_strings(fields)


def _postman_body_fields(body: Any) -> tuple[list[str], list[str]]:
    if not isinstance(body, dict):
        return [], []
    mode = str(body.get("mode") or "").strip()
    fields: list[str] = []
    if mode == "raw" and isinstance(body.get("raw"), str):
        try:
            fields.extend(_json_field_names(json.loads(body["raw"])))
        except (json.JSONDecodeError, TypeError):
            pass
    elif mode in {"formdata", "urlencoded"}:
        for item in body.get(mode) or []:
            if isinstance(item, dict) and item.get("key"):
                fields.append(str(item["key"]))
    elif mode == "graphql" and isinstance(body.get("graphql"), dict):
        variables = body["graphql"].get("variables")
        if isinstance(variables, str):
            try:
                fields.extend(_json_field_names(json.loads(variables)))
            except json.JSONDecodeError:
                pass
    return _unique_strings(fields), ([mode] if mode else [])


def _postman_variable_refs(value: Any) -> list[str]:
    """Extract variable names only; never retain Postman variable values."""
    if isinstance(value, str):
        return _unique_strings(match.group(1).strip() for match in _POSTMAN_VARIABLE_RE.finditer(value))
    if isinstance(value, dict):
        return _unique_strings(
            item
            for key, nested in value.items()
            for item in [*_postman_variable_refs(key), *_postman_variable_refs(nested)]
        )
    if isinstance(value, list):
        return _unique_strings(item for value_item in value for item in _postman_variable_refs(value_item))
    return []


def _postman_saved_response_examples(item: dict) -> list[dict]:
    """Capture response shape metadata without persisting response payloads."""
    examples = []
    for response in item.get("response") or []:
        if not isinstance(response, dict):
            continue
        body_fields: list[str] = []
        body = response.get("body")
        if isinstance(body, str):
            try:
                body_fields = _json_field_names(json.loads(body))
            except (json.JSONDecodeError, TypeError):
                body_fields = []
        header_names = _unique_strings(
            header.get("key")
            for header in response.get("header") or []
            if isinstance(header, dict) and header.get("key")
        )
        examples.append({
            "name": " ".join(str(response.get("name") or "Saved response").split())[:160],
            "status": " ".join(str(response.get("status") or "").split())[:80],
            "code": response.get("code") if isinstance(response.get("code"), int) else None,
            "header_names": header_names,
            "body_fields": body_fields[:48],
            "has_body": bool(body),
        })
    return examples[:12]


def _unique_dicts(values) -> list[dict]:
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            continue
        key = json.dumps(value, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def parse_postman_document(document: dict) -> dict:
    collection = document.get("collection") if isinstance(document.get("collection"), dict) else document
    if not isinstance(collection.get("info"), dict) or not isinstance(collection.get("item"), list):
        if document.get("openapi") or document.get("swagger"):
            raise ValueError("This looks like an OpenAPI/Swagger document. Select OpenAPI / Swagger and retry.")
        raise ValueError("The file is not a valid Postman Collection: missing info or item")

    scenarios: list[dict] = []
    evidence_items: list[dict] = []
    known_variables = {
        str(item.get("key")).strip()
        for item in (collection.get("variable") or [])
        if isinstance(item, dict) and str(item.get("key") or "").strip()
    }
    unresolved_variables: set[str] = set()
    ignored_script_count = 0

    def script_count(events: Any) -> int:
        nonlocal ignored_script_count
        count = 0
        for event in events or []:
            if not isinstance(event, dict) or event.get("listen") not in {"prerequest", "test"}:
                continue
            exec_block = (event.get("script") or {}).get("exec") if isinstance(event.get("script"), dict) else None
            if isinstance(exec_block, list):
                count += 1
            elif exec_block:
                count += 1
        ignored_script_count += count
        return count

    script_count(collection.get("event"))

    def walk(items: list, folders: list[str], inherited_auth: Any):
        for item in items:
            if not isinstance(item, dict):
                continue
            name = " ".join(str(item.get("name") or "Unnamed request").split())
            effective_auth = item.get("auth", inherited_auth)
            item_script_count = script_count(item.get("event"))
            if "request" not in item and isinstance(item.get("item"), list):
                walk(item["item"], [*folders, name], effective_auth)
                continue
            if "request" not in item:
                continue
            request = item["request"]
            if isinstance(request, str):
                request = {"method": "GET", "url": request}
            if not isinstance(request, dict):
                continue
            request_auth = request.get("auth", effective_auth)
            auth_source = (
                "request" if "auth" in request
                else "item" if "auth" in item
                else "inherited" if effective_auth is not None
                else "none"
            )
            method = str(request.get("method") or "GET").upper()
            path = _postman_url_path(request.get("url"))
            security_status, auth_methods = _postman_auth(request_auth)
            body_fields, body_modes = _postman_body_fields(request.get("body"))
            variable_refs = _postman_variable_refs(request)
            unresolved_refs = sorted(set(variable_refs) - known_variables, key=str.casefold)
            unresolved_variables.update(unresolved_refs)
            saved_response_examples = _postman_saved_response_examples(item)
            response_fields = _unique_strings(
                field
                for example in saved_response_examples
                for field in example.get("body_fields", [])
            )
            url = request.get("url") if isinstance(request.get("url"), dict) else {}
            query_names = _unique_strings(
                query.get("key") for query in (url.get("query") or []) if isinstance(query, dict) and query.get("key")
            )
            header_names = _unique_strings(
                header.get("key") for header in (request.get("header") or []) if isinstance(header, dict) and header.get("key")
            )
            service = _service_from_path(path, folders[:1])
            locator = " / ".join([*folders, name])
            description = request.get("description")
            if isinstance(description, dict):
                description = description.get("content")
            description = " ".join(str(description or "").split())[:320]
            scenario = {
                "name": name,
                "folder": " / ".join(folders),
                "method": method,
                "path": path,
                "match_key": operation_match_key(method, path),
                "service": service,
                "security_status": security_status,
                "auth_methods": auth_methods,
                "auth_source": auth_source,
                "request_fields": _unique_strings([*query_names, *body_fields]),
                "query_parameters": query_names,
                "header_names": header_names,
                "body_modes": body_modes,
                "response_fields": response_fields,
                "saved_response_examples": saved_response_examples,
                "variable_refs": variable_refs,
                "unresolved_variable_refs": unresolved_refs,
                "scripts_not_executed": item_script_count,
                "locator": locator,
            }
            scenarios.append(scenario)
            if len(description) >= 20 and len(evidence_items) < 12:
                evidence_items.append({"snippet": description, "locator": locator, "topics": [f"{method} {path}", service]})

    walk(collection["item"], [], collection.get("auth"))
    if not scenarios:
        raise ValueError("Postman Collection contains no supported requests")

    grouped: dict[str, list[dict]] = defaultdict(list)
    for scenario in scenarios:
        grouped[scenario["match_key"]].append(scenario)

    operations: list[dict] = []
    for match_key in sorted(grouped):
        group = grouped[match_key]
        first = group[0]
        known_security = _unique_strings(
            scenario["security_status"] for scenario in group if scenario["security_status"] != "unknown"
        )
        security_status = known_security[0] if len(known_security) == 1 else ("conflict" if known_security else "unknown")
        operations.append({
            "key": f"{first['method']} {first['path']}",
            "match_key": match_key,
            "method": first["method"],
            "path": first["path"],
            "service": first["service"],
            "operation_id": None,
            "summary": first["name"],
            "tags": _unique_strings(scenario["folder"] for scenario in group if scenario["folder"]),
            "security_status": security_status,
            "auth_methods": _unique_strings(method for scenario in group for method in scenario["auth_methods"]),
            "auth_sources": _unique_strings(scenario.get("auth_source") for scenario in group),
            "parameters": [],
            "request_fields": _unique_strings(field for scenario in group for field in scenario["request_fields"]),
            "response_fields": _unique_strings(field for scenario in group for field in scenario.get("response_fields", [])),
            "saved_response_examples": _unique_dicts(
                example for scenario in group for example in scenario.get("saved_response_examples", [])
            ),
            "unresolved_variable_refs": _unique_strings(
                value for scenario in group for value in scenario.get("unresolved_variable_refs", [])
            ),
            "content_types": _unique_strings(mode for scenario in group for mode in scenario["body_modes"]),
            "scenarios": [{key: value for key, value in scenario.items() if key not in {"match_key", "service"}} for scenario in group],
            "locator": first["locator"],
        })

    services = _unique_strings(operation["service"] for operation in operations)
    data_fields = _unique_strings(
        field
        for operation in operations
        for field in [*operation["request_fields"], *operation.get("response_fields", [])]
    )
    auth_methods = _unique_strings(method for operation in operations for method in operation["auth_methods"])
    name = str(collection.get("info", {}).get("name") or "Postman Collection")
    duplicate_count = len(scenarios) - len(operations)
    warnings = []
    if duplicate_count:
        warnings.append(f"{duplicate_count} request variants were attached as scenarios instead of duplicate entry points.")
    if unresolved_variables:
        warnings.append(
            f"{len(unresolved_variables)} Postman variable reference(s) could not be resolved; names were preserved without values."
        )
    if ignored_script_count:
        warnings.append(
            f"{ignored_script_count} Postman pre-request/test script(s) were detected and intentionally not executed."
        )
    return {
        "actors": [],
        "components": services,
        "data_flows": _flows_from_operations(operations),
        "endpoints": [operation["key"] for operation in operations],
        "data_fields": data_fields,
        "external_systems": [],
        "auth_methods": auth_methods,
        "critical_actions": _critical_actions(operations),
        "existing_controls": auth_methods,
        "evidence_items": evidence_items,
        "has_pii": _has_sensitive_fields(data_fields),
        "summary": f"{name}: {len(scenarios)} request scenarios mapped to {len(operations)} unique API operations.",
        "operations": operations,
        "warnings": warnings,
        "stats": {
            "request_count": len(scenarios),
            "operation_count": len(operations),
            "duplicate_scenario_count": duplicate_count,
            "service_count": len(services),
            "unresolved_variable_count": len(unresolved_variables),
            "ignored_script_count": ignored_script_count,
        },
        "parser": {
            "kind": "postman",
            "version": PARSER_VERSION,
            "document_version": str(collection.get("info", {}).get("schema") or "unknown"),
            "wrapped": collection is not document,
        },
    }


def _flows_from_operations(operations: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for operation in operations:
        grouped[operation.get("service") or "Application API"].append(operation)
    flows = []
    for service in sorted(grouped):
        service_operations = grouped[service]
        data = _unique_strings(
            field for operation in service_operations for field in operation.get("request_fields", [])
        )[:20]
        flows.append({
            "source": "External API client",
            "destination": service,
            "protocol": "HTTPS",
            "data": data or ["API request data"],
            "operation_count": len(service_operations),
            "evidence_type": "derived",
            "basis": "Aggregated from API operations grouped by logical service label; deployment topology is not asserted.",
            "confidence": "Medium",
        })
    return flows


def _critical_actions(operations: list[dict]) -> list[str]:
    result = []
    keywords = {"admin", "auth", "delete", "login", "password", "payment", "reset", "token", "upload"}
    for operation in operations:
        text = f"{operation.get('path', '')} {operation.get('summary', '')}".lower()
        if operation.get("method") in {"POST", "PUT", "PATCH", "DELETE"} or any(word in text for word in keywords):
            result.append(operation["key"])
    return _unique_strings(result)


def _has_sensitive_fields(fields: list[str]) -> bool:
    for field in fields:
        tokens = set(re.findall(r"[a-z0-9]+", field.lower()))
        if tokens & SENSITIVE_FIELD_TOKENS:
            return True
    return False


def _basic_extract(content: str) -> dict:
    endpoints = re.findall(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)", content)
    pii_patterns = ["email", "phone", "password", "ssn", "nama", "address", "dob", "ktp"]
    has_pii = any(pattern in content.lower() for pattern in pii_patterns)
    return {
        "actors": [],
        "components": [],
        "data_flows": [],
        "endpoints": _unique_strings(endpoints),
        "data_fields": [],
        "external_systems": [],
        "auth_methods": [],
        "critical_actions": [],
        "existing_controls": [],
        "use_cases": [],
        "evidence_items": _basic_evidence_items(content),
        "has_pii": has_pii,
        "summary": "Artifact parsed with basic extraction (AI not available).",
        "operations": [],
        "warnings": ["Structured extraction was unavailable for this artifact type."],
        "stats": {},
        "parser": {"kind": "basic", "version": PARSER_VERSION},
    }


def _basic_evidence_items(content: str) -> list[dict]:
    keywords = {
        "api", "endpoint", "database", "data", "auth", "token", "user", "privacy",
        "personal", "pii", "external", "third-party", "webhook", "store", "retention",
        "location", "image", "model", "admin", "public", "encrypt", "access",
    }
    ranked = []
    for index, raw_line in enumerate(content.splitlines(), start=1):
        line = " ".join(raw_line.split())
        if len(line) < 28 or len(line) > 500:
            continue
        line_tokens = set(re.findall(r"[a-z0-9_-]+", line.lower()))
        matched = sorted(line_tokens & keywords)
        if not matched:
            continue
        ranked.append((len(matched), index, line[:320], matched[:6]))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [
        {"snippet": line, "locator": f"Extracted text · line {index}", "topics": topics}
        for _, index, line, topics in ranked[:12]
    ]
