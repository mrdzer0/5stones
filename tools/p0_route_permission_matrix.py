#!/usr/bin/env python3
"""Export the observed API route authorization matrix and enterprise caveats."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.main import app
from backend.utils.access_control import auth_mode


PUBLIC_API_ROUTES = {
    "/api/health",
    "/api/ux-telemetry/events",
    "/api/auth/config",
    "/api/auth/register",
    "/api/auth/login",
}


def walk(dependency):
    yield dependency.call
    for child in dependency.dependencies:
        yield from walk(child)


def role_sets(calls) -> list[set[str]]:
    found = []
    for call in calls:
        code = getattr(call, "__code__", None)
        closure = getattr(call, "__closure__", None) or ()
        if not code or "allowed" not in code.co_freevars:
            continue
        values = next((cell.cell_contents for name, cell in zip(code.co_freevars, closure) if name == "allowed"), None)
        if isinstance(values, set):
            found.append({str(role).casefold() for role in values})
    return found


def scope_for(path: str) -> str:
    if path == "/api/health":
        return "public_health"
    if path == "/api/ux-telemetry/events":
        return "anonymous_coarse_telemetry"
    if path == "/api/auth/config":
        return "public_auth_mode_discovery"
    if path == "/api/auth/register":
        return "registration_key_gated_analyst_signup"
    if path == "/api/auth/login":
        return "public_credential_exchange_rate_limited"
    if path in {"/api/docs", "/api/redoc", "/api/openapi.json"}:
        return "developer_documentation"
    if path.startswith("/api/settings"):
        return "verified_workspace_settings"
    if path == "/api/projects/import-archive":
        return "authenticated_account_scoped_archive_import"
    if path in {"/api/projects/legacy-import", "/api/projects/legacy-import/status"}:
        return "sole_local_admin_legacy_recovery"
    if "{project_id}" in path:
        return "workspace_scoped_project"
    if path == "/api/projects":
        return "workspace_project_collection"
    if path == "/api/projects/artifact/policy":
        return "authenticated_upload_policy"
    return "platform_api"


def build_matrix() -> dict:
    routes = []
    unclassified = []
    developer_docs = {path for path in (app.docs_url, app.redoc_url, app.openapi_url) if path}
    observed_auth_mode = auth_mode()
    for route in app.routes:
        path = str(getattr(route, "path", ""))
        if not path.startswith("/api"):
            continue
        methods = sorted(getattr(route, "methods", None) or [])
        calls = list(walk(route.dependant)) if hasattr(route, "dependant") else []
        names = {getattr(call, "__name__", "") for call in calls if call is not None}
        workspace_auth = "_require_workspace_access_dependency" in names
        explicitly_public = path in PUBLIC_API_ROUTES
        dev_docs = path in developer_docs
        scopes = role_sets(calls)
        effective = set.intersection(*scopes) if scopes else set()
        if explicitly_public:
            classification = "public_explicit"
            auth_dependency_declared = False
            allowed_roles = []
        elif dev_docs:
            classification = "public_local_docs_only"
            auth_dependency_declared = False
            allowed_roles = []
        elif workspace_auth:
            classification = "protected_when_auth_enabled"
            auth_dependency_declared = True
            allowed_roles = sorted(effective)
        else:
            classification = "unclassified_or_unprotected"
            auth_dependency_declared = False
            allowed_roles = []
            unclassified.append({"path": path, "methods": methods, "route_type": type(route).__name__})
        routes.append({
            "path": path,
            "methods": methods,
            "endpoint": getattr(getattr(route, "endpoint", None), "__name__", type(route).__name__),
            "scope": scope_for(path),
            "classification": classification,
            "workspace_auth_dependency_declared": auth_dependency_declared,
            "auth_enforced_in_observed_profile": auth_dependency_declared and observed_auth_mode != "disabled",
            "allowed_roles": allowed_roles,
        })

    static_routes = []
    for route in app.routes:
        path = str(getattr(route, "path", ""))
        if path in {"/", "/favicon.ico", "/{page}.html", "/static"}:
            static_routes.append({
                "path": path,
                "methods": sorted(getattr(route, "methods", None) or ["ALL"]),
                "classification": "unauthenticated_static_frontend",
                "enterprise_requirement": "Protect with the IdP/front-door or deployment proxy; FastAPI API authentication does not protect these resources.",
            })

    api_protected = sum(item["workspace_auth_dependency_declared"] for item in routes)
    api_enforced = sum(item["auth_enforced_in_observed_profile"] for item in routes)
    api_public = sum(item["classification"] == "public_explicit" for item in routes)
    docs_public = sum(item["classification"] == "public_local_docs_only" for item in routes)
    app_env = os.getenv("APP_ENV", "local_dev").strip().casefold() or "local_dev"
    return {
        "schema_version": "p0-route-permission-matrix-v1",
        "captured_at": datetime.now(ZoneInfo("Asia/Jakarta")).isoformat(),
        "deployment_profile_observed": app_env,
        "auth_mode_observed": observed_auth_mode,
        "enterprise_profile_contract": {
            "api_docs_enabled": bool(developer_docs),
            "api_docs_must_be_disabled": True,
            "static_frontend_auth_enforced_in_app": False,
            "static_frontend_must_be_protected_at_deployment_edge": True,
        },
        "deployment_profiles": {
            "local_dev": {
                "app_env": "local_dev",
                "auth_mode_default": "local_users",
                "auth_mode_legacy_opt_out": "disabled",
                "bind_host_default": "127.0.0.1",
                "api_docs": "enabled for local development",
                "persistence": "project data remains file-backed JSON; local user and session records use SQLite under DATA_DIR/auth",
                "provider_policy": "cloud hosts must be allowlisted; local_only requires a local provider",
            },
            "enterprise": {
                "app_env": "enterprise",
                "auth_mode_required": "oidc_jwt",
                "required_identity_config": ["HTTPS AUTH_JWKS_URL", "AUTH_ISSUER", "AUTH_AUDIENCE", "workspace claim", "roles claim"],
                "required_browser_origin_config": "explicit HTTPS CORS_ALLOWED_ORIGINS without wildcard",
                "required_secret": "unique APP_SECRET_KEY with at least 32 characters",
                "api_docs": "disabled at application construction",
                "static_frontend": "requires IdP/front-door or reverse-proxy protection",
                "browser_sso_status": "not implemented in repository",
                "durable_storage_status": "not ready; project/report/DFD state remains file-backed JSON",
                "production_release_ready": False,
            },
        },
        "data_classification_contract": {
            "default_handling": "Treat uploaded PRDs, API specifications, DFDs, reports, and prompts as confidential architecture data that may contain personal or regulated information until the data owner classifies them.",
            "qualification_inputs": "CR8 regression PRDs are synthetic; do not use production project data for provider qualification without organizational provider/egress/data-policy approval.",
        },
        "summary": {
            "api_route_entries": len(routes),
            "workspace_auth_dependency_entries": api_protected,
            "auth_enforced_in_observed_profile_entries": api_enforced,
            "explicit_public_api_entries": api_public,
            "local_developer_docs_entries": docs_public,
            "unclassified_api_entries": len(unclassified),
            "static_frontend_entries": len(static_routes),
        },
        "public_api_allowlist": sorted(PUBLIC_API_ROUTES),
        "developer_docs_routes": sorted(developer_docs),
        "routes": sorted(routes, key=lambda item: (item["path"], ",".join(item["methods"]))),
        "static_frontend_routes": sorted(static_routes, key=lambda item: item["path"]),
        "unclassified_routes": unclassified,
    }


def render_markdown(matrix: dict) -> str:
    summary = matrix["summary"]
    lines = [
        "# P0 API Route Permission Matrix", "",
        f"- Profile observed: `{matrix['deployment_profile_observed']}`",
        f"- Auth mode observed: `{matrix['auth_mode_observed']}`",
        f"- API entries: {summary['api_route_entries']} ({summary['workspace_auth_dependency_entries']} declare workspace-auth dependencies; {summary['auth_enforced_in_observed_profile_entries']} enforced in this profile; {summary['explicit_public_api_entries']} explicitly public; {summary['local_developer_docs_entries']} local docs)",
        f"- Unclassified/unprotected API entries: {summary['unclassified_api_entries']}",
        f"- Static frontend entries requiring edge protection: {summary['static_frontend_entries']}",
        "",
        "## API routes", "",
        "| Methods | Path | Classification | Auth enforced here? | Scope | Roles |", "|---|---|---|---|---|---|",
    ]
    for item in matrix["routes"]:
        enforced = "Yes" if item["auth_enforced_in_observed_profile"] else "No"
        lines.append(f"| {', '.join(item['methods'])} | `{item['path']}` | {item['classification']} | {enforced} | {item['scope']} | {', '.join(item['allowed_roles']) or '—'} |")
    lines += ["", "## Static frontend routes", "", "These routes do not inherit API auth dependencies. Enterprise deployment must protect them at the IdP/front door or reverse proxy.", "", "| Methods | Path | Classification |", "|---|---|---|"]
    for item in matrix["static_frontend_routes"]:
        lines.append(f"| {', '.join(item['methods'])} | `{item['path']}` | {item['classification']} |")
    lines += ["", "## Deployment profiles", "", "| Profile | Contract |", "|---|---|"]
    for name, profile in matrix["deployment_profiles"].items():
        detail = "; ".join(f"{key}: {value}" for key, value in profile.items())
        lines.append(f"| {name} | {detail} |")
    lines += ["", "## Data classification", "", matrix["data_classification_contract"]["default_handling"], "", matrix["data_classification_contract"]["qualification_inputs"], ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    markdown = Path(args.markdown).resolve() if args.markdown else output.with_suffix(".md")
    matrix = build_matrix()
    output.parent.mkdir(parents=True, exist_ok=True)
    markdown.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    markdown.write_text(render_markdown(matrix), encoding="utf-8")
    print(json.dumps({"summary": matrix["summary"], "output": str(output), "markdown": str(markdown)}, indent=2))
    return 1 if matrix["unclassified_routes"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
