#!/usr/bin/env python3
"""Create a reproducible, non-secret P0 source/corpus/provider fingerprint."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "prd_corpus"
ARTIFACT_ROOT = ROOT / "artifacts" / "p0"
SKIP_PREFIXES = (
    ".git/", ".venv/", "node_modules/", "artifacts/", "__pycache__/",
    "backend/data/projects/", "backend/data/reports/", "backend/data/analysis_runs/",
    "backend/data/dfd_models/", "backend/data/report_revisions/",
    "backend/data/workspace_settings/",
)
SKIP_EXACT = {".env", "backend/data/settings.json"}
SKIP_SUFFIXES = {".pyc", ".log", ".sqlite", ".sqlite3", ".db", ".pem", ".crt", ".p12", ".pfx", ".key"}
DEPENDENCIES = (
    "fastapi", "uvicorn", "pydantic", "openai", "cryptography",
    "PyJWT", "python-dotenv", "starlette",
)
EVIDENCE_REFERENCES = (
    "artifacts/p0/2026-10-04/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_after_live_harness_fix_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_release_gate_integrity_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_release_gate_integrity_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_fixture_project_release_decision_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_project_release_decision_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_fixture_metric_provenance_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_local_profile_loopback_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_atomic_storage_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_cas_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_project_cas_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_analysis_ready_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_provider_model_source_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_retry1/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_retry1/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_retry1/cr8_release_decision_evaluator_v1_1.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_retry1/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_p0_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_p0_final/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_p0_final/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_p0_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_p0_final/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_p0_interrupted_before_provider/cr8_qualification.json",
    "artifacts/p0/2026-10-04/p0_route_permission_matrix.json",
    "artifacts/p0/2026-10-04/p0_route_permission_matrix.md",
    "artifacts/p0/2026-10-04/p0_route_permission_matrix_enterprise_profile.json",
    "artifacts/p0/2026-10-04/p0_route_permission_matrix_enterprise_profile.md",
    "artifacts/p0/2026-10-04/p0_self_threat_matrix.md",
    "fixtures/p0_self_threat_matrix.json",
    "artifacts/p0/2026-10-04/golden_corpus_offline_evaluation.json",
    "artifacts/p0/2026-10-04/golden_corpus_offline_evaluation.md",
    "artifacts/p0/2026-10-04/p0_additional_regression_validation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_isolated_review_questions/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_scoped_dfd_questions_coverage/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_cleanup_regression/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_cleanup_regression/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_cleanup_regression/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_framework_coverage_false_complete_fix/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_framework_coverage_false_complete_fix/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_framework_coverage_false_complete_fix/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_post_telemetry_fix/run_harness_error.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_cleanup_fixed/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_cleanup_fixed/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_cleanup_fixed/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_cleanup_fixed/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_cleanup_fixed/cr8_release_decision_coverage_rechecked.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_cleanup_fixed/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/cr8_fixture_audit_chain_hardening/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_audit_chain_hardening/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_audit_chain_hardening/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_audit_chain_hardening/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_audit_chain_hardening/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_audit_chain_hardening/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/cr8_fixture_performance_censored_gate_v4/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_performance_censored_gate_v4/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_performance_censored_gate_v4/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_batch_coverage_v4/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_batch_coverage_v4/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_batch_coverage_v4/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_batch_coverage_v4/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_live_sumopod_deepseek-v4-flash_batch_coverage_v4/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/sumopod_provider_preflight_current.json",
    "artifacts/p0/2026-10-04/p0_preflight_validation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_request_body_limit_streaming/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_request_body_limit_streaming/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_request_body_limit_streaming/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/p0_request_body_limit_validation.json",
    "artifacts/p0/2026-10-04/p0_analysis_concurrency_validation.json",
    "artifacts/p0/2026-10-04/p0_oidc_clock_skew_validation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_p0_security_followup_latest/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_p0_security_followup_latest/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/p0_security_followup_validation.json",
    "artifacts/p0/2026-10-04/cr8_release_decision_request_body_limit_recheck.json",
    "artifacts/p0/2026-10-04/cr8_fixture_exhaustive_framework_coverage_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_exhaustive_framework_coverage_final/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_exhaustive_framework_coverage_final/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_exhaustive_framework_coverage_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_fixture_exhaustive_framework_coverage_final/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/p0_fixture_framework_coverage_validation.json",
    "artifacts/p0/2026-10-04/p0_dfd_owner_review_handoff_fixture_latest.md",
    "artifacts/p0/2026-10-04/p0_dfd_owner_handoff_validation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_artifact_json_upload_hardening/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_artifact_json_upload_hardening/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_artifact_json_upload_hardening/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_artifact_json_upload_hardening/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/cr8_fixture_artifact_json_upload_hardening/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/p0_artifact_upload_integrity_validation.json",
    "artifacts/p0/2026-10-04/p0_enterprise_release_authority_validation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_enterprise_release_authority_guard_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_enterprise_release_authority_guard_final/prd_corpus_e2e_v2.json",
    "artifacts/p0/2026-10-04/cr8_fixture_enterprise_release_authority_guard_final/prd_corpus_evaluation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_enterprise_release_authority_guard_final/reviewer_evidence_pending.json",
    "artifacts/p0/2026-10-04/cr8_fixture_enterprise_release_authority_guard_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/cr8_fixture_export_release_verdict_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_export_release_verdict_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/p0_export_release_decision_validation.json",
    "artifacts/p0/2026-10-04/cr8_fixture_report_signed_authority_browser_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_report_signed_authority_browser_final/cr8_release_decision.json",
    "artifacts/p0/2026-10-04/p0_report_release_decision_ui_validation.json",
    "artifacts/p0/2026-10-04/p0_project_release_action_validation.json",
    "artifacts/p0/2026-10-04/p0_definition_of_done_audit.json",
    "artifacts/p0/2026-10-04/p0_definition_of_done_audit.md",
    "artifacts/p0/2026-10-04/cr8_fixture_report_signed_authority_complete_blockers_final/cr8_qualification.json",
    "artifacts/p0/2026-10-04/cr8_fixture_report_signed_authority_complete_blockers_final/cr8_release_decision.json",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def included(path: str) -> bool:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if Path(normalized).name.lower() == ".env.example":
        return True
    if normalized in SKIP_EXACT or normalized.startswith(SKIP_PREFIXES):
        return False
    if Path(normalized).suffix.lower() in SKIP_SUFFIXES:
        return False
    if Path(normalized).name.lower().startswith((".env.", "id_rsa", "id_ed25519")):
        return False
    return True


def status_summary() -> dict:
    raw = git("status", "--porcelain=v1", "--untracked-files=all", "-z")
    entries = [item for item in raw.split(b"\0") if item]
    counts = {"staged": 0, "worktree": 0, "untracked": 0, "deleted": 0}
    paths = []
    index = 0
    while index < len(entries):
        item = entries[index]
        index += 1
        status = item[:2].decode("ascii", "replace")
        path = item[3:].decode("utf-8", "surrogateescape")
        if status.startswith("R") or status.startswith("C"):
            index += 1  # The next NUL-delimited value is the rename source path.
        if not included(path):
            continue
        if status == "??":
            counts["untracked"] += 1
        else:
            if status[0] not in (" ", "?"):
                counts["staged"] += 1
            if status[1] not in (" ", "?"):
                counts["worktree"] += 1
            if "D" in status:
                counts["deleted"] += 1
        paths.append({"status": status, "path": path})
    return {"dirty": bool(paths), "counts": counts, "paths": paths}


def source_inventory() -> tuple[list[dict], str]:
    raw = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    paths = sorted({item.decode("utf-8", "surrogateescape") for item in raw.split(b"\0") if item and included(item.decode("utf-8", "surrogateescape"))})
    files = []
    for relative in paths:
        target = ROOT / relative
        if target.is_symlink():
            link_target = os.readlink(target)
            entry = {"path": relative, "kind": "symlink", "bytes": len(link_target.encode()), "sha256": sha256_bytes(link_target.encode())}
        elif target.is_file():
            entry = {"path": relative, "kind": "file", "bytes": target.stat().st_size, "sha256": sha256_file(target)}
        else:
            continue
        files.append(entry)
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return files, sha256_bytes(canonical)


def corpus_fingerprint() -> dict:
    manifest_path = CORPUS / "manifest.json"
    contract_path = CORPUS / "metric_contract.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = []
    for item in manifest.get("cases", []):
        path = CORPUS / item["file"]
        cases.append({"case_id": item["id"], "file": item["file"], "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    case_bytes = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
    return {
        "version": manifest.get("version"),
        "case_count": len(cases),
        "manifest_sha256": sha256_file(manifest_path),
        "metric_contract_sha256": sha256_file(contract_path),
        "cases": cases,
        "cases_fingerprint_sha256": sha256_bytes(case_bytes),
    }


def nonsecret_provider_config() -> dict:
    settings_path = ROOT / "backend" / "data" / "settings.json"
    if not settings_path.exists():
        return {"source": "local_settings", "status": "not_configured"}
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    active_id = settings.get("active_provider_id")
    provider = next((item for item in settings.get("providers", []) if item.get("provider_id") == active_id), None)
    if not provider:
        return {"source": "local_settings", "status": "no_active_provider", "data_policy": settings.get("default_data_policy")}
    endpoint = urlsplit(str(provider.get("base_url") or ""))
    return {
        "source": "local_settings",
        "status": "active_provider",
        "provider_name": provider.get("name"),
        "provider_type": provider.get("provider_type"),
        "model": provider.get("model"),
        "endpoint_hostname": (endpoint.hostname or "").lower(),
        "endpoint_https": endpoint.scheme.lower() == "https",
        "credential_present": bool(provider.get("_api_key")),
        "data_policy": settings.get("default_data_policy"),
    }


def nonsecret_runtime_policy() -> dict:
    try:
        from dotenv import dotenv_values
        file_values = dotenv_values(ROOT / ".env")
    except Exception:
        file_values = {}
    selected = {}
    for name in ("LLM_PROVIDER_ALLOWLIST", "LLM_TIMEOUT_SECONDS", "LLM_MAX_RETRIES", "LLM_MAX_TOKENS_LIMIT", "LLM_TIMEOUT_MAX_SECONDS"):
        value = os.getenv(name) or file_values.get(name)
        if not value:
            continue
        if name == "LLM_PROVIDER_ALLOWLIST":
            selected["provider_allowlist_hosts"] = sorted({host.strip().casefold().rstrip(".") for host in str(value).split(",") if host.strip()})
        else:
            selected[name.lower()] = str(value)
    return selected


def dependency_versions() -> dict:
    versions = {name: importlib.metadata.version(name) for name in DEPENDENCIES if _has_distribution(name)}
    for key, command in (("node", "node"), ("npm", "npm")):
        result = subprocess.run([command, "--version"], cwd=ROOT, capture_output=True, text=True, check=False)
        versions[key] = result.stdout.strip() if result.returncode == 0 else None
    versions["python"] = sys.version.split()[0]
    return versions


def _has_distribution(name: str) -> bool:
    try:
        importlib.metadata.version(name)
        return True
    except importlib.metadata.PackageNotFoundError:
        return False


def qualification_reference(relative: str) -> dict:
    path = ROOT / relative
    if not path.is_file():
        return {"path": relative, "present": False}
    reference = {"path": relative, "present": True, "file_sha256": sha256_file(path), "bytes": path.stat().st_size}
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return reference
    if report.get("schema_version") == "cr8-qualification-v1":
        selection = report.get("provider_selection") or {}
        reference.update({
            "run_id": report.get("namespace"),
            "artifact_hash": report.get("artifact_hash"),
            "mode": report.get("mode"),
            "release_verdict": report.get("release_gate", {}).get("verdict"),
            "live_provider_status": report.get("live_provider_qualification", {}).get("status"),
            "case_count": len(report.get("cases", [])),
            "completed_case_count": sum(bool(item.get("metrics")) for item in report.get("cases", [])),
            "provider_selection": {
                key: selection.get(key)
                for key in ("provider_name", "model", "endpoint_hostname", "timeout_seconds", "max_retries", "corpus_case_count")
                if selection.get(key) is not None
            },
        })
    elif report.get("schema_version") == "cr8-release-decision-v1":
        reference.update({"run_id": report.get("run_id"), "release_verdict": report.get("verdict")})
    elif report.get("schema_version") == "p0-route-permission-matrix-v1":
        reference.update({
            "observed_profile": report.get("deployment_profile_observed"),
            "route_summary": report.get("summary"),
        })
    elif report.get("corpus_id") == "5stones-core-threat-model":
        reference.update({
            "candidate_source": report.get("candidate_source"),
            "corpus_revision": report.get("corpus_revision"),
            "case_count": report.get("case_count"),
            "evaluation_fingerprint": report.get("evaluation_fingerprint"),
            "gate_passed": report.get("gate", {}).get("passed"),
            "metrics": report.get("metrics"),
        })
    return reference


def render_markdown(snapshot: dict) -> str:
    config = snapshot["provider_config"]
    corpus = snapshot["corpus"]
    lines = [
        "# P0 Workspace Snapshot Fingerprint", "",
        f"- Captured: {snapshot['captured_at']} ({snapshot['timezone']})",
        f"- Git HEAD: `{snapshot['git']['head']}`",
        f"- Worktree dirty: `{snapshot['git']['worktree']['dirty']}`",
        f"- Included source files: {snapshot['source_tree']['file_count']}",
        f"- Source tree SHA-256: `{snapshot['source_tree']['sha256']}`",
        f"- Corpus cases: {corpus['case_count']}",
        f"- Corpus cases SHA-256: `{corpus['cases_fingerprint_sha256']}`",
        f"- Metric contract SHA-256: `{corpus['metric_contract_sha256']}`",
        f"- Provider/model: {config.get('provider_name', 'not configured')} / {config.get('model', 'not configured')}",
        f"- Provider endpoint host: {config.get('endpoint_hostname', 'not configured')}",
        "- Secret values are excluded; only credential-presence metadata is retained.",
        "- Generated artifact directories and runtime project/settings stores are excluded from the source-tree hash; qualification artifacts are fingerprinted separately.",
        "",
        "## Evidence artifacts", "",
        "| Artifact | Mode/status | Cases/routes | File SHA-256 |", "|---|---|---:|---|",
    ]
    for item in snapshot["evidence_artifacts"]:
        status = item.get("live_provider_status") or item.get("release_verdict")
        if not status and item.get("route_summary"):
            route_summary = item["route_summary"]
            status = f"{route_summary.get('workspace_auth_dependency_entries', 0)} auth dependencies; {route_summary.get('auth_enforced_in_observed_profile_entries', 0)} enforced here; {route_summary.get('unclassified_api_entries', 0)} unclassified"
        if not status and item.get("candidate_source"):
            status = f"{item['candidate_source']}; gate {'passed' if item.get('gate_passed') else 'failed'}"
        status = status or "artifact"
        if item.get("route_summary"):
            volume = f"{item['route_summary'].get('workspace_auth_dependency_entries', 0)}/{item['route_summary'].get('api_route_entries', 0)}"
        elif item.get("case_count") is not None:
            volume = f"{item.get('completed_case_count', 0)}/{item['case_count']}"
        else:
            volume = "—"
        lines.append(f"| `{item['path']}` | {status} | {volume} | `{item.get('file_sha256', '—')}` |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="JSON output path (default: dated artifacts/p0 folder)")
    parser.add_argument("--markdown", help="Markdown output path")
    args = parser.parse_args()
    captured = datetime.now(ZoneInfo("Asia/Jakarta"))
    dated_dir = ARTIFACT_ROOT / captured.strftime("%Y-%m-%d")
    output = Path(args.output).resolve() if args.output else dated_dir / "p0_snapshot_fingerprint_current.json"
    markdown = Path(args.markdown).resolve() if args.markdown else output.with_suffix(".md")

    files, tree_hash = source_inventory()
    commit = git("rev-parse", "HEAD").decode().strip()
    snapshot = {
        "schema_version": "p0-workspace-snapshot-v1",
        "captured_at": captured.isoformat(),
        "timezone": "Asia/Jakarta",
        "git": {"head": commit, "worktree": status_summary()},
        "source_tree": {"file_count": len(files), "sha256": tree_hash, "files": files},
        "runtime_versions": dependency_versions(),
        "corpus": corpus_fingerprint(),
        "provider_config": nonsecret_provider_config(),
        "provider_runtime_policy": nonsecret_runtime_policy(),
        "evidence_artifacts": [qualification_reference(item) for item in EVIDENCE_REFERENCES],
        "exclusions": {
            "secret_values": [".env", "backend/data/settings.json", workspace_settings_store],
            "runtime_data": ["backend/data/projects", "backend/data/reports", "backend/data/analysis_runs", "backend/data/dfd_models", "backend/data/report_revisions"],
            "generated_artifacts": "artifacts/ (referenced qualification reports are hashed separately)",
            "self_reference": [str(output.relative_to(ROOT)) if output.is_relative_to(ROOT) else str(output), str(markdown.relative_to(ROOT)) if markdown.is_relative_to(ROOT) else str(markdown)],
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    markdown.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(snapshot, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    markdown.write_text(render_markdown(snapshot), encoding="utf-8")
    print(json.dumps({
        "snapshot_sha256": sha256_file(output),
        "source_tree_sha256": tree_hash,
        "source_files": len(files),
        "worktree_dirty": snapshot["git"]["worktree"]["dirty"],
        "provider": snapshot["provider_config"].get("provider_name"),
        "model": snapshot["provider_config"].get("model"),
        "output": str(output),
        "markdown": str(markdown),
    }, indent=2))
    return 0


workspace_settings_store = "backend/data/workspace_settings"

if __name__ == "__main__":
    raise SystemExit(main())
