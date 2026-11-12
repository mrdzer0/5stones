"""Read-only, fail-closed release decision for the current project report."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.services.formal_report_service import (
    project_context_fingerprint,
    report_snapshot_fingerprint,
    source_manifest,
)
from backend.utils.access_control import release_authority_context


def _hash(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _revision(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_release_decision(
    project: dict | None,
    report: dict | None,
    canonical_dfd: dict | None,
    signed_snapshot: dict | None,
    quality_gate: dict | None,
    *,
    signed_metadata: dict | None = None,
    report_exists: bool | None = None,
) -> dict:
    has_report = bool(report) if report_exists is None else bool(report_exists)
    project = project if isinstance(project, dict) else {}
    report = report if isinstance(report, dict) else {}
    canonical_dfd = canonical_dfd if isinstance(canonical_dfd, dict) else {}
    signed_snapshot = signed_snapshot if isinstance(signed_snapshot, dict) else {}
    quality_gate = quality_gate if isinstance(quality_gate, dict) else {}
    stored_formal = report.get("formal_report") if isinstance(report.get("formal_report"), dict) else {}
    formal = signed_metadata if isinstance(signed_metadata, dict) else stored_formal
    snapshot_formal = signed_snapshot.get("formal_report") if isinstance(signed_snapshot.get("formal_report"), dict) else {}
    approval_formal = snapshot_formal if snapshot_formal else formal
    blockers: list[dict] = []
    stale_reasons: list[str] = []
    deployment_profile, identity_mode = release_authority_context()

    def block(code: str, message: str) -> None:
        blockers.append({"code": code, "message": message})

    if not has_report:
        block("report_missing", "No threat-model report exists for this project.")
    if formal.get("status") == "superseded":
        stale_reasons.append("The signed report was superseded by a later report change.")
    elif formal.get("status") != "signed":
        block("report_unsigned", "The current report revision has not been signed by a Reviewer.")

    if deployment_profile != "enterprise" or identity_mode != "oidc_jwt":
        block("enterprise_release_authority", "Release readiness requires the enterprise deployment profile with OIDC/JWT identity.")
    if formal.get("status") == "signed" and (
        approval_formal.get("signed_deployment_profile") != "enterprise"
        or approval_formal.get("signed_identity_mode") != "oidc_jwt"
    ):
        block("signer_enterprise_identity", "The report was not signed under enterprise OIDC/JWT identity.")

    report_revision = _revision(report.get("report_revision"))
    formal_revision = _revision(formal.get("revision"))
    snapshot_revision = _revision(snapshot_formal.get("revision"))
    revision_id = f"report-r{formal_revision}-signed" if formal_revision is not None else None
    if formal.get("status") == "signed" and (report_revision is None or formal_revision != report_revision):
        stale_reasons.append("The signed report revision does not match the current report revision.")
    if formal.get("status") == "signed" and not signed_snapshot:
        block("signed_snapshot_missing", "The immutable signed report snapshot is missing.")
    elif signed_snapshot:
        if signed_snapshot.get("status") != "signed" or snapshot_formal.get("status") != "signed":
            block("signed_snapshot_invalid", "The referenced immutable revision is not a signed snapshot.")
        supplied_snapshot_hash = str(signed_snapshot.get("snapshot_sha256") or "")
        if len(supplied_snapshot_hash) != 64 or supplied_snapshot_hash != report_snapshot_fingerprint(signed_snapshot):
            block("signed_snapshot_integrity", "The signed snapshot hash is missing or does not match its contents.")
        if snapshot_revision != formal_revision or signed_snapshot.get("revision_id") != revision_id:
            stale_reasons.append("The signed snapshot revision does not match the current signed metadata.")
        for field in ("signed_by", "signed_at", "signed_deployment_profile", "signed_identity_mode"):
            if snapshot_formal.get(field) != formal.get(field):
                block("signed_approval_metadata_mismatch", "Current approval metadata does not match the immutable signed snapshot.")
                break

    context_hash = project_context_fingerprint(project)
    current_sources = source_manifest(project)
    if formal.get("status") == "signed":
        if formal.get("project_context_sha256") != context_hash:
            stale_reasons.append("Project threat-model context changed after sign-off.")
        if formal.get("source_manifest") != current_sources:
            stale_reasons.append("The project's source artifact manifest changed after sign-off.")

        current_dfd_revision = canonical_dfd.get("revision")
        current_dfd_hash = canonical_dfd.get("semantic_hash")
        if formal.get("dfd_revision") != current_dfd_revision or formal.get("dfd_semantic_hash") != current_dfd_hash:
            stale_reasons.append("The canonical DFD changed after sign-off.")
        snapshot_report = signed_snapshot.get("report") if isinstance(signed_snapshot.get("report"), dict) else {}
        signed_dfd = snapshot_report.get("dfd_model") if isinstance(snapshot_report.get("dfd_model"), dict) else {}
        if signed_dfd and (signed_dfd.get("revision") != current_dfd_revision or signed_dfd.get("semantic_hash") != current_dfd_hash):
            stale_reasons.append("The immutable snapshot is bound to a different DFD revision.")
        current_run_id = (report.get("analysis_run") or {}).get("run_id") or report.get("analysis_run_id")
        if formal.get("analysis_run_id") != current_run_id:
            stale_reasons.append("The signed snapshot references a different analysis run.")
        if signed_snapshot:
            if snapshot_formal.get("project_context_sha256") != formal.get("project_context_sha256"):
                stale_reasons.append("The immutable snapshot project-context fingerprint does not match current signed metadata.")
            if snapshot_formal.get("source_manifest") != formal.get("source_manifest"):
                stale_reasons.append("The immutable snapshot source manifest does not match current signed metadata.")

        if not formal.get("signed_by") or not formal.get("signed_at"):
            block("signer_identity_missing", "Signed report metadata lacks a reviewer identity or timestamp.")
    if quality_gate.get("signoff_ready") is not True:
        reasons = quality_gate.get("blocking_reasons") or ["The current report quality gate is not ready for sign-off."]
        for reason in reasons:
            block("quality_gate", str(reason))

    blockers.extend({"code": "superseded", "message": reason} for reason in stale_reasons)
    if stale_reasons:
        status = "superseded"
    elif blockers:
        status = "not_ready"
    else:
        status = "ready"
    decision = {
        "schema_version": "project-release-decision-v1",
        "status": status,
        "project_id": project.get("project_id"),
        "report_revision": report_revision,
        "revision_id": revision_id,
        "signed_snapshot_sha256": signed_snapshot.get("snapshot_sha256") if signed_snapshot else None,
        "dfd_revision": canonical_dfd.get("revision"),
        "dfd_semantic_hash": canonical_dfd.get("semantic_hash"),
        "project_context_sha256": context_hash,
        "source_manifest_sha256": _hash(current_sources),
        "analysis_run_id": (report.get("analysis_run") or {}).get("run_id") or report.get("analysis_run_id"),
        "approval_actor": approval_formal.get("signed_by") if formal.get("status") == "signed" else None,
        "approved_at": approval_formal.get("signed_at") if formal.get("status") == "signed" else None,
        "deployment_profile": deployment_profile,
        "identity_mode": identity_mode,
        "signer_deployment_profile": approval_formal.get("signed_deployment_profile") if formal.get("status") == "signed" else None,
        "signer_identity_mode": approval_formal.get("signed_identity_mode") if formal.get("status") == "signed" else None,
        "blockers": blockers,
    }
    decision["decision_fingerprint"] = _hash({key: value for key, value in decision.items() if key != "decision_fingerprint"})
    return decision
