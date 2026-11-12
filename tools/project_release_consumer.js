#!/usr/bin/env node
"use strict";

/*
 * Authenticated CI consumer for a project's current 5STONES release decision.
 * Only a complete, fingerprint-valid `ready` decision exits successfully.
 * Blocker messages are intentionally omitted from stdout to avoid leaking
 * architecture details into CI logs; blocker codes remain actionable.
 */

const crypto = require("node:crypto");

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function hashDecision(decision) {
  const unsigned = {...decision};
  delete unsigned.decision_fingerprint;
  return crypto.createHash("sha256").update(JSON.stringify(stable(unsigned)), "utf8").digest("hex");
}

function blockerCodes(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(item => String(item?.code || "").trim()).filter(Boolean))].sort();
}

function validateDecision(decision, expectedProjectId) {
  const errors = [];
  if (!decision || typeof decision !== "object" || Array.isArray(decision)) {
    return {allowed: false, status: "invalid", blocker_codes: [], errors: ["invalid_json_object"]};
  }
  if (decision.schema_version !== "project-release-decision-v1") errors.push("unsupported_schema");
  if (!expectedProjectId || decision.project_id !== expectedProjectId) errors.push("project_id_mismatch");

  const suppliedFingerprint = String(decision.decision_fingerprint || "");
  if (!/^[a-f0-9]{64}$/i.test(suppliedFingerprint) || hashDecision(decision) !== suppliedFingerprint.toLowerCase()) {
    errors.push("decision_fingerprint_invalid");
  }
  if (!Array.isArray(decision.blockers)) errors.push("blockers_missing");
  const blockers = Array.isArray(decision.blockers) ? decision.blockers : [];
  const codes = blockerCodes(blockers);
  const status = String(decision.status || "invalid");

  if (status === "ready") {
    if (blockers.length) errors.push("ready_decision_has_blockers");
    if (decision.deployment_profile !== "enterprise") errors.push("deployment_profile_not_enterprise");
    if (decision.identity_mode !== "oidc_jwt") errors.push("identity_mode_not_oidc_jwt");
    if (decision.signer_deployment_profile !== "enterprise") errors.push("signer_profile_not_enterprise");
    if (decision.signer_identity_mode !== "oidc_jwt") errors.push("signer_identity_mode_not_oidc_jwt");
    if (!Number.isInteger(decision.report_revision) || decision.report_revision < 1) errors.push("report_revision_missing");
    if (decision.revision_id !== `report-r${decision.report_revision}-signed`) errors.push("signed_revision_mismatch");
    if (!Number.isInteger(decision.dfd_revision) || decision.dfd_revision < 1) errors.push("dfd_revision_missing");
    for (const field of ["signed_snapshot_sha256", "dfd_semantic_hash", "project_context_sha256", "source_manifest_sha256"]) {
      if (!/^[a-f0-9]{64}$/i.test(String(decision[field] || ""))) errors.push(`${field}_invalid`);
    }
    if (!String(decision.analysis_run_id || "").trim()) errors.push("analysis_run_missing");
    if (!String(decision.approval_actor || "").trim()) errors.push("approval_actor_missing");
    if (!Number.isFinite(Date.parse(decision.approved_at || ""))) errors.push("approval_timestamp_invalid");
  } else if (!["not_ready", "superseded"].includes(status)) {
    errors.push("unknown_decision_status");
  }

  return {
    allowed: status === "ready" && errors.length === 0,
    status,
    blocker_codes: codes,
    errors: [...new Set(errors)],
  };
}

function validateDecisionUrl(raw, expectedProjectId) {
  let url;
  try { url = new URL(raw); }
  catch (_) { return {ok: false, code: "decision_url_invalid"}; }
  if (url.username || url.password || url.search || url.hash) return {ok: false, code: "decision_url_contains_credentials_or_query"};
  const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname.toLowerCase());
  if (url.protocol !== "https:" && !(url.protocol === "http:" && localHost)) return {ok: false, code: "decision_url_requires_https"};
  const pathParts = url.pathname.split("/").filter(Boolean);
  let projectPathId = "";
  try { projectPathId = pathParts.length >= 4 ? decodeURIComponent(pathParts[pathParts.length - 2]) : ""; }
  catch (_) { return {ok: false, code: "decision_url_project_mismatch"}; }
  if (pathParts.length < 4 || pathParts[pathParts.length - 4] !== "api"
    || pathParts[pathParts.length - 3] !== "projects" || pathParts[pathParts.length - 1] !== "release-decision") {
    return {ok: false, code: "decision_url_must_target_release_decision"};
  }
  if (!expectedProjectId || projectPathId !== expectedProjectId) return {ok: false, code: "decision_url_project_mismatch"};
  return {ok: true, url};
}

async function boundedResponseText(response, limitBytes) {
  const declaredLength = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > limitBytes) return {ok: false};
  if (response.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > limitBytes) {
          await reader.cancel();
          return {ok: false};
        }
        chunks.push(Buffer.from(value));
      }
      return {ok: true, text: Buffer.concat(chunks).toString("utf8")};
    } catch (_) {
      return {ok: false};
    }
  }
  try {
    const text = await response.text();
    return Buffer.byteLength(text, "utf8") <= limitBytes ? {ok: true, text} : {ok: false};
  } catch (_) {
    return {ok: false};
  }
}

async function runConsumerGate({decisionUrl, projectId, token, fetchImpl = globalThis.fetch, timeoutMs = 10000}) {
  const checkedUrl = validateDecisionUrl(decisionUrl || "", projectId);
  if (!checkedUrl.ok) return {exit_code: 2, gate: "project_release", allowed: false, errors: [checkedUrl.code]};
  if (!String(projectId || "").trim()) return {exit_code: 2, gate: "project_release", allowed: false, errors: ["project_id_required"]};
  if (!String(token || "").trim() || /[\r\n]/.test(String(token))) return {exit_code: 2, gate: "project_release", allowed: false, errors: ["release_api_token_required"]};
  if (typeof fetchImpl !== "function") return {exit_code: 2, gate: "project_release", allowed: false, errors: ["fetch_unavailable"]};

  let response;
  try {
    response = await fetchImpl(checkedUrl.url, {
      method: "GET",
      headers: {Accept: "application/json", Authorization: `Bearer ${token}`},
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (_) {
    return {exit_code: 2, gate: "project_release", allowed: false, errors: ["release_decision_request_failed"]};
  }
  if (!response.ok) return {exit_code: 2, gate: "project_release", allowed: false, errors: [`release_decision_http_${response.status}`]};
  if (!String(response.headers?.get?.("content-type") || "").toLowerCase().includes("application/json")) {
    return {exit_code: 2, gate: "project_release", allowed: false, errors: ["release_decision_content_type_invalid"]};
  }

  let body;
  try {
    const raw = await boundedResponseText(response, 65536);
    if (!raw.ok) return {exit_code: 2, gate: "project_release", allowed: false, errors: ["release_decision_response_too_large_or_unreadable"]};
    body = JSON.parse(raw.text);
  } catch (_) {
    return {exit_code: 2, gate: "project_release", allowed: false, errors: ["release_decision_json_invalid"]};
  }
  const decision = validateDecision(body, projectId);
  return {
    exit_code: decision.allowed ? 0 : (decision.errors.length ? 2 : 1),
    gate: "project_release",
    allowed: decision.allowed,
    project_id: body.project_id || null,
    status: decision.status,
    report_revision: Number.isInteger(body.report_revision) ? body.report_revision : null,
    dfd_revision: Number.isInteger(body.dfd_revision) ? body.dfd_revision : null,
    blocker_codes: decision.blocker_codes,
    errors: decision.errors,
  };
}

function parseArgs(argv) {
  const result = {decisionUrl: null, projectId: null};
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--decision-url") result.decisionUrl = argv[++index] || null;
    else if (arg === "--project-id") result.projectId = argv[++index] || null;
    else throw new Error("unsupported_argument");
  }
  if (!result.decisionUrl || !result.projectId) throw new Error("decision_url_and_project_id_required");
  return result;
}

async function main() {
  let options;
  try { options = parseArgs(process.argv); }
  catch (_) {
    process.stderr.write("Usage: node tools/project_release_consumer.js --decision-url <https://host/api/projects/id/release-decision> --project-id <id>\n");
    process.exitCode = 2;
    return;
  }
  const result = await runConsumerGate({...options, token: process.env.CR8_PROJECT_RELEASE_TOKEN});
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.exit_code;
}

if (require.main === module) main().catch(() => {
  process.stdout.write(`${JSON.stringify({exit_code: 2, gate: "project_release", allowed: false, errors: ["release_decision_unexpected_error"]}, null, 2)}\n`);
  process.exitCode = 2;
});

module.exports = {boundedResponseText, hashDecision, runConsumerGate, stable, validateDecision, validateDecisionUrl};
