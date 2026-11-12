"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const {spawnSync} = require("node:child_process");
const path = require("node:path");
const test = require("node:test");
const {hashDecision, runConsumerGate, validateDecision, validateDecisionUrl} = require("../tools/project_release_consumer.js");

function readyDecision() {
  const decision = {
    schema_version: "project-release-decision-v1",
    status: "ready",
    project_id: "payments-api",
    report_revision: 8,
    revision_id: "report-r8-signed",
    signed_snapshot_sha256: "a".repeat(64),
    dfd_revision: 5,
    dfd_semantic_hash: "b".repeat(64),
    project_context_sha256: "c".repeat(64),
    source_manifest_sha256: "d".repeat(64),
    analysis_run_id: "run-123",
    approval_actor: "reviewer-42",
    approved_at: "2026-10-04T12:00:00Z",
    deployment_profile: "enterprise",
    identity_mode: "oidc_jwt",
    signer_deployment_profile: "enterprise",
    signer_identity_mode: "oidc_jwt",
    blockers: [],
  };
  decision.decision_fingerprint = hashDecision(decision);
  return decision;
}

function jsonResponse(value, status = 200, contentType = "application/json") {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {get: name => name.toLowerCase() === "content-type" ? contentType : null},
    text: async () => typeof value === "string" ? value : JSON.stringify(value),
  };
}

test("only a complete, fingerprint-valid current ready decision passes", () => {
  const result = validateDecision(readyDecision(), "payments-api");
  assert.equal(result.allowed, true);
  assert.deepEqual(result.errors, []);
});

test("not_ready and superseded decisions always block", () => {
  for (const status of ["not_ready", "superseded"]) {
    const decision = {...readyDecision(), status, blockers: [{code: status, message: "private detail"}]};
    decision.decision_fingerprint = hashDecision(decision);
    const result = validateDecision(decision, "payments-api");
    assert.equal(result.allowed, false);
    assert.equal(result.status, status);
    assert.deepEqual(result.blocker_codes, [status]);
    assert.deepEqual(result.errors, []);
  }
});

test("a stale fingerprint, project mismatch, or ready response with blockers is rejected", () => {
  const tampered = readyDecision();
  tampered.dfd_revision += 1;
  assert.ok(validateDecision(tampered, "payments-api").errors.includes("decision_fingerprint_invalid"));

  assert.ok(validateDecision(readyDecision(), "another-project").errors.includes("project_id_mismatch"));

  const contradictory = {...readyDecision(), blockers: [{code: "quality_gate", message: "blocked"}]};
  contradictory.decision_fingerprint = hashDecision(contradictory);
  assert.ok(validateDecision(contradictory, "payments-api").errors.includes("ready_decision_has_blockers"));
});

test("ready requires signed snapshot, DFD, report, analysis, and approval bindings", () => {
  const decision = {...readyDecision(), signed_snapshot_sha256: null, analysis_run_id: null, approval_actor: null};
  decision.decision_fingerprint = hashDecision(decision);
  const result = validateDecision(decision, "payments-api");
  assert.equal(result.allowed, false);
  assert.ok(result.errors.includes("signed_snapshot_sha256_invalid"));
  assert.ok(result.errors.includes("analysis_run_missing"));
  assert.ok(result.errors.includes("approval_actor_missing"));
});

test("ready requires enterprise deployment and OIDC identity for decision and signer", () => {
  const localDecision = {...readyDecision(), deployment_profile: "local_dev"};
  localDecision.decision_fingerprint = hashDecision(localDecision);
  assert.ok(validateDecision(localDecision, "payments-api").errors.includes("deployment_profile_not_enterprise"));

  const localSigner = {...readyDecision(), signer_identity_mode: "disabled"};
  localSigner.decision_fingerprint = hashDecision(localSigner);
  assert.ok(validateDecision(localSigner, "payments-api").errors.includes("signer_identity_mode_not_oidc_jwt"));
});

test("consumer endpoint requires HTTPS outside loopback and a release-decision route", () => {
  assert.equal(validateDecisionUrl("https://security.example/api/projects/a/release-decision", "a").ok, true);
  assert.equal(validateDecisionUrl("http://localhost:8000/api/projects/a/release-decision", "a").ok, true);
  assert.equal(validateDecisionUrl("http://security.example/api/projects/a/release-decision", "a").code, "decision_url_requires_https");
  assert.equal(validateDecisionUrl("https://security.example/api/projects/a/report", "a").code, "decision_url_must_target_release_decision");
  assert.equal(validateDecisionUrl("https://user:secret@security.example/api/projects/a/release-decision", "a").code, "decision_url_contains_credentials_or_query");
  assert.equal(validateDecisionUrl("https://security.example/api/projects/b/release-decision", "a").code, "decision_url_project_mismatch");
});

test("authenticated consumer sends bearer token and returns a minimal pass record", async () => {
  let request;
  const result = await runConsumerGate({
    decisionUrl: "https://security.example/api/projects/payments-api/release-decision",
    projectId: "payments-api",
    token: "test-token",
    fetchImpl: async (url, options) => {
      request = {url: String(url), options};
      return jsonResponse(readyDecision());
    },
  });
  assert.equal(result.exit_code, 0);
  assert.equal(result.allowed, true);
  assert.equal(request.options.headers.Authorization, "Bearer test-token");
  assert.equal(request.options.redirect, "error");
  assert.equal(JSON.stringify(result).includes("test-token"), false);
});

test("HTTP errors, invalid media, malformed JSON, and request failures fail closed", async () => {
  const options = {decisionUrl: "https://security.example/api/projects/payments-api/release-decision", projectId: "payments-api", token: "test-token"};
  assert.equal((await runConsumerGate({...options, fetchImpl: async () => jsonResponse({}, 503)})).exit_code, 2);
  assert.equal((await runConsumerGate({...options, fetchImpl: async () => jsonResponse({}, 200, "text/html")})).exit_code, 2);
  assert.equal((await runConsumerGate({...options, fetchImpl: async () => jsonResponse("not-json")})).exit_code, 2);
  assert.equal((await runConsumerGate({...options, fetchImpl: async () => { throw new Error("secret-bearing network detail"); }})).exit_code, 2);
});

test("missing token and non-ready live response have nonzero consumer exit codes", async () => {
  const decisionUrl = "https://security.example/api/projects/payments-api/release-decision";
  assert.equal((await runConsumerGate({decisionUrl, projectId: "payments-api", token: "", fetchImpl: async () => { throw new Error(); }})).exit_code, 2);
  const blocked = {...readyDecision(), status: "not_ready", blockers: [{code: "framework_validation", message: "private detail"}]};
  blocked.decision_fingerprint = hashDecision(blocked);
  const result = await runConsumerGate({decisionUrl, projectId: "payments-api", token: "test-token", fetchImpl: async () => jsonResponse(blocked)});
  assert.equal(result.exit_code, 1);
  assert.equal(result.status, "not_ready");
  assert.deepEqual(result.blocker_codes, ["framework_validation"]);
  assert.equal(JSON.stringify(result).includes("private detail"), false);
});

test("CLI process exits nonzero when CI has no release API token", () => {
  const script = path.join(__dirname, "..", "tools", "project_release_consumer.js");
  const result = spawnSync(process.execPath, [script, "--decision-url", "https://security.example/api/projects/payments-api/release-decision", "--project-id", "payments-api"], {
    encoding: "utf8",
    env: {...process.env, CR8_PROJECT_RELEASE_TOKEN: ""},
    timeout: 5000,
  });
  assert.equal(result.status, 2);
  assert.deepEqual(JSON.parse(result.stdout).errors, ["release_api_token_required"]);
});

test("GitHub composite action forwards project inputs and token to the fail-closed CLI", () => {
  const actionPath = path.join(__dirname, "..", ".github", "actions", "project-release-gate", "action.yml");
  const action = fs.readFileSync(actionPath, "utf8");
  assert.match(action, /using:\s*composite/);
  for (const input of ["project_id", "qualification_path", "reviewer_evidence_path", "review_evidence_hmac_key", "decision_url", "release_api_token"]) {
    assert.match(action, new RegExp(`${input}:\\n\\s+description:[^\\n]+\\n\\s+required: true`));
  }
  assert.match(action, /PROJECT_ID:\s*\$\{\{ inputs\.project_id \}\}/);
  assert.match(action, /DECISION_URL:\s*\$\{\{ inputs\.decision_url \}\}/);
  assert.match(action, /CR8_PROJECT_RELEASE_TOKEN:\s*\$\{\{ inputs\.release_api_token \}\}/);
  assert.match(action, /ACTION_PATH:\s*\$\{\{ github\.action_path \}\}/);
  assert.match(action, /node "\$ACTION_PATH\/\.\.\/\.\.\/\.\.\/tools\/project_release_consumer\.js"/);
  assert.match(action, /node "\$ACTION_PATH\/\.\.\/\.\.\/\.\.\/tools\/cr8_release_gate\.js"/);
  assert.match(action, /CR8_REVIEW_EVIDENCE_HMAC_KEY:\s*\$\{\{ inputs\.review_evidence_hmac_key \}\}/);
  assert.equal(
    fs.existsSync(path.resolve(path.dirname(actionPath), "..", "..", "..", "tools", "project_release_consumer.js")),
    true,
  );
  assert.equal(
    fs.existsSync(path.resolve(path.dirname(actionPath), "..", "..", "..", "tools", "cr8_release_gate.js")),
    true,
  );
  assert.doesNotMatch(action, /set -x|echo\s+.*(?:CR8_PROJECT_RELEASE_TOKEN|CR8_REVIEW_EVIDENCE_HMAC_KEY)/);
});
