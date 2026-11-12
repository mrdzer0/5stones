#!/usr/bin/env node
"use strict";

/*
 * CR8 release qualification.
 *
 * The fixture lane is intentionally self-contained: it creates projects in an
 * isolated DATA_DIR, uploads every synthetic PRD through the browser, points
 * the application at a local OpenAI-compatible contract provider, runs the
 * real pipeline, and then exercises the six user-facing workspaces. The live
 * lane is opt-in and never treats fallback/timeout output as a passing result.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {spawn, spawnSync, execFileSync} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const CORPUS_DIR = path.join(REPO, "tests", "prd_corpus");
const MANIFEST_PATH = path.join(CORPUS_DIR, "manifest.json");
const CONTRACT_PATH = path.join(CORPUS_DIR, "metric_contract.json");
const BASELINE_PATH = path.join(CORPUS_DIR, "e2e_results.json");
// A live analysis can run two 360s framework stages serially plus deterministic
// parsing and persistence. Keep the browser harness above that application cap.
const ANALYSIS_RESPONSE_TIMEOUT_MS = 900000;
const CR8_PROVIDER_MAX_RETRIES = 1;
const CR8_BATCH_PROFILE = {
  max_batches: 32,
  flows_per_batch: 3,
  concurrency: 2,
  max_batch_retries: 1,
  stage_budget_seconds: 360,
  batch_budget_seconds: 60,
  output_budget_tokens: 4096,
};
const ROUTES = ["analysis", "model", "findings", "action-plan", "evidence", "report"];
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900},
];
const READY_SELECTORS = {
  analysis: "#analysis-overview",
  model: "#threat-diagram-canvas canvas, #diagram-text-alternative",
  findings: "#findings-list",
  "action-plan": "#action-list",
  evidence: "#evidence-list",
  report: "#report-dfd-snapshot-caption",
};

function parseArgs(argv) {
  const value = {
    mode: "fixture",
    output: null,
    markdown: null,
    artifactDir: null,
    screenshotDir: null,
    caseId: null,
    providerName: null,
    model: null,
    noFail: false,
    keepData: false,
  };
  for (let index = 2; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--mode") value.mode = argv[++index] || "fixture";
    else if (argument === "--output") value.output = argv[++index];
    else if (argument === "--markdown") value.markdown = argv[++index];
    else if (argument === "--artifact-dir") value.artifactDir = argv[++index];
    else if (argument === "--screenshot-dir") value.screenshotDir = argv[++index];
    else if (argument === "--case-id") value.caseId = argv[++index];
    else if (argument === "--provider-name") value.providerName = argv[++index];
    else if (argument === "--model") value.model = argv[++index];
    else if (argument === "--no-fail") value.noFail = true;
    else if (argument === "--keep-data") value.keepData = true;
  }
  if (!["fixture", "live"].includes(value.mode)) throw new Error(`Unsupported CR8 mode: ${value.mode}`);
  return value;
}

function loadModule(name) {
  try { return require(name); } catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve(name, {paths: [globalRoot]}));
  }
}

function loadAxeSource() {
  let axePath;
  try { axePath = require.resolve("axe-core/axe.min.js"); }
  catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    axePath = require.resolve("axe-core/axe.min.js", {paths: [globalRoot]});
  }
  return {
    version: require(path.join(path.dirname(axePath), "package.json")).version,
    source: fs.readFileSync(axePath, "utf8"),
  };
}

function readJson(file) { return JSON.parse(fs.readFileSync(file, "utf8")); }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function hash(value) { return crypto.createHash("sha256").update(typeof value === "string" ? value : JSON.stringify(value)).digest("hex"); }
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}
function stableHash(value) { return crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex"); }
function safeFileName(value) { return String(value).replace(/[^a-zA-Z0-9_.-]+/g, "-").slice(0, 160); }
function normalize(value) { return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim(); }

function observeProviderResponseModels(stageMetadata) {
  const manifest = stageMetadata?.generation_manifest && typeof stageMetadata.generation_manifest === "object"
    ? stageMetadata.generation_manifest : {};
  const batches = Array.isArray(manifest.batches) ? manifest.batches : [];
  const models = [];
  let validBatchCount = 0;
  let validBatchesMissingModel = 0;
  for (const batch of batches) {
    const batchModels = [];
    const responseMetadata = [
      batch?.response_metadata,
      ...(Array.isArray(batch?.attempts) ? batch.attempts.map(attempt => attempt?.response_metadata) : []),
    ];
    for (const response of responseMetadata) {
      if (response?.model_source !== "provider_response") continue;
      const model = typeof response.response_model === "string" ? response.response_model.trim() : "";
      if (model) batchModels.push(model);
    }
    models.push(...batchModels);
    if (String(batch?.status || "").toLowerCase() === "valid") {
      validBatchCount += 1;
      if (!batchModels.length) validBatchesMissingModel += 1;
    }
  }
  const uniqueModels = [...new Set(models)];
  const recorded = validBatchCount > 0
    && validBatchesMissingModel === 0
    && uniqueModels.length === 1;
  return {
    model: recorded ? uniqueModels[0] : null,
    models: uniqueModels,
    recorded,
    response_count: models.length,
    valid_batch_count: validBatchCount,
    valid_batches_missing_model: validBatchesMissingModel,
  };
}

function isGeneratedCandidatePath(value) {
  const normalized = String(value || "").replace(/\\/g, "/").replace(/^\.\//, "");
  return normalized === ".env"
    || normalized === "backend/data/settings.json"
    || normalized.startsWith("artifacts/")
    || normalized.startsWith(".venv/")
    || normalized.startsWith("node_modules/")
    || normalized.startsWith("backend/data/projects/")
    || normalized.startsWith("backend/data/reports/")
    || normalized.startsWith("backend/data/analysis_runs/")
    || normalized.startsWith("backend/data/dfd_models/")
    || normalized.startsWith("backend/data/report_revisions/")
    || normalized.startsWith("backend/data/workspace_settings/")
    || /\.(?:pyc|log|sqlite|sqlite3|db|pem|crt|p12|pfx|key)$/i.test(normalized);
}

function captureCandidateIdentity(repoRoot = REPO) {
  try {
    const git = (...args) => execFileSync("git", args, {cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"]});
    const commitSha = git("rev-parse", "--verify", "HEAD").trim();
    const treeSha = git("rev-parse", "HEAD^{tree}").trim();
    const trackedChanges = git("diff", "--name-only", "-z", "HEAD", "--").split("\0").filter(Boolean);
    const untrackedChanges = git("ls-files", "--others", "--exclude-standard", "-z").split("\0").filter(Boolean);
    const sourceChanges = [...new Set([...trackedChanges, ...untrackedChanges])].filter(item => !isGeneratedCandidatePath(item));
    return {
      git_commit_sha: commitSha,
      git_tree_sha: treeSha,
      source_identity_sha256: hash(`${commitSha}:${treeSha}`),
      source_worktree_clean: sourceChanges.length === 0,
      source_change_count: sourceChanges.length,
    };
  } catch (_) {
    return {
      git_commit_sha: null,
      git_tree_sha: null,
      source_identity_sha256: null,
      source_worktree_clean: false,
      source_change_count: null,
    };
  }
}

function matchLabel(actual, expected) {
  const a = normalize(actual);
  const e = normalize(expected);
  return Boolean(a && e && (a === e || a.includes(e) || e.includes(a)));
}
function metric(numerator, denominator, reason, eligibleForGate = true) {
  const value = {numerator, denominator, reason};
  if (!eligibleForGate) value.eligible_for_gate = false;
  return value;
}

function threatBatchConfiguration(stages) {
  const manifests = ["stride", "linddun"]
    .map(framework => stages?.[framework]?.response_metadata?.generation_manifest)
    .filter(item => item && typeof item === "object");
  const manifest = manifests.find(item => Number.isInteger(item.max_batches)) || {};
  return Object.fromEntries(Object.entries(CR8_BATCH_PROFILE).map(([key, fallback]) => [
    key,
    Number.isFinite(manifest[key]) ? manifest[key] : fallback,
  ]));
}

function buildCorpusRunProvenance({
  mode,
  providerSelection,
  observedProviders,
  observedModels,
  applicationCommit,
  namespace,
  sourceHash,
  batchConfig,
}) {
  const fixture = mode === "fixture";
  const provider = fixture
    ? "cr8-contract-fixture"
    : (providerSelection?.provider_name || (observedProviders.length === 1 ? observedProviders[0] : observedProviders.join(", ")) || null);
  const model = fixture
    ? "cr8-contract-fixture"
    : (providerSelection?.model || (observedModels.length === 1 ? observedModels[0] : null));
  return {
    application_commit: applicationCommit || "unknown",
    provider,
    model,
    model_source: fixture ? "fixture" : (providerSelection?.model ? "selected_configuration" : "observed_responses"),
    observed_models: [...observedModels],
    timeout_seconds: 30,
    retry_config: {max_retries: CR8_PROVIDER_MAX_RETRIES, format_retry: 1},
    batch_config: {...batchConfig},
    source_revision: "multi-case",
    source_hash: sourceHash,
    dfd_revision: "per-case",
    dfd_semantic_hash: "per-case",
    run_id: namespace,
  };
}

function evaluatePerformanceBudget(cases) {
  const completedSamples = cases.filter(item => {
    const framework = item.metrics?.framework_validation || {};
    const frameworkEvidence = item.observed?.framework_assessments || {};
    const strideSeconds = item.performance?.stages_seconds?.stride;
    const linddunSeconds = item.performance?.stages_seconds?.linddun;
    return Number.isFinite(item.performance?.core_analysis_ms)
      && item.performance.core_analysis_ms > 0
      && Number.isFinite(strideSeconds)
      && strideSeconds > 0
      && Number.isFinite(linddunSeconds)
      && linddunSeconds > 0
      && Number(item.observed?.dfd_flows || 0) > 0
      && Number.isInteger(framework.numerator)
      && Number.isInteger(framework.denominator)
      && framework.denominator > 0
      && framework.numerator === framework.denominator
      && ["stride", "linddun"].every(name => frameworkEvidence[name]?.assessment_status === "complete"
        && frameworkEvidence[name]?.coverage?.complete === true)
      && Boolean(item.provenance?.provider)
      && Boolean(item.provenance?.model)
      && item.provenance?.provider_fallback_used === false
      && ["completed", "completed_with_warnings"].includes(item.run_status);
  });
  const censored = cases.filter(item => !completedSamples.includes(item)).map(item => item.case_id);
  const samples = {
    core_analysis_seconds: completedSamples.map(item => Number(item.performance.core_analysis_ms) / 1000),
    stride_seconds: completedSamples.map(item => item.performance.stages_seconds.stride),
    linddun_seconds: completedSamples.map(item => item.performance.stages_seconds.linddun),
  };
  const p95 = Object.fromEntries(Object.entries(samples).map(([name, values]) => [name, percentile(values)]));
  const passed = cases.length > 0
    && completedSamples.length === cases.length
    && (p95.core_analysis_seconds ?? Infinity) <= 180
    && (p95.stride_seconds ?? Infinity) <= 60
    && (p95.linddun_seconds ?? Infinity) <= 60;
  return {
    sample_count: completedSamples.length,
    requested_sample_count: cases.length,
    percentile: 0.95,
    p95_seconds: p95,
    budgets_seconds: {core_analysis_seconds: 180, stride_seconds: 60, linddun_seconds: 60},
    failed_or_censored_samples: censored,
    gate: {
      passed,
      reason: `${completedSamples.length}/${cases.length} complete threat-analysis samples; P95 core=${p95.core_analysis_seconds ?? "n/a"}s, STRIDE=${p95.stride_seconds ?? "n/a"}s, LINDDUN=${p95.linddun_seconds ?? "n/a"}s${censored.length ? `; incomplete/censored cases: ${censored.join(", ")}` : ""}.`,
    },
  };
}

function waitForServer(url, timeoutMs = 20000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, response => {
        response.resume();
        if (response.statusCode === 200) return resolve();
        if (Date.now() - started > timeoutMs) return reject(new Error(`server returned ${response.statusCode}: ${url}`));
        setTimeout(probe, 100);
      });
      request.on("error", () => {
        if (Date.now() - started > timeoutMs) reject(new Error(`server did not start: ${url}`));
        else setTimeout(probe, 100);
      });
      request.setTimeout(1000, () => request.destroy());
    };
    probe();
  });
}

function hasExited(child) {
  return !child || child.exitCode !== null || child.signalCode !== null;
}

async function terminateChild(child, graceMs = 5000) {
  if (hasExited(child)) return;
  let exited = false;
  let resolveExit;
  const exitPromise = new Promise(resolve => { resolveExit = resolve; });
  const onExit = (code, signal) => {
    exited = true;
    resolveExit({code, signal});
  };
  child.once("exit", onExit);
  child.kill("SIGTERM");
  let timeoutHandle;
  const timeout = new Promise(resolve => { timeoutHandle = setTimeout(() => resolve(null), graceMs); });
  const gracefulExit = await Promise.race([exitPromise, timeout]);
  if (gracefulExit) {
    clearTimeout(timeoutHandle);
    return gracefulExit;
  }
  if (!exited && !hasExited(child)) child.kill("SIGKILL");
  return exitPromise;
}

async function removeDirectoryWithRetry(target, attempts = 4) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      fs.rmSync(target, {recursive: true, force: true, maxRetries: 2, retryDelay: 100});
      return;
    } catch (error) {
      lastError = error;
      if (!new Set(["ENOTEMPTY", "EBUSY", "EPERM", "EMFILE", "ENFILE"]).has(error.code) || attempt === attempts - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 100 * (attempt + 1)));
    }
  }
  throw lastError;
}

function requestJson(url, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(url, {...options, headers: {...(options.headers || {})}}, response => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", chunk => { body += chunk; });
      response.on("end", () => {
        let payload;
        try { payload = body ? JSON.parse(body) : {}; } catch (_) { payload = {raw: body}; }
        if (response.statusCode >= 400) {
          const error = new Error(`${options.method || "GET"} ${url} returned ${response.statusCode}`);
          error.status = response.statusCode;
          error.payload = payload;
          return reject(error);
        }
        resolve({status: response.statusCode, payload});
      });
    });
    request.on("error", reject);
    if (options.body) request.write(options.body);
    request.end();
  });
}

function expectedForCase(manifest, caseId) {
  const entry = manifest.cases.find(item => item.id === caseId);
  if (!entry) return {must_detect_actors: ["User"], must_detect_components: ["Application"], must_detect_data: ["User data"], must_surface_topics: ["insufficient evidence"], expected_deferred_topics: ["Missing context"]};
  return entry.expected || {};
}

function caseIdFromPrompt(prompt) {
  const match = String(prompt).match(/(?:cr8-case-|CR8_CASE_ID:\s*)([a-z0-9-]+)/i);
  return match ? match[1].toLowerCase() : null;
}

function jsonResponse(payload, model = "cr8-contract-fixture", finishReason = "stop") {
  const content = JSON.stringify(payload);
  return {
    id: `cr8-${crypto.randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{index: 0, finish_reason: finishReason, message: {role: "assistant", content}}],
    usage: {prompt_tokens: 100, completion_tokens: Math.ceil(content.length / 4), total_tokens: 100 + Math.ceil(content.length / 4)},
  };
}

function firstEvidenceSnippet(prompt) {
  const content = String(prompt).split("ARTIFACT CONTENT CHUNK:").slice(1).join("ARTIFACT CONTENT CHUNK:");
  const lines = content.split(/\r?\n/).map(item => item.trim()).filter(item => item && !item.startsWith("<!--"));
  const line = lines.find(item => item.length >= 20) || lines.join(" ");
  return (line || "The uploaded PRD describes the feature workflow and system context.").slice(0, 300);
}

function ingestionPayload(expected, prompt) {
  const actors = expected.must_detect_actors || ["User"];
  const components = expected.must_detect_components || ["Application"];
  const external = expected.must_detect_external_systems || [];
  const data = expected.must_detect_data || ["User data"];
  const flows = [];
  if (actors[0] && components[0]) flows.push({source: actors[0], destination: components[0], data: data.slice(0, 2), protocol: "HTTPS", evidence_type: "direct", evidence_locator: "CR8 fixture PRD"});
  for (let index = 0; index < components.length - 1; index += 1) {
    flows.push({source: components[index], destination: components[index + 1], data: data.slice(index % Math.max(data.length, 1), (index % Math.max(data.length, 1)) + 2), protocol: "HTTPS", evidence_type: "direct", evidence_locator: "CR8 fixture PRD"});
  }
  if (external[0] && components[components.length - 1]) {
    flows.push({source: components[components.length - 1], destination: external[0], data: data.slice(-2), protocol: "HTTPS", evidence_type: "direct", evidence_locator: "CR8 fixture PRD"});
  }
  return {
    actors,
    components,
    data_flows: flows,
    endpoints: [components[0] || "Application"],
    data_fields: data,
    external_systems: external,
    auth_methods: [],
    critical_actions: (expected.must_surface_topics || []).slice(0, 3),
    existing_controls: [],
    use_cases: [{
      name: `${components[0] || "Application"} workflow`,
      actor: actors[0] || "User",
      trigger: "User starts the documented workflow",
      preconditions: [],
      steps: flows.slice(0, 4).map(flow => ({type: "action", label: `${flow.source} sends data to ${flow.destination}`, target: flow.destination, data: flow.data})),
      data,
      evidence_snippet: firstEvidenceSnippet(prompt),
      evidence_locator: "CR8 fixture PRD",
    }],
    evidence_items: [{snippet: firstEvidenceSnippet(prompt), locator: "CR8 fixture PRD", topics: expected.must_surface_topics || []}],
    has_pii: data.some(item => /email|identity|medical|face|address|message|profile|membership|name|phone/i.test(item)),
    summary: `Contract fixture extraction for ${components[0] || "the application"}.`,
  };
}

function canonicalContext(prompt) {
  const match = String(prompt).match(/CANONICAL DFD INTERACTION [^:]+:\n([^\n]+)/);
  if (!match) return {revision: "cr8-unknown", semantic_hash: "cr8-unknown", flows: []};
  try { return JSON.parse(match[1]); } catch (_) { return {revision: "cr8-invalid", semantic_hash: "cr8-invalid", flows: []}; }
}

function threatPayload(manifest, prompt, framework) {
  const context = canonicalContext(prompt);
  const caseId = caseIdFromPrompt(prompt);
  const expected = caseId ? expectedForCase(manifest, caseId) : {};
  const topics = expected.must_surface_topics || [framework === "STRIDE" ? "integrity" : "privacy disclosure"];
  const flows = Array.isArray(context.flows) ? context.flows : [];
  const category = framework === "STRIDE" ? "Tampering" : "Data Disclosure";
  const categories = framework === "STRIDE"
    ? ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
    : ["Linking", "Identifying", "Non-repudiation", "Detecting", "Data Disclosure", "Unawareness & Unintervenability", "Non-compliance"];
  return {
    // This local fixture validates the exhaustive response shape only. Its
    // expected-topic-derived candidate/negative rows are never live quality
    // evidence and the external release gate rejects fixture provenance.
    coverage: flows.flatMap(flow => categories.map(coveredCategory => ({
      element_ref: flow.id,
      category: coveredCategory,
      status: coveredCategory === category ? "candidate_identified" : "reviewed_no_candidate",
      reason: coveredCategory === category
        ? "The contract fixture assessed this canonical interaction."
        : "Synthetic negative row exercising the complete framework coverage contract.",
      applicability: "applicable",
      applicability_rationale: "The local contract fixture exercises a connected canonical interaction.",
      mapping_refs: [flow.id],
    }))),
    threats: flows.slice(0, 2).map((flow, index) => ({
      framework,
      taxonomy_version: framework === "STRIDE" ? "stride-v1" : "linddun-v1",
      title: `${category} review for ${flow.name || flow.id}`,
      scenario: `${topics.join("; ")} may affect the sender-to-receiver interaction ${flow.id}.`,
      threat_category: category,
      component: flow.target_id || flow.target || "Application",
      source: flow.source_id || flow.source || "Unknown source",
      destination: flow.target_id || flow.target || "Unknown destination",
      primary_interaction_ref: flow.id,
      affected_refs: [flow.id],
      dfd_context_refs: [flow.source_id, flow.target_id].filter(Boolean),
      analysis_revision: context.revision,
      dfd_semantic_hash: context.semantic_hash,
      asset: (expected.must_detect_data || ["system data"])[index % Math.max((expected.must_detect_data || ["system data"]).length, 1)],
      data_classification: framework === "LINDDUN" ? "PII" : "Unknown",
      threat_description: `Review ${topics.join(", ")} for the canonical DFD flow ${flow.id}. This is a contract-fixture scenario, not a confirmed vulnerability.`,
      abuse_case: "A caller changes or observes data across the documented interaction.",
      recommended_control: framework === "STRIDE" ? "Validate input and enforce authorization at the receiver." : "Minimize data and restrict recipient scope.",
      recommended_mitigations: ["Confirm the control with the owner", "Record verification evidence"],
      scenario_evidence_refs: [],
      evidence_refs: [],
      context_evidence_refs: [],
      control_gap_evidence_refs: [],
      assumption: "Authentication and lifecycle details require review where the PRD is silent.",
      missing_info: (expected.expected_deferred_topics || []).slice(0, 2).join("; "),
      preconditions: ["The caller can reach the documented interaction"],
      impact: "Loss of integrity, confidentiality, or privacy expectation if the scenario is confirmed.",
      validation_steps: [`Exercise ${flow.id} with a controlled input and capture the receiver response.`],
      confidence: "Medium",
      provider_risk_level: "High",
      owner: "Security",
    })),
  };
}

function missingInfoPayload(manifest, prompt) {
  const caseId = caseIdFromPrompt(prompt);
  const expected = caseId ? expectedForCase(manifest, caseId) : {};
  return {
    items: (expected.expected_deferred_topics || []).map((topic, index) => ({
      area: topic,
      question: `What is the confirmed owner and implementation for ${topic}?`,
      why_it_matters: "The decision changes DFD grounding, control applicability, or verification scope.",
      priority: index < 2 ? "High" : "Medium",
      target_team: "Security / Engineering",
      question_to_ask: `Please provide evidence for ${topic}.`,
    })),
  };
}

function extractParenthesizedIds(prompt) {
  return [...String(prompt).matchAll(/\(ID:\s*([^\)]+)\)/g)]
    .map(match => match[1].trim())
    .filter(Boolean)
    .filter((value, index, values) => values.indexOf(value) === index);
}

function controlPayload(prompt) {
  const threatIds = extractParenthesizedIds(prompt);
  return {
    controls: threatIds.map((threatId, index) => ({
      name: `CR8 control for ${threatId}`,
      description: `Validate the security property represented by threat ${threatId} at the canonical interaction.`,
      implementation_guidance: "Enforce the control at the receiver and retain verification evidence.",
      status: "Unknown",
      implementation_status: "Unknown",
      implementation_state: "unknown",
      evidence: "Capture configuration or runtime evidence before classifying implementation status.",
      implementation_evidence_requested: ["Owner-approved configuration or runtime verification evidence"],
      verification_evidence_refs: [],
      implementation_evidence_refs: [],
      runtime_verification_refs: [],
      priority: index % 3 === 0 ? "High" : "Medium",
      owner: "Security",
      threat_ids: [threatId],
      target_refs: [],
      location_ref: null,
    })),
  };
}

function testScenarioPayload(prompt) {
  const threatIds = extractParenthesizedIds(prompt);
  const controlIds = [...String(prompt).matchAll(/- ID:\s*([^\s·]+)/g)]
    .map(match => match[1].trim())
    .filter(value => value.startsWith("control-") || value.startsWith("ctrl-"));
  return {
    scenarios: threatIds.map((threatId, index) => ({
      scenario_name: `CR8 verification for ${threatId}`,
      preconditions: "A controlled test account and an observable request/response path are available.",
      steps: [
        `Locate the canonical DFD interaction referenced by ${threatId}.`,
        "Send the controlled boundary or authorization test input.",
        "Capture the receiver decision, logs, and request-response evidence.",
      ],
      expected_result: "The receiver enforces the documented security property and produces an auditable result.",
      evidence_needed: ["Request-response log", "Receiver decision or audit event"],
      related_control: controlIds[index] || null,
      related_control_id: controlIds[index] || null,
      priority: index % 3 === 0 ? "High" : "Medium",
      owner: "QA/Security",
      threat_id: threatId,
      target_refs: [],
      execution_status: "Not Run",
      actual_result: "",
      execution_evidence_refs: [],
      applicability_status: "applicable",
      applicability_reason: "The fixture contract supplies a canonical threat interaction.",
    })),
  };
}

function startContractProvider(manifest, {mode = "fixture", port}) {
  const calls = [];
  let activeCaseId = null;
  const server = http.createServer((request, response) => {
    if (request.method !== "POST" || !String(request.url || "").includes("/chat/completions")) {
      response.writeHead(404); response.end(); return;
    }
    let body = "";
    request.on("data", chunk => { body += chunk; });
    request.on("end", () => {
      let payload;
      try { payload = JSON.parse(body); } catch (_) { response.writeHead(400); response.end("invalid json"); return; }
      const system = String(payload.messages?.[0]?.content || "");
      const prompt = String(payload.messages?.[1]?.content || "");
      const explicitCaseId = caseIdFromPrompt(`${system}\n${prompt}`);
      if (explicitCaseId) activeCaseId = explicitCaseId;
      const call = {system_chars: system.length, prompt_chars: prompt.length, case_id: activeCaseId};
      calls.push(call);
      let result;
      if (mode === "partial" && system.includes("STRIDE") && calls.filter(item => item.case_id === call.case_id).length === 1) {
        response.writeHead(200, {"content-type": "application/json"});
        response.end(JSON.stringify({...jsonResponse({threats: []}, "cr8-contract-fixture", "length"), choices: [{index: 0, finish_reason: "length", message: {role: "assistant", content: '{"threats": ['}}]}));
        return;
      }
      if (prompt.includes("ARTIFACT CONTENT CHUNK:")) result = ingestionPayload(expectedForCase(manifest, call.case_id), prompt);
      else if (system.includes("STRIDE")) result = threatPayload(manifest, prompt, "STRIDE");
      else if (system.includes("LINDDUN")) result = threatPayload(manifest, prompt, "LINDDUN");
      else if (prompt.includes('Return one JSON object with an "items" array')) result = missingInfoPayload(manifest, prompt);
      else if (prompt.includes('Return one JSON object with a "controls" array')) result = controlPayload(prompt);
      else if (prompt.includes('Return one JSON object with a "scenarios" array')) result = testScenarioPayload(prompt);
      else result = {};
      response.writeHead(200, {"content-type": "application/json"});
      response.end(JSON.stringify(jsonResponse(result)));
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve({server, calls}));
  });
}

function configureFixtureProvider(dataDir, providerPort) {
  const settingsPath = path.join(dataDir, "settings.json");
  const settings = fs.existsSync(settingsPath) ? readJson(settingsPath) : {};
  settings.active_provider_id = "cr8-contract-fixture";
  settings.providers = [{
    provider_id: "cr8-contract-fixture",
    name: "CR8 contract fixture",
    provider_type: "local",
    base_url: `http://127.0.0.1:${providerPort}/v1`,
    model: "cr8-contract-fixture",
    max_tokens: 4096,
    is_local: true,
    is_active: true,
    api_key_masked: "fixture",
    _api_key: "fixture",
  }];
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
}

function configureLiveProvider(dataDir, providerName, model) {
  const settingsPath = path.join(dataDir, "settings.json");
  const settings = readJson(settingsPath);
  const providers = Array.isArray(settings.providers) ? settings.providers : [];
  const targetName = String(providerName || "").trim().toLocaleLowerCase();
  const matches = providers.filter(item => String(item.name || "").trim().toLocaleLowerCase() === targetName);
  if (matches.length !== 1) {
    throw new Error(`Live provider preflight expected exactly one provider named ${providerName}; found ${matches.length}.`);
  }
  const provider = matches[0];
  if (!provider.provider_id || !provider._api_key) {
    throw new Error(`Live provider preflight found no saved credential for ${providerName}.`);
  }
  let endpoint;
  try { endpoint = new URL(provider.base_url); }
  catch (_) { throw new Error(`Live provider preflight found an invalid endpoint for ${providerName}.`); }
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash) {
    throw new Error(`Live provider preflight rejected the endpoint for ${providerName}; HTTPS without embedded credentials is required.`);
  }

  // Only the isolated CR8 copy is changed. The user's saved settings remain
  // untouched, while the requested provider/model are made unambiguous.
  settings.active_provider_id = provider.provider_id;
  for (const item of providers) item.is_active = item.provider_id === provider.provider_id;
  provider.model = model;
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
  return {
    provider_name: provider.name,
    model: provider.model,
    endpoint_hostname: endpoint.hostname.toLocaleLowerCase(),
    endpoint_https: endpoint.protocol === "https:",
    credential_available: true,
  };
}

function isolatedServerEnvironment(baseEnv, dataDir, appPort) {
  return {
    ...baseEnv,
    // Fixture qualification uses synthetic data in an isolated loopback-only
    // server. Keep it independent from the developer's local account DB.
    AUTH_MODE: "disabled",
    DATA_DIR: dataDir,
    AUDIT_LOG_PATH: path.join(dataDir, "audit.log"),
    PORT: String(appPort),
    LLM_TIMEOUT_SECONDS: baseEnv.LLM_TIMEOUT_SECONDS || "30",
    LLM_MAX_RETRIES: String(CR8_PROVIDER_MAX_RETRIES),
  };
}

function attachDiagnostics(page, result, label) {
  page.on("pageerror", error => result.page_errors.push({label, message: error.message}));
  page.on("console", message => {
    if (["error", "warning"].includes(message.type())) result.console_messages.push({label, type: message.type(), text: message.text()});
  });
  page.on("requestfailed", request => {
    const url = request.url();
    const failure = request.failure()?.errorText || "failed";
    const readOnlyProjectRequest = /\/api\/projects\/[^/]+(?:\/(?:report(?:\/revisions(?:\/[^/]+)?)?|dfd))?$/.test(url);
    const expectedAbort = failure.includes("ERR_ABORTED") && request.method() === "GET" && (
      url.endsWith("/report") || url.includes("/analyze/progress") || readOnlyProjectRequest
    );
    if (expectedAbort) {
      result.allowed_request_failures.push({label, url, failure, reason: "Navigation cancelled an in-flight read-only workspace request."});
    } else if (url.includes("/api/") && !url.includes("/api/ux-telemetry/events")) {
      result.failed_requests.push({label, url, failure});
    }
  });
  page.on("response", response => {
    if (response.url().includes("/api/") && response.status() >= 400 && !response.url().includes("/api/ux-telemetry/events")) {
      result.http_errors.push({label, url: response.url(), status: response.status()});
    }
    if (response.url().includes("/analyze/progress")) {
      response.json().then(payload => result.progress_samples.push({label, status: payload.status, active_stage: payload.active_stage, analysis_state: payload.analysis_state?.result_state})).catch(() => {});
    }
  });
}

function pageUrl(port, route, projectId) {
  return `http://127.0.0.1:${port}/${route}.html?id=${encodeURIComponent(projectId)}`;
}

async function waitRoute(page, port, route, projectId) {
  await page.goto(pageUrl(port, route, projectId), {waitUntil: "domcontentloaded", timeout: 30000});
  await page.waitForSelector(READY_SELECTORS[route], {state: "visible", timeout: 30000});
  if (route === "analysis") {
    await page.waitForFunction(
      () => document.body.dataset.analysisWorkspaceReady === "true",
      null,
      {timeout: 30000},
    );
  }
  await page.waitForTimeout(120);
}

async function saveFailureArtifacts(page, artifactDir, label, error) {
  const stem = safeFileName(label);
  const message = {label, error: String(error?.message || error), url: page.url(), captured_at: new Date().toISOString()};
  fs.mkdirSync(artifactDir, {recursive: true});
  fs.writeFileSync(path.join(artifactDir, `${stem}.json`), JSON.stringify(message, null, 2) + "\n");
  try { await page.screenshot({path: path.join(artifactDir, `${stem}.png`), fullPage: false}); } catch (_) {}
  try { fs.writeFileSync(path.join(artifactDir, `${stem}.html`), await page.content()); } catch (_) {}
}

async function createProjectFromBrowser(page, port, entry, content, namespace) {
  await page.goto(`http://127.0.0.1:${port}/project-new.html`, {waitUntil: "domcontentloaded", timeout: 30000});
  await page.evaluate(() => sessionStorage.clear());
  await page.locator("#onboarding-start-doc").click();
  await page.locator("#project-name").fill(`CR8 ${entry.id} ${namespace}`);
  await page.locator("#project-desc").fill(`Synthetic CR8 qualification for ${entry.domain}. cr8-case-${entry.id}.`);
  await page.locator("#project-env").selectOption("staging");
  for (let step = 1; step <= 3; step += 1) {
    await page.locator("#btn-next").click();
    await page.waitForFunction(nextStep => {
      const element = document.getElementById(`step-${nextStep}`);
      return Boolean(element && getComputedStyle(element).display !== "none");
    }, step + 1, {timeout: 5000});
  }
  await page.locator("#artifact-type").selectOption("markdown");
  await page.locator("#artifact-file").setInputFiles({
    name: entry.file,
    mimeType: "text/markdown",
    buffer: Buffer.from(`CR8_CASE_ID: ${entry.id}\n${content}`, "utf8"),
  });
  const uploadResponse = page.waitForResponse(response =>
    response.url().match(/\/api\/projects\/[^/]+\/artifact\/file$/)
      && response.request().method() === "POST",
  {timeout: 180000});
  await page.locator("#btn-next").click();
  const upload = await uploadResponse;
  if (!upload.ok()) throw new Error(`Initial PRD upload returned HTTP ${upload.status()}.`);
  await page.waitForURL(url => /\/analysis\.html$/.test(url.pathname)
    && url.searchParams.get("id") !== null, {timeout: 30000});
  if (new URL(page.url()).searchParams.has("artifact_error")) {
    throw new Error("Initial PRD upload completed with an artifact error.");
  }
  const projectId = new URL(page.url()).searchParams.get("id");
  assert.ok(projectId, `project id missing after create: ${entry.id}`);
  return projectId;
}

async function runAnalysisJourney(page, port, projectId, result) {
  await waitRoute(page, port, "analysis", projectId);
  const analyzeResponse = waitForAnalysisResponse(page, projectId);
  const started = Date.now();
  await page.locator("#btn-run-analysis").click();
  const response = await analyzeResponse;
  const elapsed = Date.now() - started;
  let body = {};
  try { body = await response.json(); } catch (_) {}
  assert.equal(response.status(), 200, `analysis returned ${response.status()}`);
  await page.waitForTimeout(250);
  const reportResponse = await page.request.get(`http://127.0.0.1:${port}/api/projects/${projectId}/report`);
  assert.equal(reportResponse.status(), 200, "report endpoint did not return the completed run");
  const report = await reportResponse.json();
  result.analysis = {
    elapsed_ms: elapsed,
    response_status: response.status(),
    run_id: report.analysis_run?.run_id,
    status: report.analysis_run?.status,
    state: report.analysis_state?.result_state,
    stages: report.analysis_state?.stages,
    provider: report.formal_report_metadata?.provenance?.provider || report.analysis_run?.provider,
    body_status: body.analysis_status,
  };
  assert.ok(result.analysis.run_id, "analysis run id was not persisted");
  return report;
}

function waitForAnalysisResponse(page, projectId) {
  return page.waitForResponse(
    response => response.url().endsWith(`/api/projects/${projectId}/analyze`)
      && response.request().method() === "POST",
    {timeout: ANALYSIS_RESPONSE_TIMEOUT_MS},
  );
}

async function inspectCoreTrace(page, port, projectId, result) {
  await waitRoute(page, port, "model", projectId);
  const modelNodes = await page.locator("#diagram-text-content [data-outline-type='node']").count().catch(() => 0);
  result.trace = {model_nodes: modelNodes};
  await waitRoute(page, port, "findings", projectId);
  const findingRows = await page.locator("#findings-list [data-finding-id]").count();
  if (findingRows) {
    await page.locator("#findings-list [data-finding-id]").first().click();
    await page.waitForTimeout(100);
  }
  await waitRoute(page, port, "action-plan", projectId);
  const actionRows = await page.locator("#action-list [data-action-key]").count();
  if (actionRows) {
    await page.locator("#action-list [data-action-key]").first().click();
    await page.waitForTimeout(100);
  }
  await waitRoute(page, port, "report", projectId);
  result.trace.finding_rows = findingRows;
  result.trace.action_rows = actionRows;
  result.trace.report_visible = await page.locator("#report-dfd-snapshot-caption").isVisible();
  assert.ok(result.trace.report_visible, "formal report snapshot was not visible");
}

async function runAxe(page, axeSource) {
  await page.addScriptTag({content: axeSource});
  return page.evaluate(async () => {
    const result = await window.axe.run(document, {resultTypes: ["violations", "incomplete"]});
    return {
      violations: result.violations.map(rule => ({id: rule.id, impact: rule.impact, nodes: rule.nodes.map(node => ({target: node.target}))})),
      incomplete: result.incomplete.map(rule => ({id: rule.id, impact: rule.impact, nodes: rule.nodes.map(node => ({target: node.target}))})),
    };
  });
}

async function inspectSurface(page) {
  return page.evaluate(() => {
    const visible = element => {
      if (!element) return false;
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return box.width > 0 && box.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    };
    const active = document.activeElement;
    const activeBox = active?.getBoundingClientRect();
    const overlap = (a, b) => a && b && Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) * Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
    const occluders = [...document.querySelectorAll("body *")].filter(element => {
      if (element === active || element.contains(active) || !visible(element)) return false;
      const style = getComputedStyle(element);
      return style.position === "fixed" && Number(style.zIndex || 0) > 0;
    }).map(element => ({id: element.id, className: String(element.className || "").slice(0, 80), area: overlap(activeBox, element.getBoundingClientRect())})).filter(item => item.area > 2);
    return {
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
      width: innerWidth,
      document_width: document.documentElement.scrollWidth,
      height: document.documentElement.scrollHeight,
      heading: Boolean([...document.querySelectorAll("h1")].some(visible)),
      occluders,
    };
  });
}

async function inspectBrowserQualification(page, port, projectId, axeSource, artifactDir, result) {
  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({width: viewport.width, height: viewport.height});
    for (const route of ROUTES) {
      const label = `${route}-${viewport.width}`;
      try {
        await waitRoute(page, port, route, projectId);
        const focusTarget = page.locator("main button:visible, main a[href]:visible, main input:visible").first();
        if (await focusTarget.count()) await focusTarget.focus();
        const surface = await inspectSurface(page);
        const axe = await runAxe(page, axeSource);
        result.browser.matrix.push({route, viewport: viewport.name, width: viewport.width, surface, axe});
        if (viewport.width === 390 || viewport.width === 1440) {
          const file = path.join(artifactDir, "screenshots", `${label}.png`);
          fs.mkdirSync(path.dirname(file), {recursive: true});
          await page.screenshot({path: file, fullPage: false});
        }
      } catch (error) {
        result.browser.errors.push({label, message: error.message});
        await saveFailureArtifacts(page, artifactDir, label, error);
      }
    }
  }

  try {
    await page.setViewportSize({width: 390, height: 844});
    await waitRoute(page, port, "report", projectId);
    const releasePanel = page.locator("#report-release-decision");
    const releaseStatus = await releasePanel.getAttribute("data-status");
    if (!(await releasePanel.isVisible()) || !["ready", "not_ready", "superseded"].includes(releaseStatus)) {
      throw new Error("Report page does not expose a valid enterprise release decision.");
    }
    const releaseText = await releasePanel.innerText();
    if (!/Enterprise release decision|Current project release decision/.test(releaseText)) {
      throw new Error("Enterprise release decision is missing its distinct label.");
    }
    await releasePanel.scrollIntoViewIfNeeded();
    await page.screenshot({path: path.join(artifactDir, "screenshots", "report-release-decision-390.png"), fullPage: false});
    result.browser.checks.push({name: "report_enterprise_release_decision_visible", status: releaseStatus});

    const reportPattern = `**/api/projects/${projectId}/report`;
    const signedButBlockedResponse = async route => {
      const response = await route.fetch();
      const payload = await response.json();
      payload.formal_report = {...(payload.formal_report || {}), status: "signed", release_decision_status: "not_ready"};
      payload.release_decision = {
        ...(payload.release_decision || {}),
        status: "not_ready",
        blockers: Array.from({length: 10}, (_item, index) => index === 0
          ? {code: "signer_enterprise_identity", message: "The report was not signed under enterprise OIDC/JWT identity."}
          : {code: `synthetic_release_blocker_${index}`, message: `Synthetic blocker ${index} validates complete blocker count display.`}),
      };
      await route.fulfill({response, json: payload});
    };
    await page.route(reportPattern, signedButBlockedResponse);
    try {
      await page.reload({waitUntil: "domcontentloaded"});
      await page.waitForFunction(() =>
        document.querySelector("#report-formal-status")?.textContent === "signed"
        && document.querySelector("#report-release-decision")?.dataset.status === "not_ready"
      );
      const signedBlockedPanel = page.locator("#report-release-decision");
      const signedBlockedText = await signedBlockedPanel.innerText();
      if (!/signer_enterprise_identity/.test(signedBlockedText) || !/2 additional blockers/.test(signedBlockedText)) {
        throw new Error("A signed report without enterprise signer authority was not shown as blocked.");
      }
      result.browser.checks.push({name: "report_signed_history_not_enterprise_ready", passed: true, blocker_count: 10});
    } finally {
      await page.unroute(reportPattern, signedButBlockedResponse);
    }
  } catch (error) {
    result.browser.errors.push({label: "report-release-decision", message: error.message});
    await saveFailureArtifacts(page, artifactDir, "report-release-decision", error);
  }

  try {
    await page.setViewportSize({width: 390, height: 844});
    await waitRoute(page, port, "findings", projectId);
    await page.locator("#findings-search").focus();
    await page.keyboard.type("flow");
    const filteredUrl = page.url();
    const firstFinding = page.locator("#findings-list [data-finding-id]").first();
    if (await firstFinding.count()) {
      await firstFinding.focus();
      await page.keyboard.press("Enter");
      await page.keyboard.press("Escape");
    }
    result.browser.checks.push({name: "keyboard_findings_search_select_close", url: filteredUrl});
  } catch (error) {
    result.browser.errors.push({label: "keyboard-findings", message: error.message});
    await saveFailureArtifacts(page, artifactDir, "keyboard-findings", error);
  }

  try {
    await waitRoute(page, port, "model", projectId);
    const trigger = page.locator("#model-review-trigger");
    if (await trigger.isVisible()) {
      await trigger.click();
      await page.keyboard.press("Escape");
    }
    result.browser.checks.push({name: "model_boundary_review_keyboard_close", passed: true});
  } catch (error) {
    result.browser.errors.push({label: "model-boundary-review", message: error.message});
    await saveFailureArtifacts(page, artifactDir, "model-boundary-review", error);
  }
}

function countCoverage(project) {
  const sources = (project.artifact_sources || []).filter(item => item.active !== false);
  let processed = 0;
  let total = 0;
  for (const source of sources) {
    const manifest = source.coverage_manifest || {};
    total += Number(manifest.chunk_count || 0);
    processed += Number(manifest.processed_chunk_count || 0);
  }
  return {processed, total};
}

function expectedEntityMetric(dfd, expected) {
  const labels = [
    ...(expected.must_detect_actors || []),
    ...(expected.must_detect_components || []),
    ...(expected.must_detect_external_systems || []),
    ...(expected.must_detect_data || []),
  ];
  const nodes = [...(dfd?.nodes || []), ...(dfd?.data_objects || [])];
  const found = labels.filter(label => nodes.some(node => matchLabel(node.name || node.label, label)));
  const precision = nodes.filter(node => labels.some(label => matchLabel(node.name || node.label, label))).length;
  return {found: found.length, expected: labels.length, precision, nodes: nodes.length};
}

function topicMetric(report, expected) {
  const text = JSON.stringify(report.threats || []).toLowerCase();
  const topics = expected.must_surface_topics || [];
  return topics.filter(topic => text.includes(String(topic).toLowerCase())).length;
}

function deferredMetric(report, expected) {
  const text = JSON.stringify({
    missing_info: report.missing_info,
    assumptions: report.assumptions,
    decisions: report.deferred_decisions,
    threats: report.threats,
  }).toLowerCase();
  const topics = expected.expected_deferred_topics || [];
  return topics.filter(topic => text.includes(String(topic).toLowerCase())).length;
}

function buildCaseResult(entry, project, report, baselineCase, mode = "live") {
  const expected = entry.expected || {};
  const dfd = report.dfd_model || {};
  const entities = expectedEntityMetric(dfd, expected);
  const semanticQuality = dfd.semantic_quality || report.dfd_validation?.semantic_quality || {};
  const qualityCounts = semanticQuality.counts || {};
  const topologyCoverage = report.dfd_validation?.readiness?.topology_coverage || {};
  const coverage = countCoverage(project);
  const run = report.analysis_run || {};
  const stages = report.ai_status || {};
  const frameworkValid = ["STRIDE", "LINDDUN"].filter(framework => {
    const stage = stages[framework.toLowerCase()] || {};
    const status = stage.assessment_status;
    const coverageSummary = report.analysis_coverage_summary?.[framework];
    const coverageManifestSummary = report.analysis_coverage_manifest?.[framework]?.summary;
    return (status === "complete" || status === "valid_empty")
      && coverageSummary?.complete === true
      && coverageManifestSummary?.complete === true;
  }).length;
  const threats = Array.isArray(report.threats) ? report.threats : [];
  const flowIds = new Set((dfd.flows || []).map(flow => flow.id));
  const mapped = threats.filter(item => flowIds.has(item.primary_interaction_ref));
  const controls = Array.isArray(report.controls) ? report.controls : [];
  const mappedControls = controls.filter(item => {
    const ids = item.threat_ids || item.finding_ids || [];
    return item.mapping_status !== "unassigned" && ids.some(id => threats.some(threat => threat.threat_id === id));
  });
  const mappedThreatIds = new Set(mappedControls.flatMap(item => (item.threat_ids || item.finding_ids || []).map(String)));
  const tests = Array.isArray(report.test_scenarios) ? report.test_scenarios : [];
  const executableTests = tests.filter(item => item.quality_status === "executable"
    && item.applicability_status === "applicable" && item.execution_status !== "Blocked");
  const duplicateCountsAvailable = ["nodes", "flows", "duplicate_nodes", "duplicate_flows"]
    .every(key => Number.isInteger(qualityCounts[key]));
  const duplicateDenominator = Number(qualityCounts.nodes || 0) + Number(qualityCounts.flows || 0);
  const duplicateNumerator = Number(qualityCounts.duplicate_nodes || 0) + Number(qualityCounts.duplicate_flows || 0);
  const topologyCountKeys = ["flows", "valid_endpoints", "cross_zone_flows", "valid_crossing_flows", "nodes", "isolated_nodes", "zones", "isolated_zones"];
  const topologyCountsAvailable = topologyCountKeys.every(key => Number.isInteger(qualityCounts[key]))
    && Number.isInteger(topologyCoverage.connected_nodes)
    && Number.isInteger(topologyCoverage.total_nodes)
    && Number.isInteger(topologyCoverage.active_zones)
    && Number.isInteger(topologyCoverage.connected_zones);
  const flowCount = Number(qualityCounts.flows || 0);
  const crossZoneFlowCount = Number(qualityCounts.cross_zone_flows || 0);
  const nodeCount = Number(qualityCounts.nodes || 0);
  const zoneCount = Number(qualityCounts.zones || 0);
  const connectedZoneChecks = Number(topologyCoverage.active_zones || 0) > 1
    ? Number(topologyCoverage.active_zones || 0)
    : 0;
  const topologyDenominator = flowCount + crossZoneFlowCount + nodeCount + zoneCount + connectedZoneChecks;
  const topologyNumerator = Number(qualityCounts.valid_endpoints || 0)
    + Number(qualityCounts.valid_crossing_flows || 0)
    + Number(topologyCoverage.connected_nodes || 0)
    + Math.max(0, zoneCount - Number(qualityCounts.isolated_zones || 0))
    + (connectedZoneChecks ? Number(topologyCoverage.connected_zones || 0) : 0);
  const expectedTopicCount = (expected.must_surface_topics || []).length;
  const expectedDeferredCount = (expected.expected_deferred_topics || []).length;
  const topicCount = topicMetric(report, expected);
  const deferredCount = deferredMetric(report, expected);
  const sourceRevision = project.artifact_sources?.find(item => item.active !== false)?.revision || 1;
  const sourceHash = project.artifact_sources?.find(item => item.active !== false)?.content_hash || hash(entry.id);
  const providerMetadata = [stages.stride, stages.linddun].map(item => item?.response_metadata || {}).filter(item => Object.keys(item).length);
  const responseModelObservations = Object.fromEntries(["stride", "linddun"].map(framework => [
    framework,
    observeProviderResponseModels(stages[framework]?.response_metadata),
  ]));
  const providerConfig = report.formal_report_metadata?.provenance?.provider
    || report.formal_report?.provenance?.provider
    || run.provider
    || {};
  const observedModels = [...new Set(Object.values(responseModelObservations).flatMap(item => item.models))];
  const providerName = providerConfig.provider_name || providerConfig.name || providerConfig.provider_type || providerConfig.source || null;
  const modelName = Object.values(responseModelObservations).length === 2
    && Object.values(responseModelObservations).every(item => item.recorded)
    && observedModels.length === 1
    ? observedModels[0]
    : null;
  const warningStages = Array.isArray(run.warning_stages) ? run.warning_stages : [];
  const frameworkDiagnostics = Object.fromEntries(["stride", "linddun"].map(framework => {
    const frameworkName = framework.toUpperCase();
    const stage = stages[framework] && typeof stages[framework] === "object" ? stages[framework] : {};
    const responseMetadata = stage.response_metadata && typeof stage.response_metadata === "object" ? stage.response_metadata : {};
    const manifest = responseMetadata.generation_manifest && typeof responseMetadata.generation_manifest === "object"
      ? responseMetadata.generation_manifest : {};
    const coverageManifest = report.analysis_coverage_manifest?.[frameworkName] || {};
    const coverageEntries = Array.isArray(coverageManifest.entries) ? coverageManifest.entries : [];
    const primaryCoverage = coverageEntries.filter(item => item?.assessment_scope === "primary_interaction");
    const coverageStatusCounts = {};
    for (const item of primaryCoverage) {
      const status = String(item?.status || "unknown").slice(0, 48);
      coverageStatusCounts[status] = (coverageStatusCounts[status] || 0) + 1;
    }
    const unresolvedCoverage = primaryCoverage
      .filter(item => ["deferred", "failed", "unprocessed"].includes(String(item?.status || "")))
      .slice(0, 12)
      .map(item => ({
        element_ref: String(item.element_ref || "").slice(0, 120),
        category: String(item.category || "").slice(0, 80),
        status: String(item.status || "").slice(0, 48),
        reason: String(item.reason || "").slice(0, 240),
      }));
    const rawCoverageSummary = report.analysis_coverage_summary?.[frameworkName] || {};
    const modelObservation = responseModelObservations[framework];
    const batches = Array.isArray(manifest.batches) ? manifest.batches : [];
    const statusCounts = {};
    const errorCodeCounts = {};
    for (const batch of batches) {
      const status = String(batch?.status || "unknown").slice(0, 48);
      statusCounts[status] = (statusCounts[status] || 0) + 1;
      if (batch?.error_code) {
        const code = String(batch.error_code).slice(0, 80);
        errorCodeCounts[code] = (errorCodeCounts[code] || 0) + 1;
      }
    }
    return [framework, {
      assessment_status: String(stage.assessment_status || "not_reported").slice(0, 48),
      engine: String(stage.engine || "not_reported").slice(0, 48),
      ok: stage.ok === true,
      error_code: stage.error_code ? String(stage.error_code).slice(0, 80) : null,
      warning_stage: warningStages.includes(framework),
      validation_warning_count: Array.isArray(stage.validation_warnings) ? stage.validation_warnings.length : 0,
      response_model: modelObservation.model,
      response_model_recorded: modelObservation.recorded,
      observed_response_models: modelObservation.models,
      provider_response_count: modelObservation.response_count,
      valid_batches_missing_response_model: modelObservation.valid_batches_missing_model,
      response_metadata_fields: Object.keys(responseMetadata).sort(),
      coverage: {
        primary_interaction_count: Number.isInteger(rawCoverageSummary.primary_interaction_count) ? rawCoverageSummary.primary_interaction_count : null,
        scoped_total: Number.isInteger(rawCoverageSummary.scoped_total) ? rawCoverageSummary.scoped_total : primaryCoverage.length,
        assessed: Number.isInteger(rawCoverageSummary.assessed) ? rawCoverageSummary.assessed : null,
        not_applicable: Number.isInteger(rawCoverageSummary.not_applicable) ? rawCoverageSummary.not_applicable : null,
        deferred: Number.isInteger(rawCoverageSummary.deferred) ? rawCoverageSummary.deferred : null,
        failed: Number.isInteger(rawCoverageSummary.failed) ? rawCoverageSummary.failed : null,
        unprocessed: Number.isInteger(rawCoverageSummary.unprocessed) ? rawCoverageSummary.unprocessed : null,
        summary_complete: rawCoverageSummary.complete === true,
        manifest_complete: coverageManifest.summary?.complete === true,
        complete: rawCoverageSummary.complete === true && coverageManifest.summary?.complete === true,
        observed_status_counts: coverageStatusCounts,
        unresolved_examples: unresolvedCoverage,
      },
      generation: {
        batch_count: Number.isInteger(manifest.batch_count) ? manifest.batch_count : null,
        completed_count: Number.isInteger(manifest.completed_count) ? manifest.completed_count : null,
        cache_hits: Number.isInteger(manifest.cache_hits) ? manifest.cache_hits : null,
        deferred_refs_count: Array.isArray(manifest.deferred_refs) ? manifest.deferred_refs.length : 0,
        non_interaction_refs_count: Array.isArray(manifest.non_interaction_refs) ? manifest.non_interaction_refs.length : 0,
        batch_status_counts: statusCounts,
        batch_error_code_counts: errorCodeCounts,
      },
    }];
  }));
  const providerFallbackUsed = Boolean(report.formal_report_metadata?.provenance?.fallback_used
    ?? report.formal_report?.provenance?.fallback_used
    ?? Object.values(stages).some(item => item?.baseline_used || item?.engine === "fallback"));
  const metrics = {
    ingestion_coverage: metric(coverage.processed, Math.max(coverage.total, 1), "Coverage manifest processed/total chunk counts."),
    dfd_entity_recall: metric(entities.found, entities.expected, "Expected actor/component/external/data labels matched against canonical DFD nodes."),
    dfd_precision: mode === "fixture"
      ? metric(entities.precision, Math.max(entities.nodes, 1), "Fixture-only required-label hit proxy; not semantic DFD precision or live quality evidence.")
      : metric(0, 0, "Not measured: independent labels for every canonical entity, data object, and flow are required to distinguish valid optional architecture from unsupported claims.", false),
    dfd_label_hit_ratio: metric(entities.precision, Math.max(entities.nodes, 1), "Diagnostic only: required entity/data labels matched divided by all canonical nodes/data objects; unlabeled candidates are not false positives.", false),
    duplicate_rate: duplicateCountsAvailable
      ? metric(duplicateNumerator, duplicateDenominator, "Semantically duplicate canonical nodes and flows divided by canonical nodes and flows.")
      : metric(0, 0, "Not measured: canonical semantic duplicate counts are missing.", false),
    topology_validity: topologyCountsAvailable
      ? metric(topologyNumerator, Math.max(topologyDenominator, 1), "Structural checks for flow endpoints, cross-zone boundaries, node connectivity, and zone coverage; does not measure semantic flow correctness.")
      : metric(0, 0, "Not measured: canonical topology coverage counts are missing.", false),
    framework_validation: metric(frameworkValid, 2, "Both stages need a complete or legitimate valid-empty result and complete current coverage summaries plus manifests; generation completion alone is insufficient."),
    finding_flow_binding: metric(mapped.length, Math.max(threats.length, 1), "Diagnostic only: generated scenarios with a canonical primary DFD interaction; this is not semantic finding precision.", false),
    finding_precision: mode === "fixture"
      ? metric(mapped.length, Math.max(threats.length, 1), "Fixture-only structural flow-binding proxy; not semantic finding precision or provider-quality evidence.")
      : metric(0, 0, "Not measured: supported/unsupported finding labels require independent blind AppSec adjudication; flow binding is reported separately.", false),
    finding_recall: metric(topicCount, Math.max(expectedTopicCount, 1), mode === "fixture"
      ? "Fixture-only manifest keyword matcher; not provider-quality evidence."
      : "Diagnostic manifest keyword matcher only; not eligible for release until the expected findings are independently blind-adjudicated.", mode === "fixture"),
    deferred_recall: metric(deferredCount, Math.max(expectedDeferredCount, 1), mode === "fixture"
      ? "Fixture-only manifest keyword matcher; not provider-quality evidence."
      : "Diagnostic manifest keyword matcher only; not eligible for release until deferred labels are independently adjudicated.", mode === "fixture"),
    control_mapping_precision: mode === "fixture"
      ? metric(mappedControls.length, Math.max(controls.length, 1), "Fixture-only finding-ID binding proxy; not semantic control precision or live quality evidence.")
      : metric(0, 0, "Not measured: independent expected control edges and reviewer judgments of applicability/correctness are required.", false),
    control_mapping_recall: mode === "fixture"
      ? metric(mappedThreatIds.size, Math.max(threats.length, 1), "Fixture-only generated-threat assignment proxy; not expected control-edge recall or live quality evidence.")
      : metric(0, 0, "Not measured: independently adjudicated expected control edges are required.", false),
    control_mapping_binding: metric(mappedControls.length, Math.max(controls.length, 1), "Diagnostic only: control records reference at least one current finding ID; semantic applicability is not judged.", false),
    threat_control_assignment_coverage: metric(mappedThreatIds.size, Math.max(threats.length, 1), "Diagnostic only: generated findings with at least one assigned control; this is not expected-edge recall.", false),
    test_executability: mode === "fixture"
      ? metric(executableTests.length, Math.max(tests.length, 1), "Fixture-only structural test-quality result; not blind test-label quality or live evidence.")
      : metric(0, 0, "Not measured: independently labeled expected tests and adjudicated execution quality are required.", false),
    test_scenario_quality_rate: metric(executableTests.length, Math.max(tests.length, 1), "Diagnostic only: scenarios passing the application's structural action-quality validator divided by generated scenarios.", false),
  };
  return {
    case_id: entry.id,
    project_id: project.project_id,
    completeness: entry.completeness,
    run_status: run.status,
    signoff_ready: Boolean(report.quality_gate?.signoff_ready),
    project_name: project.name,
    source_file: entry.file,
    metrics,
    observed: {
      dfd_nodes: (dfd.nodes || []).length,
      dfd_flows: (dfd.flows || []).length,
      dfd_boundaries: (dfd.boundaries || []).length,
      stride_count: threats.filter(item => item.framework === "STRIDE").length,
      linddun_count: threats.filter(item => item.framework === "LINDDUN").length,
      control_count: controls.length,
    test_count: tests.length,
    deferred_count: report.analysis_state?.trusted_result_scope?.deferred_findings || 0,
      warning_stages: run.warning_stages || [],
      framework_assessments: frameworkDiagnostics,
    dfd_validation: {
      valid: report.dfd_validation?.valid,
      errors: report.dfd_validation?.errors || [],
      readiness: report.dfd_validation?.readiness?.status,
      topology: report.dfd_validation?.readiness?.topology_coverage?.status,
      blocking_reasons: report.dfd_validation?.readiness?.blocking_reasons || [],
      topology_issues: report.dfd_validation?.readiness?.topology_coverage?.issues || [],
      knowledge_issues: report.dfd_validation?.readiness?.knowledge_completeness?.issues || [],
      reviewer_issues: report.dfd_validation?.readiness?.reviewer_acceptance?.issues || [],
      open_questions: (dfd.questions || []).filter(item => ["open", "deferred"].includes(String(item.status || "open").toLowerCase())).map(item => ({id: item.id, question: item.question, status: item.status, affected_refs: item.affected_refs || []})),
      deferred_interactions: (dfd.deferred_interactions || []).map(item => ({id: item.id, name: item.name, status: item.status, reason: item.reason, next_action: item.next_action})),
      flow_summaries: (dfd.flows || []).map(item => ({id: item.id, name: item.name, source_id: item.source_id, target_id: item.target_id, data_object_ids: item.data_object_ids || [], boundary_crossings: item.boundary_crossings || [], crossing_status: item.crossing_status, evidence_refs: item.evidence_refs || []})),
      semantic_quality: dfd.semantic_quality || report.dfd_validation?.semantic_quality || null,
    },
    coverage: (project.artifact_sources || [])
      .filter(item => item && item.active !== false)
      .map(item => ({
        filename: item.filename,
        status: item.coverage_manifest?.status,
        chunks: item.coverage_manifest?.chunk_count,
        processed: item.coverage_manifest?.processed_chunk_count,
        empty: item.coverage_manifest?.empty_chunk_count,
        deferred: item.coverage_manifest?.deferred_chunk_count,
        statuses: (item.coverage_manifest?.chunks || []).map(chunk => ({chunk_id: chunk.chunk_id, section: chunk.section, status: chunk.status, reason: chunk.reason})),
      })),
  },
    provenance: {
      application_commit: process.env.CR8_APPLICATION_COMMIT || "worktree-uncommitted",
      provider: providerName,
      model: modelName,
      configured_model: providerConfig.model || null,
      observed_response_models: observedModels,
      provider_source: providerConfig.source || null,
      provider_fallback_used: providerFallbackUsed,
      timeout_seconds: 30,
      retry_config: {max_retries: CR8_PROVIDER_MAX_RETRIES, format_retry: 1},
      batch_config: threatBatchConfiguration(stages),
      source_revision: String(sourceRevision),
      source_hash: sourceHash,
      dfd_revision: dfd.revision || "unknown",
      dfd_semantic_hash: dfd.semantic_hash || "unknown",
      run_id: run.run_id || "unknown",
      provider_metadata: providerMetadata,
      observed_response_models: observedModels,
    },
    before: baselineCase ? {
      run_status: baselineCase.run_status,
      framework_validation_pct: baselineCase.framework_validation_pct,
      overall_pct: baselineCase.overall_pct,
    } : null,
  };
}

function aggregateCurrent(cases) {
  const aggregate = {};
  for (const name of Object.keys(cases[0]?.metrics || {})) {
    const observations = cases.map(item => item.metrics[name]);
    aggregate[name] = {
      numerator: observations.reduce((sum, item) => sum + item.numerator, 0),
      denominator: observations.reduce((sum, item) => sum + item.denominator, 0),
    };
    aggregate[name].value = aggregate[name].denominator ? Number((aggregate[name].numerator / aggregate[name].denominator).toFixed(4)) : null;
  }
  return aggregate;
}

function percentile(values, percentileValue = 0.95) {
  const sorted = values.filter(value => Number.isFinite(value)).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * percentileValue) - 1));
  return sorted[index];
}

function renderQualificationMarkdown(report) {
  const lines = [
    "# CR8 Release Qualification",
    "",
    `- Verdict: **${report.release_gate.verdict}**`,
    `- Mode: ${report.mode}`,
    `- Browser: ${report.browser.engine} ${report.browser.playwright}`,
    `- Corpus cases: ${report.cases.length}`,
    `- Fixture quality gate: ${report.fixture_quality_gate.passed ? "PASS" : "FAIL"}`,
    `- Live-provider qualification: ${report.live_provider_qualification.status}`,
    ...(report.provider_selection ? [`- Live provider/model: ${report.provider_selection.provider_name} / ${report.provider_selection.model}`, `- Endpoint host: ${report.provider_selection.endpoint_hostname}`, `- Provider timeout/retries: ${report.provider_selection.timeout_seconds}s / ${report.provider_selection.max_retries}`] : []),
    "",
    "## Release gate",
    "",
    "| Gate | Status | Reason |",
    "|---|---|---|",
    ...Object.entries(report.release_gate.checks).map(([name, item]) => `| ${name} | ${item.passed ? "PASS" : "FAIL"} | ${item.reason} |`),
    "",
    "## Aggregate measured metrics",
    "",
    "| Metric | Count | Ratio |",
    "|---|---:|---:|",
    ...Object.entries(report.aggregate.metrics).map(([name, item]) => `| ${name} | ${item.numerator}/${item.denominator} | ${item.value ?? "n/a"} |`),
    "",
    "## Case comparison",
    "",
    "| Case | Before framework | After framework | Run | Sign-off |",
    "|---|---:|---:|---|---|",
    ...report.cases.map(item => {
      const framework = item.metrics?.framework_validation;
      return `| ${item.case_id} | ${item.before?.framework_validation_pct ?? "n/a"} | ${framework ? `${framework.numerator}/${framework.denominator}` : "n/a"} | ${item.run_status || "failed"} | ${item.signoff_ready ?? false} |`;
    }),
    "",
    "## Browser qualification",
    "",
    `- Viewport samples: ${report.browser.matrix.length}`,
    `- Browser errors: ${report.browser.errors.length}`,
    `- Serious/critical axe violations: ${report.browser.serious_or_critical_violations}`,
    `- Page errors: ${report.diagnostics.page_errors.length}`,
    `- Unexpected API failures: ${report.diagnostics.failed_requests.length + report.diagnostics.http_errors.length}`,
    "",
    "## Limitations",
    "",
    "- The fixture lane proves application contracts and user journey against a local structured-output provider; it is not evidence that a cloud provider/model is reliable.",
    "- Live-provider qualification remains an explicit release prerequisite and is fail-closed when no scheduled/manual live artifact is supplied.",
    "- Reviewer sampling is recorded as pending until an AppSec reviewer and a product/engineering reviewer complete the task log.",
    "",
  ];
  return lines.join("\n");
}

async function runCase(page, port, entry, namespace, artifactDir, baselineCase, result) {
  const caseResult = {case_id: entry.id, errors: [], progress_samples: []};
  const content = fs.readFileSync(path.join(CORPUS_DIR, entry.file), "utf8");
  try {
    const projectId = await createProjectFromBrowser(page, port, entry, content, namespace);
    caseResult.project_id = projectId;
    const report = await runAnalysisJourney(page, port, projectId, caseResult);
    const projectResponse = await page.request.get(`http://127.0.0.1:${port}/api/projects/${projectId}`);
    assert.equal(projectResponse.status(), 200, "project detail did not load after analysis");
    const project = await projectResponse.json();
    caseResult.qualification = buildCaseResult(entry, project, report, baselineCase, result.mode);
    caseResult.qualification.provenance.application_commit = result.candidate_identity.git_commit_sha || "unknown";
    caseResult.qualification.performance = {
      core_analysis_ms: caseResult.analysis?.elapsed_ms ?? null,
      stages_seconds: Object.fromEntries(
        Object.entries(report.ai_status || {})
          .filter(([, status]) => Number.isFinite(Number(status?.duration_seconds)))
          .map(([stage, status]) => [stage, Number(status.duration_seconds)])
      ),
    };
    await inspectCoreTrace(page, port, projectId, caseResult);
  } catch (error) {
    caseResult.errors.push({message: error.message, stack: error.stack});
    await saveFailureArtifacts(page, artifactDir, `case-${entry.id}`, error);
  }
  result.cases.push(caseResult.qualification || {
    case_id: entry.id,
    project_id: caseResult.project_id || null,
    run_status: "failed",
    errors: caseResult.errors,
  });
  result.diagnostics.case_errors.push(...caseResult.errors.map(error => ({case_id: entry.id, ...error})));
}

async function main() {
  const options = parseArgs(process.argv);
  const manifest = readJson(MANIFEST_PATH);
  const contract = readJson(CONTRACT_PATH);
  const baseline = readJson(BASELINE_PATH);
  const entries = manifest.cases.filter(entry => !options.caseId || entry.id === options.caseId);
  if (!entries.length) throw new Error(`No corpus entry selected for ${options.caseId}`);
  const artifactDir = path.resolve(options.artifactDir || fs.mkdtempSync(path.join(os.tmpdir(), "5stones-cr8-")));
  fs.mkdirSync(artifactDir, {recursive: true});
  const screenshotDir = options.screenshotDir ? path.resolve(options.screenshotDir) : path.join(artifactDir, "screenshots");
  fs.mkdirSync(screenshotDir, {recursive: true});
  const namespace = `run-${new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14)}-${process.pid}`;
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-cr8-data-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const providerPort = 25000 + Math.floor(Math.random() * 400);
  const appPort = providerPort + 1;
  let provider;
  let server;
  let browser;
  const serverLogs = [];
  const cleanupErrors = [];
  const playwright = loadModule("playwright");
  const axe = loadAxeSource();
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const result = {
    schema_version: "cr8-qualification-v1",
    captured_at: new Date().toISOString(),
    mode: options.mode,
    namespace,
    candidate_identity: {
      ...captureCandidateIdentity(REPO),
      declared_application_commit: process.env.CR8_APPLICATION_COMMIT || null,
    },
    artifact_dir: artifactDir,
    corpus_version: manifest.version,
    contract_id: contract.contract_id,
    browser: {engine: "Chromium", playwright: require("playwright/package.json").version, axe_version: axe.version},
    cases: [],
    browser: {engine: "Chromium", playwright: require("playwright/package.json").version, axe_version: axe.version, matrix: [], checks: [], errors: []},
    diagnostics: {console_messages: [], page_errors: [], failed_requests: [], allowed_request_failures: [], http_errors: [], case_errors: []},
    live_provider_qualification: {status: options.mode === "live" ? "not_measured" : "not_run", reason: "Fixture execution cannot certify a live provider/model."},
  };
  try {
    if (options.mode === "fixture") {
      provider = await startContractProvider(manifest, {mode: "fixture", port: providerPort});
      configureFixtureProvider(dataDir, providerPort);
    } else {
      const requestedProvider = options.providerName || "sumopod";
      const requestedModel = options.model || "deepseek-v4-flash";
      result.provider_selection = configureLiveProvider(dataDir, requestedProvider, requestedModel);
      result.provider_selection.timeout_seconds = 30;
      result.provider_selection.max_retries = CR8_PROVIDER_MAX_RETRIES;
      result.provider_selection.corpus_case_count = entries.length;
      result.live_provider_qualification = {status: "requested", reason: "One bounded live qualification pass; provider and model are selected in an isolated copy of the saved settings."};
    }
    server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(appPort)], {
      cwd: REPO,
      env: isolatedServerEnvironment(process.env, dataDir, appPort),
      stdio: ["ignore", "pipe", "pipe"],
    });
    server.stdout.on("data", chunk => serverLogs.push({stream: "stdout", text: String(chunk).slice(0, 4000)}));
    server.stderr.on("data", chunk => serverLogs.push({stream: "stderr", text: String(chunk).slice(0, 4000)}));
    await waitForServer(`http://127.0.0.1:${appPort}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 390, height: 844}, acceptDownloads: true});
    const page = await context.newPage();
    const globalDiagnostics = {page_errors: [], console_messages: [], failed_requests: [], allowed_request_failures: [], http_errors: [], progress_samples: []};
    attachDiagnostics(page, globalDiagnostics, "corpus");
    for (const entry of entries) await runCase(page, appPort, entry, namespace, artifactDir, baseline.cases?.find(item => item.case_id === entry.id), result);
    const caseErrors = result.diagnostics.case_errors;
    result.diagnostics = {...globalDiagnostics, case_errors: caseErrors};
    const successful = result.cases.filter(item => item.metrics);
    if (successful.length) {
      const browserCase = successful[0];
      await inspectBrowserQualification(page, appPort, browserCase.project_id, axe.source, artifactDir, result);
      result.browser.serious_or_critical_violations = result.browser.matrix.flatMap(item => item.axe.violations).filter(item => ["serious", "critical"].includes(item.impact)).length;
    } else result.browser.errors.push({label: "browser-qualification", message: "No successful corpus case available for UI qualification."});
    await page.close();
    await context.close();
  } finally {
    if (browser) {
      try { await browser.close(); }
      catch (error) { cleanupErrors.push(`Browser shutdown failed: ${error.message}`); }
    }
    if (server) {
      try { await terminateChild(server); }
      catch (error) { cleanupErrors.push(`Application server shutdown failed: ${error.message}`); }
    }
    if (provider) {
      try { await new Promise((resolve, reject) => provider.server.close(error => error ? reject(error) : resolve())); }
      catch (error) { cleanupErrors.push(`Contract provider shutdown failed: ${error.message}`); }
    }
    if (!options.keepData) {
      try { await removeDirectoryWithRetry(tempRoot); }
      catch (error) { cleanupErrors.push(`Isolated data directory cleanup failed: ${error.message}`); }
    }
  }

  result.harness_cleanup = {passed: cleanupErrors.length === 0, errors: cleanupErrors};
  const currentCases = result.cases.filter(item => item.metrics);
  const baselineById = new Map((baseline.cases || []).map(item => [item.case_id, item]));
  result.cases = result.cases.map(item => ({...item, before: item.before || baselineById.get(item.case_id) || null}));
  const aggregateMetrics = currentCases.length ? aggregateCurrent(currentCases) : {};
  result.performance = evaluatePerformanceBudget(currentCases);
  const frameworkValidCases = currentCases.filter(item => item.metrics.framework_validation.numerator === item.metrics.framework_validation.denominator).length;
  const observedProviders = [...new Set(currentCases.map(item => item.provenance?.provider).filter(Boolean))];
  const observedModels = [...new Set(currentCases.map(item => item.provenance?.model).filter(Boolean))];
  if (currentCases.length === entries.length) {
    const sourceHash = hash(entries.map(item => item.id));
    const batchConfig = currentCases[0]?.provenance?.batch_config || CR8_BATCH_PROFILE;
    const corpusProvenance = buildCorpusRunProvenance({
      mode: options.mode,
      providerSelection: result.provider_selection,
      observedProviders,
      observedModels,
      applicationCommit: result.candidate_identity.git_commit_sha,
      namespace,
      sourceHash,
      batchConfig,
    });
    const corpusResult = {
      schema_version: "prd-corpus-e2e-v2",
      captured_at: result.captured_at,
      application_commit: result.candidate_identity.git_commit_sha || "unknown",
      provider: corpusProvenance.provider,
      model: corpusProvenance.model,
      provider_timeout_seconds: 30,
      retry_config: corpusProvenance.retry_config,
      batch_config: corpusProvenance.batch_config,
      source_revision: "multi-case",
      source_hash: sourceHash,
      dfd_revision: "per-case",
      dfd_semantic_hash: "per-case",
      run_id: namespace,
      provenance: {
        ...corpusProvenance,
        endpoint_hostname: result.provider_selection?.endpoint_hostname || null,
      },
      cases: currentCases.map(item => ({
        case_id: item.case_id,
        project_id: item.project_id,
        completeness: item.completeness,
        run_status: item.run_status,
        signoff_ready: item.signoff_ready,
        metrics: item.metrics,
        provenance: item.provenance,
        provider_metadata: item.provenance.provider_metadata,
      })),
      aggregate: {cases: currentCases.length, metrics: aggregateMetrics},
    };
    result.corpus_result_hash = stableHash(corpusResult);
    const corpusPath = path.join(artifactDir, "prd_corpus_e2e_v2.json");
    const evaluationPath = path.join(artifactDir, "prd_corpus_evaluation.json");
    fs.writeFileSync(corpusPath, JSON.stringify(corpusResult, null, 2) + "\n");
    result.corpus_result_path = corpusPath;
    result.corpus_evaluation_path = evaluationPath;
    if (entries.length === manifest.cases.length) {
      const evaluationRun = spawnSync(python, ["-m", "backend.services.prd_corpus_evaluator", "--results", corpusPath, "--manifest", MANIFEST_PATH, "--contract", CONTRACT_PATH, "--output", evaluationPath, "--no-fail"], {cwd: REPO, encoding: "utf8"});
      result.corpus_evaluation_command_exit = evaluationRun.status;
      result.corpus_evaluation_stdout = String(evaluationRun.stdout || "").slice(-4000);
      result.corpus_evaluation_stderr = String(evaluationRun.stderr || "").slice(-4000);
      if (fs.existsSync(evaluationPath)) result.corpus_evaluation = readJson(evaluationPath);
    } else {
      result.corpus_evaluation_status = "skipped_subset";
    }
  }
  const liveProviderFailures = [];
  if (options.mode !== "live") liveProviderFailures.push("Run was performed with the contract fixture, not a live provider.");
  if (currentCases.length !== entries.length || entries.length !== manifest.cases.length) liveProviderFailures.push("The full corpus did not complete.");
  if (currentCases.some(item => !item.provenance?.provider || !item.provenance?.model)) liveProviderFailures.push("Provider or observed model provenance is missing from at least one case.");
  if (currentCases.some(item => /cr8-contract-fixture/i.test(`${item.provenance?.provider} ${item.provenance?.model}`))) liveProviderFailures.push("Fixture provider provenance is present in at least one case.");
  if (options.mode === "live" && currentCases.some(item => normalize(item.provenance?.provider) !== normalize(options.providerName || "sumopod"))) liveProviderFailures.push("At least one case did not report the requested live provider.");
  if (options.mode === "live" && currentCases.some(item => normalize(item.provenance?.model) !== normalize(options.model || "deepseek-v4-flash"))) liveProviderFailures.push("At least one case did not report the requested live model.");
  if (currentCases.some(item => item.provenance?.provider_fallback_used)) liveProviderFailures.push("A fallback/baseline result was used.");
  if (currentCases.some(item => item.metrics.framework_validation.numerator !== item.metrics.framework_validation.denominator)) liveProviderFailures.push("One or more STRIDE/LINDDUN assessments are not validated.");
  if (!result.corpus_evaluation?.gate?.passed) liveProviderFailures.push("The fail-closed PRD corpus metric contract did not pass.");
  result.live_provider_qualification = {
    status: liveProviderFailures.length ? (options.mode === "live" ? "failed" : "not_run") : "qualified",
    provider_names: [...new Set(currentCases.map(item => item.provenance?.provider).filter(Boolean))],
    model_names: [...new Set(currentCases.map(item => item.provenance?.model).filter(Boolean))],
    case_count: currentCases.length,
    reasons: liveProviderFailures,
  };
  const contractMetricNames = contract.metrics.map(item => item.name);
  const fixtureGateChecks = {
    all_cases_completed: {passed: currentCases.length === entries.length && result.diagnostics.case_errors.length === 0, reason: `${currentCases.length}/${entries.length} cases completed without journey errors.`},
    framework_validated: {passed: frameworkValidCases === entries.length, reason: `${frameworkValidCases}/${entries.length} cases have complete STRIDE and LINDDUN stages.`},
    metric_evaluator_ready: {passed: currentCases.every(item => contractMetricNames.every(name => Object.hasOwn(item.metrics, name)) && Object.hasOwn(item.metrics, "finding_flow_binding")), reason: "Every successful case contains every contract metric and the separate finding-flow-binding diagnostic; unmeasured metrics remain fail-closed."},
    corpus_metric_gate: {passed: entries.length !== manifest.cases.length || result.corpus_evaluation?.gate?.passed === true, reason: entries.length !== manifest.cases.length ? "Skipped for a case subset; full-corpus command is required for release." : (result.corpus_evaluation?.gate?.passed ? "CR0 metric contract passed." : "CR0 metric contract is fail-closed until every threshold is measured and satisfied.")},
  };
  result.aggregate = {cases: currentCases.length, metrics: aggregateMetrics, fixture_gate: fixtureGateChecks};
  result.fixture_quality_gate = {passed: Object.values(fixtureGateChecks).every(item => item.passed), checks: fixtureGateChecks};
  const axeViolations = result.browser.serious_or_critical_violations;
  const accessibilityMeasured = Number.isInteger(axeViolations) && result.browser.matrix.length > 0;
  result.release_gate = {
    verdict: "NOT_READY",
    checks: {
      fixture_quality: {passed: result.fixture_quality_gate.passed, reason: result.fixture_quality_gate.passed ? "Local contract qualification passed." : "Local contract qualification failed."},
      performance_budget: result.performance.gate,
      browser_journey: {passed: result.browser.errors.length === 0 && result.browser.matrix.length === entries.length ? true : result.browser.errors.length === 0 && result.browser.matrix.length > 0, reason: `${result.browser.matrix.length} viewport-route samples, ${result.browser.errors.length} browser errors.`},
      accessibility: {
        passed: accessibilityMeasured && axeViolations === 0,
        reason: accessibilityMeasured
          ? `${axeViolations} serious/critical axe violations.`
          : "Accessibility was not measured because no successful corpus case was available.",
      },
      unexpected_runtime_errors: {passed: result.diagnostics.page_errors.length === 0 && result.diagnostics.failed_requests.length === 0 && result.diagnostics.http_errors.length === 0, reason: `${result.diagnostics.page_errors.length} page errors, ${result.diagnostics.failed_requests.length} failed API requests, ${result.diagnostics.http_errors.length} HTTP API errors.`},
      harness_cleanup: {passed: result.harness_cleanup.passed, reason: cleanupErrors.length ? cleanupErrors.join(" ") : "Temporary provider settings and server resources were shut down and cleaned successfully."},
      live_provider: {passed: result.live_provider_qualification.status === "qualified", reason: result.live_provider_qualification.reasons.join(" ") || "Live provider passed the measured full-corpus checks."},
      reviewer_sampling: {passed: false, reason: "AppSec and product/engineering reviewer task logs are pending."},
    },
  };
  result.release_gate.verdict = Object.values(result.release_gate.checks).every(item => item.passed) ? "PASS" : "NOT_READY";
  result.provider_calls = provider?.calls || [];
  result.server_logs = serverLogs.slice(-40);
  const candidateAtCompletion = captureCandidateIdentity(REPO);
  result.candidate_identity = {
    ...result.candidate_identity,
    source_worktree_clean: result.candidate_identity.source_worktree_clean
      && candidateAtCompletion.source_worktree_clean
      && result.candidate_identity.source_change_count === 0
      && candidateAtCompletion.source_change_count === 0,
    source_change_count: Math.max(result.candidate_identity.source_change_count || 0, candidateAtCompletion.source_change_count || 0),
    capture_stable: result.candidate_identity.git_commit_sha === candidateAtCompletion.git_commit_sha
      && result.candidate_identity.git_tree_sha === candidateAtCompletion.git_tree_sha
      && result.candidate_identity.source_worktree_clean
      && candidateAtCompletion.source_worktree_clean,
  };
  result.artifact_hash = stableHash(result);
  const outputPath = path.resolve(options.output || path.join(artifactDir, "cr8_qualification.json"));
  const markdownPath = path.resolve(options.markdown || path.join(artifactDir, "cr8_qualification.md"));
  fs.mkdirSync(path.dirname(outputPath), {recursive: true});
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n");
  fs.writeFileSync(markdownPath, renderQualificationMarkdown(result));
  console.log(JSON.stringify({
    verdict: result.release_gate.verdict,
    mode: result.mode,
    cases: result.cases.length,
    successful_cases: currentCases.length,
    fixture_quality: result.fixture_quality_gate.passed,
    browser_samples: result.browser.matrix.length,
    axe_serious_or_critical: result.browser.serious_or_critical_violations || 0,
    page_errors: result.diagnostics.page_errors.length,
    failed_requests: result.diagnostics.failed_requests.length,
    http_errors: result.diagnostics.http_errors.length,
    output: outputPath,
    markdown: markdownPath,
  }, null, 2));
if ((!result.fixture_quality_gate.passed || result.browser.errors.length || !result.release_gate.checks.accessibility.passed || !result.harness_cleanup.passed) && !options.noFail) process.exitCode = 1;
}

if (require.main === module) main().catch(error => { console.error(`CR8 qualification error: ${error.stack || error.message}`); process.exitCode = 1; });

module.exports = {
  buildCaseResult,
  configureLiveProvider,
  configureFixtureProvider,
  captureCandidateIdentity,
  createProjectFromBrowser,
  expectedEntityMetric,
  expectedForCase,
  metric,
  normalize,
  observeProviderResponseModels,
  ANALYSIS_RESPONSE_TIMEOUT_MS,
  CR8_PROVIDER_MAX_RETRIES,
  threatBatchConfiguration,
  buildCorpusRunProvenance,
  evaluatePerformanceBudget,
  waitForAnalysisResponse,
  isolatedServerEnvironment,
  removeDirectoryWithRetry,
  startContractProvider,
  terminateChild,
  threatPayload,
};
