"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {execFileSync, spawn} = require("node:child_process");
const test = require("node:test");

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "prd_corpus", "manifest.json"), "utf8"));
const metricContract = JSON.parse(fs.readFileSync(path.join(__dirname, "prd_corpus", "metric_contract.json"), "utf8"));
const {evaluate, qualificationHash, stable} = require("../tools/cr8_release_gate.js");
const {ANALYSIS_RESPONSE_TIMEOUT_MS, CR8_PROVIDER_MAX_RETRIES, buildCaseResult, buildCorpusRunProvenance, captureCandidateIdentity, evaluatePerformanceBudget, isolatedServerEnvironment, observeProviderResponseModels, removeDirectoryWithRetry, terminateChild, threatBatchConfiguration, threatPayload, waitForAnalysisResponse} = require("../tools/cr8_release_qualification.js");

const HMAC_KEY = "test-only-release-evidence-key-with-32-plus-characters";

function cleanCandidate() {
  const gitCommitSha = "a".repeat(40);
  const gitTreeSha = "b".repeat(40);
  return {
    git_commit_sha: gitCommitSha,
    git_tree_sha: gitTreeSha,
    source_identity_sha256: crypto.createHash("sha256").update(`${gitCommitSha}:${gitTreeSha}`).digest("hex"),
    source_worktree_clean: true,
    source_change_count: 0,
    capture_stable: true,
    declared_application_commit: "a".repeat(40),
  };
}

function canonicalHash(value) {
  return crypto.createHash("sha256").update(JSON.stringify(stable(value))).digest("hex");
}

function makeCase(entry) {
  const incomplete = entry.completeness === "incomplete";
  return {
    case_id: entry.id,
    completeness: entry.completeness,
    run_status: "completed",
    errors: [],
    signoff_ready: !incomplete,
    metrics: {framework_validation: {numerator: 2, denominator: 2}},
    provenance: {application_commit: "a".repeat(40), provider: "sumopod", model: "deepseek-v4-flash", provider_fallback_used: false},
    performance: {
      core_analysis_ms: 1000,
      stages_seconds: {stride: 2, linddun: 3},
    },
    observed: {
      dfd_flows: 3,
      dfd_validation: {
        valid: true,
        readiness: incomplete ? "not_ready" : "ready",
        blocking_reasons: [],
        open_questions: [],
        deferred_interactions: [],
      },
      framework_assessments: Object.fromEntries(["stride", "linddun"].map(framework => [framework, {
        assessment_status: "complete",
        response_model: "deepseek-v4-flash",
        response_model_recorded: true,
        coverage: {complete: true},
      }])),
    },
  };
}

function makeQualification() {
  const candidate = cleanCandidate();
  const resultHash = "d".repeat(64);
  const evaluationMetrics = {sample_ratio: 1.0};
  const contractHash = canonicalHash(metricContract);
  const manifestHash = canonicalHash(manifest);
  const evaluationVersion = metricContract.evaluator_version;
  const evaluationFingerprint = canonicalHash({
    evaluator_version: evaluationVersion,
    contract_hash: contractHash,
    manifest_hash: manifestHash,
    results_hash: resultHash,
    metrics: evaluationMetrics,
  });
  const cases = manifest.cases.map(makeCase);
  const qualification = {
    schema_version: "cr8-qualification-v1",
    mode: "live",
    namespace: "run-synthetic-contract",
    corpus_version: manifest.version,
    candidate_identity: candidate,
    provider_selection: {
      provider_name: "sumopod",
      model: "deepseek-v4-flash",
      endpoint_hostname: "ai.sumopod.com",
      endpoint_https: true,
      credential_available: true,
    },
    cases,
    corpus_result_hash: resultHash,
    corpus_evaluation: {
      schema_version: "prd-corpus-evaluation-v1",
      evaluator_version: evaluationVersion,
      corpus_revision: manifest.version,
      evaluation_fingerprint: evaluationFingerprint,
      source_artifacts: {contract_hash: contractHash, manifest_hash: manifestHash, results_hash: resultHash},
      metrics: evaluationMetrics,
      provenance: {application_commit: candidate.git_commit_sha},
      gate: {
        passed: true,
        checks: Object.fromEntries(metricContract.metrics.map(item => [item.name, {passed: true}])),
      },
    },
    live_provider_qualification: {
      status: "qualified",
      case_count: manifest.cases.length,
      provider_names: ["sumopod"],
      model_names: ["deepseek-v4-flash"],
    },
    performance: evaluatePerformanceBudget(cases),
    browser: {errors: [], matrix: Array.from({length: 24}, (_, index) => ({sample: index})), serious_or_critical_violations: 0},
    diagnostics: {case_errors: [], page_errors: [], failed_requests: [], http_errors: []},
  };
  qualification.artifact_hash = qualificationHash(qualification);
  return qualification;
}

test("response-model provenance requires a model echoed by provider responses", () => {
  const observed = observeProviderResponseModels({generation_manifest: {batches: [
    {status: "valid", response_metadata: {model: "deepseek-v4-flash", response_model: "deepseek-v4-flash", model_source: "provider_response"}},
    {status: "valid", attempts: [{response_metadata: {model: "deepseek-v4-flash", response_model: "deepseek-v4-flash", model_source: "provider_response"}}]},
    {status: "timed_out", response_metadata: {model: "deepseek-v4-flash", response_model: null, model_source: "configured_fallback"}},
  ]}});

  assert.deepEqual(observed, {
    model: "deepseek-v4-flash",
    models: ["deepseek-v4-flash"],
    recorded: true,
    response_count: 2,
    valid_batch_count: 2,
    valid_batches_missing_model: 0,
  });

  const fallbackOnly = observeProviderResponseModels({generation_manifest: {batches: [
    {status: "valid", response_metadata: {model: "deepseek-v4-flash", response_model: null, model_source: "configured_fallback"}},
  ]}});
  assert.equal(fallbackOnly.model, null);
  assert.equal(fallbackOnly.recorded, false);

  const mixed = observeProviderResponseModels({generation_manifest: {batches: [
    {status: "valid", response_metadata: {response_model: "deepseek-v4-flash", model_source: "provider_response"}},
    {status: "valid", response_metadata: {response_model: "other-model", model_source: "provider_response"}},
  ]}});
  assert.equal(mixed.model, null);
  assert.equal(mixed.recorded, false);
});

test("contract fixture returns a coverage row for every framework category per flow", () => {
  const flows = [
    {id: "flow-fixture-1", name: "Fixture interaction one", source_id: "entity-source", target_id: "process-target"},
    {id: "flow-fixture-2", name: "Fixture interaction two", source_id: "process-target", target_id: "store-target"},
  ];
  const prompt = `CR8_CASE_ID: ${manifest.cases[0].id}\nCANONICAL DFD INTERACTION batch-1:\n${JSON.stringify({revision: 1, semantic_hash: "fixture-hash", flows})}`;
  const stride = threatPayload(manifest, prompt, "STRIDE");
  const linddun = threatPayload(manifest, prompt, "LINDDUN");

  assert.equal(stride.coverage.length, 12);
  assert.equal(linddun.coverage.length, 14);
  for (const result of [stride, linddun]) {
    assert.equal(new Set(result.coverage.map(item => `${item.element_ref}:${item.category}`)).size, result.coverage.length);
    for (const flow of flows) {
      const flowRows = result.coverage.filter(item => item.element_ref === flow.id);
      assert.equal(flowRows.length, result.coverage.length / flows.length);
      assert.ok(flowRows.every(item => item.mapping_refs.includes(flow.id)));
    }
  }
  assert.equal(stride.coverage.find(item => item.category === "Tampering").status, "candidate_identified");
  assert.equal(stride.coverage.filter(item => item.status === "reviewed_no_candidate").length, 10);
  assert.equal(linddun.coverage.find(item => item.category === "Data Disclosure").status, "candidate_identified");
  assert.equal(linddun.coverage.filter(item => item.status === "reviewed_no_candidate").length, 12);
});

test("live DFD/control/test precision metrics fail closed without independent labels", () => {
  const dfd = {
    id: "dfd-1",
    revision: 1,
    semantic_hash: "a".repeat(64),
    nodes: [
      {id: "customer", name: "Customer"},
      {id: "api", name: "Registration API"},
    ],
    data_objects: [{id: "profile", name: "Profile"}],
    flows: [{id: "flow-1", source_id: "customer", target_id: "api", data_object_ids: ["profile"]}],
    zones: [{id: "zone-app"}],
    boundaries: [],
    questions: [],
    deferred_interactions: [],
    semantic_quality: {counts: {
      nodes: 2, flows: 1, zones: 1,
      duplicate_nodes: 0, duplicate_flows: 0,
      valid_endpoints: 1, cross_zone_flows: 0, valid_crossing_flows: 0,
      isolated_nodes: 0, isolated_zones: 0,
    }},
  };
  const report = {
    dfd_model: dfd,
    dfd_validation: {valid: true, readiness: {status: "ready", topology_coverage: {
      connected_nodes: 2, total_nodes: 2, active_zones: 1, connected_zones: 0,
    }}},
    analysis_run: {run_id: "run-1", status: "completed"},
    ai_status: {
      stride: {assessment_status: "complete"},
      linddun: {assessment_status: "complete"},
    },
    analysis_coverage_summary: {
      STRIDE: {primary_interaction_count: 1, scoped_total: 2, assessed: 1, not_applicable: 0, deferred: 1, failed: 0, unprocessed: 0, complete: false},
      LINDDUN: {primary_interaction_count: 1, scoped_total: 1, assessed: 1, not_applicable: 0, deferred: 0, failed: 0, unprocessed: 0, complete: true},
    },
    analysis_coverage_manifest: {
      STRIDE: {summary: {complete: false}, entries: [
        {assessment_scope: "primary_interaction", element_ref: "flow-1", category: "Spoofing", status: "deferred", reason: "Authentication evidence is absent."},
        {assessment_scope: "dfd_context", element_ref: "api", category: "Repudiation", status: "context_only", reason: "Context only."},
      ]},
      LINDDUN: {summary: {complete: true}, entries: [
        {assessment_scope: "primary_interaction", element_ref: "flow-1", category: "Linking", status: "assessed", reason: "Reviewed."},
      ]},
    },
    threats: [{threat_id: "threat-1", primary_interaction_ref: "flow-1"}],
    controls: [{control_id: "control-1", threat_ids: ["threat-1"], mapping_status: "mapped"}],
    test_scenarios: [{test_id: "test-1", applicability_status: "applicable", execution_status: "Not Run", quality_status: "executable"}],
  };
  const entry = {
    id: "case-1",
    file: "case.md",
    completeness: "complete",
    expected: {
      must_detect_actors: ["Customer"],
      must_detect_components: ["Registration API"],
      must_detect_external_systems: [],
      must_detect_data: ["Profile"],
    },
  };
  const project = {project_id: "project-1", name: "Project", artifact_sources: []};

  const live = buildCaseResult(entry, project, report, null, "live");
  for (const name of ["dfd_precision", "control_mapping_precision", "control_mapping_recall", "test_executability"]) {
    assert.equal(live.metrics[name].eligible_for_gate, false, `${name} must require independent labels`);
    assert.equal(live.metrics[name].denominator, 0, `${name} must be not measured`);
  }
  assert.deepEqual(live.metrics.dfd_label_hit_ratio, {
    numerator: 3,
    denominator: 3,
    reason: "Diagnostic only: required entity/data labels matched divided by all canonical nodes/data objects; unlabeled candidates are not false positives.",
    eligible_for_gate: false,
  });
  assert.equal(live.metrics.duplicate_rate.numerator, 0);
  assert.equal(live.metrics.duplicate_rate.denominator, 3);
  assert.equal(live.metrics.topology_validity.numerator, 4);
  assert.equal(live.metrics.topology_validity.denominator, 4);
  assert.deepEqual(live.metrics.framework_validation, {
    numerator: 1,
    denominator: 2,
    reason: "Both stages need a complete or legitimate valid-empty result and complete current coverage summaries plus manifests; generation completion alone is insufficient.",
  });
  assert.deepEqual(live.observed.framework_assessments.stride.coverage.observed_status_counts, {deferred: 1});
  assert.deepEqual(live.observed.framework_assessments.stride.coverage.unresolved_examples, [{
    element_ref: "flow-1",
    category: "Spoofing",
    status: "deferred",
    reason: "Authentication evidence is absent.",
  }]);
  assert.equal(live.observed.framework_assessments.stride.coverage.complete, false);
  assert.equal(live.observed.framework_assessments.linddun.coverage.complete, true);

  const fixture = buildCaseResult(entry, project, report, null, "fixture");
  assert.equal(fixture.metrics.dfd_precision.denominator, 3);
  assert.match(fixture.metrics.dfd_precision.reason, /Fixture-only/);
  assert.match(fixture.metrics.control_mapping_precision.reason, /Fixture-only/);
  assert.match(fixture.metrics.test_executability.reason, /Fixture-only/);
});

function makeEvidence(qualification, mutate = () => {}) {
  const evidence = {
    schema_version: "cr8-review-evidence-v1",
    run_id: qualification.namespace,
    qualification_artifact_hash: qualification.artifact_hash,
    decision: "approved",
    approvals: [
      {role: "appsec", decision: "approved", subject: "appsec-reviewer-1", recorded_at: new Date().toISOString()},
      {role: "product_engineering", decision: "approved", subject: "engineering-reviewer-2", recorded_at: new Date().toISOString()},
    ],
    finding_quality_evidence: {
      schema_version: "cr8-blind-finding-quality-v1",
      run_id: qualification.namespace,
      qualification_artifact_hash: qualification.artifact_hash,
      corpus_result_hash: qualification.corpus_result_hash,
      blind_review: true,
      adjudication_complete: true,
      label_set_sha256: "e".repeat(64),
      reviewers: [
        {role: "appsec", subject: "appsec-label-reviewer-1", recorded_at: new Date().toISOString()},
        {role: "appsec", subject: "appsec-label-reviewer-2", recorded_at: new Date().toISOString()},
      ],
      case_scores: manifest.cases.map(entry => ({
        case_id: entry.id,
        supported_findings: 2,
        unsupported_findings: 0,
        generated_findings: 2,
        expected_findings: 2,
        missed_findings: 0,
        surfaced_deferred: 2,
        expected_deferred: 2,
      })),
    },
  };
  mutate(evidence);
  const unsigned = {...evidence};
  delete unsigned.signature;
  evidence.signature = crypto.createHmac("sha256", HMAC_KEY).update(JSON.stringify(stable(unsigned))).digest("hex");
  return evidence;
}

function decision(qualification = makeQualification(), evidence = null) {
  return evaluate(qualification, evidence || makeEvidence(qualification), HMAC_KEY);
}

test("a fully evidenced synthetic contract can pass the release-gate contract", () => {
  const qualification = makeQualification();
  const result = decision(qualification);

  assert.equal(result.verdict, "PASS", JSON.stringify(result.blockers));
  assert.equal(result.checks.candidate_identity.passed, true);
  assert.equal(result.checks.full_corpus.passed, true);
  assert.equal(result.checks.dfd_readiness_integrity.passed, true);
  assert.equal(result.checks.provider_provenance.passed, true);
  assert.equal(result.checks.blind_finding_quality.passed, true);
});

test("blind finding quality fails closed when evidence is missing or bound to another run", () => {
  const qualification = makeQualification();
  const missing = makeEvidence(qualification, evidence => { delete evidence.finding_quality_evidence; });
  assert.equal(decision(qualification, missing).checks.blind_finding_quality.passed, false);

  const mismatched = makeEvidence(qualification, evidence => {
    evidence.finding_quality_evidence.run_id = "another-run";
  });
  assert.equal(decision(qualification, mismatched).checks.blind_finding_quality.passed, false);
});

test("blind finding scores must be complete, internally consistent, and above thresholds", () => {
  const qualification = makeQualification();
  const incomplete = makeEvidence(qualification, evidence => {
    evidence.finding_quality_evidence.case_scores.pop();
  });
  assert.equal(decision(qualification, incomplete).checks.blind_finding_quality.passed, false);

  const lowPrecision = makeEvidence(qualification, evidence => {
    const score = evidence.finding_quality_evidence.case_scores[0];
    score.unsupported_findings = 1;
    score.generated_findings = 3;
  });
  assert.equal(decision(qualification, lowPrecision).checks.blind_finding_quality.passed, false);
});

test("metric evaluator must report every contract metric before the gate can bind it", () => {
  const qualification = makeQualification();
  delete qualification.corpus_evaluation.gate.checks.ingestion_coverage;
  qualification.artifact_hash = qualificationHash(qualification);
  assert.equal(decision(qualification).checks.metric_contract.passed, false);
});

test("blind labels may satisfy evaluator metrics that are explicitly not measured", () => {
  const qualification = makeQualification();
  qualification.corpus_evaluation.gate.checks.finding_precision.passed = false;
  qualification.corpus_evaluation.gate.checks.finding_recall.passed = false;
  qualification.corpus_evaluation.gate.checks.deferred_recall.passed = false;
  qualification.corpus_evaluation.gate.passed = false;
  qualification.artifact_hash = qualificationHash(qualification);
  const result = decision(qualification);
  assert.equal(result.checks.blind_finding_quality.passed, true);
  assert.equal(result.checks.metric_contract.passed, true);
});

test("candidate changes and declared-commit mismatch fail closed", () => {
  const dirty = makeQualification();
  dirty.candidate_identity.source_worktree_clean = false;
  dirty.candidate_identity.source_change_count = 1;
  dirty.artifact_hash = qualificationHash(dirty);
  assert.equal(decision(dirty).checks.candidate_identity.passed, false);

  const mismatch = makeQualification();
  mismatch.candidate_identity.declared_application_commit = "d".repeat(40);
  mismatch.artifact_hash = qualificationHash(mismatch);
  assert.equal(decision(mismatch).checks.candidate_identity.passed, false);
});

test("duplicate or missing corpus cases cannot satisfy the manifest gate", () => {
  const qualification = makeQualification();
  qualification.cases[1].case_id = qualification.cases[0].case_id;
  qualification.artifact_hash = qualificationHash(qualification);
  assert.equal(decision(qualification).checks.full_corpus.passed, false);
});

test("DFD readiness cannot claim ready with blockers or unresolved questions", () => {
  const blockedReady = makeQualification();
  blockedReady.cases[0].observed.dfd_validation.blocking_reasons.push("unresolved architecture issue");
  blockedReady.artifact_hash = qualificationHash(blockedReady);
  assert.equal(decision(blockedReady).checks.dfd_readiness_integrity.passed, false);

  const incompleteReady = makeQualification();
  const incomplete = incompleteReady.cases.find(item => item.completeness === "incomplete");
  incomplete.observed.dfd_validation.readiness = "ready";
  incomplete.signoff_ready = true;
  incomplete.observed.dfd_validation.open_questions.push({id: "missing-owner-decision", status: "open"});
  incomplete.artifact_hash = qualificationHash(incompleteReady);
  assert.equal(decision(incompleteReady).checks.dfd_readiness_integrity.passed, false);
});

test("provider selection must match every observed case and cannot use fallback", () => {
  const wrongModel = makeQualification();
  wrongModel.cases[0].provenance.model = "other-model";
  wrongModel.artifact_hash = qualificationHash(wrongModel);
  assert.equal(decision(wrongModel).checks.provider_provenance.passed, false);

  const fallback = makeQualification();
  fallback.cases[0].provenance.provider_fallback_used = true;
  fallback.artifact_hash = qualificationHash(fallback);
  assert.equal(decision(fallback).checks.no_fallback.passed, false);
});

test("provider provenance requires model metadata for both framework responses", () => {
  const missingModelMetadata = makeQualification();
  missingModelMetadata.cases[0].observed.framework_assessments.linddun.response_model_recorded = false;
  missingModelMetadata.cases[0].observed.framework_assessments.linddun.response_model = null;
  missingModelMetadata.artifact_hash = qualificationHash(missingModelMetadata);
  assert.equal(decision(missingModelMetadata).checks.provider_provenance.passed, false);
});

test("release gate recomputes performance from complete per-case samples", () => {
  const staleFastEmpty = makeQualification();
  for (const item of staleFastEmpty.cases) {
    item.performance.core_analysis_ms = 229;
    item.performance.stages_seconds = {stride: 0.003, linddun: 0.001};
    item.observed.dfd_flows = 0;
    item.metrics.framework_validation = {numerator: 0, denominator: 2};
    item.provenance.model = null;
    item.provenance.provider_fallback_used = true;
  }
  staleFastEmpty.performance = {
    sample_count: manifest.cases.length,
    requested_sample_count: manifest.cases.length,
    percentile: 0.95,
    p95_seconds: {core_analysis_seconds: 0.229, stride_seconds: 0.003, linddun_seconds: 0.001},
    budgets_seconds: {core_analysis_seconds: 180, stride_seconds: 60, linddun_seconds: 60},
    failed_or_censored_samples: [],
    gate: {passed: true},
  };
  staleFastEmpty.artifact_hash = qualificationHash(staleFastEmpty);
  const emptyResult = decision(staleFastEmpty);
  assert.equal(emptyResult.checks.performance.passed, false);
  assert.match(emptyResult.checks.performance.reason, /0\/9 complete per-case/);

  const forgedP95 = makeQualification();
  forgedP95.performance.p95_seconds.stride_seconds = 0.001;
  forgedP95.artifact_hash = qualificationHash(forgedP95);
  const forgedResult = decision(forgedP95);
  assert.equal(forgedResult.checks.performance.passed, false);
  assert.match(forgedResult.checks.performance.reason, /does not match recomputed/);
});

test("review evidence requires valid signature, fresh approvals, and distinct subjects", () => {
  const qualification = makeQualification();
  const badSignature = makeEvidence(qualification);
  badSignature.signature = "0".repeat(64);
  assert.equal(decision(qualification, badSignature).checks.reviewer_sampling.passed, false);

  const sameSubject = makeEvidence(qualification, evidence => {
    evidence.approvals[1].subject = evidence.approvals[0].subject;
  });
  assert.equal(decision(qualification, sameSubject).checks.reviewer_sampling.passed, false);

  const expired = makeEvidence(qualification, evidence => {
    evidence.approvals[0].recorded_at = new Date(Date.now() - 31 * 86400000).toISOString();
  });
  assert.equal(decision(qualification, expired).checks.reviewer_sampling.passed, false);
});

test("qualification artifact tampering fails its integrity check", () => {
  const qualification = makeQualification();
  const evidence = makeEvidence(qualification);
  qualification.cases[0].run_status = "failed";
  assert.equal(decision(qualification, evidence).checks.qualification_integrity.passed, false);
});

test("runner candidate identity ignores generated artifacts but detects source edits", () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "cr8-candidate-fixture-"));
  try {
    execFileSync("git", ["init", "-q"], {cwd: repo});
    execFileSync("git", ["config", "user.email", "cr8-test@example.invalid"], {cwd: repo});
    execFileSync("git", ["config", "user.name", "CR8 test"], {cwd: repo});
    fs.writeFileSync(path.join(repo, "app.py"), "application source\n");
    execFileSync("git", ["add", "app.py"], {cwd: repo});
    execFileSync("git", ["commit", "-q", "-m", "candidate"], {cwd: repo});

    assert.equal(captureCandidateIdentity(repo).source_worktree_clean, true);
    fs.mkdirSync(path.join(repo, "artifacts", "run-1"), {recursive: true});
    fs.writeFileSync(path.join(repo, "artifacts", "run-1", "report.json"), "{}\n");
    assert.equal(captureCandidateIdentity(repo).source_worktree_clean, true);
    fs.writeFileSync(path.join(repo, "new-source.py"), "uncommitted source\n");
    const identity = captureCandidateIdentity(repo);
    assert.equal(identity.source_worktree_clean, false);
    assert.equal(identity.source_change_count, 1);
  } finally {
    fs.rmSync(repo, {recursive: true, force: true});
  }
});

test("qualification waits for the application server to exit before removing isolated data", async () => {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {stdio: "ignore"});
  await terminateChild(child, 2000);
  assert.ok(child.exitCode !== null || child.signalCode !== null, "child process must be reaped before cleanup continues");

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cr8-cleanup-regression-"));
  fs.mkdirSync(path.join(tempRoot, "data", "reports"), {recursive: true});
  fs.writeFileSync(path.join(tempRoot, "data", "reports", "late-writer.lock"), "test-only");
  await removeDirectoryWithRetry(tempRoot);
  assert.equal(fs.existsSync(tempRoot), false);
});

test("qualification directs audit records into its isolated DATA_DIR", () => {
  const dataDir = path.join(os.tmpdir(), "cr8-isolated-data");
  const environment = isolatedServerEnvironment({AUDIT_LOG_PATH: "/private/operator/audit.log", LLM_TIMEOUT_SECONDS: "45"}, dataDir, 8123);
  assert.equal(environment.DATA_DIR, dataDir);
  assert.equal(environment.AUDIT_LOG_PATH, path.join(dataDir, "audit.log"));
  assert.notEqual(environment.AUDIT_LOG_PATH, "/private/operator/audit.log");
  assert.equal(environment.PORT, "8123");
  assert.equal(environment.LLM_TIMEOUT_SECONDS, "45");
  assert.equal(environment.LLM_MAX_RETRIES, "1");
});

test("threat batch provenance records the actual generation manifest profile", () => {
  const profile = threatBatchConfiguration({stride: {response_metadata: {generation_manifest: {
    max_batches: 24,
    flows_per_batch: 2,
    concurrency: 1,
    max_batch_retries: 2,
    stage_budget_seconds: 120,
    batch_budget_seconds: 40,
    output_budget_tokens: 3072,
  }}}});
  assert.deepEqual(profile, {
    max_batches: 24,
    flows_per_batch: 2,
    concurrency: 1,
    max_batch_retries: 2,
    stage_budget_seconds: 120,
    batch_budget_seconds: 40,
    output_budget_tokens: 3072,
  });
});

test("corpus provenance separates selected provider config from observed model output", () => {
  const provenance = buildCorpusRunProvenance({
    mode: "live",
    providerSelection: {provider_name: "sumopod", model: "deepseek-v4-flash"},
    observedProviders: ["sumopod"],
    observedModels: [],
    applicationCommit: "abc123",
    namespace: "run-fixture",
    sourceHash: "source-hash",
    batchConfig: {max_batches: 32},
  });
  assert.equal(CR8_PROVIDER_MAX_RETRIES, 1);
  assert.equal(provenance.provider, "sumopod");
  assert.equal(provenance.model, "deepseek-v4-flash");
  assert.equal(provenance.model_source, "selected_configuration");
  assert.deepEqual(provenance.observed_models, []);
  assert.equal(provenance.retry_config.max_retries, 1);
});

test("performance budget does not treat fast fallback or empty analysis as a valid sample", () => {
  const result = evaluatePerformanceBudget([{
    case_id: "fast-fallback",
    performance: {core_analysis_ms: 207, stages_seconds: {stride: 0.003, linddun: 0.001}},
    observed: {dfd_flows: 0},
    metrics: {framework_validation: {numerator: 0, denominator: 2}},
    provenance: {provider: "sumopod", model: null, provider_fallback_used: true},
  }]);
  assert.equal(result.sample_count, 0);
  assert.equal(result.requested_sample_count, 1);
  assert.equal(result.p95_seconds.core_analysis_seconds, null);
  assert.deepEqual(result.failed_or_censored_samples, ["fast-fallback"]);
  assert.equal(result.gate.passed, false);
});

test("performance budget measures only complete, non-fallback threat analyses", () => {
  const result = evaluatePerformanceBudget([{
    case_id: "complete-analysis",
    performance: {core_analysis_ms: 10000, stages_seconds: {stride: 12, linddun: 15}},
    metrics: {framework_validation: {numerator: 2, denominator: 2}},
    run_status: "completed",
    observed: {
      dfd_flows: 4,
      framework_assessments: Object.fromEntries(["stride", "linddun"].map(name => [name, {
        assessment_status: "complete", coverage: {complete: true},
      }])),
    },
    provenance: {provider: "sumopod", model: "deepseek-v4-flash", provider_fallback_used: false},
  }]);
  assert.equal(result.sample_count, 1);
  assert.equal(result.p95_seconds.core_analysis_seconds, 10);
  assert.equal(result.gate.passed, true);
});

test("performance budget censors analyses without positive stage timing samples", () => {
  const result = evaluatePerformanceBudget([{
    case_id: "missing-stage-timing",
    performance: {core_analysis_ms: 10000, stages_seconds: {stride: 12}},
    observed: {dfd_flows: 4},
    metrics: {framework_validation: {numerator: 2, denominator: 2}},
    provenance: {provider: "sumopod", model: "deepseek-v4-flash", provider_fallback_used: false},
  }]);
  assert.equal(result.sample_count, 0);
  assert.equal(result.p95_seconds.linddun_seconds, null);
  assert.deepEqual(result.failed_or_censored_samples, ["missing-stage-timing"]);
  assert.equal(result.gate.passed, false);
});

test("analysis browser wait covers both bounded framework stages and persistence", () => {
  let captured;
  const armed = waitForAnalysisResponse({
    waitForResponse(predicate, options) {
      captured = {predicate, options};
      return "armed";
    },
  }, "project-123");
  assert.equal(armed, "armed");
  assert.equal(ANALYSIS_RESPONSE_TIMEOUT_MS, 900000);
  assert.equal(captured.options.timeout, ANALYSIS_RESPONSE_TIMEOUT_MS);
  assert.equal(captured.predicate({
    url: () => "http://127.0.0.1/api/projects/project-123/analyze",
    request: () => ({method: () => "POST"}),
  }), true);
  assert.equal(captured.predicate({
    url: () => "http://127.0.0.1/api/projects/project-123/analyze",
    request: () => ({method: () => "GET"}),
  }), false);
});

test("fixture and provider-evidence-free output cannot pass", () => {
  const qualification = makeQualification();
  qualification.mode = "fixture";
  qualification.provider_selection = null;
  qualification.live_provider_qualification.status = "not_run";
  qualification.artifact_hash = qualificationHash(qualification);
  const result = decision(qualification);
  assert.equal(result.verdict, "NOT_READY");
  assert.equal(result.checks.live_mode.passed, false);
  assert.equal(result.checks.live_provider_qualification.passed, false);
});
