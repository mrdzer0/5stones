#!/usr/bin/env node
"use strict";

/* Final, fail-closed CR8 release decision. This consumes a completed live
 * qualification plus a reviewer artifact authenticated by the trusted
 * release system. A requested live run or a fixture result cannot pass. */

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function args(argv) {
  const value = {qualification: null, reviewerEvidence: null, output: null};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--qualification") value.qualification = argv[++i];
    else if (argv[i] === "--reviewer-evidence") value.reviewerEvidence = argv[++i];
    else if (argv[i] === "--output") value.output = argv[++i];
  }
  if (!value.qualification || !value.reviewerEvidence) {
    throw new Error("Usage: node tools/cr8_release_gate.js --qualification <cr8-live.json> --reviewer-evidence <signed-review.json> [--output <release-gate.json>]");
  }
  return value;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  }
  return value;
}

function qualificationHash(qualification) {
  const unsigned = {...qualification};
  delete unsigned.artifact_hash;
  return crypto.createHash("sha256").update(JSON.stringify(stable(unsigned))).digest("hex");
}

function verifyQualificationIntegrity(qualification) {
  const supplied = String(qualification.artifact_hash || "");
  if (!/^[a-f0-9]{64}$/i.test(supplied)) return false;
  const expected = Buffer.from(qualificationHash(qualification), "hex");
  const actual = Buffer.from(supplied, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function verifyEvidence(evidence, qualification, secret) {
  const reasons = [];
  evidence = evidence && typeof evidence === "object" && !Array.isArray(evidence) ? evidence : {};
  if (!secret || secret.length < 32) reasons.push("CR8_REVIEW_EVIDENCE_HMAC_KEY is missing or shorter than 32 characters.");
  if (evidence.schema_version !== "cr8-review-evidence-v1") reasons.push("Reviewer evidence schema is unsupported.");
  if (evidence.run_id !== qualification.namespace) reasons.push("Reviewer evidence references a different qualification run.");
  if (evidence.qualification_artifact_hash !== qualification.artifact_hash) reasons.push("Reviewer evidence is not bound to this qualification artifact hash.");
  if (evidence.decision !== "approved") reasons.push("Reviewer evidence decision is not approved.");

  const approvals = Array.isArray(evidence.approvals) ? evidence.approvals : [];
  const required = ["appsec", "product_engineering"];
  const subjects = new Set();
  for (const role of required) {
    const matches = approvals.filter(item => item && String(item.role).toLowerCase() === role && item.decision === "approved");
    if (matches.length !== 1) {
      reasons.push(`Exactly one approved ${role} review is required.`);
      continue;
    }
    const approval = matches[0];
    const subject = String(approval.subject || "").trim();
    const recorded = Date.parse(approval.recorded_at || "");
    if (!subject) reasons.push(`${role} review has no verified subject.`);
    if (!Number.isFinite(recorded) || recorded > Date.now() + 300000 || Date.now() - recorded > 30 * 86400000) {
      reasons.push(`${role} review timestamp is invalid, future dated, or older than 30 days.`);
    }
    if (subject) subjects.add(subject);
  }
  if (subjects.size !== required.length) reasons.push("AppSec and product/engineering approvals must be from distinct identities.");

  const signature = String(evidence.signature || "");
  if (secret && secret.length >= 32 && /^[a-f0-9]{64}$/i.test(signature)) {
    const unsigned = {...evidence};
    delete unsigned.signature;
    const expected = crypto.createHmac("sha256", secret).update(JSON.stringify(stable(unsigned))).digest();
    const supplied = Buffer.from(signature, "hex");
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      reasons.push("Reviewer evidence HMAC signature is invalid.");
    }
  } else {
    reasons.push("Reviewer evidence HMAC signature is missing or malformed.");
  }
  return {passed: reasons.length === 0, reasons};
}

function verifyFindingQualityEvidence(evidence, qualification, manifest, contract) {
  const reasons = [];
  const quality = evidence?.finding_quality_evidence && typeof evidence.finding_quality_evidence === "object"
    ? evidence.finding_quality_evidence : {};
  if (quality.schema_version !== "cr8-blind-finding-quality-v1") reasons.push("Blind finding-label evidence schema is missing or unsupported.");
  if (quality.run_id !== qualification.namespace) reasons.push("Blind finding-label evidence references a different qualification run.");
  if (quality.qualification_artifact_hash !== qualification.artifact_hash) reasons.push("Blind finding-label evidence is not bound to this qualification artifact.");
  if (quality.corpus_result_hash !== qualification.corpus_result_hash) reasons.push("Blind finding-label evidence is not bound to this corpus result.");
  if (quality.blind_review !== true || quality.adjudication_complete !== true) reasons.push("Finding labels must be blind to model output and fully adjudicated.");
  if (!/^[a-f0-9]{64}$/i.test(String(quality.label_set_sha256 || ""))) reasons.push("Blind finding-label set hash is missing or malformed.");

  const reviewers = Array.isArray(quality.reviewers) ? quality.reviewers : [];
  const reviewerSubjects = reviewers.map(item => String(item?.subject || "").trim()).filter(Boolean);
  const uniqueReviewers = new Set(reviewerSubjects);
  const appsecReviewers = reviewers.filter(item => String(item?.role || "").toLowerCase() === "appsec");
  if (appsecReviewers.length < 2 || new Set(appsecReviewers.map(item => String(item?.subject || "").trim()).filter(Boolean)).size < 2) {
    reasons.push("Two distinct AppSec reviewers are required for finding labels.");
  }
  const now = Date.now();
  for (const reviewer of reviewers) {
    const recorded = Date.parse(reviewer?.recorded_at || "");
    if (!reviewer?.subject || !Number.isFinite(recorded) || recorded > now + 300000 || now - recorded > 30 * 86400000) {
      reasons.push("Finding-label reviewer identity or timestamp is invalid, future dated, or older than 30 days.");
      break;
    }
  }
  if (uniqueReviewers.size !== reviewerSubjects.length) reasons.push("Finding-label reviewers must have distinct identities.");

  const expectedIds = (Array.isArray(manifest?.cases) ? manifest.cases : []).map(item => String(item?.id || "")).filter(Boolean).sort();
  const scores = Array.isArray(quality.case_scores) ? quality.case_scores : [];
  const actualIds = scores.map(item => String(item?.case_id || "")).sort();
  if (!expectedIds.length || scores.length !== expectedIds.length || new Set(actualIds).size !== actualIds.length || JSON.stringify(actualIds) !== JSON.stringify(expectedIds)) {
    reasons.push("Blind finding labels must contain exactly one score for every current corpus case.");
  }
  const countFields = ["supported_findings", "unsupported_findings", "generated_findings", "expected_findings", "missed_findings", "surfaced_deferred", "expected_deferred"];
  let totals = Object.fromEntries(countFields.map(field => [field, 0]));
  for (const score of scores) {
    const validCounts = countFields.every(field => Number.isInteger(score?.[field]) && score[field] >= 0);
    if (!validCounts
      || score.supported_findings + score.unsupported_findings !== score.generated_findings
      || score.supported_findings + score.missed_findings !== score.expected_findings
      || score.surfaced_deferred > score.expected_deferred) {
      reasons.push("Per-case finding-label counts are invalid or internally inconsistent.");
      break;
    }
    for (const field of countFields) totals[field] += score[field];
  }
  const precision = totals.generated_findings ? totals.supported_findings / totals.generated_findings : null;
  const recall = totals.expected_findings ? totals.supported_findings / totals.expected_findings : null;
  const deferredRecall = totals.expected_deferred ? totals.surfaced_deferred / totals.expected_deferred : null;
  const unsupportedRate = totals.generated_findings ? totals.unsupported_findings / totals.generated_findings : null;
  const thresholds = contract?.thresholds || {};
  const metrics = {finding_precision: precision, finding_recall: recall, deferred_recall: deferredRecall, unsupported_finding_rate: unsupportedRate};
  if (precision === null || precision < thresholds.min_finding_precision) reasons.push("Blind reviewed finding precision is below threshold or has no denominator.");
  if (recall === null || recall < thresholds.min_finding_recall) reasons.push("Blind reviewed finding recall is below threshold or has no denominator.");
  if (deferredRecall === null || deferredRecall < thresholds.min_deferred_recall) reasons.push("Blind reviewed deferred recall is below threshold or has no denominator.");
  if (unsupportedRate === null || unsupportedRate > thresholds.max_unsupported_finding_rate) reasons.push("Blind reviewed unsupported-finding rate exceeds threshold or has no denominator.");
  return {
    passed: reasons.length === 0,
    reasons,
    metrics,
    label_set_sha256: quality.label_set_sha256 || null,
    reviewers: [...uniqueReviewers].sort(),
  };
}

function percentile(values, percentileValue = 0.95) {
  const sorted = values.filter(Number.isFinite).sort((left, right) => left - right);
  if (!sorted.length) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * percentileValue) - 1));
  return sorted[index];
}

function verifyPerformanceEvidence(qualification, expectedCaseCount) {
  const cases = Array.isArray(qualification.cases) ? qualification.cases : [];
  const completed = cases.filter(item => {
    const framework = item.metrics?.framework_validation || {};
    const frameworkEvidence = item.observed?.framework_assessments || {};
    const coreMs = item.performance?.core_analysis_ms;
    const strideSeconds = item.performance?.stages_seconds?.stride;
    const linddunSeconds = item.performance?.stages_seconds?.linddun;
    return [coreMs, strideSeconds, linddunSeconds].every(value => Number.isFinite(value) && value > 0)
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
  const censored = cases.filter(item => !completed.includes(item)).map(item => String(item.case_id || "unknown"));
  const p95 = {
    core_analysis_seconds: percentile(completed.map(item => Number(item.performance.core_analysis_ms) / 1000)),
    stride_seconds: percentile(completed.map(item => item.performance.stages_seconds.stride)),
    linddun_seconds: percentile(completed.map(item => item.performance.stages_seconds.linddun)),
  };
  const sampleGatePassed = cases.length === expectedCaseCount
    && expectedCaseCount > 0
    && completed.length === cases.length
    && p95.core_analysis_seconds <= 180
    && p95.stride_seconds <= 60
    && p95.linddun_seconds <= 60;

  const reported = qualification.performance || {};
  const reportedP95 = reported.p95_seconds || {};
  const percentileMatches = Object.entries(p95).every(([key, value]) => value === null
    ? reportedP95[key] === null
    : Number.isFinite(reportedP95[key]) && reportedP95[key] === value);
  const budgets = reported.budgets_seconds || {};
  const budgetContractMatches = budgets.core_analysis_seconds === 180
    && budgets.stride_seconds === 60
    && budgets.linddun_seconds === 60;
  const summaryMatches = reported.sample_count === completed.length
    && reported.requested_sample_count === cases.length
    && reported.percentile === 0.95
    && percentileMatches
    && budgetContractMatches
    && reported.gate?.passed === sampleGatePassed
    && Array.isArray(reported.failed_or_censored_samples)
    && JSON.stringify(reported.failed_or_censored_samples) === JSON.stringify(censored);

  let reason;
  if (cases.length !== expectedCaseCount || completed.length !== cases.length) {
    reason = `${completed.length}/${cases.length} complete per-case threat-analysis samples; every corpus case needs positive core/STRIDE/LINDDUN durations, DFD flows, complete framework coverage, live provider provenance, and no fallback.`;
  } else if (!sampleGatePassed) {
    reason = "Recomputed P95 exceeds one or more fixed performance budgets.";
  } else if (!summaryMatches) {
    reason = "Stored performance summary does not match recomputed per-case samples and fixed budgets.";
  } else {
    reason = "Recomputed per-case samples and stored P95 summary match all fixed performance budgets.";
  }
  return {passed: sampleGatePassed && summaryMatches, reason, completedSampleCount: completed.length, censored};
}

function evaluate(qualification, evidence, secret) {
  qualification = qualification && typeof qualification === "object" && !Array.isArray(qualification) ? qualification : {};
  const checks = {};
  const add = (name, passed, reason) => { checks[name] = {passed: Boolean(passed), reason}; };
  const cases = Array.isArray(qualification.cases) ? qualification.cases : [];
  const evaluation = qualification.corpus_evaluation;
  let manifest = null;
  let metricContract = null;
  try { manifest = readJson(path.join(__dirname, "..", "tests", "prd_corpus", "manifest.json")); } catch (_) { /* fail closed below */ }
  try { metricContract = readJson(path.join(__dirname, "..", "tests", "prd_corpus", "metric_contract.json")); } catch (_) { /* fail closed below */ }
  const manifestCases = Array.isArray(manifest?.cases) ? manifest.cases : [];
  const expectedIds = manifestCases.map(item => String(item?.id || "")).filter(Boolean).sort();
  const actualIds = cases.map(item => String(item?.case_id || "")).sort();
  const expectedCases = expectedIds.length;
  const selection = qualification.provider_selection || {};
  const selectedProvider = String(selection.provider_name || "").trim().toLowerCase();
  const selectedModel = String(selection.model || "").trim().toLowerCase();
  const validCandidateSha = value => /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(String(value || ""));
  const candidate = qualification.candidate_identity || {};
  const expectedSourceIdentity = validCandidateSha(candidate.git_commit_sha) && validCandidateSha(candidate.git_tree_sha)
    ? crypto.createHash("sha256").update(`${candidate.git_commit_sha}:${candidate.git_tree_sha}`).digest("hex")
    : null;
  const candidateIdentityValid = validCandidateSha(candidate.git_commit_sha)
    && validCandidateSha(candidate.git_tree_sha)
    && candidate.source_identity_sha256 === expectedSourceIdentity
    && candidate.source_worktree_clean === true
    && candidate.capture_stable === true
    && candidate.source_change_count === 0
    && (!candidate.declared_application_commit || candidate.declared_application_commit === candidate.git_commit_sha)
    && cases.length === expectedCases
    && cases.every(item => item?.provenance?.application_commit === candidate.git_commit_sha)
    && evaluation?.provenance?.application_commit === candidate.git_commit_sha;
  const dfdStateConsistent = cases.length === expectedCases && cases.every(item => {
    const dfd = item?.observed?.dfd_validation;
    if (!dfd || typeof dfd.readiness !== "string" || typeof item.signoff_ready !== "boolean") return false;
    const ready = dfd.readiness.toLowerCase() === "ready";
    const blockers = Array.isArray(dfd.blocking_reasons) ? dfd.blocking_reasons : [];
    const questions = Array.isArray(dfd.open_questions) ? dfd.open_questions : [];
    const unresolvedQuestions = questions.some(question => ["open", "deferred", "unresolved"].includes(String(question?.status || "open").toLowerCase()));
    const deferredInteractions = Array.isArray(dfd.deferred_interactions) ? dfd.deferred_interactions : [];
    const unresolvedInteractions = deferredInteractions.some(interaction => ["open", "deferred", "unresolved", "candidate"].includes(String(interaction?.status || "open").toLowerCase()));
    if (ready && (blockers.length || unresolvedQuestions || unresolvedInteractions)) return false;
    if (item.signoff_ready && (!ready || blockers.length || unresolvedQuestions || unresolvedInteractions)) return false;
    return dfd.valid === true;
  });
  const providerProvenanceConsistent = cases.length === expectedCases
    && Boolean(selectedProvider && selectedModel && selection.credential_available === true && selection.endpoint_https === true && String(selection.endpoint_hostname || "").trim())
    && cases.every(item => String(item?.provenance?.provider || "").trim().toLowerCase() === selectedProvider
      && String(item?.provenance?.model || "").trim().toLowerCase() === selectedModel
      && ["stride", "linddun"].every(framework => {
        const assessment = item?.observed?.framework_assessments?.[framework];
        return assessment?.response_model_recorded === true
          && String(assessment?.response_model || "").trim().toLowerCase() === selectedModel;
      }));
  const providerNames = qualification.live_provider_qualification?.provider_names;
  const modelNames = qualification.live_provider_qualification?.model_names;
  const liveQualificationPassed = qualification.live_provider_qualification?.status === "qualified"
    && qualification.live_provider_qualification?.case_count === expectedCases
    && Array.isArray(providerNames) && providerNames.length === 1 && String(providerNames[0]).trim().toLowerCase() === selectedProvider
    && Array.isArray(modelNames) && modelNames.length === 1 && String(modelNames[0]).trim().toLowerCase() === selectedModel;
  const performanceVerification = verifyPerformanceEvidence(qualification, expectedCases);
  const evaluationSources = evaluation?.source_artifacts || {};
  const expectedEvaluationFingerprint = evaluation?.evaluator_version && evaluationSources.contract_hash && evaluationSources.manifest_hash && evaluationSources.results_hash
    ? crypto.createHash("sha256").update(JSON.stringify(stable({
      evaluator_version: evaluation.evaluator_version,
      contract_hash: evaluationSources.contract_hash,
      manifest_hash: evaluationSources.manifest_hash,
      results_hash: evaluationSources.results_hash,
      metrics: evaluation.metrics,
    }))).digest("hex")
    : null;
  const findingQualityVerification = verifyFindingQualityEvidence(evidence, qualification, manifest, metricContract);
  const labelBackedMetrics = new Set(["finding_precision", "finding_recall", "deferred_recall"]);
  const metricChecks = evaluation?.gate?.checks && typeof evaluation.gate.checks === "object"
    ? evaluation.gate.checks : null;
  const requiredMetricNames = Array.isArray(metricContract?.metrics)
    ? metricContract.metrics.map(item => String(item?.name || "")).filter(Boolean) : [];
  const nonLabelMetricChecksPass = Boolean(metricChecks && requiredMetricNames.length)
    && requiredMetricNames.every(name => Object.hasOwn(metricChecks, name)
      && (labelBackedMetrics.has(name) || metricChecks[name]?.passed === true))
    && Object.entries(metricChecks).every(([name, check]) => labelBackedMetrics.has(name) || check?.passed === true);
  const metricEvaluationBound = Boolean(metricContract && manifest && nonLabelMetricChecksPass && evaluation?.metrics && typeof evaluation.metrics === "object")
    && evaluation.schema_version === "prd-corpus-evaluation-v1"
    && evaluation.evaluator_version === metricContract?.evaluator_version
    && evaluation?.corpus_revision === manifest?.version
    && evaluationSources.contract_hash === crypto.createHash("sha256").update(JSON.stringify(stable(metricContract))).digest("hex")
    && evaluationSources.manifest_hash === crypto.createHash("sha256").update(JSON.stringify(stable(manifest))).digest("hex")
    && evaluationSources.results_hash === qualification.corpus_result_hash
    && /^[a-f0-9]{64}$/i.test(String(evaluationSources.results_hash || ""))
    && /^[a-f0-9]{64}$/i.test(String(evaluation.evaluation_fingerprint || ""))
    && evaluation.evaluation_fingerprint === expectedEvaluationFingerprint;
  add("qualification_schema", qualification.schema_version === "cr8-qualification-v1", "Qualification artifact must use cr8-qualification-v1.");
  add("qualification_integrity", verifyQualificationIntegrity(qualification), "Qualification artifact SHA-256 must match its canonical contents; tampered or legacy artifacts are rejected.");
  add("candidate_identity", candidateIdentityValid, "Qualification must be bound to a valid Git commit/tree with no uncommitted source changes.");
  add("live_mode", qualification.mode === "live", "Only an explicitly executed live-provider qualification can pass.");
  add("full_corpus", Boolean(manifest) && qualification.corpus_version === manifest?.version && cases.length === expectedCases && expectedCases > 0 && new Set(actualIds).size === actualIds.length && JSON.stringify(actualIds) === JSON.stringify(expectedIds), `${cases.length}/${expectedCases || "manifest unavailable"} corpus cases are present and uniquely match the current manifest.`);
  add("case_journeys", cases.length === expectedCases && cases.every(item => item.run_status !== "failed" && !item.errors?.length) && !(qualification.diagnostics?.case_errors || []).length, `All ${expectedCases || "manifest"} browser/API case journeys must complete without errors.`);
  add("dfd_readiness_integrity", dfdStateConsistent, "Every case needs DFD readiness evidence; unresolved gaps must keep a case not_ready, and no ready/signoff state may contain open blockers.");
  add("metric_contract", metricEvaluationBound && findingQualityVerification.passed, "The fail-closed corpus metric contract, current manifest/contract hashes, evaluator fingerprint, run result hash, candidate commit binding, and blind AppSec quality evidence must all pass.");
  add("blind_finding_quality", findingQualityVerification.passed, findingQualityVerification.reasons.join(" ") || "Two distinct AppSec reviewers adjudicated the complete blind corpus above all quality thresholds.");
  add("framework_validation", cases.length === expectedCases && cases.every(item => item.metrics?.framework_validation?.numerator === item.metrics?.framework_validation?.denominator && item.metrics?.framework_validation?.denominator === 2), "Both STRIDE and LINDDUN need a validated outcome in every case.");
  add("provider_provenance", cases.length === expectedCases && providerProvenanceConsistent && cases.every(item => item.provenance?.provider && item.provenance?.model && !/cr8-contract-fixture/i.test(`${item.provenance.provider} ${item.provenance.model}`)), "Every case and both STRIDE/LINDDUN responses must report the selected provider/model, with a saved credential and HTTPS endpoint; missing response-level model provenance, fixture, or inconsistent provenance is rejected.");
  add("live_provider_qualification", liveQualificationPassed, "The runner must report a qualified full-corpus provider result matching the selected provider/model.");
  add("no_fallback", cases.length === expectedCases && cases.every(item => item.provenance?.provider_fallback_used === false), "Fallback or baseline output cannot satisfy live qualification.");
  add("performance", performanceVerification.passed, performanceVerification.reason);
  add("browser", !(qualification.browser?.errors || []).length && (qualification.browser?.matrix || []).length >= 24, "At least 24 route/viewport samples with no browser errors are required.");
  add("accessibility", Number(qualification.browser?.serious_or_critical_violations) === 0, "There must be zero serious/critical accessibility violations.");
  add("runtime", !(qualification.diagnostics?.page_errors || []).length && !(qualification.diagnostics?.failed_requests || []).length && !(qualification.diagnostics?.http_errors || []).length, "There must be zero unexpected runtime or API errors.");
  const evidenceVerification = verifyEvidence(evidence, qualification, secret);
  add("reviewer_sampling", evidenceVerification.passed, evidenceVerification.reasons.join(" ") || "Two distinct reviewer subjects approved this qualification in HMAC-bound evidence; identity-provider verification remains an organization integration requirement.");
  const passed = Object.values(checks).every(item => item.passed);
  return {
    schema_version: "cr8-release-decision-v1",
    verdict: passed ? "PASS" : "NOT_READY",
    created_at: new Date().toISOString(),
    run_id: qualification.namespace || null,
    qualification_artifact_hash: qualification.artifact_hash || null,
    corpus_evaluation_fingerprint: evaluation?.evaluation_fingerprint || null,
    finding_label_set_sha256: findingQualityVerification.label_set_sha256,
    finding_quality_metrics: findingQualityVerification.metrics,
    checks,
    blockers: Object.entries(checks).filter(([, item]) => !item.passed).map(([name, item]) => `${name}: ${item.reason}`),
  };
}

function main() {
  const options = args(process.argv);
  const qualificationPath = path.resolve(options.qualification);
  const qualification = readJson(qualificationPath);
  const evidence = readJson(path.resolve(options.reviewerEvidence));
  const result = evaluate(qualification, evidence, process.env.CR8_REVIEW_EVIDENCE_HMAC_KEY || "");
  const outputPath = path.resolve(options.output || path.join(path.dirname(qualificationPath), "cr8_release_decision.json"));
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify({verdict: result.verdict, blockers: result.blockers.length, output: outputPath}, null, 2));
  if (result.verdict !== "PASS") process.exitCode = 1;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(`CR8 release gate error: ${error.message}`); process.exitCode = 2; }
}

module.exports = {evaluate, stable, qualificationHash, verifyQualificationIntegrity, verifyEvidence, verifyFindingQualityEvidence};
