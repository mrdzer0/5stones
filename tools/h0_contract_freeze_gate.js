#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {execFileSync} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const CONTRACT_PATH = path.join(REPO, "fixtures", "h0_contract_freeze.json");
const INVENTORY_PATH = path.join(REPO, "fixtures", "h0_a01_navigation_inventory.json");
const BASELINE_PATH = path.join(REPO, "fixtures", "h0_a07_baseline_manifest.json");
const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, "utf8"));
const inventory = JSON.parse(fs.readFileSync(INVENTORY_PATH, "utf8"));
const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8"));
const assertTarget = process.argv.includes("--assert-target");

function unique(values, label) {
  assert.equal(new Set(values).size, values.length, `${label} must be unique`);
}

function routeKeys() {
  return contract.project_workflow.map(item => item.key === "overview" ? "analysis" : item.key);
}

function validateContract() {
  assert.equal(contract.contract, "UX-M0");
  assert.match(contract.version, /^h0-contract-freeze-/);
  assert.equal(contract.default_locale, "en-US");

  const globalItems = contract.global_shell.items;
  assert.deepEqual(globalItems.map(item => item.key), ["dashboard", "projects", "new-project", "settings"]);
  unique(globalItems.map(item => item.key), "global shell keys");
  unique(globalItems.map(item => item.label), "global shell labels");
  globalItems.forEach(item => {
    assert.ok(item.route.startsWith("/"), `${item.key} must have an app route`);
    assert.ok(item.icon, `${item.key} must have an icon contract`);
  });

  const workflow = contract.project_workflow;
  assert.deepEqual(workflow.map(item => item.key), ["overview", "model", "findings", "action-plan", "evidence", "report"]);
  unique(workflow.map(item => item.key), "workflow keys");
  unique(workflow.map(item => item.route), "workflow routes");
  unique(workflow.map(item => item.phase), "workflow phases");
  workflow.forEach(item => {
    assert.ok(item.label && item.goal && item.icon, `${item.key} needs label, goal, and icon`);
  });

  const pages = contract.page_contracts;
  assert.deepEqual(Object.keys(pages), routeKeys(), "page contracts must cover workflow in order");
  Object.entries(pages).forEach(([key, page]) => {
    assert.ok(page.route && page.h1 && page.goal && page.primary_cta && page.status, `${key} page anatomy is incomplete`);
    assert.ok(Array.isArray(page.secondary), `${key} secondary actions must be an array`);
  });

  const requiredUrlKeys = contract.url_state.required.map(item => item.key);
  const optionalUrlKeys = contract.url_state.optional.map(item => item.key);
  unique(requiredUrlKeys.concat(optionalUrlKeys), "URL state keys");
  assert.deepEqual(requiredUrlKeys, ["id"]);
  assert.ok(optionalUrlKeys.includes("run") && optionalUrlKeys.includes("revision"));
  assert.deepEqual(contract.url_state.optional.find(item => item.key === "phase").values, ["overview", "model", "findings", "action-plan", "evidence", "signoff"]);
  assert.equal(new RegExp(contract.url_state.optional.find(item => item.key === "selected").pattern).test("dfd-flow:flow-123"), true);
  unique(contract.url_state.legacy.map(item => item.input), "legacy URL inputs");
  unique(contract.url_state.legacy.map(item => `${item.maps_to.phase}:${item.maps_to.view}`), "legacy URL targets");
  assert.equal(contract.url_state.transition_rules.length >= 5, true);

  const dictionary = contract.content_dictionary;
  ["overview", "model", "finding", "control", "verification_test", "evidence_gap", "report", "deferred"].forEach(key => assert.ok(dictionary.nouns[key], `missing canonical noun: ${key}`));
  ["open", "review", "resolve", "assign", "verify", "defer", "continue", "save"].forEach(key => assert.ok(dictionary.verbs[key], `missing canonical verb: ${key}`));
  ["insufficient_evidence", "not_scored", "preserved_result", "manual_decision", "signed_immutable"].forEach(key => assert.ok(dictionary.state_copy[key], `missing state copy: ${key}`));
  assert.equal(JSON.stringify({nouns: dictionary.nouns, verbs: dictionary.verbs, state_copy: dictionary.state_copy}).includes("Belum tahu"), false, "default locale must not mix Indonesian copy");

  const widths = contract.responsive_contract.breakpoints.flatMap(item => item.test_widths);
  [320, 390, 768, 1280, 1440].forEach(width => assert.equal(widths.includes(width), true, `missing responsive test width ${width}`));
  assert.equal(contract.responsive_contract.model.some(rule => rule.includes("55%")), true);

  Object.values(contract.success_criteria).forEach(metric => assert.ok(metric.baseline && metric.target, "success metric needs baseline and target"));
  assert.deepEqual(contract.change_control.required_fields, ["action_id", "decision", "affected_routes", "owner", "reason", "acceptance_impact", "rollback_plan", "reviewer", "date"]);
}

function validateBaselineCoverage() {
  assert.equal(baseline.contract, "H0-A07");
  assert.equal(baseline.route_matrix.length, 6);
  assert.equal(baseline.viewports.length, 4);
  assert.equal(baseline.result.initial_route_viewport_captures, 24);
  assert.equal(baseline.result.interactive_state_captures, 15);
  assert.equal(baseline.result.screenshots, 39);
  assert.equal(baseline.result.page_errors, 0);
  assert.equal(baseline.result.failed_api_requests, 0);
}

function detectExpectedBaselineDrift() {
  if (assertTarget) {
    execFileSync(process.execPath, [path.join(REPO, "tests", "test_h1_shared_shell.js")], {cwd: REPO, stdio: "pipe"});
    return [];
  }
  const expectedIds = ["NAV-C01", "NAV-C02", "NAV-C03", "NAV-C04", "NAV-C05", "NAV-C06"];
  const findings = inventory.findings.filter(item => expectedIds.includes(item.id));
  assert.deepEqual(findings.map(item => item.id), expectedIds, "H0-A08 must retain all expected baseline drift findings");
  assert.equal(inventory.routes.analysis.workflow.length, 6);
  assert.equal(Object.values(inventory.routes).filter(route => route.workflow.length > 0).length, 1);
  assert.equal(new Set(Object.values(inventory.routes).map(route => route.sidebar.length)).size > 1, true, "old sidebar variants must remain detectable");
  assert.equal(new Set(Object.values(inventory.routes).map(route => route.sidebar.find(item => item.key === "report")?.label)).size > 1, true, "old Report label variant must remain detectable");
  assert.equal(Object.values(inventory.routes).every(route => route.breadcrumb.present === false), true);

  // Re-run the static inventory against the actual six route files. This makes
  // the fixture a contract witness rather than an unverified copied snapshot.
  execFileSync(process.execPath, [path.join(REPO, "tests", "test_h0_a01_navigation_inventory.js"), "--assert-target"], {cwd: REPO, stdio: "pipe"});
  return findings.map(item => ({id: item.id, priority: item.priority, finding: item.finding}));
}

function main() {
  validateContract();
  validateBaselineCoverage();
  const expectedDrift = detectExpectedBaselineDrift();
  const report = {
    contract: contract.version,
    mode: assertTarget ? "assert-target" : "baseline-drift-detection",
    canonical_ready: expectedDrift.length === 0,
    contract_checks: "pass",
    baseline_checks: "pass",
    expected_drift_detected: expectedDrift,
    next_action: expectedDrift.length ? "Complete H1-A01/H1-A04, then rerun with --assert-target." : "Proceed to H1 validation and release gates.",
  };
  console.log(JSON.stringify(report, null, 2));
  if (assertTarget && expectedDrift.length) {
    throw new Error(`canonical target is not ready; ${expectedDrift.length} documented baseline drift item(s) remain`);
  }
}

try {
  main();
} catch (error) {
  console.error(`H0 contract freeze gate failed: ${error.message}`);
  process.exitCode = 1;
}
