"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const apiSource = fs.readFileSync(path.join(__dirname, "..", "frontend", "js", "api.js"), "utf8");
const reportSource = fs.readFileSync(path.join(__dirname, "..", "frontend", "js", "report.js"), "utf8");

function reportContext() {
  const elements = {
    "threats-tbody": {innerHTML: ""},
    "controls-tbody": {innerHTML: ""},
    "tests-tbody": {innerHTML: ""},
  };
  const context = vm.createContext({
    document: {
      addEventListener() {},
      getElementById(id) { return elements[id] || null; },
    },
    window: {},
  });
  vm.runInContext(apiSource, context, {filename: "frontend/js/api.js"});
  vm.runInContext(reportSource, context, {filename: "frontend/js/report.js"});
  vm.runInContext('projectId = "report-table-fixture"; currentReport = {formal_report: {dfd_revision: 2}};', context);
  return {context, elements};
}

test("report tables keep summaries short and retain full information in a single detail row", () => {
  const {context, elements} = reportContext();
  context.fixture = {
    threat: {
      threat_id: "T-1", framework: "STRIDE", finding_state: "grounded",
      threat_category: "Input validation", threat_description: "Long scenario description for the full detail view.",
      risk_level: "High", confidence: "Medium", evidence_type: "direct",
      evidence_snippet: "Evidence excerpt from the source artifact.", recommended_control: "Validate request bodies.",
      asset: "Customer data", trust_boundary: "Internet to API", primary_interaction_ref: "F-1",
      target_refs: [{id: "F-1", type: "data_flow", label: "Submit request"}],
    },
    control: {
      control_id: "C-1", name: 'Request "validation" <script>', implementation_status: "Partial",
      implementation_guidance: "Reject malformed input and record the decision.",
      checklist_items: ["Test invalid payloads", "Review error handling"], owner: "API team",
    },
    securityTest: {
      test_id: "TM-1", scenario_name: "Reject malformed request", priority: "High",
      steps: ["Send invalid payload", "Inspect response"], expected_result: "Request is rejected.", owner: "QA",
    },
  };
  vm.runInContext(`
    renderThreatsTable([fixture.threat]);
    renderControlsTable([fixture.control]);
    renderTestsTable([fixture.securityTest]);
  `, context);

  for (const id of ["threats-tbody", "controls-tbody", "tests-tbody"]) {
    const html = elements[id].innerHTML;
    assert.equal((html.match(/<tr\b/g) || []).length, 2, `${id} has one summary and one detail row`);
    assert.match(html, /class="report-detail-row" hidden/);
    assert.match(html, /<td colspan="3">/);
    assert.match(html, /aria-expanded="false">View details<\/button>/);
  }
  assert.match(elements["threats-tbody"].innerHTML, /Long scenario description for the full detail view/);
  assert.match(elements["threats-tbody"].innerHTML, /Internet to API/);
  assert.match(elements["controls-tbody"].innerHTML, /Reject malformed input and record the decision/);
  assert.match(elements["controls-tbody"].innerHTML, /Review error handling/);
  assert.match(elements["controls-tbody"].innerHTML, /Request &quot;validation&quot; &lt;script&gt;/);
  assert.doesNotMatch(elements["controls-tbody"].innerHTML, /<script>/);
  assert.match(elements["tests-tbody"].innerHTML, /Send invalid payload/);
  assert.match(elements["tests-tbody"].innerHTML, /Request is rejected/);
});

test("report detail toggle updates the row, panel, and accessible state", () => {
  const {context, elements} = reportContext();
  const detail = {hidden: true};
  elements["threat-detail-T-1-1"] = detail;
  const attributes = new Map([["aria-controls", "threat-detail-T-1-1"], ["aria-expanded", "false"]]);
  const classes = new Set();
  const row = {classList: {toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); }}};
  const button = {
    dataset: {detailName: "T-1"},
    textContent: "View details",
    getAttribute(name) { return attributes.get(name); },
    setAttribute(name, value) { attributes.set(name, value); },
    closest() { return row; },
  };
  context.detailButton = button;

  vm.runInContext("setReportRowExpanded(detailButton, true)", context);
  assert.equal(detail.hidden, false);
  assert.equal(attributes.get("aria-expanded"), "true");
  assert.equal(button.textContent, "Hide details");
  assert.ok(classes.has("is-expanded"));

  vm.runInContext("setReportRowExpanded(detailButton, false)", context);
  assert.equal(detail.hidden, true);
  assert.equal(attributes.get("aria-expanded"), "false");
  assert.equal(button.textContent, "View details");
  assert.ok(!classes.has("is-expanded"));
});
