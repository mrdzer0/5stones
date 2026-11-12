"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const reportSource = fs.readFileSync(path.join(__dirname, "..", "frontend", "js", "report.js"), "utf8");

function makeContext({disabled = false} = {}) {
  const button = {disabled};
  const calls = {signoff: [], reloads: 0, toasts: [], prompts: 0};
  const context = vm.createContext({
    calls,
    document: {
      addEventListener() {},
      getElementById(id) { return id === "sign-report" ? button : null; },
    },
    window: {
      prompt() { calls.prompts += 1; throw new Error("Reviewer identity prompt must not be shown"); },
    },
    API: {
      analysis: {
        async signReport(projectId, payload) {
          calls.signoff.push({projectId, payload});
          return {formal_report: {status: "signed", signed_by: "server-owned-principal"}};
        },
      },
    },
    async loadReport() { calls.reloads += 1; },
    showToast(...args) { calls.toasts.push(args); },
    renderFormalReportMetadata() {},
  });
  vm.runInContext(reportSource, context, {filename: "frontend/js/report.js"});
  vm.runInContext(`
    projectId = "report-ui-fixture";
    currentReport = {formal_report: {status: "draft"}};
    loadReport = async () => { calls.reloads += 1; };
    renderFormalReportMetadata = () => {};
  `, context);
  return {context, button, calls};
}

test("report sign-off uses the server-owned reviewer identity", async () => {
  const {context, button, calls} = makeContext();

  await vm.runInContext("signReport()", context);

  assert.deepEqual(JSON.parse(JSON.stringify(calls.signoff)), [{projectId: "report-ui-fixture", payload: {}}]);
  assert.equal(calls.prompts, 0);
  assert.equal(calls.reloads, 1);
  assert.equal(button.disabled, false);
  assert.equal(calls.toasts[0][1], "success");
});

test("report sign-off does not send a request when the button is disabled", async () => {
  const {context, button, calls} = makeContext({disabled: true});

  await vm.runInContext("signReport()", context);

  assert.deepEqual(JSON.parse(JSON.stringify(calls.signoff)), []);
  assert.equal(calls.prompts, 0);
  assert.equal(button.disabled, true);
});

test("report metadata renders the analysis state in its risk summary", () => {
  const disposition = {innerHTML: ""};
  const context = vm.createContext({
    document: {
      addEventListener() {},
      getElementById(id) { return id === "report-risk-disposition" ? disposition : null; },
    },
    window: {},
  });
  vm.runInContext(reportSource, context, {filename: "frontend/js/report.js"});

  vm.runInContext(`
    currentReport = {analysis_state: {result_state: "not_started"}, risk_summary: {}};
    renderFormalReportMetadata({}, {});
  `, context);
  assert.match(disposition.innerHTML, /Assessment not started/);

  vm.runInContext(`
    currentReport.analysis_state.result_state = "partial";
    renderFormalReportMetadata({}, {});
  `, context);
  assert.match(disposition.innerHTML, /Assessment incomplete/);
});
