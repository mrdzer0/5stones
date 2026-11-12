#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const {spawn, execFileSync} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const FIXTURE_PATH = path.join(REPO, "fixtures", "u7_release_gate_fixture.json");
const ROUTES = ["analysis.html", "model.html", "findings.html", "action-plan.html", "evidence.html", "report.html"];
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900}
];

function args(argv) {
  const result = {reportOnly: false, output: null, screenshotDir: process.env.U7_SCREENSHOT_DIR || null, projectId: process.env.U7_PROJECT_ID || "9b3aeb5d-1e7b-4f62-809c-0f74b33a1510"};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--report-only") result.reportOnly = true;
    else if (argv[i] === "--output") result.output = argv[++i];
    else if (argv[i] === "--screenshot-dir") result.screenshotDir = argv[++i];
    else if (argv[i] === "--project-id") result.projectId = argv[++i];
  }
  return result;
}

function loadModule(name) {
  try { return require(name); } catch (error) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve(name, {paths: [globalRoot]}));
  }
}

function loadAxeSource() {
  let axePath;
  try { axePath = require.resolve("axe-core/axe.min.js"); } catch (error) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    try { axePath = require.resolve("axe-core/axe.min.js", {paths: [globalRoot]}); } catch (_) {
      throw new Error("Pinned axe-core dependency is unavailable; install npm dependencies before running the gate.");
    }
  }
  return {version: require(path.join(path.dirname(axePath), "package.json")).version, source: fs.readFileSync(axePath, "utf8")};
}

function uniqueIds(items, label) {
  const ids = items.map((item) => item.id);
  assert.equal(new Set(ids).size, ids.length, `${label} ids must be unique`);
  return new Set(ids);
}

function validateFixture(fixture) {
  assert.match(fixture.fixture_version, /^u7-release-gate-v\d+$/);
  assert.ok(fixture.project && fixture.project.sensitive_content === false, "fixture must be synthetic/non-sensitive");
  const nodeIds = uniqueIds(fixture.dfd.nodes, "DFD node");
  const flowIds = uniqueIds(fixture.dfd.flows, "DFD flow");
  const boundaryIds = uniqueIds(fixture.dfd.boundaries, "boundary");
  const findingIds = uniqueIds(fixture.findings, "finding");
  const controlIds = uniqueIds(fixture.controls, "control");
  const testIds = uniqueIds(fixture.tests, "test");
  assert.ok(nodeIds.size >= 4 && flowIds.size >= 2, "fixture needs a connected multi-flow DFD");
  assert.ok(fixture.dfd.boundaries.some((item) => item.status === "candidate"), "fixture needs a candidate boundary");
  assert.ok(fixture.dfd.boundaries.some((item) => item.status === "confirmed"), "fixture needs a confirmed boundary");
  assert.ok(fixture.findings.length >= 25, "fixture needs enough findings to exercise pagination/deep links");
  assert.ok(new Set(fixture.findings.map((item) => item.framework)).size === 2, "fixture needs STRIDE and LINDDUN");
  assert.ok(fixture.findings.some((item) => item.state === "deferred"), "fixture needs a deferred finding");
  assert.ok(fixture.controls.some((item) => item.applicability === "unassigned"), "fixture needs an unassigned control");
  assert.ok(fixture.tests.some((item) => item.state === "executable") && fixture.tests.some((item) => item.state === "blocked"), "fixture needs executable and blocked tests");
  assert.ok(fixture.sources.some((item) => item.sections_deferred?.length), "fixture needs unread/deferred source sections");
  assert.ok(fixture.gaps.some((item) => item.state === "unresolved" && !item.owner), "fixture needs an unresolved owner gap");
  assert.ok(fixture.state_variants.includes("partial_preserved") && fixture.state_variants.includes("signed") && fixture.state_variants.includes("superseded"), "fixture state inventory is incomplete");
  for (const flow of fixture.dfd.flows) {
    assert.ok(nodeIds.has(flow.source_id) && nodeIds.has(flow.target_id), `flow ${flow.id} must have known endpoints`);
    assert.ok(flow.zone_ids?.length >= 2, `flow ${flow.id} must cross or identify its zones`);
  }
  for (const boundary of fixture.dfd.boundaries) {
    assert.ok(boundary.zone_ids?.length >= 2, `boundary ${boundary.id} must identify both zones`);
  }
  for (const trace of fixture.expected_trace) {
    if (trace.flow_id) assert.ok(flowIds.has(trace.flow_id), `trace flow missing: ${trace.flow_id}`);
    assert.ok(findingIds.has(trace.finding_id), `trace finding missing: ${trace.finding_id}`);
    assert.ok(controlIds.has(trace.control_id), `trace control missing: ${trace.control_id}`);
    if (trace.test_id) assert.ok(testIds.has(trace.test_id), `trace test missing: ${trace.test_id}`);
    const finding = fixture.findings.find((item) => item.id === trace.finding_id);
    if (trace.flow_id) assert.equal(finding.primary_interaction_ref, trace.flow_id, `finding ${trace.finding_id} must point to its expected flow`);
    const control = fixture.controls.find((item) => item.id === trace.control_id);
    assert.ok(control.finding_ids.includes(trace.finding_id), `control ${trace.control_id} must reference ${trace.finding_id}`);
    if (trace.test_id) {
      const test = fixture.tests.find((item) => item.id === trace.test_id);
      assert.equal(test.finding_id, trace.finding_id, `test ${trace.test_id} must reference ${trace.finding_id}`);
      assert.equal(test.control_id, trace.control_id, `test ${trace.test_id} must reference ${trace.control_id}`);
    }
  }
  return {node_count: nodeIds.size, flow_count: flowIds.size, boundary_count: boundaryIds.size, finding_count: findingIds.size, control_count: controlIds.size, test_count: testIds.size};
}

function waitForServer(url, timeoutMs = 15000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, (response) => { response.resume(); if (response.statusCode === 200) return resolve(); setTimeout(probe, 100); });
      request.on("error", () => { if (Date.now() - started > timeoutMs) reject(new Error(`server did not start: ${url}`)); else setTimeout(probe, 100); });
      request.setTimeout(1000, () => request.destroy());
    };
    probe();
  });
}

async function runAxe(page, axeSource) {
  await page.addScriptTag({content: axeSource});
  return page.evaluate(async () => {
    const result = await window.axe.run(document, {resultTypes: ["violations", "incomplete"]});
    return {
      violations: result.violations.map((rule) => ({id: rule.id, impact: rule.impact, help: rule.help, nodes: rule.nodes.map((node) => ({target: node.target}))})),
      incomplete: result.incomplete.map((rule) => ({id: rule.id, impact: rule.impact, nodes: rule.nodes.length}))
    };
  });
}

async function main() {
  const options = args(process.argv);
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const fixtureSummary = validateFixture(fixture);
  const axe = loadAxeSource();
  const playwright = loadModule("playwright");
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-u7-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 18000 + Math.floor(Math.random() * 1000);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  let browser;
  const report = {gate: "U7-Package-A", fixture: {path: path.relative(REPO, FIXTURE_PATH), version: fixture.fixture_version, ...fixtureSummary}, axe: {version: axe.version}, project_id: options.projectId, states: fixture.state_variants, pages: [], errors: []};
  if (options.screenshotDir) fs.mkdirSync(path.resolve(options.screenshotDir), {recursive: true});
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    for (const viewport of VIEWPORTS) {
      for (const route of ROUTES) {
        const page = await browser.newPage({viewport});
        const url = `http://127.0.0.1:${port}/${route}?project_id=${encodeURIComponent(options.projectId)}`;
        try {
          await page.goto(url, {waitUntil: "networkidle", timeout: 20000});
          await page.waitForTimeout(500);
          const result = await runAxe(page, axe.source);
          const screenshotPath = options.screenshotDir ? path.join(path.resolve(options.screenshotDir), `${route.replace(/\.html$/, "")}-${viewport.width}.png`) : null;
          if (screenshotPath) await page.screenshot({path: screenshotPath, fullPage: false});
          report.pages.push({route, state: "initial", viewport: viewport.name, width: viewport.width, screenshot: screenshotPath, violations: result.violations, incomplete: result.incomplete});
        } catch (error) {
          report.errors.push({route, viewport: viewport.name, message: error.message});
        } finally { await page.close(); }
      }
    }
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  const violationSummary = report.pages.flatMap((item) => item.violations.map((rule) => ({route: item.route, viewport: item.viewport, id: rule.id, impact: rule.impact, node_count: rule.nodes.length})));
  report.summary = {page_count: report.pages.length, error_count: report.errors.length, violation_count: violationSummary.length, serious_or_critical: violationSummary.filter((item) => ["serious", "critical"].includes(item.impact)).length, violations: violationSummary};
  const output = options.output ? path.resolve(options.output) : null;
  if (output) { fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n"); }
  console.log(JSON.stringify({...report, pages: undefined}, null, 2));
  const gateFailed = report.errors.length > 0 || report.summary.serious_or_critical > 0 || report.summary.page_count !== ROUTES.length * VIEWPORTS.length;
  if (gateFailed && !options.reportOnly) process.exitCode = 1;
}

main().catch((error) => { console.error(`U7 Package A gate error: ${error.message}`); process.exitCode = 1; });
