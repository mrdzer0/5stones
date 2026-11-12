#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {spawn, execFileSync} = require("node:child_process");
const {fixtureReport, installFixtureMock, pageUrl, loadPlaywright} = require("./u7_package_g_gate.js");

const REPO = path.resolve(__dirname, "..");
const FIXTURE_PATH = path.join(REPO, "fixtures", "u7_release_gate_fixture.json");
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900},
];
const WORKSPACES = [
  {route: "findings", trigger: "findings-filters-toggle", dialog: "findings-filter-dialog", search: "findings-filter-search", group: "findings-framework", first: "STRIDE", param: "ff", list: "#findings-list", row: "[data-finding-id]", panel: "#findings-inspector", rowAttr: "data-finding-id", query: "q", queryValue: "Checkout"},
  {route: "action-plan", trigger: "action-filters-toggle", dialog: "action-filter-dialog", search: "action-filter-search", group: "action-type", first: "control", param: "atype", list: "#action-list", row: "[data-action-key]", panel: "#action-inspector", rowAttr: "data-action-key", query: "aq", queryValue: "checkout"},
  {route: "evidence", trigger: "evidence-filters-toggle", dialog: "evidence-filter-dialog", search: "evidence-filter-search", group: "evidence-type", first: "gap", param: "etype", list: "#evidence-list", row: "[data-evidence-key]", panel: "#evidence-inspector", rowAttr: "data-evidence-key", query: "eq", queryValue: "provider"},
];

function waitForServer(url, timeoutMs = 15000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, response => { response.resume(); if (response.statusCode === 200) return resolve(); setTimeout(probe, 100); });
      request.on("error", () => { if (Date.now() - started > timeoutMs) reject(new Error(`server did not start: ${url}`)); else setTimeout(probe, 100); });
      request.setTimeout(1000, () => request.destroy());
    };
    probe();
  });
}

async function waitForRows(page, workspace) {
  await page.waitForSelector(`${workspace.list} ${workspace.row}`, {state: "visible", timeout: 15000});
  await page.waitForTimeout(120);
}

async function inspectFilterContract(page, workspace, projectId, port, result) {
  const base = pageUrl(port, workspace.route, projectId);
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(base, {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, workspace);
  assert.equal(await page.locator(`#${workspace.trigger}`).textContent().then(text => text.trim().startsWith("Filters")), true, `${workspace.route} does not expose the shared Filters trigger`);
  await page.locator(`#${workspace.trigger}`).click();
  assert.equal(await page.locator(`#${workspace.dialog}`).evaluate(node => node.open), true, `${workspace.route} filter dialog did not open`);
  assert.equal(await page.evaluate(() => document.activeElement?.id), workspace.search, `${workspace.route} filter search did not receive focus`);
  await page.locator(`#${workspace.dialog} [data-filter-option]`).first().click();
  await page.locator(`#${workspace.dialog} [data-filter-apply]`).click();
  await page.waitForTimeout(100);
  assert.equal(new URL(page.url()).searchParams.getAll(workspace.param).includes(workspace.first), true, `${workspace.route} filter was not serialized in URL state`);
  assert.ok(Number(await page.locator(`#${workspace.trigger} .filter-count`).textContent() || 0) >= 1, `${workspace.route} filter count did not update`);
  result.checks.push(`${workspace.route} shared filter drawer + checkbox apply + URL serialization`);

  await page.locator(`#${workspace.trigger}`).click();
  await page.locator(`#${workspace.dialog} [data-filter-select-all]`).click();
  assert.ok(await page.locator(`#${workspace.dialog} [data-filter-group] input[type="checkbox"]:checked`).count() > 0, `${workspace.route} select-all did not select visible options`);
  await page.locator(`#${workspace.dialog} [data-filter-clear-all]`).click();
  assert.equal(await page.locator(`#${workspace.dialog} [data-filter-group] input[type="checkbox"]:checked`).count(), 0, `${workspace.route} clear-all did not clear options`);
  await page.locator(`#${workspace.dialog} [data-filter-cancel]`).first().click();

  await page.goBack();
  await page.waitForTimeout(100);
  assert.equal(new URL(page.url()).searchParams.getAll(workspace.param).includes(workspace.first), false, `${workspace.route} Back did not restore the previous filter state`);
  await page.goForward();
  await page.waitForTimeout(100);
  assert.equal(new URL(page.url()).searchParams.getAll(workspace.param).includes(workspace.first), true, `${workspace.route} Forward did not restore the applied filter state`);
  result.checks.push(`${workspace.route} filter Back/Forward state restoration`);

  await page.locator(`#${workspace.trigger}`).click();
  await page.locator(`#${workspace.dialog} [data-filter-option]`).first().click();
  await page.locator(`#${workspace.dialog} [data-filter-cancel]`).first().click();
  assert.equal(await page.locator(`#${workspace.dialog}`).evaluate(node => node.open), false, `${workspace.route} filter cancel did not close`);
  assert.equal(new URL(page.url()).searchParams.getAll(workspace.param).includes(workspace.first), true, `${workspace.route} cancel changed committed filters`);
  assert.equal(await page.evaluate(id => document.activeElement?.id === id, workspace.trigger), true, `${workspace.route} filter close did not return focus`);
  result.checks.push(`${workspace.route} filter cancel/Escape focus contract`);

  await page.locator(`#${workspace.trigger}`).click();
  await page.locator(`#${workspace.search}`).fill(workspace.first === "STRIDE" ? "LINDDUN" : workspace.first === "control" ? "test" : "assumption");
  const visibleOptions = await page.locator(`#${workspace.dialog} [data-filter-option]:visible`).count();
  assert.equal(visibleOptions, 1, `${workspace.route} filter option search did not narrow options`);
  await page.keyboard.press("Escape");
  assert.equal(await page.locator(`#${workspace.dialog}`).evaluate(node => node.open), false, `${workspace.route} Escape did not close filter dialog`);
  result.checks.push(`${workspace.route} searchable checkbox options`);

  const deepLink = new URL(base);
  deepLink.searchParams.set(workspace.param, workspace.first);
  deepLink.searchParams.set(workspace.query, workspace.queryValue);
  await page.goto(deepLink.toString(), {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, workspace);
  assert.equal(await page.locator(`#${workspace.trigger}`).textContent().then(text => text.includes("1")), true, `${workspace.route} deep-link filter count was not restored`);
  await page.locator(`#${workspace.trigger}`).click();
  assert.equal(await page.locator(`#${workspace.group} input[type="checkbox"]`).first().isChecked(), true, `${workspace.route} deep-link checkbox state was not restored`);
  await page.keyboard.press("Escape");
  result.checks.push(`${workspace.route} deep-link query/filter restoration`);

  await page.goto(base, {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, workspace);
  await page.locator(workspace.list).focus();
  await page.keyboard.press("ArrowDown");
  const key = await page.evaluate(({list, attr}) => document.activeElement?.getAttribute(attr), {list: workspace.list, attr: workspace.rowAttr});
  assert.ok(key, `${workspace.route} first row is not keyboard reachable`);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(80);
  assert.equal(await page.evaluate(selector => document.querySelector(selector)?.getAttribute("role"), workspace.panel), "dialog", `${workspace.route} inspector lacks dialog semantics`);
  assert.equal(await page.evaluate(selector => document.querySelector(selector)?.contains(document.activeElement), workspace.panel), true, `${workspace.route} inspector did not receive focus`);
  await page.keyboard.press("Escape");
  assert.equal(await page.evaluate(({list, attr, key}) => document.activeElement?.getAttribute(attr) === key, {list: workspace.list, attr: workspace.rowAttr, key}), true, `${workspace.route} inspector did not return focus`);
  result.checks.push(`${workspace.route} shared keyboard list → inspector → Escape journey`);
}

async function main() {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const report = fixtureReport(fixture);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-uxm4-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 20700 + Math.floor(Math.random() * 400);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "UX-M4/unified-workspaces", project_id: fixture.project.project_id, matrix: [], checks: [], errors: [], page_errors: [], failed_requests: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    page.on("pageerror", error => result.page_errors.push(error.message));
    page.on("requestfailed", request => { if (request.url().includes("/api/")) result.failed_requests.push({url: request.url(), failure: request.failure()?.errorText || "failed"}); });
    await installFixtureMock(page, fixture, report);
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize({width: viewport.width, height: viewport.height});
      for (const workspace of WORKSPACES) {
        await page.goto(pageUrl(port, workspace.route, fixture.project.project_id), {waitUntil: "networkidle", timeout: 20000});
        await waitForRows(page, workspace);
        const surface = await page.evaluate(() => ({overflow: document.documentElement.scrollWidth > innerWidth + 1, nestedList: [...document.querySelectorAll(".findings-list, .action-list, .evidence-list")].some(node => getComputedStyle(node).overflowY !== "visible" && node.scrollHeight > node.clientHeight + 1)}));
        assert.equal(surface.overflow, false, `${workspace.route} horizontal overflow at ${viewport.width}`);
        if (viewport.width <= 768) assert.equal(surface.nestedList, false, `${workspace.route} retains a nested scrolling list on mobile/tablet`);
        result.matrix.push({route: workspace.route, viewport: viewport.name, ...surface});
      }
    }
    for (const workspace of WORKSPACES) await inspectFilterContract(page, workspace, fixture.project.project_id, port, result);
  } catch (error) { result.errors.push({message: error.message, stack: error.stack}); }
  finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {matrix_count: result.matrix.length, check_count: result.checks.length, error_count: result.errors.length, page_error_count: result.page_errors.length, failed_request_count: result.failed_requests.length};
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "UX-M4 unified workspace gate failed");
  assert.equal(result.page_errors.length, 0, `UX-M4 page errors: ${result.page_errors.join(" | ")}`);
  assert.equal(result.failed_requests.length, 0, "UX-M4 failed API requests");
  assert.equal(result.matrix.length, VIEWPORTS.length * WORKSPACES.length, "UX-M4 did not complete the viewport matrix");
  assert.equal(result.checks.length, 18, "UX-M4 did not complete all workspace checks");
}

if (require.main === module) main().catch(error => { console.error(`UX-M4 gate error: ${error.message}`); process.exitCode = 1; });
