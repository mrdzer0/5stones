#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {spawn} = require("node:child_process");
const {fixtureReport, installFixtureMock, pageUrl, loadPlaywright} = require("./u7_package_g_gate.js");

const REPO = path.resolve(__dirname, "..");
const FIXTURE_PATH = path.join(REPO, "fixtures", "u7_release_gate_fixture.json");
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "desktop", width: 1280, height: 900},
];

function waitForServer(url, timeoutMs = 15000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, response => {
        response.resume();
        if (response.statusCode === 200) return resolve();
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

async function open(page, port, route, projectId) {
  await page.goto(pageUrl(port, route, projectId), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForTimeout(120);
}

async function inspectAnalysis(page, port, projectId, result) {
  await open(page, port, "analysis", projectId);
  await page.waitForSelector("#analysis-overview", {state: "visible", timeout: 15000});
  const desktop = await page.evaluate(() => {
    const visible = selector => [...document.querySelectorAll(selector)].filter(node => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && getComputedStyle(node).display !== "none";
    }).length;
    return {
      metricCount: visible(".analysis-overview-stat"),
      nextActionCount: document.querySelectorAll("#analysis-next-actions-list > li").length,
      intakeOpen: document.querySelector("#artifact-upload-card")?.open,
      contextCollapsed: document.querySelector("#project-context-card")?.classList.contains("is-collapsed"),
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
    };
  });
  assert.equal(desktop.metricCount, 3, `Analysis should expose three summary metrics, got ${desktop.metricCount}`);
  assert.ok(desktop.nextActionCount <= 3, `Analysis next-action queue has ${desktop.nextActionCount} items`);
  assert.equal(desktop.intakeOpen, false, "Analysis artifact intake is expanded in the first viewport");
  assert.equal(desktop.contextCollapsed, true, "Analysis project context is not collapsed by default");
  assert.equal(desktop.overflow, false, "Analysis has horizontal overflow");
  result.checks.push("Analysis lifecycle summary keeps three metrics, max-three next actions, and secondary intake/context collapsed");

  await page.setViewportSize({width: 390, height: 844});
  await page.waitForTimeout(100);
  const mobileOverflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
  assert.equal(mobileOverflow, false, "Analysis mobile surface has horizontal overflow");
  result.checks.push("Analysis mobile first viewport remains bounded");
}

async function inspectModel(page, port, projectId, result) {
  await page.setViewportSize({width: 1280, height: 900});
  await open(page, port, "model", projectId);
  await page.waitForSelector("#threat-diagram-canvas canvas", {timeout: 15000});
  const link = page.locator("#btn-model-findings");
  assert.equal(await link.count(), 1, "Model has no contextual Findings continuation");
  const href = new URL(await link.getAttribute("href"), page.url());
  assert.equal(href.pathname, "/findings.html", "Model Findings continuation targets the wrong route");
  assert.equal(href.searchParams.get("id"), projectId, "Model Findings continuation lost the project identity");
  const canvas = await page.evaluate(() => {
    const shell = document.querySelector("#diagram-canvas-shell")?.getBoundingClientRect();
    return {top: shell?.top || 0, height: shell?.height || 0, overflow: document.documentElement.scrollWidth > innerWidth + 1};
  });
  assert.ok(canvas.top < 360 && canvas.height > 300, `Model canvas is not first-viewport usable: ${JSON.stringify(canvas)}`);
  assert.equal(canvas.overflow, false, "Model has horizontal overflow");
  result.checks.push("Model preserves canvas-first geometry and adds direct Model → Findings continuation");
}

async function inspectActionPlan(page, port, projectId, result) {
  await page.setViewportSize({width: 1280, height: 900});
  await open(page, port, "action-plan", projectId);
  await page.waitForSelector("#action-list [data-action-key]", {timeout: 15000});
  const queue = await page.evaluate(() => [...document.querySelectorAll("#action-queue .action-queue-card")].map(card => Number(card.querySelector("strong")?.textContent.trim() || 0)));
  assert.ok(queue.every(value => value > 0), `Action queue contains a zero-count card: ${JSON.stringify(queue)}`);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
  assert.equal(overflow, false, "Action Plan has horizontal overflow");
  result.checks.push("Action Plan queue hides zero-count cards and keeps list/inspector surface bounded");
}

async function inspectEvidence(page, port, projectId, result) {
  await page.setViewportSize({width: 1280, height: 900});
  await open(page, port, "evidence", projectId);
  await page.waitForSelector("#evidence-list [data-evidence-key]", {timeout: 15000});
  const geometry = await page.evaluate(() => {
    const rect = selector => document.querySelector(selector)?.getBoundingClientRect();
    const visible = selector => [...document.querySelectorAll(selector)].filter(node => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && getComputedStyle(node).display !== "none";
    }).length;
    const toolbar = rect(".evidence-toolbar");
    const workspace = rect(".evidence-workspace");
    const intake = rect("#evidence-intake");
    return {
      toolbarTop: toolbar?.top || 0,
      workspaceTop: workspace?.top || 0,
      intakeTop: intake?.top || 0,
      intakeOpen: document.querySelector("#evidence-intake")?.open,
      coverageOpen: document.querySelector("#evidence-coverage")?.open,
      contextCtas: visible("#open-context-editor, #open-context-editor-inline"),
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
    };
  });
  assert.ok(geometry.toolbarTop < geometry.intakeTop, `Evidence filters are below intake: ${JSON.stringify(geometry)}`);
  assert.ok(geometry.workspaceTop < geometry.intakeTop, `Evidence review queue is below intake: ${JSON.stringify(geometry)}`);
  assert.equal(geometry.intakeOpen, false, "Evidence intake is expanded by default");
  assert.equal(geometry.coverageOpen, false, "Evidence coverage is expanded by default");
  assert.equal(geometry.contextCtas, 1, `Evidence exposes ${geometry.contextCtas} visible context CTAs instead of one`);
  assert.equal(geometry.overflow, false, "Evidence has horizontal overflow");
  result.checks.push("Evidence places review queue and filters before secondary intake/coverage with one context CTA");

  await page.setViewportSize({width: 390, height: 844});
  await page.waitForTimeout(100);
  const mobile = await page.evaluate(() => ({
    contextCtas: [...document.querySelectorAll("#open-context-editor, #open-context-editor-inline")].filter(node => {
      const box = node.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && getComputedStyle(node).display !== "none";
    }).length,
    overflow: document.documentElement.scrollWidth > innerWidth + 1,
  }));
  assert.equal(mobile.contextCtas, 1, `Evidence mobile exposes ${mobile.contextCtas} visible context CTAs`);
  assert.equal(mobile.overflow, false, "Evidence mobile has horizontal overflow");
  result.checks.push("Evidence mobile keeps a single discoverable context action without overflow");
}

async function inspectReport(page, port, projectId, result) {
  await page.setViewportSize({width: 1280, height: 900});
  await open(page, port, "report", projectId);
  await page.waitForSelector("#report-dfd-snapshot-caption", {state: "visible", timeout: 15000});
  assert.equal(await page.locator(".report-export-menu").count(), 1, "Report export actions are not grouped");
  assert.equal(await page.locator(".report-export-menu").evaluate(node => node.open), false, "Report export menu is expanded by default");
  assert.equal(await page.locator(".report-export-popover .btn:visible").count(), 0, "Report export actions render before the user opens Export");
  await page.locator(".report-export-menu > summary").click();
  assert.equal(await page.locator(".report-export-popover .btn:visible").count(), 3, "Report Export did not reveal MD/CSV/JSON actions");
  await page.locator(".report-export-menu > summary").click();
  await page.setViewportSize({width: 390, height: 844});
  await page.waitForTimeout(100);
  assert.equal(await page.locator("#save-draft-report").isVisible(), false, "Report mobile exposes duplicate Save draft action");
  assert.equal(await page.locator("#sign-report").isVisible(), true, "Report mobile hides the primary sign-off action");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
  assert.equal(overflow, false, "Report mobile has horizontal overflow");
  result.checks.push("Report keeps sign-off primary and export actions progressively disclosed on mobile/desktop");
}

async function main() {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const report = fixtureReport(fixture);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-uxm5-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 20800 + Math.floor(Math.random() * 300);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "UX-M5/page-simplification", project_id: fixture.project.project_id, checks: [], errors: [], page_errors: [], failed_requests: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    page.on("pageerror", error => result.page_errors.push(error.message));
    page.on("requestfailed", request => { if (request.url().includes("/api/")) result.failed_requests.push({url: request.url(), failure: request.failure()?.errorText || "failed"}); });
    await installFixtureMock(page, fixture, report);
    await inspectAnalysis(page, port, fixture.project.project_id, result);
    await inspectModel(page, port, fixture.project.project_id, result);
    await inspectActionPlan(page, port, fixture.project.project_id, result);
    await inspectEvidence(page, port, fixture.project.project_id, result);
    await inspectReport(page, port, fixture.project.project_id, result);
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {check_count: result.checks.length, error_count: result.errors.length, page_error_count: result.page_errors.length, failed_request_count: result.failed_requests.length};
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "UX-M5 page simplification gate failed");
  assert.equal(result.page_errors.length, 0, `UX-M5 page errors: ${result.page_errors.join(" | ")}`);
  assert.equal(result.failed_requests.length, 0, "UX-M5 failed API requests");
  assert.equal(result.checks.length, 7, "UX-M5 did not complete all simplification/continuity checks");
}

if (require.main === module) main().catch(error => { console.error(`UX-M5 gate error: ${error.message}`); process.exitCode = 1; });
