#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {execFileSync, spawn} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const DEFAULT_PROJECT_ID = "9b3aeb5d-1e7b-4f62-809c-0f74b33a1510";

function loadPlaywright() {
  try { return require("playwright"); } catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve("playwright", {paths: [globalRoot]}));
  }
}

function parseArgs(argv) {
  const result = {output: null, screenshotDir: null, projectId: process.env.U7_PROJECT_ID || DEFAULT_PROJECT_ID};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--output") result.output = argv[++i];
    else if (argv[i] === "--screenshot-dir") result.screenshotDir = argv[++i];
    else if (argv[i] === "--project-id") result.projectId = argv[++i];
  }
  return result;
}

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

function url(port, page, projectId, extra = "") {
  return `http://127.0.0.1:${port}/${page}.html?id=${encodeURIComponent(projectId)}${extra}`;
}

async function waitWorkspace(page, selector) {
  await page.waitForSelector(selector, {state: "visible", timeout: 15000});
  await page.waitForFunction((id) => !document.getElementById(id)?.textContent.includes("Loading"), selector.slice(1), {timeout: 15000});
}

async function inspectWorkspaceSurface(page, selector, name, viewport, result, options) {
  const surface = await page.evaluate((listSelector) => {
    const first = document.querySelector(`${listSelector} [data-finding-id], ${listSelector} [data-action-key], ${listSelector} [data-evidence-key]`);
    const advanced = document.querySelector(".advanced-filter-panel");
    return {
      firstTop: first ? first.getBoundingClientRect().top : null,
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
      advancedOpen: Boolean(advanced?.open),
      firstVisible: Boolean(first && first.getBoundingClientRect().height > 0),
      boxes: [...document.querySelectorAll(".page-body > section, .progressive-toolbar, .findings-workspace, .action-plan-workspace, .evidence-workspace")].map(node => ({className: node.className, top: node.getBoundingClientRect().top, height: node.getBoundingClientRect().height})),
    };
  }, selector);
  result.metrics.push({name, viewport, ...surface});
  if (options.screenshotDir) { const target = path.join(options.screenshotDir, `package-f-${name.replace(/\s+/g, "-")}-${viewport.width}.png`); await page.screenshot({path: target, fullPage: false}); result.screenshots.push(target); }
  assert.equal(surface.overflow, false, `${name} has horizontal overflow at ${viewport.width}px`);
  assert.equal(surface.advancedOpen, false, `${name} advanced filters are expanded by default`);
  assert.equal(surface.firstVisible, true, `${name} has no visible first review row`);
  assert.ok(surface.firstTop !== null && surface.firstTop <= 420, `${name} first meaningful row starts at ${surface.firstTop}px; expected <= 420px`);
}

async function inspectFindings(page, options, result) {
  await page.goto(url(options.port, "findings", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitWorkspace(page, "#findings-list");
  await inspectWorkspaceSurface(page, "#findings-list", "findings", {width: 390, height: 844}, result, options);
  await page.locator("#findings-preset").selectOption("needs-review");
  assert.match(await page.evaluate(() => location.search), /fst=Open/);
  assert.equal(await page.locator("#findings-advanced-filters").evaluate(node => node.open), false);
  const first = page.locator("#findings-list [data-finding-id]").first();
  await first.click();
  await page.waitForSelector("#findings-inspector .finding-risk-section", {state: "visible", timeout: 5000});
  await page.locator("#findings-inspector .findings-inspector-close").click();
  assert.equal(await page.locator("#findings-list [data-finding-id].is-selected").count(), 0, "closing a finding left stale selection styling");
  result.checks.push("findings quick preset → URL state → inspect/close without losing list");

  await page.locator("#start-findings-guided").click();
  await page.waitForSelector("#finding-guided-review", {state: "visible", timeout: 5000});
  assert.match(await page.locator("#finding-guided-review").textContent(), /What might happen|Evidence available/i);
  assert.ok(await page.locator("#finding-guided-review select").count() === 1);
  result.checks.push("novice guided finding review → plain-language question and explicit deferred path");
}

async function inspectActionPlan(page, options, result) {
  await page.goto(url(options.port, "action-plan", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitWorkspace(page, "#action-list");
  await inspectWorkspaceSurface(page, "#action-list", "action plan", {width: 390, height: 844}, result, options);
  await page.locator("#action-preset").selectOption("needs-decision");
  assert.match(await page.evaluate(() => location.search), /aexec=needs_review/);
  assert.equal(await page.locator("#action-advanced-filters").evaluate(node => node.open), false);
  result.checks.push("action plan quick preset → needs-decision URL state → compact queue");
}

async function inspectEvidence(page, options, result) {
  await page.goto(url(options.port, "evidence", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitWorkspace(page, "#evidence-list");
  await inspectWorkspaceSurface(page, "#evidence-list", "evidence", {width: 390, height: 844}, result, options);
  assert.equal(await page.locator("#evidence-intake").evaluate(node => node.open), false, "evidence intake expanded by default");
  assert.equal(await page.locator("#evidence-coverage").evaluate(node => node.open), false, "coverage details expanded by default");
  await page.locator("#evidence-preset").selectOption("needs-attention");
  assert.match(await page.evaluate(() => location.search), /est=Open/);
  await page.locator("#evidence-list [data-evidence-key]").first().click();
  await page.waitForSelector("#evidence-item-source", {state: "visible", timeout: 5000});
  result.checks.push("evidence needs-attention → unresolved item inspector with source locator");
}

async function inspectModelAndOnboarding(page, options, result) {
  await page.goto(url(options.port, "model", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#model-boundary-queue", {state: "visible", timeout: 15000});
  if (await page.locator("#model-review-trigger").isVisible()) await page.locator("#model-review-trigger").click();
  await page.locator("#start-boundary-guided").click();
  await page.waitForSelector("#node-inspector", {state: "visible", timeout: 5000});
  assert.equal(await page.locator("[data-guided-boundary]").count(), 3, "boundary guided review does not expose three novice choices");
  assert.match(await page.locator("#inspector-body").textContent(), /Belum tahu/);
  result.checks.push("DFD boundary guided review → access-difference question and explicit unknown state");

  await page.goto(`http://127.0.0.1:${options.port}/project-new.html`, {waitUntil: "networkidle", timeout: 20000});
  await page.locator("#onboarding-start-doc").click();
  assert.equal(await page.locator("#project-desc").getAttribute("required"), null, "document intake still requires technical description");
  await page.locator("#project-name").fill("Guided fixture");
  await page.locator("#btn-next").click();
  await page.waitForSelector("#step-2", {state: "visible", timeout: 3000});
  assert.match(await page.locator("#onboarding-guidance").textContent(), /document|source/i);
  result.checks.push("document-first onboarding → minimum name → guided questions remain optional");
}

async function inspectRecovery(page, options, result) {
  await page.goto(url(options.port, "findings", "00000000-0000-4000-8000-000000000000"), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#findings-retry-load", {state: "visible", timeout: 10000});
  assert.match(await page.locator("#findings-list").textContent(), /could not be loaded/i);
  assert.ok(await page.locator("#findings-list a[href*='analysis.html']").count() === 1);
  result.checks.push("load failure → retry action and safe return to analysis");
}

async function main() {
  const options = parseArgs(process.argv);
  const playwright = loadPlaywright();
  if (options.screenshotDir) fs.mkdirSync(path.resolve(options.screenshotDir), {recursive: true});
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-package-f-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  options.port = 20100 + Math.floor(Math.random() * 600);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(options.port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(options.port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "U7-Package-F", project_id: options.projectId, metrics: [], checks: [], screenshots: [], errors: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${options.port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    try {
      await inspectFindings(page, options, result);
      await inspectActionPlan(page, options, result);
      await inspectEvidence(page, options, result);
      await inspectModelAndOnboarding(page, options, result);
      await inspectRecovery(page, options, result);
    } finally { await page.close(); }
  } catch (error) { result.errors.push({message: error.message, stack: error.stack}); }
  finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {check_count: result.checks.length, error_count: result.errors.length, screenshot_count: result.screenshots.length, metric_count: result.metrics.length};
  if (options.output) { const output = path.resolve(options.output); fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n"); }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "Package F Chromium gate failed");
  assert.equal(result.checks.length, 7, "Package F did not complete all guided-work checks");
}

main().catch(error => { console.error(`U7 Package F gate error: ${error.message}`); process.exitCode = 1; });
