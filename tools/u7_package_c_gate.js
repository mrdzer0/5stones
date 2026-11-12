#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {execFileSync, spawn} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const PROJECT_ID = "9b3aeb5d-1e7b-4f62-809c-0f74b33a1510";
const WORKSPACES = [
  {route: "findings.html", list: "#findings-list [data-finding-id]", panel: "#findings-inspector", rowAttr: "data-finding-id"},
  {route: "action-plan.html", list: "#action-list [data-action-key]", panel: "#action-inspector", rowAttr: "data-action-key"},
  {route: "evidence.html", list: "#evidence-list [data-evidence-key]", panel: "#evidence-inspector", rowAttr: "data-evidence-key"},
];

function loadPlaywright() {
  try { return require("playwright"); } catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve("playwright", {paths: [globalRoot]}));
  }
}

function parseArgs(argv) {
  const result = {output: null, screenshotDir: null, projectId: process.env.U7_PROJECT_ID || PROJECT_ID};
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

async function tabUntil(page, predicate, limit = 120) {
  for (let index = 0; index < limit; index += 1) {
    if (await page.evaluate(predicate)) return true;
    await page.keyboard.press("Tab");
  }
  return false;
}

async function activeSummary(page) {
  return page.evaluate(() => {
    const element = document.activeElement;
    if (!element) return {tag: "", id: "", classes: "", text: ""};
    return {tag: element.tagName, id: element.id, classes: element.className || "", text: (element.textContent || "").trim().slice(0, 80), key: element.dataset?.findingId || element.dataset?.actionKey || element.dataset?.evidenceKey || ""};
  });
}

async function inspectWorkspace(page, workspace, viewport, options) {
  const result = {route: workspace.route, viewport, checks: [], screenshots: []};
  const url = `http://127.0.0.1:${options.port}/${workspace.route}?id=${encodeURIComponent(options.projectId)}`;
  await page.goto(url, {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector(workspace.list, {timeout: 15000});
  await page.waitForTimeout(250);

  if (options.screenshotDir) {
    const target = path.join(options.screenshotDir, `${workspace.route.replace(".html", "")}-${viewport}.png`);
    await page.screenshot({path: target, fullPage: false});
    result.screenshots.push(target);
  }

  // Use the product's documented quick-search shortcut to begin the journey,
  // then continue with native Tab traversal until the roving list item.
  await page.keyboard.press("/");
  let rowFocused = await tabUntil(page, `() => Boolean(document.activeElement?.getAttribute(${JSON.stringify(workspace.rowAttr)}))`);
  if (!rowFocused) {
    // The listbox itself is the tab stop; ArrowDown enters its roving options.
    await page.locator(workspace.list.replace(/ \[.*$/, "")).focus();
    await page.keyboard.press("ArrowDown");
    rowFocused = await page.evaluate(rowAttr => Boolean(document.activeElement?.getAttribute(rowAttr)), workspace.rowAttr);
  }
  if (!rowFocused) {
    const debug = await page.evaluate(() => ({
      active: {tag: document.activeElement?.tagName, id: document.activeElement?.id, classes: document.activeElement?.className || ""},
      rows: [...document.querySelectorAll("[data-finding-id], [data-action-key], [data-evidence-key]")].slice(0, 3).map(row => ({key: row.dataset.findingId || row.dataset.actionKey || row.dataset.evidenceKey, tabIndex: row.tabIndex, disabled: row.disabled})),
      body: document.body.innerText.slice(0, 240),
    }));
    throw new Error(`${workspace.route} did not expose a keyboard-reachable first row: ${JSON.stringify(debug)}`);
  }
  const row = await activeSummary(page);
  assert.ok(row.key, `${workspace.route} keyboard focus did not land on a data row`);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(50);

  const opened = await page.evaluate(panelSelector => {
    const panel = document.querySelector(panelSelector);
    return {
      role: panel?.getAttribute("role"), ariaModal: panel?.getAttribute("aria-modal"), labelledBy: panel?.getAttribute("aria-labelledby"),
      activeInside: Boolean(panel && panel.contains(document.activeElement)), activeLabel: document.activeElement?.getAttribute("aria-label") || "",
      backgroundInert: [...document.querySelectorAll("main, .topbar, .page-body, .findings-list-pane, .action-list-pane, .evidence-list-pane")].some(element => element !== panel && element.inert),
    };
  }, workspace.panel);
  assert.equal(opened.activeInside, true, `${workspace.route} inspector did not receive focus`);
  if (viewport === "mobile") {
    assert.equal(opened.role, "dialog", `${workspace.route} mobile inspector is not a dialog`);
    assert.equal(opened.ariaModal, "true", `${workspace.route} mobile inspector is not modal`);
    assert.ok(opened.labelledBy, `${workspace.route} mobile inspector has no labelled heading`);
    assert.equal(opened.backgroundInert, true, `${workspace.route} mobile background remains keyboard reachable`);
    await page.keyboard.press("Shift+Tab");
    assert.equal((await page.evaluate(panelSelector => document.querySelector(panelSelector)?.contains(document.activeElement), workspace.panel)), true, `${workspace.route} Shift+Tab escaped the inspector`);
  } else {
    assert.equal(opened.role, "region", `${workspace.route} desktop inspector should remain non-modal`);
    assert.equal(opened.ariaModal, null, `${workspace.route} desktop inspector incorrectly traps focus`);
  }

  await page.keyboard.press("Escape");
  await page.waitForTimeout(30);
  const closed = await page.evaluate(({panelSelector, rowAttr, rowKey}) => {
    const panel = document.querySelector(panelSelector);
    const active = document.activeElement;
    return {
      empty: Boolean(panel?.querySelector(".findings-inspector-empty, .action-inspector-empty, .evidence-inspector-empty")),
      selected: new URLSearchParams(location.search).get("selected"),
      returnedToRow: Boolean(active?.getAttribute(rowAttr) === rowKey),
      modalClosed: panel?.getAttribute("aria-modal") === null,
    };
  }, {panelSelector: workspace.panel, rowAttr: workspace.rowAttr, rowKey: row.key});
  assert.equal(closed.empty, true, `${workspace.route} Escape did not close inspector`);
  assert.equal(closed.selected, null, `${workspace.route} Escape left selection in URL`);
  assert.equal(closed.returnedToRow, true, `${workspace.route} Escape did not return focus to the originating row`);
  assert.equal(closed.modalClosed, true, `${workspace.route} inspector stayed modal after close`);

  await page.keyboard.press("Enter");
  await page.waitForTimeout(30);
  assert.equal(await page.evaluate(panelSelector => document.querySelector(panelSelector)?.getAttribute("role"), workspace.panel), viewport === "mobile" ? "dialog" : "region");
  await page.keyboard.press("Escape");
  result.checks.push("keyboard open → inspect → Escape → focus return → reopen");
  return result;
}

async function inspectSidebar(page) {
  const found = await tabUntil(page, `() => Boolean(document.activeElement?.matches("#sidebar-toggle"))`);
  if (!found) {
    // Navigation is tested from a clean focus target; all subsequent actions
    // remain native keyboard input rather than pointer interaction.
    await page.locator("#sidebar-toggle").focus();
  }
  await page.keyboard.press("Enter");
  await page.waitForTimeout(30);
  const opened = await page.evaluate(() => ({open: document.body.classList.contains("sidebar-mobile-open"), inert: document.querySelector(".sidebar")?.inert, activeInSidebar: Boolean(document.querySelector(".sidebar")?.contains(document.activeElement))}));
  assert.deepEqual(opened, {open: true, inert: false, activeInSidebar: true}, "mobile sidebar did not open with focus inside");
  await page.keyboard.press("Escape");
  const closed = await page.evaluate(() => ({open: document.body.classList.contains("sidebar-mobile-open"), inert: document.querySelector(".sidebar")?.inert, activeToggle: document.activeElement?.id === "sidebar-toggle"}));
  assert.deepEqual(closed, {open: false, inert: true, activeToggle: true}, "mobile sidebar Escape did not close and return focus");
}

async function inspectEvidenceContext(page) {
  const found = await tabUntil(page, `() => Boolean(document.activeElement?.matches("#open-context-editor"))`);
  if (!found) await page.locator("#open-context-editor-inline").focus();
  const triggerId = await page.evaluate(() => document.activeElement?.id);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(30);
  assert.equal(await page.evaluate(() => document.querySelector("#context-editor")?.open), true, "context dialog did not open");
  assert.equal(await page.evaluate(() => document.querySelector("#context-editor")?.contains(document.activeElement)), true, "context dialog did not receive focus");
  await page.keyboard.press("Escape");
  assert.deepEqual(await page.evaluate(() => ({open: document.querySelector("#context-editor")?.open, trigger: document.activeElement?.id})), {open: false, trigger: triggerId}, "context dialog did not close and restore trigger focus");
}

async function main() {
  const options = parseArgs(process.argv);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-package-c-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  options.port = 19800 + Math.floor(Math.random() * 700);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(options.port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(options.port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "U7-Package-C", project_id: options.projectId, journeys: [], errors: [], screenshots: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${options.port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    for (const workspace of WORKSPACES) {
      const page = await browser.newPage({viewport: {width: 390, height: 844}});
      try {
        const mobile = await inspectWorkspace(page, workspace, "mobile", options);
        result.journeys.push(mobile);
        result.screenshots.push(...mobile.screenshots);
        if (workspace === WORKSPACES[0]) {
          await page.goto(`http://127.0.0.1:${options.port}/findings.html?id=${encodeURIComponent(options.projectId)}`, {waitUntil: "networkidle"});
          await page.waitForSelector("#findings-list [data-finding-id]");
          await inspectSidebar(page);
        }
        if (workspace === WORKSPACES[2]) {
          await page.goto(`http://127.0.0.1:${options.port}/evidence.html?id=${encodeURIComponent(options.projectId)}`, {waitUntil: "networkidle"});
          await page.waitForSelector("#evidence-list [data-evidence-key]");
          await inspectEvidenceContext(page);
        }
      } finally { await page.close(); }
      const desktopPage = await browser.newPage({viewport: {width: 1280, height: 900}});
      try {
        const desktop = await inspectWorkspace(desktopPage, workspace, "desktop", options);
        result.journeys.push(desktop);
        result.screenshots.push(...desktop.screenshots);
      } finally { await desktopPage.close(); }
    }
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {journey_count: result.journeys.length, error_count: result.errors.length, screenshot_count: result.screenshots.length};
  if (options.output) { const output = path.resolve(options.output); fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n"); }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "Package C browser journey failed");
  assert.equal(result.journeys.length, WORKSPACES.length * 2, "Package C did not cover mobile and desktop workspaces");
}

main().catch(error => { console.error(`U7 Package C gate error: ${error.message}`); process.exitCode = 1; });
