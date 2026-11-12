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
const APPENDIX_IDS = ["report-boundaries", "report-threats", "report-controls", "report-tests", "report-gaps", "report-assumptions"];

function loadPlaywright() {
  try { return require("playwright"); } catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve("playwright", {paths: [globalRoot]}));
  }
}

function parseArgs(argv) {
  const result = {
    output: null,
    screenshotDir: null,
    projectId: process.env.U7_PROJECT_ID || DEFAULT_PROJECT_ID,
  };
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === "--output") result.output = argv[++index];
    else if (argv[index] === "--screenshot-dir") result.screenshotDir = argv[++index];
    else if (argv[index] === "--project-id") result.projectId = argv[++index];
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

function reportUrl(port, projectId, extra = "") {
  return `http://127.0.0.1:${port}/report.html?id=${encodeURIComponent(projectId)}${extra}`;
}

async function fetchReport(page) {
  return page.evaluate(async () => {
    const projectId = new URLSearchParams(location.search).get("id");
    const response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/report`);
    if (!response.ok) throw new Error(`report fetch failed: ${response.status}`);
    return response.json();
  });
}

async function inspectReportSurface(page, viewport, options, result) {
  await page.waitForSelector("#report-dfd-snapshot-caption", {state: "visible", timeout: 15000});
  await page.waitForSelector("#report-revision-select", {state: "visible", timeout: 15000});
  await page.waitForFunction(() => document.querySelectorAll(".report-section-toggle").length === 6, null, {timeout: 15000});
  const surface = await page.evaluate((appendixIds) => {
    const visible = element => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && box.width > 0 && box.height > 0;
    };
    const cards = appendixIds.map(id => {
      const section = document.getElementById(id);
      const card = section?.querySelector(":scope > .card");
      const toggle = section?.querySelector(":scope > .report-section-toggle");
      return {id, hidden: Boolean(card?.hidden), toggleVisible: Boolean(toggle && visible(toggle))};
    });
    const snapshot = document.querySelector("#report-dfd-snapshot");
    const snapshotBox = snapshot?.getBoundingClientRect();
    const toc = document.querySelector(".report-toc");
    const commandbar = document.querySelector(".report-commandbar");
    return {
      viewport: {width: innerWidth, height: innerHeight},
      documentHeight: document.documentElement.scrollHeight,
      horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
      cards,
      snapshotVisible: Boolean(snapshot && visible(snapshot)),
      snapshotHeight: snapshotBox?.height || 0,
      snapshotCaption: document.querySelector("#report-dfd-snapshot-caption")?.textContent.trim() || "",
      modelHref: document.querySelector("#report-dfd-open")?.getAttribute("href") || "",
      tocPosition: toc ? getComputedStyle(toc).position : "missing",
      commandbarPosition: commandbar ? getComputedStyle(commandbar).position : "missing",
    };
  }, APPENDIX_IDS);
  assert.ok(surface.documentHeight <= viewport.height * 3, `${viewport.name} default report surface is ${surface.documentHeight}px; expected <= ${viewport.height * 3}px`);
  assert.equal(surface.horizontalOverflow, false, `${viewport.name} report has horizontal overflow`);
  assert.ok(surface.cards.every(card => card.hidden && card.toggleVisible), `${viewport.name} appendix cards are not collapsed behind visible controls`);
  assert.equal(surface.snapshotVisible, true, `${viewport.name} DFD snapshot is not visible`);
  assert.match(surface.snapshotCaption, /Canonical DFD r\d+/i, `${viewport.name} DFD snapshot has no canonical revision caption`);
  assert.match(surface.modelHref, /model\.html\?/, "DFD snapshot does not link to the Model workspace");
  if (viewport.width <= 700) assert.equal(surface.tocPosition, "static", "mobile report TOC still competes with the sticky command bar");
  if (options.screenshotDir) {
    const target = path.join(options.screenshotDir, `report-${viewport.name}-${viewport.width}.png`);
    await page.screenshot({path: target, fullPage: false});
    result.screenshots.push(target);
  }
  result.metrics.push(surface);
  return surface;
}

async function inspectAppendixAndDeepLink(page, report, options, result) {
  const threat = (report.threats || []).slice(20).find(item => item?.threat_id) || (report.threats || []).find(item => item?.threat_id);
  assert.ok(threat, "fixture has no threat scenario for report deep-link validation");
  const toggle = page.locator("#report-threats > .report-section-toggle");
  await toggle.click();
  await page.waitForSelector("#report-threats-content", {state: "visible", timeout: 5000});
  assert.equal(await page.locator("#report-threats > .report-section-toggle").getAttribute("aria-expanded"), "true", "threat appendix did not open on demand");
  result.checks.push("collapsed appendix → on-demand threat appendix");

  await page.goto(reportUrl(options.port, options.projectId, `&selected=${encodeURIComponent(`threat:${threat.threat_id}`)}`), {waitUntil: "networkidle", timeout: 20000});
  const row = page.locator(`#threats-tbody tr[data-threat-id="${threat.threat_id}"]`);
  await row.waitFor({state: "visible", timeout: 15000});
  const selectedState = await page.evaluate(() => ({
    routeSelected: Boolean(document.querySelector("#threats-tbody tr.route-selected")),
    appendixOpen: !document.querySelector("#report-threats-content")?.hidden,
    selection: new URLSearchParams(location.search).get("selected"),
  }));
  assert.equal(selectedState.selection, `threat:${threat.threat_id}`, "report deep-link selection was not preserved");
  assert.equal(selectedState.routeSelected, true, "report deep-link did not mark the selected threat row");
  assert.equal(selectedState.appendixOpen, true, "report deep-link did not open the threat appendix");
  if ((report.threats || []).indexOf(threat) >= 20) {
    assert.equal(await page.locator("#report-pagination-threats .is-active").textContent(), "2", "report deep-link did not resolve the selected threat to page 2");
  }
  result.checks.push("threat deep-link → selected row and automatically opened appendix");
}

async function inspectRevisionReaderAndExport(page, options, result) {
  let optionCount = await page.locator("#report-revision-select option").count();
  if (optionCount < 2) {
    const createResponse = page.waitForResponse(response => response.url().includes("/report/revisions") && response.request().method() === "POST", {timeout: 15000});
    await page.locator("#save-draft-report").click();
    await createResponse;
    await page.waitForFunction(() => document.querySelectorAll("#report-revision-select option").length >= 2, null, {timeout: 15000});
    optionCount = await page.locator("#report-revision-select option").count();
  }
  assert.ok(optionCount >= 2, "report revision reader has no materialized immutable revision");
  const revisionId = await page.locator("#report-revision-select option").nth(1).getAttribute("value");
  assert.ok(revisionId, "revision selector option has no stable revision ID");
  await page.locator("#report-revision-select").selectOption(revisionId);
  await page.waitForFunction(() => /immutable read-only snapshot/i.test(document.querySelector("#report-revision-reader-status")?.textContent || ""), null, {timeout: 15000});
  assert.equal(await page.locator("#save-draft-report").isDisabled(), true, "Save draft remained enabled while reading an immutable revision");
  const selected = await page.evaluate(() => ({
    status: document.querySelector("#report-revision-reader-status")?.textContent || "",
    dfdRevision: document.querySelector("#report-dfd-revision")?.textContent || "",
    caption: document.querySelector("#report-dfd-snapshot-caption")?.textContent || "",
  }));
  assert.match(selected.status, /immutable read-only snapshot/i);
  assert.match(selected.caption, /Canonical DFD r\d+/i);
  assert.match(selected.dfdRevision, /^r\d+$/i, "immutable revision did not expose a DFD revision");

  const [exportResponse] = await Promise.all([
    page.waitForResponse(response => response.url().includes(`/export?`) && response.status() === 200, {timeout: 15000}),
    page.locator("#export-json").click(),
  ]);
  const exported = await exportResponse.json();
  assert.equal(String(exported.formal_report?.revision), String(await page.evaluate(async revision => {
    const response = await fetch(`/api/projects/${encodeURIComponent(new URLSearchParams(location.search).get("id"))}/report/revisions/${encodeURIComponent(revision)}`);
    const snapshot = await response.json();
    return snapshot.formal_report?.revision;
  }, revisionId)), "export did not preserve the selected report revision");
  assert.equal(String(exported.formal_report?.dfd_revision), selected.dfdRevision.replace(/^r/i, ""), "export DFD revision diverged from the selected immutable snapshot");
  result.checks.push("immutable revision reader → disabled edits → revision-consistent JSON export");

  await page.locator("#report-revision-current").click();
  await page.waitForFunction(() => /Current report is read-only/i.test(document.querySelector("#report-revision-reader-status")?.textContent || ""), null, {timeout: 5000});
  assert.equal(await page.locator("#save-draft-report").isDisabled(), false, "return-to-current did not restore draft action");
}

async function main() {
  const options = parseArgs(process.argv);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-package-e-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  options.port = 20100 + Math.floor(Math.random() * 600);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(options.port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(options.port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "U7-Package-E", project_id: options.projectId, metrics: [], checks: [], screenshots: [], errors: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${options.port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 390, height: 844}, acceptDownloads: true});
    try {
      await page.goto(reportUrl(options.port, options.projectId), {waitUntil: "networkidle", timeout: 20000});
      const report = await fetchReport(page);
      await inspectReportSurface(page, {name: "mobile", width: 390, height: 844}, options, result);
      await inspectAppendixAndDeepLink(page, report, options, result);
      await page.setViewportSize({width: 1440, height: 900});
      await page.goto(reportUrl(options.port, options.projectId), {waitUntil: "networkidle", timeout: 20000});
      await inspectReportSurface(page, {name: "desktop", width: 1440, height: 900}, options, result);
      await inspectRevisionReaderAndExport(page, options, result);
    } finally { await page.close(); }
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {check_count: result.checks.length, error_count: result.errors.length, screenshot_count: result.screenshots.length, metric_count: result.metrics.length};
  if (options.output) {
    const output = path.resolve(options.output);
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "Package E Chromium report gate failed");
  assert.equal(result.checks.length, 3, "Package E did not complete all report checks");
}

main().catch(error => { console.error(`U7 Package E gate error: ${error.message}`); process.exitCode = 1; });
