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

async function waitForTrace(page, selector, timeout = 12000) {
  await page.waitForSelector(selector, {state: "visible", timeout});
}

async function fetchTrace(page) {
  return page.evaluate(async () => {
    const projectId = new URLSearchParams(location.search).get("id");
    const response = await fetch(`/api/projects/${encodeURIComponent(projectId)}/report`);
    if (!response.ok) throw new Error(`report fetch failed: ${response.status}`);
    const report = await response.json();
    const visibility = (report.threats || []).filter(threat => {
      const boundaries = report.trust_boundaries || [];
      if (!boundaries.length) return true;
      const linked = (threat.trust_boundary_ids || []).map(String);
      if (!linked.length) return true;
      const active = new Set(boundaries.filter(item => item.status !== "Rejected").map(item => String(item.boundary_id)));
      return !linked.some(id => boundaries.some(boundary => String(boundary.boundary_id) === id)) || linked.some(id => active.has(id));
    });
    const flow = (report.dfd_model?.flows || []).find(candidate => {
      return visibility.some(threat => (threat.target_refs || []).some(ref => ref.type === "data_flow" && String(ref.id) === String(candidate.id)));
    });
    if (!flow) throw new Error("fixture has no DFD flow with a linked threat");
    const threat = visibility.find(candidate => (candidate.target_refs || []).some(ref => ref.type === "data_flow" && String(ref.id) === String(flow.id)));
    const control = (report.controls || []).find(candidate => (candidate.threat_ids || []).some(id => String(id) === String(threat.threat_id)));
    const test = (report.test_scenarios || []).find(candidate => String(candidate.threat_id || "") === String(threat.threat_id)
      && (String(candidate.related_control_id || "") === String(control?.control_id || "") || String(candidate.related_control || "") === String(control?.name || "")));
    if (!control || !test) throw new Error(`fixture trace is incomplete for ${threat.threat_id}`);
    return {
      flowId: String(flow.id),
      threatId: String(threat.threat_id),
      controlId: String(control.control_id),
      testId: String(test.test_id),
    };
  });
}

async function inspectCanvas(page, trace, options, result) {
  await page.waitForSelector("#threat-diagram-canvas canvas", {timeout: 15000});
  await page.waitForTimeout(350);
  const canvas = await page.evaluate(() => {
    const shell = document.querySelector("#diagram-canvas-shell");
    const canvas = document.querySelector("#threat-diagram-canvas canvas");
    const shellRect = shell?.getBoundingClientRect();
    const canvasRect = canvas?.getBoundingClientRect();
    const visibleTop = Math.max(0, shellRect?.top || 0);
    const visibleBottom = Math.min(innerHeight, shellRect?.bottom || 0);
    const x = (canvasRect?.left || 0) + (canvasRect?.width || 0) / 2;
    const y = (canvasRect?.top || 0) + Math.min(80, (canvasRect?.height || 0) / 2);
    const hit = document.elementFromPoint(x, y);
    return {
      shellTop: shellRect?.top || 0,
      shellVisibleHeight: Math.max(0, visibleBottom - visibleTop),
      canvasWidth: canvasRect?.width || 0,
      canvasHeight: canvasRect?.height || 0,
      hitCanvas: Boolean(hit && (hit === canvas || canvas?.contains(hit))),
      outlineDisplay: getComputedStyle(document.querySelector("#diagram-text-alternative")).display,
    };
  });
  assert.ok(canvas.shellTop <= 260, `DFD canvas starts below the first viewport contract: ${canvas.shellTop}`);
  assert.ok(canvas.shellVisibleHeight >= 495, `DFD canvas has only ${canvas.shellVisibleHeight}px visible at 1440x900`);
  assert.ok(canvas.canvasWidth > 500 && canvas.canvasHeight > 300, "DFD canvas is not materially visible");
  assert.equal(canvas.hitCanvas, true, "DFD canvas is covered by another element");
  assert.equal(canvas.outlineDisplay, "block", "accessible DFD outline is hidden by CSS");

  await page.locator("#btn-diagram-fit").click();
  await page.waitForTimeout(300);
  const boxes = await page.evaluate(() => window.__5stonesDfdDebug?.getNodeBoxes?.() || []);
  assert.ok(boxes.length > 0, "canonical DFD did not expose inspectable node geometry");
  const overlaps = [];
  for (let left = 0; left < boxes.length; left += 1) {
    for (let right = left + 1; right < boxes.length; right += 1) {
      const a = boxes[left].box; const b = boxes[right].box;
      if (!a || !b) continue;
      const width = Math.min(a.right, b.right) - Math.max(a.left, b.left);
      const height = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (width > 4 && height > 4) overlaps.push([boxes[left].id, boxes[right].id]);
    }
  }
  assert.deepEqual(overlaps, [], `DFD nodes overlap after Fit: ${JSON.stringify(overlaps)}`);

  if (options.screenshotDir) {
    const target = path.join(options.screenshotDir, "model-desktop-1440.png");
    await page.screenshot({path: target, fullPage: false});
    result.screenshots.push(target);
  }
  await page.locator("#diagram-text-alternative summary").click();
  const outline = page.locator(`#diagram-text-alternative [data-outline-type="flow"][data-outline-id="${trace.flowId}"]`);
  await outline.click();
  await page.waitForTimeout(100);
  const selection = await page.evaluate(() => new URLSearchParams(location.search).get("selected"));
  assert.equal(selection, `dfd-flow:${trace.flowId}`, "outline flow did not select the canonical flow by ID");
  assert.ok(await page.locator("#node-inspector").isVisible(), "outline flow did not open the model inspector");

  result.checks.push("1440x900 canvas visibility + fit geometry + keyboard-visible outline");
}

async function inspectTrace(page, trace, options, result) {
  const modelUrl = `http://127.0.0.1:${options.port}/model.html?id=${encodeURIComponent(options.projectId)}&phase=model&selected=${encodeURIComponent(`dfd-flow:${trace.flowId}`)}`;
  await page.goto(modelUrl, {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#node-inspector a.model-finding-link", {timeout: 15000});
  const findingLink = page.locator("#node-inspector a.model-finding-link").filter({hasText: trace.threatId}).first();
  assert.equal(await findingLink.count(), 1, "DFD inspector did not expose the exact linked threat ID");
  const findingHref = await findingLink.getAttribute("href");
  assert.ok(findingHref.includes("/findings.html"), `DFD finding link points to the wrong workspace: ${findingHref}`);
  assert.ok(findingHref.includes(encodeURIComponent(`threat:${trace.threatId}`)), "DFD finding link lost the threat selection ID");
  await findingLink.click();
  await waitForTrace(page, `#findings-list [data-finding-id="${trace.threatId}"]`);
  assert.ok((await page.locator("#findings-inspector .finding-id").textContent()).includes(trace.threatId), "Findings inspector selected the wrong threat");

  const controlLink = page.locator(`#findings-inspector a[href*="selected=${encodeURIComponent(`control:${trace.controlId}`)}"]`).first();
  assert.equal(await controlLink.count(), 1, "Finding inspector did not expose the exact linked control ID");
  await controlLink.click();
  await waitForTrace(page, `#action-list [data-action-key="control:${trace.controlId}"]`);
  assert.ok((await page.locator("#action-inspector .action-id").textContent()).includes(trace.controlId), "Action plan selected the wrong control");

  const testButton = page.locator(`#action-inspector [data-open-action="test:${trace.testId}"]`).first();
  assert.equal(await testButton.count(), 1, "Control inspector did not expose the exact linked test ID");
  await testButton.click();
  await waitForTrace(page, `#action-list [data-action-key="test:${trace.testId}"]`);
  assert.ok((await page.locator("#action-inspector .action-id").textContent()).includes(trace.testId), "Action plan selected the wrong test");
  result.checks.push("DFD flow → finding → control → verification test exact-ID trace");
}

async function inspectMobileModel(page, options, result) {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(`http://127.0.0.1:${options.port}/model.html?id=${encodeURIComponent(options.projectId)}`, {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#threat-diagram-canvas canvas", {timeout: 15000});
  const firstNode = await page.locator("#diagram-text-content [data-outline-type='node']").first().count();
  assert.ok(firstNode, "mobile model does not expose a keyboard-selectable outline");
  await page.locator("#diagram-text-alternative summary").click();
  await page.locator("#diagram-text-content [data-outline-type='node']").first().click();
  const state = await page.evaluate(() => ({role: document.querySelector("#node-inspector")?.getAttribute("role"), modal: document.querySelector("#node-inspector")?.getAttribute("aria-modal"), activeInside: document.querySelector("#node-inspector")?.contains(document.activeElement)}));
  assert.deepEqual(state, {role: "dialog", modal: "true", activeInside: true}, "mobile model inspector is not an accessible dialog");
  await page.keyboard.press("Escape");
  assert.equal(await page.locator("#node-inspector").getAttribute("aria-modal"), null, "mobile model inspector did not restore after Escape");
  result.checks.push("390x844 outline selection → modal inspector → Escape");
}

async function main() {
  const options = parseArgs(process.argv);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-package-d-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  options.port = 19900 + Math.floor(Math.random() * 700);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(options.port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(options.port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "U7-Package-D", project_id: options.projectId, trace: null, checks: [], screenshots: [], errors: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${options.port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 1440, height: 900}});
    try {
      await page.goto(`http://127.0.0.1:${options.port}/model.html?id=${encodeURIComponent(options.projectId)}`, {waitUntil: "networkidle", timeout: 20000});
      result.trace = await fetchTrace(page);
      await inspectCanvas(page, result.trace, options, result);
      await inspectTrace(page, result.trace, options, result);
      await inspectMobileModel(page, options, result);
    } finally { await page.close(); }
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {check_count: result.checks.length, error_count: result.errors.length, screenshot_count: result.screenshots.length};
  if (options.output) {
    const output = path.resolve(options.output);
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "Package D Chromium trace gate failed");
  assert.equal(result.checks.length, 3, "Package D did not complete all trace/canvas checks");
}

main().catch(error => { console.error(`U7 Package D gate error: ${error.message}`); process.exitCode = 1; });
