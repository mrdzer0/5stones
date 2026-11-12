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
const ROUTES = ["analysis", "model", "findings", "action-plan", "evidence", "report"];
const VIEWPORTS = [
  {name: "narrow", width: 320, height: 760},
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900},
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

function visible(element) {
  const style = getComputedStyle(element);
  const box = element.getBoundingClientRect();
  return box.width > 0 && box.height > 0 && style.display !== "none" && style.visibility !== "hidden";
}

async function inspectSurface(page, route, viewport) {
  return page.evaluate(({route, viewport}) => {
    const isVisible = element => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return box.width > 0 && box.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    };
    const overflow = [...document.querySelectorAll("body *")].map(element => {
      const box = element.getBoundingClientRect();
      return {element, box};
    }).filter(({element, box}) => isVisible(element) && (box.right > innerWidth + 1 || box.left < -1))
      .sort((a, b) => Math.max(b.box.right - innerWidth, -b.box.left) - Math.max(a.box.right - innerWidth, -a.box.left))
      .slice(0, 8)
      .map(({element, box}) => ({tag: element.tagName.toLowerCase(), id: element.id, className: String(element.className || "").slice(0, 100), left: Math.round(box.left), right: Math.round(box.right), width: Math.round(box.width), text: String(element.textContent || "").trim().replace(/\s+/g, " ").slice(0, 90)}));
    const rightmost = [...document.querySelectorAll("body *")].map(element => {
      const box = element.getBoundingClientRect();
      return {element, box};
    }).filter(({element}) => isVisible(element)).sort((a, b) => b.box.right - a.box.right).slice(0, 4)
      .map(({element, box}) => ({tag: element.tagName.toLowerCase(), id: element.id, className: String(element.className || "").slice(0, 100), left: Math.round(box.left), right: Math.round(box.right), width: Math.round(box.width), text: String(element.textContent || "").trim().replace(/\s+/g, " ").slice(0, 90)}));
    const orientation = {
      analysis: ["#analysis-overview-status", "#analysis-next-actions-list"],
      model: ["#model-readiness-summary", "#btn-diagram-fit"],
      findings: ["#findings-orientation-status", "#findings-orientation-next", "#start-findings-guided"],
      "action-plan": ["#action-orientation-status", "#action-primary-review"],
      evidence: ["#evidence-orientation-status", "#evidence-orientation-next", "#open-context-editor"],
      report: ["#report-orientation-status", "#report-orientation-next", "#sign-report"],
    }[route].map(selector => ({selector, present: Boolean(document.querySelector(selector)), visible: Boolean(document.querySelector(selector) && isVisible(document.querySelector(selector)))}));
    const targetSelectors = "button, a[href], input, select, textarea, [role=button], summary";
    const smallTargets = [...document.querySelectorAll(targetSelectors)].filter(isVisible).map(element => {
      const box = element.getBoundingClientRect();
      return {tag: element.tagName.toLowerCase(), id: element.id, className: String(element.className || "").slice(0, 80), href: element.getAttribute("href"), text: String(element.textContent || element.getAttribute("aria-label") || element.getAttribute("placeholder") || "").trim().replace(/\s+/g, " ").slice(0, 80), width: Math.round(box.width), height: Math.round(box.height)};
    }).filter(item => item.width < 40 || item.height < 40).slice(0, 12);
    const essentialSelectors = [
      "h1", "h2", "h3", ".page-title", ".page-subtitle", ".analysis-overview-kicker",
      ".analysis-overview-guidance", ".analysis-overview-status", ".analysis-next-actions-heading",
      ".findings-heading p", ".action-plan-heading p", ".evidence-heading p", ".model-workspace-header p",
      ".ux-orientation-item span", ".ux-orientation-item strong", ".btn", ".finding-list-item > strong",
      ".finding-list-description", ".action-list-item > strong", ".action-list-meta", ".evidence-list-item > strong",
      ".evidence-list-item > p", ".report-header-meta", ".report-formal-meta span", ".report-formal-meta strong",
    ];
    const smallText = [...new Set(essentialSelectors.flatMap(selector => [...document.querySelectorAll(selector)]))]
      .filter(isVisible)
      .map(element => ({selector: element.id ? `#${element.id}` : element.className ? `.${String(element.className).split(/\s+/)[0]}` : element.tagName.toLowerCase(), size: parseFloat(getComputedStyle(element).fontSize), text: String(element.textContent || "").trim().replace(/\s+/g, " ").slice(0, 90)}))
      .filter(item => item.size < 12)
      .slice(0, 20);
    return {
      route, viewport,
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
      documentWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
      viewportWidth: innerWidth,
      overflowElements: overflow,
      rightmost,
      orientation,
      smallTargets,
      smallText,
      documentHeight: document.documentElement.scrollHeight,
    };
  }, {route, viewport});
}

async function main() {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const report = fixtureReport(fixture);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-uxm3-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 20200 + Math.floor(Math.random() * 500);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "UX-M3/H3", project_id: fixture.project.project_id, matrix: [], checks: [], errors: [], page_errors: [], failed_requests: []};
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
      for (const route of ROUTES) {
        await page.goto(pageUrl(port, route, fixture.project.project_id), {waitUntil: "domcontentloaded", timeout: 20000});
        await page.waitForTimeout(300);
        const surface = await inspectSurface(page, route, viewport);
        assert.equal(surface.overflow, false, `${route} overflows at ${viewport.width}px: ${JSON.stringify({documentWidth: surface.documentWidth, bodyWidth: surface.bodyWidth, viewportWidth: surface.viewportWidth, elements: surface.overflowElements, rightmost: surface.rightmost})}`);
        assert.ok(surface.orientation.every(item => item.present && item.visible), `${route} is missing first-viewport orientation: ${JSON.stringify(surface.orientation)}`);
        assert.equal(surface.smallTargets.length, 0, `${route} has undersized visible targets: ${JSON.stringify(surface.smallTargets)}`);
        assert.equal(surface.smallText.length, 0, `${route} has essential text below 12px: ${JSON.stringify(surface.smallText)}`);
        result.matrix.push(surface);
      }
    }
    await page.setViewportSize({width: 320, height: 760});
    await page.goto(pageUrl(port, "findings", fixture.project.project_id), {waitUntil: "domcontentloaded", timeout: 20000});
    await page.waitForTimeout(300);
    await page.evaluate(() => { document.documentElement.style.fontSize = "32px"; });
    const textZoom = await inspectSurface(page, "findings", {name: "text-zoom-200", width: 320, height: 760});
    assert.equal(textZoom.overflow, false, `200% text zoom overflows: ${JSON.stringify({documentWidth: textZoom.documentWidth, viewportWidth: textZoom.viewportWidth, elements: textZoom.overflowElements, rightmost: textZoom.rightmost})}`);
    assert.ok(textZoom.orientation.every(item => item.present && item.visible), "200% text zoom lost findings orientation");
    await page.evaluate(() => { document.documentElement.style.fontSize = ""; });
    result.checks.push("200% text zoom reflow keeps orientation and no horizontal overflow");

    await page.setViewportSize({width: 1280, height: 480});
    for (const route of ROUTES) {
      await page.goto(pageUrl(port, route, fixture.project.project_id), {waitUntil: "domcontentloaded", timeout: 20000});
      await page.waitForTimeout(220);
      const short = await page.evaluate(({route}) => {
        const heading = document.querySelector("h1");
        const box = heading?.getBoundingClientRect();
        return {route, headingVisible: Boolean(box && box.width > 0 && box.height > 0), overflow: document.documentElement.scrollWidth > innerWidth + 1};
      }, {route});
      assert.equal(short.overflow, false, `${route} short-height viewport overflows`);
      assert.equal(short.headingVisible, true, `${route} loses page goal at short height`);
    }
    result.checks.push("short-height 1280x480 keeps page goal visible without horizontal overflow");

    await page.goto(pageUrl(port, "findings", fixture.project.project_id), {waitUntil: "domcontentloaded", timeout: 20000});
    await page.emulateMedia({reducedMotion: "reduce", forcedColors: "active"});
    const media = await page.evaluate(() => ({reduced: matchMedia("(prefers-reduced-motion: reduce)").matches, forced: matchMedia("(forced-colors: active)").matches, transition: getComputedStyle(document.querySelector(".btn")).transitionDuration}));
    assert.equal(media.reduced, true, "reduced motion was not applied");
    assert.equal(media.forced, true, "forced colors was not applied");
    assert.ok(parseFloat(media.transition) <= 0.01, `reduced motion transition remains ${media.transition}`);
    result.checks.push("route × 5 viewport readability/overflow/orientation matrix");
    result.checks.push("40px interactive target and essential text >=12px gate");
    result.checks.push("reduced-motion and forced-colors media validation");
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {matrix_count: result.matrix.length, check_count: result.checks.length, error_count: result.errors.length, page_error_count: result.page_errors.length, failed_request_count: result.failed_requests.length};
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "UX-M3 Chromium readability gate failed");
  assert.equal(result.page_errors.length, 0, `UX-M3 found page errors: ${result.page_errors.join(" | ")}`);
  assert.equal(result.failed_requests.length, 0, "UX-M3 found failed API requests");
  assert.equal(result.matrix.length, ROUTES.length * VIEWPORTS.length, "UX-M3 did not complete the full matrix");
}

if (require.main === module) main().catch(error => { console.error(`UX-M3 gate error: ${error.message}`); process.exitCode = 1; });
