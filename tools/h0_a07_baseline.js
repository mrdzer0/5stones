#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {execFileSync, spawn} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const PROJECT_ID = process.env.H0_PROJECT_ID || "9b3aeb5d-1e7b-4f62-809c-0f74b33a1510";
const ROUTES = ["analysis", "model", "findings", "action-plan", "evidence", "report"];
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900},
];

function loadPlaywright() {
  try { return require("playwright"); } catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve("playwright", {paths: [globalRoot]}));
  }
}

function parseArgs(argv) {
  const result = {output: null, screenshotDir: null};
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === "--output") result.output = argv[++index];
    if (argv[index] === "--screenshot-dir") result.screenshotDir = argv[++index];
  }
  return result;
}

function waitForServer(url, timeoutMs = 20000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, response => {
        response.resume();
        if (response.statusCode === 200) return resolve();
        if (Date.now() - started > timeoutMs) return reject(new Error(`server returned ${response.statusCode}: ${url}`));
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

function urlFor(port, route) {
  return `http://127.0.0.1:${port}/${route}.html?id=${encodeURIComponent(PROJECT_ID)}`;
}

async function waitForWorkspace(page) {
  await page.waitForSelector("h1", {state: "visible", timeout: 15000});
  await page.waitForTimeout(250);
}

async function surfaceMetrics(page) {
  return page.evaluate(() => {
    const visible = element => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && box.width > 0 && box.height > 0;
    };
    const h1 = document.querySelector("h1");
    const body = document.body;
    return {
      h1: h1?.textContent.trim() || "",
      documentHeight: Math.max(body.scrollHeight, document.documentElement.scrollHeight),
      horizontalOverflow: document.documentElement.scrollWidth > window.innerWidth + 1,
      visibleActions: [...document.querySelectorAll("a, button")].filter(visible).length,
      visibleBlankActions: [...document.querySelectorAll("a, button")].filter(element => visible(element) && !element.textContent.trim() && !element.getAttribute("aria-label")).length,
      primaryNavigation: [...document.querySelectorAll(".sidebar-nav a")].filter(visible).map(element => element.textContent.trim()),
    };
  });
}

async function capture(page, result, route, state, viewport, screenshotDir, {synthetic = false} = {}) {
  const metrics = await surfaceMetrics(page);
  const target = screenshotDir ? path.join(screenshotDir, `${route}-${viewport.name}-${state}.png`) : null;
  if (target) await page.screenshot({path: target, animations: "disabled"});
  result.captures.push({route, state, viewport: viewport.name, width: viewport.width, height: viewport.height, synthetic, metrics, screenshot: target});
}

async function openRoute(browser, port, route, viewport, result, screenshotDir) {
  const page = await browser.newPage({viewport: {width: viewport.width, height: viewport.height}});
  try {
    page.on("pageerror", error => result.page_errors.push({route, state: "navigation", message: error.message}));
    page.on("requestfailed", request => {
      if (request.url().includes("/api/")) result.failed_requests.push({route, url: request.url(), failure: request.failure()?.errorText || "failed"});
    });
    await page.goto(urlFor(port, route), {waitUntil: "networkidle", timeout: 20000});
    await waitForWorkspace(page);
    return page;
  } catch (error) {
    result.errors.push({route, state: "navigation", message: error.message});
    await page.close();
    return null;
  }
}

async function main() {
  const options = parseArgs(process.argv);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-h0-a07-server-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 20600 + Math.floor(Math.random() * 300);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {
    cwd: REPO,
    env: {...process.env, DATA_DIR: dataDir, PORT: String(port)},
    stdio: ["ignore", "pipe", "pipe"],
  });
  const result = {
    contract: "H0-A07",
    project_id: PROJECT_ID,
    browser: "Playwright Chromium",
    playwright_version: playwright.chromium ? "installed" : "unknown",
    captured_at: "2026-09-24",
    viewports: VIEWPORTS,
    captures: [],
    errors: [],
    page_errors: [],
    failed_requests: [],
  };
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const screenshotDir = options.screenshotDir ? path.resolve(options.screenshotDir) : null;
    if (screenshotDir) fs.mkdirSync(screenshotDir, {recursive: true});

    for (const viewport of VIEWPORTS) {
      for (const route of ROUTES) {
        const page = await openRoute(browser, port, route, viewport, result, screenshotDir);
        if (!page) continue;
        await capture(page, result, route, "initial", viewport, screenshotDir);
        await page.close();
      }
    }

    const mobile = {name: "mobile", width: 390, height: 844};
    for (const route of ROUTES) {
      const page = await openRoute(browser, port, route, mobile, result, screenshotDir);
      if (!page) continue;
      const toggle = page.locator("#sidebar-toggle");
      if (await toggle.count()) {
        await toggle.click();
        await page.waitForTimeout(100);
        await capture(page, result, route, "sidebar-open", mobile, screenshotDir);
      }
      await page.close();
    }

    for (const route of ["findings", "action-plan", "evidence"]) {
      const page = await openRoute(browser, port, route, mobile, result, screenshotDir);
      if (!page) continue;
      const toggleId = route === "findings" ? "#findings-filters-toggle" : route === "action-plan" ? "#action-filters-toggle" : "#evidence-filters-toggle";
      await page.locator(toggleId).click();
      await page.waitForTimeout(100);
      await capture(page, result, route, "filters-open", mobile, screenshotDir);
      await page.close();
    }

    for (const route of ["findings", "action-plan", "evidence"]) {
      const page = await openRoute(browser, port, route, mobile, result, screenshotDir);
      if (!page) continue;
      const selector = route === "findings" ? "#findings-list [data-finding-id]" : route === "action-plan" ? "#action-list [data-action-key]" : "#evidence-list [data-evidence-key]";
      await page.waitForSelector(selector, {state: "visible", timeout: 15000});
      await page.locator(selector).first().click();
      await page.waitForTimeout(150);
      await capture(page, result, route, "inspector-open", mobile, screenshotDir);
      await page.close();
    }

    const warningPage = await openRoute(browser, port, "analysis", mobile, result, screenshotDir);
    if (warningPage) {
      const warningState = await warningPage.evaluate(() => {
        const banner = document.querySelector("#analysis-run-state");
        if (!banner) return "missing";
        if (getComputedStyle(banner).display === "none") {
          banner.style.display = "grid";
          document.querySelector("#analysis-run-state-title").textContent = "Baseline warning state";
          document.querySelector("#analysis-run-state-message").textContent = "A phase needs review before results are used.";
          document.querySelector("#analysis-blocker-phases").textContent = "Synthetic visual baseline state";
          return "synthetic";
        }
        return "live";
      });
      await capture(warningPage, result, "analysis", "warning", mobile, screenshotDir, {synthetic: warningState === "synthetic"});
      await warningPage.close();
    }

    const modelPage = await openRoute(browser, port, "model", mobile, result, screenshotDir);
    if (modelPage) {
      await modelPage.locator("#model-inspector-rail").waitFor({state: "visible", timeout: 15000});
      await capture(modelPage, result, "model", "boundary-rail-current", mobile, screenshotDir);
      await modelPage.close();
    }

    const evidencePage = await openRoute(browser, port, "evidence", mobile, result, screenshotDir);
    if (evidencePage) {
      const contextTrigger = evidencePage.locator("#open-context-editor:visible, #open-context-editor-inline:visible").first();
      await contextTrigger.click();
      await evidencePage.locator("#context-editor[open]").waitFor({state: "visible", timeout: 5000});
      await capture(evidencePage, result, "evidence", "context-editor-open", mobile, screenshotDir);
      await evidencePage.close();
    }
  } catch (error) {
    result.errors.push({state: "runner", message: error.message});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {
    initial_matrix: result.captures.filter(item => item.state === "initial").length,
    interactive_states: result.captures.filter(item => item.state !== "initial").length,
    screenshot_count: result.captures.filter(item => item.screenshot).length,
    error_count: result.errors.length,
    page_error_count: result.page_errors.length,
    failed_request_count: result.failed_requests.length,
  };
  if (options.output) {
    const output = path.resolve(options.output);
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.summary.initial_matrix, ROUTES.length * VIEWPORTS.length, "H0-A07 initial matrix incomplete");
  assert.equal(result.errors.length, 0, "H0-A07 baseline runner failed");
  assert.equal(result.page_errors.length, 0, "H0-A07 found page errors");
  assert.equal(result.failed_requests.length, 0, "H0-A07 found failed API requests");
}

main().catch(error => { console.error(`H0-A07 baseline error: ${error.message}`); process.exitCode = 1; });
