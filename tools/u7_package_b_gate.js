#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {execFileSync, spawn} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const ROUTES = ["analysis.html", "model.html", "findings.html", "action-plan.html", "evidence.html", "report.html"];
const VIEWPORTS = [
  {name: "small-mobile", width: 320, height: 844},
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900}
];

function loadPlaywright() {
  try { return require("playwright"); } catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve("playwright", {paths: [globalRoot]}));
  }
}

function parseArgs(argv) {
  const result = {output: null, projectId: process.env.U7_PROJECT_ID || "9b3aeb5d-1e7b-4f62-809c-0f74b33a1510"};
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--output") result.output = argv[++i];
    else if (argv[i] === "--project-id") result.projectId = argv[++i];
  }
  return result;
}

function waitForServer(url, timeoutMs = 15000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const probe = () => {
      const request = http.get(url, (response) => {
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

async function inspectPage(page) {
  return page.evaluate(() => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity) !== 0 && box.width > 0 && box.height > 0;
    };
    const actionItems = [...document.querySelectorAll(".topbar-actions .btn")].filter(visible).map((element) => {
      const box = element.getBoundingClientRect();
      return {
        id: element.id || null,
        text: element.textContent.trim().replace(/\s+/g, " "),
        aria_label: element.getAttribute("aria-label") || "",
        title: element.getAttribute("title") || "",
        font_size: getComputedStyle(element).fontSize,
        width: Math.round(box.width),
        height: Math.round(box.height)
      };
    });
    const selects = [...document.querySelectorAll("select")].filter(visible).map((element) => ({
      id: element.id || null,
      name: element.getAttribute("aria-label") || element.labels?.[0]?.textContent.trim() || element.getAttribute("title") || ""
    }));
    return {
      h1_count: document.querySelectorAll("h1").length,
      horizontal_overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
      action_items: actionItems,
      blank_actions: actionItems.filter((item) => !item.text && !item.aria_label && !item.title),
      undersized_actions: actionItems.filter((item) => item.width < 36 || item.height < 36),
      unnamed_selects: selects.filter((item) => !item.name),
      report_metadata_surface: Boolean(document.querySelector("#report-formal-meta"))
    };
  });
}

async function main() {
  const options = parseArgs(process.argv);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-package-b-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 19000 + Math.floor(Math.random() * 800);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "U7-Package-B", project_id: options.projectId, pages: [], errors: [], summary: null};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    for (const viewport of VIEWPORTS) {
      for (const route of ROUTES) {
        const page = await browser.newPage({viewport});
        try {
          await page.goto(`http://127.0.0.1:${port}/${route}?project_id=${encodeURIComponent(options.projectId)}`, {waitUntil: "networkidle", timeout: 20000});
          await page.waitForTimeout(500);
          result.pages.push({route, viewport: viewport.name, width: viewport.width, ...await inspectPage(page)});
        } catch (error) {
          result.errors.push({route, viewport: viewport.name, message: error.message});
        } finally { await page.close(); }
      }
    }
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  const pageIssues = result.pages.flatMap((page) => [
    ...page.blank_actions.map((item) => ({route: page.route, viewport: page.viewport, issue: "blank_action", id: item.id})),
    ...page.undersized_actions.map((item) => ({route: page.route, viewport: page.viewport, issue: "undersized_action", id: item.id, width: item.width, height: item.height})),
    ...page.unnamed_selects.map((item) => ({route: page.route, viewport: page.viewport, issue: "unnamed_select", id: item.id})),
    ...(page.horizontal_overflow ? [{route: page.route, viewport: page.viewport, issue: "horizontal_overflow"}] : []),
    ...(page.h1_count < 1 ? [{route: page.route, viewport: page.viewport, issue: "missing_h1"}] : [])
  ]);
  result.summary = {page_count: result.pages.length, error_count: result.errors.length, issue_count: pageIssues.length, issues: pageIssues};
  if (options.output) { const output = path.resolve(options.output); fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n"); }
  console.log(JSON.stringify({...result, pages: undefined}, null, 2));
  assert.equal(result.errors.length, 0, "Package B browser navigation errors detected");
  assert.equal(result.pages.length, ROUTES.length * VIEWPORTS.length, "Package B did not cover the complete matrix");
  assert.equal(pageIssues.length, 0, "Package B UI/UX contract failed");
}

main().catch((error) => { console.error(`U7 Package B gate error: ${error.message}`); process.exitCode = 1; });
