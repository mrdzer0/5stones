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
const ROUTES = ["analysis", "model", "findings", "action-plan", "evidence", "report"];
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900},
];
const WORKSPACES = [
  {route: "findings", trigger: "findings-filters-toggle", dialog: "findings-filter-dialog", search: "findings-filter-search", param: "ff", list: "#findings-list", row: "[data-finding-id]", panel: "#findings-inspector", attr: "data-finding-id", option: "STRIDE"},
  {route: "action-plan", trigger: "action-filters-toggle", dialog: "action-filter-dialog", search: "action-filter-search", param: "atype", list: "#action-list", row: "[data-action-key]", panel: "#action-inspector", attr: "data-action-key", option: "control"},
  {route: "evidence", trigger: "evidence-filters-toggle", dialog: "evidence-filter-dialog", search: "evidence-filter-search", param: "etype", list: "#evidence-list", row: "[data-evidence-key]", panel: "#evidence-inspector", attr: "data-evidence-key", option: "gap"},
];

function parseArgs(argv) {
  const result = {output: null, screenshotDir: null};
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === "--output") result.output = argv[++index];
    else if (argv[index] === "--screenshot-dir") result.screenshotDir = argv[++index];
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function loadAxeSource() {
  let axePath;
  try { axePath = require.resolve("axe-core/axe.min.js"); }
  catch (_) {
    const globalRoot = execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    axePath = require.resolve("axe-core/axe.min.js", {paths: [globalRoot]});
  }
  return {version: require(path.join(path.dirname(axePath), "package.json")).version, source: fs.readFileSync(axePath, "utf8")};
}

function attachDiagnostics(page, result, label) {
  page.on("pageerror", error => result.page_errors.push({label, message: error.message}));
  page.on("console", message => {
    if (["error", "warning"].includes(message.type())) result.console_messages.push({label, type: message.type(), text: message.text()});
  });
  page.on("requestfailed", request => {
    if (request.url().includes("/api/") && !request.url().includes("/api/ux-telemetry/events")) result.failed_requests.push({label, url: request.url(), failure: request.failure()?.errorText || "failed"});
  });
  page.on("response", response => {
    if (response.url().includes("/api/") && response.status() >= 400) result.http_errors.push({label, url: response.url(), status: response.status()});
  });
}

async function openRoute(page, port, route, projectId) {
  await page.goto(pageUrl(port, route, projectId), {waitUntil: "networkidle", timeout: 20000});
  const ready = {
    analysis: "#analysis-overview",
    model: "#threat-diagram-canvas canvas",
    findings: "#findings-list [data-finding-id]",
    "action-plan": "#action-list [data-action-key]",
    evidence: "#evidence-list [data-evidence-key]",
    report: "#report-dfd-snapshot-caption",
  }[route];
  await page.waitForSelector(ready, {state: "visible", timeout: 15000});
  await page.waitForTimeout(100);
}

function visibleBox(element) {
  const box = element.getBoundingClientRect();
  const style = getComputedStyle(element);
  return box.width > 0 && box.height > 0 && style.display !== "none" && style.visibility !== "hidden";
}

async function inspectSurface(page, route, viewport) {
  return page.evaluate(({route, viewport}) => {
    const isVisible = element => {
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return box.width > 0 && box.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    };
    const clickable = [...document.querySelectorAll("button, a[href], input, select, textarea, summary")].filter(isVisible);
    const undersized = clickable.map(element => {
      const box = element.getBoundingClientRect();
      return {tag: element.tagName.toLowerCase(), id: element.id, text: (element.textContent || element.getAttribute("aria-label") || element.getAttribute("placeholder") || "").trim().replace(/\s+/g, " ").slice(0, 80), width: Math.round(box.width), height: Math.round(box.height)};
    }).filter(item => item.width < 32 || item.height < 32).filter(item => item.tag !== "summary" || item.id);
    const focusTarget = clickable.find(element => !element.matches(".sidebar a")) || clickable[0];
    focusTarget?.focus({preventScroll: true});
    const active = document.activeElement;
    const activeBox = active?.getBoundingClientRect();
    const overlap = (a, b) => a && b && Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left)) * Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
    const fixedOccluders = [...document.querySelectorAll("body *")].filter(element => {
      if (element === active || element.contains(active) || !isVisible(element)) return false;
      const position = getComputedStyle(element).position;
      return position === "fixed" && Number(getComputedStyle(element).zIndex || 0) > 0;
    }).map(element => ({id: element.id, className: String(element.className || "").slice(0, 80), area: overlap(activeBox, element.getBoundingClientRect())})).filter(item => item.area > 2);
    return {
      route,
      viewport,
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: innerWidth,
      headingVisible: Boolean(document.querySelector("h1") && isVisible(document.querySelector("h1"))),
      undersized,
      fixedOccluders,
      documentHeight: document.documentElement.scrollHeight,
    };
  }, {route, viewport});
}

async function runAxe(page, axeSource) {
  await page.addScriptTag({content: axeSource});
  return page.evaluate(async () => {
    const result = await window.axe.run(document, {resultTypes: ["violations", "incomplete"]});
    return {
      violations: result.violations.map(rule => ({id: rule.id, impact: rule.impact, help: rule.help, nodes: rule.nodes.map(node => ({target: node.target}))})),
      incomplete: result.incomplete.map(rule => ({id: rule.id, impact: rule.impact, nodes: rule.nodes.map(node => ({target: node.target}))})),
    };
  });
}

async function inspectViewportMatrix(page, port, projectId, result, options) {
  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({width: viewport.width, height: viewport.height});
    for (const route of ROUTES) {
      const started = Date.now();
      await openRoute(page, port, route, projectId);
      const surface = await inspectSurface(page, route, viewport);
      assert.equal(surface.overflow, false, `${route} has horizontal overflow at ${viewport.width}: ${JSON.stringify(surface)}`);
      assert.equal(surface.headingVisible, true, `${route} loses its page goal at ${viewport.width}`);
      assert.deepEqual(surface.fixedOccluders, [], `${route} has a fixed overlay over the focused item at ${viewport.width}: ${JSON.stringify(surface.fixedOccluders)}`);
      assert.ok(surface.undersized.length <= 2, `${route} has too many undersized visible controls at ${viewport.width}: ${JSON.stringify(surface.undersized)}`);
      result.matrix.push({...surface, load_ms: Date.now() - started});
      if (options.screenshotDir && (viewport.width === 390 || viewport.width === 1440)) {
        fs.mkdirSync(path.resolve(options.screenshotDir), {recursive: true});
        const file = path.join(path.resolve(options.screenshotDir), `${route}-${viewport.width}.png`);
        await page.screenshot({path: file, fullPage: false});
        result.screenshots.push(file);
      }
    }
  }
  result.checks.push("six-route × 390/768/1280/1440 Chromium matrix: headings, overflow, focus occlusion, and target geometry");
}

async function inspectNavigationAndOverview(page, port, projectId, result) {
  const expected = {
    workspace: ["Dashboard", "New project"],
    project: ["Overview", "DFD model", "Findings", "Action plan", "Evidence", "Report & sign-off"],
    configuration: ["Settings & BYOK"],
  };
  const signatures = [];
  for (const route of ROUTES) {
    await page.setViewportSize({width: 1280, height: 900});
    await openRoute(page, port, route, projectId);
    const snapshot = await page.evaluate(() => {
      const sections = [...document.querySelectorAll("#app-sidebar .sidebar-section")];
      return {
        labels: sections.map(section => section.querySelector(".sidebar-section-label")?.textContent.trim()),
        items: sections.map(section => [...section.querySelectorAll(".sidebar-nav a")].map(link => link.textContent.replace(/\s+/g, " ").trim())),
        active: [...document.querySelectorAll("#project-workflow-nav .project-workflow-link.active")].map(link => ({id: link.id, current: link.getAttribute("aria-current")})),
        workflow: [...document.querySelectorAll("#project-workflow-nav .project-workflow-link")].map(link => link.querySelector(".project-workflow-copy > span")?.textContent.trim()),
        svgCount: document.querySelectorAll("#app-sidebar .sidebar-nav a svg").length,
      };
    });
    assert.deepEqual(snapshot.labels, ["Workspace", "Configuration"], `${route} sidebar sections drifted`);
    assert.deepEqual(snapshot.items, [expected.workspace, expected.configuration], `${route} sidebar labels/order drifted`);
    assert.deepEqual(snapshot.workflow, expected.project, `${route} project workflow labels/order drifted`);
    assert.equal(snapshot.svgCount, 3, `${route} global sidebar icon contract drifted`);
    assert.deepEqual(snapshot.active, [{id: `nav-${route === "analysis" ? "analysis" : route}`, current: "step"}], `${route} workflow active state drifted`);
    signatures.push(JSON.stringify({...snapshot, active: []}));
  }
  assert.equal(new Set(signatures).size, 1, "sidebar structure is not shared across project routes");
  result.checks.push("canonical sidebar contract: same sections, labels, icons, order, active state, and project workflow across six routes");

  await page.setViewportSize({width: 1280, height: 900});
  await openRoute(page, port, "findings", projectId);
  await Promise.all([
    page.waitForURL(url => new URL(url).pathname.endsWith("/model.html"), {timeout: 10000}),
    page.locator("#nav-model").click(),
  ]);
  assert.equal(new URL(page.url()).searchParams.get("id"), projectId, "desktop workflow navigation lost project identity");
  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "model", projectId);
  await Promise.all([
    page.waitForURL(url => new URL(url).pathname.endsWith("/report.html"), {timeout: 10000}),
    page.locator("#project-workflow-stage").selectOption("report"),
  ]);
  assert.equal(new URL(page.url()).searchParams.get("id"), projectId, "mobile workflow picker lost project identity");
  result.checks.push("desktop workflow link and mobile stage picker preserve project identity while moving between stages");

  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "findings", projectId);
  await page.locator("#sidebar-toggle").click();
  assert.equal(await page.locator("body").evaluate(body => body.classList.contains("sidebar-mobile-open")), true, "mobile sidebar did not open");
  assert.equal(await page.locator("#app-sidebar").isVisible(), true, "opened mobile sidebar is not visible");
  assert.equal(await page.locator("#app-sidebar").locator("a").first().evaluate(link => link === document.activeElement), true, "mobile sidebar did not move focus into navigation");
  await page.keyboard.press("Escape");
  assert.equal(await page.locator("body").evaluate(body => body.classList.contains("sidebar-mobile-open")), false, "mobile sidebar did not close on Escape");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "sidebar-toggle", "mobile sidebar did not return focus to toggle");
  result.checks.push("mobile sidebar open → focus containment → Escape → focus return journey");

  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "analysis", projectId);
  const metric = await page.locator(".analysis-overview-stat.is-critical").evaluate(card => ({
    scored: card.querySelector("#overview-scored")?.textContent.trim(),
    critical: card.querySelector("#overview-critical")?.textContent.trim(),
    high: card.querySelector("#overview-high")?.textContent.trim(),
    scrollWidth: card.scrollWidth,
    clientWidth: card.clientWidth,
    smallText: card.querySelector("small")?.textContent.replace(/\s+/g, " ").trim(),
  }));
  const readOverviewGrid = () => page.locator(".analysis-overview-grid").evaluate(grid => ({
    childCount: grid.children.length,
    columnCount: getComputedStyle(grid).gridTemplateColumns.split(" ").length,
    emptyCells: [...grid.children].filter(child => !child.textContent.trim()).length,
  }));
  const mobileOverviewGrid = await readOverviewGrid();
  await page.setViewportSize({width: 1280, height: 900});
  const desktopOverviewGrid = await readOverviewGrid();
  const desktopRailGeometry = await page.evaluate(() => {
    const context = document.querySelector("#project-context-card")?.getBoundingClientRect();
    const overview = document.querySelector("#analysis-overview")?.getBoundingClientRect();
    return context && overview
      ? {contextLeft: Math.round(context.left), contextWidth: Math.round(context.width), overviewLeft: Math.round(overview.left), overviewWidth: Math.round(overview.width)}
      : null;
  });
  await page.setViewportSize({width: 390, height: 844});
  assert.match(metric.scored || "", /^\d+$/, `Scored risk is not a total numeric value: ${JSON.stringify(metric)}`);
  assert.match(metric.critical || "", /^\d+$/, `Critical severity is not numeric: ${JSON.stringify(metric)}`);
  assert.match(metric.high || "", /^\d+$/, `High severity is not numeric: ${JSON.stringify(metric)}`);
  assert.match(metric.smallText || "", /critical.*high/i, `Scored risk detail copy is incomplete: ${JSON.stringify(metric)}`);
  assert.ok(metric.scrollWidth <= metric.clientWidth + 1, `Scored risk card overflows: ${JSON.stringify(metric)}`);
  assert.deepEqual(mobileOverviewGrid, {childCount: 3, columnCount: 2, emptyCells: 0}, `Analysis overview summary is invalid on mobile: ${JSON.stringify(mobileOverviewGrid)}`);
  assert.deepEqual(desktopOverviewGrid, {childCount: 3, columnCount: 3, emptyCells: 0}, `Analysis overview summary has an empty or unbalanced desktop card cell: ${JSON.stringify(desktopOverviewGrid)}`);
  assert.ok(desktopRailGeometry && desktopRailGeometry.contextLeft === desktopRailGeometry.overviewLeft && desktopRailGeometry.contextWidth === desktopRailGeometry.overviewWidth, `Analysis content rails are misaligned: ${JSON.stringify(desktopRailGeometry)}`);
  result.checks.push("Analysis Scored risk card separates total from Critical/High detail; summary grid has three balanced cards, no text overflow, and Context/lifecycle rails align");
}

async function inspectKeyboardWorkspaces(page, port, projectId, result) {
  for (const workspace of WORKSPACES) {
    await page.setViewportSize({width: 390, height: 844});
    await openRoute(page, port, workspace.route, projectId);
    const searchId = workspace.route === "findings" ? "findings-search" : workspace.route === "action-plan" ? "action-search" : "evidence-search";
    await page.locator(`#${searchId}`).click();
    await page.locator(`#${searchId}`).pressSequentially(workspace.route === "findings" ? "Checkout" : workspace.route === "action-plan" ? "checkout" : "provider", {delay: 4});
    assert.equal(await page.evaluate(() => document.activeElement?.id), searchId, `${workspace.route} search focus moved while typing`);
    await page.locator(`#${workspace.trigger}`).click();
    await page.locator(`#${workspace.dialog}`).waitFor({state: "visible"});
    await page.locator(`#${workspace.search}`).pressSequentially(workspace.option, {delay: 4});
    const option = page.locator(`#${workspace.dialog} [data-filter-option]`).filter({hasText: workspace.option}).first();
    await option.locator("input").check();
    await page.locator(`#${workspace.dialog} [data-filter-apply]`).click();
    assert.ok(new URL(page.url()).searchParams.getAll(workspace.param).length >= 1, `${workspace.route} filter was not committed to URL state`);
    // Applying a filter updates URL state and rerenders the list asynchronously.
    // Wait for the post-filter row before starting the keyboard journey so a
    // slow response cannot produce a false negative on the focus assertion.
    await page.waitForSelector(`${workspace.list} ${workspace.row}`, {state: "visible", timeout: 5000});
    await page.locator(workspace.list).focus();
    await page.keyboard.press("ArrowDown");
    const key = await page.evaluate(({selector, attr}) => document.activeElement?.getAttribute(attr), {selector: workspace.list, attr: workspace.attr});
    assert.ok(key, `${workspace.route} list did not expose a keyboard-selected row`);
    await page.keyboard.press("Enter");
    await page.waitForSelector(`${workspace.panel}[role="dialog"]`, {state: "visible", timeout: 5000});
    assert.equal(await page.evaluate(selector => document.querySelector(selector)?.contains(document.activeElement), workspace.panel), true, `${workspace.route} inspector did not receive focus`);
    await page.keyboard.press("Escape");
    assert.equal(await page.evaluate(({attr, key}) => document.activeElement?.getAttribute(attr) === key, {attr: workspace.attr, key}), true, `${workspace.route} Escape did not restore row focus`);
  }
  result.checks.push("keyboard-only search → filter dialog → apply → list row → inspector → Escape focus journey on Findings/Action Plan/Evidence");
}

async function inspectModelTouchAndOutline(page, port, projectId, fixture, result) {
  const trace = fixture.expected_trace.find(item => item.test_id && item.status !== "deferred");
  assert.ok(trace, "fixture has no executable trace");
  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "model", projectId);
  await page.locator("#model-review-trigger").click();
  await page.waitForFunction(() => document.body.classList.contains("model-sheet-open"));
  assert.equal(await page.locator("#model-inspector-rail").getAttribute("role"), "dialog");
  await page.keyboard.press("Escape");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "model-review-trigger");
  await page.locator("#diagram-text-alternative summary").click();
  await page.locator(`#diagram-text-content [data-outline-type="flow"][data-outline-id="${trace.flow_id}"]`).click();
  await page.waitForSelector("#node-inspector", {state: "visible"});
  assert.ok(await page.locator("#node-inspector").textContent().then(text => text.includes(trace.flow_id) || text.includes(trace.finding_id)), "accessible DFD outline did not select the requested flow");
  result.checks.push("mobile review sheet touch/click/Escape journey and accessible DFD outline selection");
}

async function inspectExactTrace(page, port, projectId, fixture, result) {
  const trace = fixture.expected_trace.find(item => item.test_id && item.status !== "deferred");
  const started = Date.now();
  await page.setViewportSize({width: 1280, height: 900});
  await openRoute(page, port, "model", projectId);
  await page.locator("#diagram-text-alternative summary").click();
  await page.locator(`#diagram-text-content [data-outline-type="flow"][data-outline-id="${trace.flow_id}"]`).click();
  await page.locator("#node-inspector a.model-finding-link").filter({hasText: trace.finding_id}).first().click();
  await page.waitForSelector(`#findings-list [data-finding-id="${trace.finding_id}"]`, {state: "visible", timeout: 15000});
  const controlLink = page.locator("#findings-inspector a.finding-dfd-link").filter({hasText: trace.control_id}).first();
  assert.equal(await controlLink.count(), 1, "finding did not expose the expected control link");
  await controlLink.click();
  await page.waitForSelector(`#action-list [data-action-key="control:${trace.control_id}"]`, {state: "visible", timeout: 15000});
  const testButton = page.locator(`#action-inspector [data-open-action="test:${trace.test_id}"]`).first();
  assert.equal(await testButton.count(), 1, "control did not expose the expected verification test");
  await testButton.click();
  await page.waitForSelector(`#action-list [data-action-key="test:${trace.test_id}"]`, {state: "visible", timeout: 15000});
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 60000, `exact trace exceeded 60 seconds: ${elapsed}ms`);
  result.journey_metrics.exact_trace_ms = elapsed;
  result.checks.push("human-like click trace DFD outline → finding → control → executable test with exact IDs");
}

async function inspectNoviceJourney(page, port, projectId, result) {
  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "model", projectId);
  await page.locator("#model-review-trigger").click();
  await page.locator("#start-boundary-guided").click();
  await page.waitForSelector("[data-guided-boundary]", {state: "visible", timeout: 5000});
  assert.equal(await page.locator("[data-guided-boundary]").count(), 3);
  assert.match(await page.locator("#inspector-body").textContent(), /Belum tahu/);
  await page.locator("[data-guided-boundary='candidate']").click();
  await page.waitForTimeout(100);

  await openRoute(page, port, "findings", projectId);
  await page.locator("#start-findings-guided").click();
  await page.waitForSelector("#finding-guided-review", {state: "visible", timeout: 5000});
  await page.locator("#finding-guided-next").fill("Confirm the source locator and assign an evidence owner.");
  await page.locator("#finding-guided-defer").click();
  await page.waitForTimeout(120);
  assert.match(await page.locator("body").textContent(), /Belum tahu|deferred/i);
  result.checks.push("novice guided boundary/finding review uses plain-language decisions and explicit deferred state");
}

async function inspectInteractiveA11y(page, port, projectId, axeSource, result) {
  const states = [];
  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "findings", projectId);
  await page.locator("#findings-list [data-finding-id]").first().click();
  states.push(["findings-inspector", await runAxe(page, axeSource)]);
  await page.keyboard.press("Escape");
  await page.locator("#findings-filters-toggle").click();
  states.push(["findings-filter-dialog", await runAxe(page, axeSource)]);
  await page.keyboard.press("Escape");

  await openRoute(page, port, "model", projectId);
  await page.locator("#model-review-trigger").click();
  states.push(["model-review-sheet", await runAxe(page, axeSource)]);
  await page.keyboard.press("Escape");

  await openRoute(page, port, "evidence", projectId);
  await page.locator("#open-context-editor-inline").click();
  states.push(["evidence-context-dialog", await runAxe(page, axeSource)]);
  await page.keyboard.press("Escape");

  await openRoute(page, port, "report", projectId);
  await page.locator(".report-export-menu > summary").click();
  states.push(["report-export-menu", await runAxe(page, axeSource)]);
  const serious = states.flatMap(([state, report]) => report.violations.filter(rule => ["serious", "critical"].includes(rule.impact)).map(rule => ({state, id: rule.id, impact: rule.impact})));
  result.a11y.states = states.map(([state, report]) => ({state, violations: report.violations, incomplete: report.incomplete}));
  const incomplete = result.a11y.states.flatMap(state => state.incomplete || []);
  result.a11y.incomplete_disposition = {
    status: incomplete.length ? "manual_review_required" : "none",
    rule_count: new Set(incomplete.map(rule => rule.id)).size,
    target_count: incomplete.reduce((total, rule) => total + rule.nodes.length, 0),
    rationale: incomplete.length
      ? "Axe could not conclusively classify every dynamic/contrast target in the live state. No serious/critical violations were reported; selectors remain listed for manual visual review before formal release sign-off."
      : "No incomplete axe checks were returned for the exercised interactive states.",
  };
  assert.deepEqual(serious, [], `interactive axe serious/critical violations: ${JSON.stringify(serious)}`);
  result.checks.push("axe on inspector, filter dialog, Model sheet, context dialog, and Report Export states: 0 serious/critical");
}

async function inspectRecoveryState(page, port, projectId, fixture, standardReport, result) {
  const recovery = clone(standardReport);
  recovery.analysis_run = {run_id: "fixture-run-recovery", status: "completed_with_warnings", warning_stages: ["stride"], retryable: true};
  recovery.analysis_recovery = {state: "previous_results_preserved", failed_stages: ["stride"], retryable: true, message: "STRIDE replacement was not validated; previous findings remain available."};
  recovery.quality_gate = {signoff_ready: false, summary: "Review the affected phase before sign-off.", blocking_reasons: ["STRIDE phase needs retry"]};
  await installFixtureMock(page, fixture, recovery);
  await page.setViewportSize({width: 1280, height: 900});
  await openRoute(page, port, "analysis", projectId);
  assert.equal(await page.locator("#analysis-run-state").isVisible(), true, "preserved-result blocker is not visible");
  assert.match(await page.locator("#analysis-run-state").textContent(), /Previous validated results preserved/i);
  assert.equal(await page.locator("#btn-retry-persisted-analysis").isVisible(), true, "affected-stage retry action is missing");
  const request = page.waitForRequest(request => request.url().endsWith(`/api/projects/${projectId}/analyze`) && request.method() === "POST", {timeout: 5000});
  await page.locator("#btn-retry-persisted-analysis").click();
  await request;
  result.checks.push("previous-results-preserved state exposes affected-phase retry and sends a deterministic retry action");
}

function buildLargeReport(base) {
  const large = clone(base);
  const threatBase = base.threats[0];
  large.threats = Array.from({length: 240}, (_, index) => ({
    ...clone(base.threats[index % base.threats.length] || threatBase),
    threat_id: `large-threat-${String(index + 1).padStart(3, "0")}`,
    threat_category: `${threatBase.threat_category} with a deliberately long scenario label for responsive wrapping ${index + 1}`,
    primary_interaction_ref: "flow-checkout-request",
  }));
  large.controls = Array.from({length: 80}, (_, index) => ({
    ...clone(base.controls[index % base.controls.length]),
    control_id: `large-control-${String(index + 1).padStart(3, "0")}`,
    name: `Control with a long implementation label for performance review ${index + 1}`,
    threat_ids: [large.threats[index % large.threats.length].threat_id],
  }));
  large.test_scenarios = Array.from({length: 80}, (_, index) => ({
    ...clone(base.test_scenarios[index % base.test_scenarios.length]),
    test_id: `large-test-${String(index + 1).padStart(3, "0")}`,
    threat_id: large.threats[index % large.threats.length].threat_id,
    related_control_id: large.controls[index % large.controls.length].control_id,
    scenario_name: `Verification scenario with a long label ${index + 1}`,
  }));
  large.missing_info = Array.from({length: 90}, (_, index) => ({...clone(base.missing_info[0]), missing_id: `large-gap-${index + 1}`, area: `Evidence gap ${index + 1}`}));
  large.assumptions = Array.from({length: 90}, (_, index) => ({...clone(base.assumptions[0]), assumption_id: `large-assumption-${index + 1}`, area: `Assumption ${index + 1}`}));
  large.risk_summary = {scored_total: 240, needs_context_total: 0, total: 240, scored: 240, deferred: 0};
  return large;
}

async function inspectLargeFixture(page, port, projectId, fixture, standardReport, result) {
  const large = buildLargeReport(standardReport);
  await installFixtureMock(page, fixture, large);
  await page.setViewportSize({width: 390, height: 844});
  const started = Date.now();
  await openRoute(page, port, "findings", projectId);
  await page.locator("#findings-search").fill("large-threat-199");
  await page.waitForFunction(() => document.querySelectorAll("#findings-list [data-finding-id]").length === 1);
  await page.locator("#findings-list [data-finding-id]").click();
  await page.waitForSelector("#findings-inspector .finding-id", {state: "visible"});
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 10000, `large fixture search/selection took ${elapsed}ms`);
  const listCount = await page.locator("#findings-list [data-finding-id]").count();
  assert.equal(listCount, 1, "large fixture search did not narrow to one canonical finding");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
  assert.equal(overflow, false, "large fixture findings surface overflows on mobile");
  result.performance.large_fixture = {finding_count: large.threats.length, control_count: large.controls.length, test_count: large.test_scenarios.length, evidence_item_count: large.missing_info.length + large.assumptions.length, search_to_selection_ms: elapsed};
  result.checks.push("large fixture (240 findings/80 controls/80 tests/180 evidence items) remains searchable, selectable, and mobile-safe");
}

async function inspectDeferredDisposition(page, port, projectId, fixture, standardReport, result) {
  const deferred = clone(standardReport);
  deferred.threats = deferred.threats.map(item => ({...item, risk_level: null, risk_status: "deferred", finding_state: "needs_context", scenario_risk_level: item.scenario_risk_level || "High"}));
  deferred.risk_summary = {scored_total: 0, needs_context_total: deferred.threats.length, total: deferred.threats.length, scored: 0, deferred: deferred.threats.length};
  deferred.quality_gate = {signoff_ready: false, blocking_reasons: ["All scenarios require context or verification before scoring"]};
  await installFixtureMock(page, fixture, deferred);
  await page.setViewportSize({width: 390, height: 844});
  await openRoute(page, port, "report", projectId);
  const disposition = await page.locator("#report-risk-disposition").textContent();
  assert.match(disposition, /0 scored/i);
  assert.match(disposition, /deferred/i);
  assert.match(disposition, /not evidence that no risk exists/i);
  assert.equal(await page.locator("#sign-report").isDisabled(), true, "deferred-only report incorrectly enables sign-off");
  result.checks.push("0 scored + N deferred report explicitly states deferred disposition and keeps sign-off blocked");
}

async function main() {
  const options = parseArgs(process.argv);
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const standardReport = fixtureReport(fixture);
  const axe = loadAxeSource();
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-uxm6-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 21000 + Math.floor(Math.random() * 300);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "UX-M6/release-signoff", project_id: fixture.project.project_id, browser: {engine: "Chromium", playwright: require("playwright/package.json").version}, matrix: [], checks: [], screenshots: [], journey_metrics: {}, a11y: {axe_version: axe.version, states: []}, performance: {}, console_messages: [], page_errors: [], failed_requests: [], http_errors: [], errors: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 390, height: 844}, hasTouch: true, acceptDownloads: true});
    const page = await context.newPage();
    attachDiagnostics(page, result, "journey");
    await installFixtureMock(page, fixture, standardReport);
    await inspectViewportMatrix(page, port, fixture.project.project_id, result, options);
    await inspectNavigationAndOverview(page, port, fixture.project.project_id, result);
    await inspectKeyboardWorkspaces(page, port, fixture.project.project_id, result);
    await inspectModelTouchAndOutline(page, port, fixture.project.project_id, fixture, result);
    await inspectExactTrace(page, port, fixture.project.project_id, fixture, result);
    await inspectNoviceJourney(page, port, fixture.project.project_id, result);
    await inspectInteractiveA11y(page, port, fixture.project.project_id, axe.source, result);
    await inspectRecoveryState(page, port, fixture.project.project_id, fixture, standardReport, result);
    await inspectLargeFixture(page, port, fixture.project.project_id, fixture, standardReport, result);
    await inspectDeferredDisposition(page, port, fixture.project.project_id, fixture, standardReport, result);
    await page.close();
    await context.close();
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {
    matrix_count: result.matrix.length,
    check_count: result.checks.length,
    screenshot_count: result.screenshots.length,
    error_count: result.errors.length,
    page_error_count: result.page_errors.length,
    failed_request_count: result.failed_requests.length,
    http_error_count: result.http_errors.length,
    console_warning_or_error_count: result.console_messages.length,
    interactive_axe_serious_or_critical: result.a11y.states.flatMap(state => state.violations || []).filter(rule => ["serious", "critical"].includes(rule.impact)).length,
  };
  if (options.output) {
    const output = path.resolve(options.output);
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "UX-M6 release sign-off gate failed");
  assert.equal(result.page_errors.length, 0, `UX-M6 page errors: ${JSON.stringify(result.page_errors)}`);
  assert.equal(result.failed_requests.length, 0, `UX-M6 failed API requests: ${JSON.stringify(result.failed_requests)}`);
  assert.equal(result.http_errors.length, 0, `UX-M6 API responses returned errors: ${JSON.stringify(result.http_errors)}`);
  assert.equal(result.console_messages.length, 0, `UX-M6 console warnings/errors: ${JSON.stringify(result.console_messages)}`);
  assert.equal(result.matrix.length, ROUTES.length * VIEWPORTS.length, "UX-M6 did not complete the full viewport matrix");
  assert.equal(result.summary.interactive_axe_serious_or_critical, 0, "UX-M6 interactive axe gate found serious/critical violations");
  assert.equal(result.checks.length, 13, "UX-M6 did not complete all release-signoff checks");
}

if (require.main === module) main().catch(error => { console.error(`UX-M6 gate error: ${error.message}`); process.exitCode = 1; });
