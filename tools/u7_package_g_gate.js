#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const {execFileSync, spawn} = require("node:child_process");

const REPO = path.resolve(__dirname, "..");
const FIXTURE_PATH = path.join(REPO, "fixtures", "u7_release_gate_fixture.json");
const DEFAULT_PROJECT_ID = "9b3aeb5d-1e7b-4f62-809c-0f74b33a1510";
const ROUTES = ["analysis", "model", "findings", "action-plan", "evidence", "report"];
const VIEWPORTS = [
  {name: "mobile", width: 390, height: 844},
  {name: "tablet", width: 768, height: 900},
  {name: "desktop", width: 1280, height: 900},
  {name: "wide", width: 1440, height: 900},
];
const WORKSPACES = [
  {route: "findings", list: "#findings-list [data-finding-id]", panel: "#findings-inspector", rowAttr: "data-finding-id"},
  {route: "action-plan", list: "#action-list [data-action-key]", panel: "#action-inspector", rowAttr: "data-action-key"},
  {route: "evidence", list: "#evidence-list [data-evidence-key]", panel: "#evidence-inspector", rowAttr: "data-evidence-key"},
];

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

function pageUrl(port, route, projectId, extra = "") {
  return `http://127.0.0.1:${port}/${route}.html?id=${encodeURIComponent(projectId)}${extra}`;
}

function fixtureReport(fixture) {
  const zones = [
    {id: "zone-public", display_id: "Z1", name: "Public facing", description: "Untrusted customer access", knowledge_status: "grounded"},
    {id: "zone-app", display_id: "Z2", name: "Internal application", description: "Application processing zone", knowledge_status: "grounded"},
    {id: "zone-restricted", display_id: "Z3", name: "Restricted data", description: "Order storage zone", knowledge_status: "grounded"},
    {id: "zone-vendor", display_id: "Z4", name: "External provider", description: "Payment provider zone", knowledge_status: "grounded"},
  ];
  const nodes = fixture.dfd.nodes.map((node, index) => ({
    ...node,
    display_id: `N${index + 1}`,
    zone_ids: [node.zone_id],
    knowledge_status: "grounded",
    implementation_status: "unknown",
    evidence_refs: ["source-checkout-prd#architecture"],
  }));
  const dataObjects = [{id: "data-order", display_id: "DO1", name: "Order and payment data", fields: ["order_id", "amount"], classification: "confidential", sensitivity: "high", evidence_refs: ["source-checkout-prd#data"]}];
  const flows = fixture.dfd.flows.map((flow, index) => ({
    ...flow,
    display_id: `F${index + 1}`,
    data_object_ids: ["data-order"],
    interaction_kind: "request",
    protocol: "HTTPS",
    authn: "session token",
    authz: "server-side policy",
    crossing_status: "resolved",
    evidence_refs: ["source-checkout-prd#flow"],
  }));
  const boundaries = fixture.dfd.boundaries.map(boundary => ({
    ...boundary,
    display_id: boundary.id.replace("boundary-", "TB-").toUpperCase(),
    name: boundary.id.replace("boundary-", "").replaceAll("-", " → "),
    types: ["network", "identity"],
    source_zone_ids: [boundary.zone_ids[0]],
    target_zone_ids: [boundary.zone_ids[1]],
    crossing_flow_ids: flows.filter(flow => flow.zone_ids.join("|") === boundary.zone_ids.join("|")).map(flow => flow.id),
    status: boundary.status === "candidate" ? "unresolved" : boundary.status,
    rationale: "Fixture boundary for guided review.",
    evidence_refs: ["source-checkout-prd#boundary"],
  }));
  const threats = fixture.findings.map(item => {
    const flow = item.primary_interaction_ref ? flows.find(candidate => candidate.id === item.primary_interaction_ref) : null;
    return {
      threat_id: item.id,
      framework: item.framework,
      threat_category: item.category,
      threat_description: `${item.category} scenario for checkout flow`,
      description: `${item.category} scenario for checkout flow`,
      asset: flow?.name || "Checkout interaction",
      component: "Checkout API",
      finding_state: item.state === "deferred" ? "needs_context" : "grounded",
      status: item.state === "deferred" ? "Needs Info" : "Open",
      scenario_risk_level: item.final_risk || "Unknown",
      risk_level: item.final_risk || "",
      risk_status: item.final_risk ? "assessed" : "deferred",
      risk_methodology_version: item.final_risk ? "risk-matrix-v1" : null,
      primary_interaction_ref: item.primary_interaction_ref,
      target_refs: flow ? [{type: "data_flow", id: flow.id, model_level: "context"}] : [],
      scenario_evidence_refs: item.state === "deferred" ? [] : ["source-checkout-prd#flow"],
      context_evidence_refs: ["source-checkout-prd#context"],
      evidence_type: item.state === "deferred" ? "inference" : "direct",
      evidence_source: "Synthetic checkout PRD",
      evidence_locator: item.state === "deferred" ? "source-checkout-prd#deferred" : "source-checkout-prd#flow",
      evidence_snippet: item.deferred_reason || "Fixture evidence supports this scenario.",
      recommended_control: "Apply the linked control and verify it with the linked test.",
    };
  });
  const controls = fixture.controls.map(item => ({
    control_id: item.id,
    name: item.name,
    description: `Control guidance for ${item.name}`,
    implementation_guidance: `Implement and review ${item.name}.`,
    priority: "High",
    mapping_status: item.applicability === "unassigned" ? "unassigned" : "assigned",
    review_status: "Open",
    implementation_state: "unknown",
    threat_ids: item.finding_ids,
    checklist_items: ["Confirm owner", "Collect evidence", "Review outcome"],
    target_refs: [{type: "data_flow", id: "flow-checkout-request", model_level: "context"}],
  }));
  const tests = fixture.tests.map(item => ({
    test_id: item.id,
    scenario_name: item.name,
    threat_id: item.finding_id,
    related_control_id: item.control_id,
    priority: "High",
    applicability_status: item.state === "blocked" ? "blocked" : "applicable",
    applicability_reason: item.blocked_reason || "Control is linked and ready for execution.",
    execution_status: "Not Run",
    preconditions: "Use the synthetic checkout fixture.",
    steps: item.steps,
    expected_result: item.state === "blocked" ? "Execution remains blocked until the deferred section is reviewed." : "The tampered request is rejected and the audit event is recorded.",
    evidence_needed: ["Response capture", "Audit event reference"],
    target_refs: [{type: "data_flow", id: "flow-checkout-request", model_level: "context"}],
  }));
  return {
    analysis_run: {run_id: "fixture-run-1", status: "complete", completed_at: "2026-09-24T00:00:00Z"},
    report_revision: 3,
    dfd_model: {revision: fixture.dfd.revision, zones, nodes, data_objects: dataObjects, flows, boundaries, questions: []},
    dfd_validation: {readiness: {status: "ready"}},
    trust_boundaries: [],
    threats,
    controls,
    test_scenarios: tests,
    missing_info: fixture.gaps.map(item => ({missing_id: item.id, area: "Provider retention", question_to_ask: item.next_action, why_it_matters: "It affects deletion and privacy verification.", status: "Open", owner: item.owner || "", priority: "High", target_refs: [{type: "node", id: item.linked_object_id}]})),
    assumptions: [{assumption_id: "assumption-auth", area: "Authentication", assumption: "The checkout token is validated server-side.", status: "Open", owner: "Security review", priority: "Medium", target_refs: [{type: "data_flow", id: "flow-checkout-request"}]}],
    risk_summary: {scored: threats.filter(item => item.risk_level).length, deferred: threats.filter(item => !item.risk_level).length},
  };
}

async function tabUntil(page, predicate, limit = 140) {
  for (let index = 0; index < limit; index += 1) {
    if (await page.evaluate(predicate)) return true;
    await page.keyboard.press("Tab");
  }
  return false;
}

async function waitForRows(page, selector) {
  await page.waitForSelector(selector, {state: "visible", timeout: 15000});
  await page.waitForTimeout(160);
}

async function inspectInitialMatrix(page, options, result) {
  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({width: viewport.width, height: viewport.height});
    for (const route of ROUTES) {
      await page.goto(pageUrl(options.port, route, options.projectId), {waitUntil: "networkidle", timeout: 20000});
      await page.waitForTimeout(180);
      const surface = await page.evaluate(() => {
        const firstHeading = document.querySelector("h1");
        const blankActions = [...document.querySelectorAll("button, a")].filter(element => {
          const box = element.getBoundingClientRect();
          const visible = box.width > 0 && box.height > 0 && getComputedStyle(element).visibility !== "hidden";
          return visible && !element.textContent.trim() && !element.getAttribute("aria-label") && !element.querySelector("svg");
        }).length;
        return {
          route: location.pathname,
          horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
          h1: firstHeading?.textContent.trim() || "",
          workflowNavCount: document.querySelectorAll("#project-workflow-nav").length,
          workflowActiveCount: document.querySelectorAll("#project-workflow-nav .project-workflow-link.active").length,
          workflowNavVisible: (() => { const nav = document.querySelector("#project-workflow-nav"); const box = nav?.getBoundingClientRect(); const style = nav ? getComputedStyle(nav) : null; return Boolean(nav && box && box.width > 0 && box.height > 0 && style.display !== "none" && style.visibility !== "hidden"); })(),
          workflowNavGeometry: (() => { const nav = document.querySelector("#project-workflow-nav"); const topbar = document.querySelector(".topbar"); const navBox = nav?.getBoundingClientRect(); const topbarBox = topbar?.getBoundingClientRect(); return { nav: navBox ? {top: navBox.top, bottom: navBox.bottom, height: navBox.height} : null, topbar: topbarBox ? {top: topbarBox.top, bottom: topbarBox.bottom, height: topbarBox.height} : null }; })(),
          blankActions,
          documentHeight: document.documentElement.scrollHeight,
          hasBody: Boolean(document.body.textContent.trim()),
        };
      });
      assert.equal(surface.horizontalOverflow, false, `${route} has horizontal overflow at ${viewport.width}px`);
      assert.equal(surface.workflowNavCount, 1, `${route} does not have exactly one shared workflow navigator at ${viewport.width}px`);
      assert.equal(surface.workflowActiveCount, 1, `${route} does not have exactly one active workflow stage at ${viewport.width}px`);
      assert.equal(surface.workflowNavVisible, true, `${route} shared workflow navigator is not visible at ${viewport.width}px`);
      const navGeometry = surface.workflowNavGeometry;
      assert.ok(navGeometry.nav && navGeometry.topbar && navGeometry.nav.top >= navGeometry.topbar.bottom - 1 && navGeometry.nav.top <= navGeometry.topbar.bottom + 2 && navGeometry.nav.bottom <= viewport.height + 1, `${route} shared workflow navigator is not aligned after the topbar at ${viewport.width}px: ${JSON.stringify(surface)}`);
      assert.equal(surface.blankActions, 0, `${route} has blank visible action at ${viewport.width}px`);
      assert.equal(surface.hasBody, true, `${route} rendered an empty document`);
      assert.ok(surface.h1, `${route} has no primary heading at ${viewport.width}px`);
      if (route === "report" && viewport.width <= 390) assert.ok(surface.documentHeight <= viewport.height * 3.5, `mobile report initial surface is ${surface.documentHeight}px`);
      result.matrix.push({...surface, viewport: viewport.name, width: viewport.width});
      if (options.screenshotDir && (viewport.width === 390 || viewport.width === 1440)) {
        const target = path.join(options.screenshotDir, `${route}-${viewport.width}.png`);
        await page.screenshot({path: target, fullPage: false});
        result.screenshots.push(target);
      }
    }
  }
  result.checks.push("initial route matrix 390/768/1280/1440 → shared workflow navigation, headings, actions, overflow, and bounded report");
}

async function inspectCanvas(page, options, result) {
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(pageUrl(options.port, "model", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#threat-diagram-canvas canvas", {timeout: 15000});
  const canvas = await page.evaluate(() => {
    const shell = document.querySelector("#diagram-canvas-shell")?.getBoundingClientRect();
    const canvas = document.querySelector("#threat-diagram-canvas canvas")?.getBoundingClientRect();
    const hit = document.elementFromPoint((canvas?.left || 0) + (canvas?.width || 0) / 2, Math.max(canvas?.top || 0, Math.min((canvas?.bottom || 0) - 2, 340)));
    return {top: shell?.top || 0, visibleHeight: Math.max(0, Math.min(innerHeight, shell?.bottom || 0) - Math.max(0, shell?.top || 0)), width: canvas?.width || 0, height: canvas?.height || 0, hitCanvas: Boolean(hit?.tagName === "CANVAS")};
  });
  // The canvas starts below the workspace heading, toolbar, and coverage strip.
  // Keep the first viewport contract semantic: enough canvas is visible for
  // orientation and it occupies at least 55% of the 900px desktop viewport.
  assert.ok(canvas.top <= 340 && canvas.visibleHeight >= 495 && canvas.width > 500 && canvas.height > 300, `DFD canvas geometry is insufficient: ${JSON.stringify(canvas)}`);
  assert.equal(canvas.hitCanvas, true, "DFD canvas is covered by another element");
  await page.locator("#btn-diagram-fit").click();
  await page.waitForTimeout(260);
  const boxes = await page.evaluate(() => window.__5stonesDfdDebug?.getNodeBoxes?.() || []);
  const overlaps = [];
  for (let left = 0; left < boxes.length; left += 1) for (let right = left + 1; right < boxes.length; right += 1) {
    const a = boxes[left].box; const b = boxes[right].box;
    if (!a || !b) continue;
    if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > 4 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 4) overlaps.push([boxes[left].id, boxes[right].id]);
  }
  assert.deepEqual(overlaps, [], `DFD Fit still overlaps: ${JSON.stringify(overlaps)}`);
  await page.locator("#diagram-text-alternative summary").click();
  assert.ok(await page.locator("#diagram-text-content [data-outline-type='node']").count(), "DFD accessible outline is empty");
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(pageUrl(options.port, "model", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#threat-diagram-canvas canvas", {timeout: 15000});
  const mobileSurface = await page.evaluate(() => {
    const shell = document.querySelector("#diagram-canvas-shell")?.getBoundingClientRect();
    const rail = document.querySelector("#model-inspector-rail");
    return {
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
      canvasHeight: shell?.height || 0,
      railState: rail?.dataset.mobileState,
      railVisibility: getComputedStyle(rail).visibility,
    };
  });
  assert.equal(mobileSurface.overflow, false, "mobile model canvas has horizontal overflow");
  assert.ok(mobileSurface.canvasHeight >= 240, `mobile canvas is too short: ${JSON.stringify(mobileSurface)}`);
  assert.equal(mobileSurface.railState, "closed", "mobile boundary review is not closed by default");
  await page.locator("#model-review-trigger").click();
  await page.waitForFunction(() => document.body.classList.contains("model-sheet-open"));
  const opened = await page.evaluate(() => {
    const rail = document.querySelector("#model-inspector-rail");
    return {role: rail?.getAttribute("role"), modal: rail?.getAttribute("aria-modal"), focusInside: Boolean(rail?.contains(document.activeElement)), expanded: document.querySelector("#model-review-trigger")?.getAttribute("aria-expanded")};
  });
  assert.deepEqual(opened, {role: "dialog", modal: "true", focusInside: true, expanded: "true"}, "model review bottom sheet focus contract failed");
  await page.keyboard.press("Escape");
  assert.equal(await page.evaluate(() => ({closed: !document.body.classList.contains("model-sheet-open"), focus: document.activeElement?.id})).then(value => value.closed && value.focus === "model-review-trigger"), true, "model review Escape did not return focus to trigger");
  result.checks.push("DFD canvas first viewport + Fit non-overlap + accessible outline + mobile review sheet");
}

async function inspectKeyboardWorkspace(page, workspace, options, result) {
  await page.setViewportSize({width: 390, height: 844});
  await page.goto(pageUrl(options.port, workspace.route, options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, workspace.list);
  await page.keyboard.press("/");
  assert.equal(await page.evaluate(() => document.activeElement?.id), workspace.route === "findings" ? "findings-search" : workspace.route === "action-plan" ? "action-search" : "evidence-search");
  const listSelector = workspace.list.replace(/ \[.*$/, "");
  await page.locator(listSelector).focus();
  await page.keyboard.press("ArrowDown");
  const rowKey = await page.evaluate(attr => document.activeElement?.getAttribute(attr), workspace.rowAttr);
  assert.ok(rowKey, `${workspace.route} first row is not keyboard reachable`);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(80);
  const opened = await page.evaluate(selector => {
    const panel = document.querySelector(selector);
    return {role: panel?.getAttribute("role"), modal: panel?.getAttribute("aria-modal"), focusInside: Boolean(panel?.contains(document.activeElement)), labelled: panel?.getAttribute("aria-labelledby")};
  }, workspace.panel);
  assert.deepEqual(opened, {role: "dialog", modal: "true", focusInside: true, labelled: opened.labelled}, `${workspace.route} mobile inspector focus contract failed`);
  assert.ok(opened.labelled, `${workspace.route} mobile inspector has no accessible title`);
  await page.keyboard.press("Escape");
  const closed = await page.evaluate(({selector, attr, key}) => ({empty: Boolean(document.querySelector(selector)?.querySelector(".findings-inspector-empty, .action-inspector-empty, .evidence-inspector-empty")), returned: document.activeElement?.getAttribute(attr) === key}), {selector: workspace.panel, attr: workspace.rowAttr, key: rowKey});
  assert.deepEqual(closed, {empty: true, returned: true}, `${workspace.route} Escape did not return focus to row`);
  result.checks.push(`${workspace.route} keyboard-only search → row → inspector → Escape focus return`);
}

async function inspectProgressiveFilters(page, options, result) {
  await page.goto(pageUrl(options.port, "findings", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, "#findings-list [data-finding-id]");
  await page.locator("#findings-search").click();
  await page.locator("#findings-search").fill("no-result-for-package-g");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "findings-search", "typing moved focus away from findings search");
  assert.match(await page.locator("#findings-list").textContent(), /No findings match/i);
  await page.locator("#findings-reset").click();
  await page.locator("#findings-filters-toggle").click();
  assert.equal(await page.locator("#findings-filter-dialog").evaluate(node => node.open), true);
  assert.equal(await page.evaluate(() => document.activeElement?.id), "findings-filter-search");
  await page.locator("#findings-filter-dialog [data-filter-cancel]").first().click();
  assert.equal(await page.locator("#findings-filter-dialog").evaluate(node => node.open), false);
  result.checks.push("unified filter drawer keeps typing focus, explains zero matches, and supports cancel/focus return");
}

async function inspectGuidedJourneys(page, options, result) {
  await page.goto(pageUrl(options.port, "findings", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, "#findings-list [data-finding-id]");
  await page.locator("#start-findings-guided").click();
  await page.waitForSelector("#finding-guided-review", {state: "visible", timeout: 5000});
  assert.match(await page.locator("#finding-guided-review").textContent(), /What might happen|Evidence available/i);
  await page.goto(pageUrl(options.port, "model", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  if (await page.locator("#model-review-trigger").isVisible()) await page.locator("#model-review-trigger").click();
  await page.locator("#start-boundary-guided").click();
  await page.waitForSelector("[data-guided-boundary]", {state: "visible", timeout: 5000});
  assert.equal(await page.locator("[data-guided-boundary]").count(), 3);
  assert.match(await page.locator("#inspector-body").textContent(), /Belum tahu/);
  result.checks.push("guided novice flow exposes plain language, progress context, and explicit Belum tahu state");
}

async function inspectEvidenceReportAndOnboarding(page, options, result) {
  await page.goto(pageUrl(options.port, "evidence", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await waitForRows(page, "#evidence-list [data-evidence-key]");
  await page.locator("#open-context-editor-inline").click();
  assert.equal(await page.locator("#context-editor").evaluate(node => node.open), true);
  await page.keyboard.press("Escape");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "open-context-editor-inline");
  await page.locator("#evidence-intake").locator("summary").click();
  assert.equal(await page.locator("#evidence-intake").evaluate(node => node.open), true);
  await page.locator("#evidence-coverage").locator("summary").click();
  assert.equal(await page.locator("#evidence-coverage").evaluate(node => node.open), true);

  await page.goto(pageUrl(options.port, "report", options.projectId), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#report-dfd-snapshot-caption", {state: "visible", timeout: 15000});
  const appendix = page.locator(".report-section-toggle").first();
  assert.equal(await appendix.getAttribute("aria-expanded"), "false");
  await appendix.click();
  assert.equal(await appendix.getAttribute("aria-expanded"), "true");
  await appendix.click();
  assert.equal(await appendix.getAttribute("aria-expanded"), "false");

  await page.goto(`http://127.0.0.1:${options.port}/project-new.html`, {waitUntil: "networkidle", timeout: 20000});
  await page.locator("#onboarding-start-doc").click();
  assert.equal(await page.locator("#project-desc").getAttribute("required"), null);
  await page.locator("#project-name").fill("Package G onboarding");
  await page.locator("#btn-next").click();
  await page.waitForSelector("#step-2", {state: "visible", timeout: 3000});
  result.checks.push("Evidence context/source disclosure, report appendix, and document-first onboarding keyboard journey");
}

async function installFixtureMock(page, fixture, report) {
  const project = {project_id: fixture.project.project_id, name: fixture.project.name, description: "Synthetic checkout review", environment: fixture.project.environment, actors: ["Customer"], entry_points: ["Checkout API"], data_involved: ["order_id", "amount"], external_systems: ["Payment Gateway"]};
  await page.route(`**/api/projects/${fixture.project.project_id}**`, async route => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname.endsWith("/report")) return route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(report)});
    if (route.request().method() === "GET") return route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(project)});
    return route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify({success: true})});
  });
  await page.route(`**/api/analysis/projects/${fixture.project.project_id}/**`, route => route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify({success: true})}));
}

async function inspectExactTrace(page, fixture, report, options, result) {
  const trace = fixture.expected_trace.find(item => item.test_id && item.status !== "deferred");
  assert.ok(trace, "fixture has no executable expected trace");
  await installFixtureMock(page, fixture, report);
  await page.goto(pageUrl(options.port, "model", fixture.project.project_id, `&selected=${encodeURIComponent(`dfd-flow:${trace.flow_id}`)}`), {waitUntil: "networkidle", timeout: 20000});
  await page.waitForSelector("#node-inspector a.model-finding-link", {timeout: 15000});
  const findingLink = page.locator("#node-inspector a.model-finding-link").filter({hasText: trace.finding_id}).first();
  assert.equal(await findingLink.count(), 1, "DFD did not expose exact finding ID");
  await findingLink.click();
  await page.waitForSelector(`#findings-list [data-finding-id="${trace.finding_id}"]`, {timeout: 15000});
  assert.match(await page.locator("#findings-inspector .finding-id").textContent(), new RegExp(trace.finding_id));
  // UIState serializes the selection token in the query string, so the colon
  // may be URL-encoded. Assert the visible canonical ID and the decoded route
  // target instead of relying on the raw href representation.
  const controlLink = page.locator("#findings-inspector a.finding-dfd-link").filter({hasText: trace.control_id}).first();
  assert.equal(await controlLink.count(), 1, "Finding did not expose exact control link");
  const controlTarget = new URL(await controlLink.getAttribute("href"), page.url());
  assert.equal(controlTarget.searchParams.get("selected"), `control:${trace.control_id}`, "Finding control link target is not exact");
  await controlLink.click();
  await page.waitForSelector(`#action-list [data-action-key="control:${trace.control_id}"]`, {timeout: 15000});
  assert.match(await page.locator("#action-inspector .action-id").textContent(), new RegExp(trace.control_id));
  const testButton = page.locator(`#action-inspector [data-open-action="test:${trace.test_id}"]`).first();
  assert.equal(await testButton.count(), 1, "Control did not expose exact test link");
  await testButton.click();
  await page.waitForSelector(`#action-list [data-action-key="test:${trace.test_id}"]`, {timeout: 15000});
  assert.match(await page.locator("#action-inspector .action-id").textContent(), new RegExp(trace.test_id));
  result.checks.push("synthetic fixture exact-ID trace DFD flow → finding → control → executable test");
}

async function main() {
  const options = parseArgs(process.argv);
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const fixtureReportData = fixtureReport(fixture);
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-package-g-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  options.port = 20200 + Math.floor(Math.random() * 500);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(options.port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(options.port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "U7-Package-G", project_id: options.projectId, matrix: [], checks: [], screenshots: [], errors: [], page_errors: [], failed_requests: []};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${options.port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    page.on("pageerror", error => result.page_errors.push(error.message));
    page.on("requestfailed", request => { if (request.url().includes("/api/")) result.failed_requests.push({url: request.url(), failure: request.failure()?.errorText || "failed"}); });
    try {
      await inspectInitialMatrix(page, options, result);
      await inspectCanvas(page, options, result);
      for (const workspace of WORKSPACES) await inspectKeyboardWorkspace(page, workspace, options, result);
      await inspectProgressiveFilters(page, options, result);
      await inspectGuidedJourneys(page, options, result);
      await inspectEvidenceReportAndOnboarding(page, options, result);
      await inspectExactTrace(page, fixture, fixtureReportData, options, result);
    } finally { await page.close(); }
  } catch (error) { result.errors.push({message: error.message, stack: error.stack}); }
  finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {matrix_count: result.matrix.length, check_count: result.checks.length, error_count: result.errors.length, page_error_count: result.page_errors.length, failed_request_count: result.failed_requests.length, screenshot_count: result.screenshots.length};
  if (options.output) { const output = path.resolve(options.output); fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n"); }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "Package G Chromium release gate failed");
  assert.equal(result.page_errors.length, 0, `Package G found page errors: ${result.page_errors.join(" | ")}`);
  assert.equal(result.failed_requests.length, 0, "Package G found failed API requests");
  assert.equal(result.matrix.length, ROUTES.length * VIEWPORTS.length, "Package G did not complete the full viewport matrix");
  assert.equal(result.checks.length, 9, "Package G did not complete all journey checks");
}

if (require.main === module) main().catch(error => { console.error(`U7 Package G gate error: ${error.message}`); process.exitCode = 1; });

module.exports = { fixtureReport, installFixtureMock, pageUrl, loadPlaywright };
