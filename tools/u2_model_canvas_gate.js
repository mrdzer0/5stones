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
const HIERARCHY_REPORT_PATH = path.join(REPO, "fixtures", "u2_dfd_hierarchy_report.json");

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

function parseArgs(argv) {
  const result = {output: null, screenshotDir: null};
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === "--output") result.output = argv[++index];
    else if (argv[index] === "--screenshot-dir") result.screenshotDir = argv[++index];
  }
  return result;
}

async function waitForModel(page) {
  await page.waitForSelector("#threat-diagram-canvas canvas", {timeout: 15000});
  await page.waitForFunction(() => typeof diagramNetwork !== "undefined" && !!diagramNetwork?.body?.data?.nodes?.length);
  await page.waitForTimeout(180);
}

function overlapPairs(boxes, threshold = 3) {
  const pairs = [];
  for (let left = 0; left < boxes.length; left += 1) for (let right = left + 1; right < boxes.length; right += 1) {
    const a = boxes[left].box;
    const b = boxes[right].box;
    if (!a || !b) continue;
    const width = Math.min(a.right, b.right) - Math.max(a.left, b.left);
    const height = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
    if (width > threshold && height > threshold) pairs.push([boxes[left].id, boxes[right].id]);
  }
  return pairs;
}

async function geometry(page) {
  return page.evaluate(() => {
    const shell = document.querySelector("#diagram-canvas-shell")?.getBoundingClientRect();
    const canvas = document.querySelector("#threat-diagram-canvas canvas")?.getBoundingClientRect();
    const rail = document.querySelector("#model-inspector-rail");
    const railBox = rail?.getBoundingClientRect();
    const boxes = window.__5stonesDfdDebug?.getNodeBoxes?.() || [];
    const selection = window.UIState?.read().selection || "";
    const selectedGraphIds = selection.startsWith("dfd-node:") ? (() => {
      const id = selection.slice(9);
      const node = diagramNetwork.body.data.nodes.get(id) || diagramNetwork.body.data.nodes.get().find(item => (item._canonicalNodeIds || []).includes(id));
      return node ? [node.id] : [];
    })() : selection.startsWith("dfd-flow:") ? (() => {
      const id = selection.slice(9);
      const edge = diagramNetwork.body.data.edges.get(id) || diagramNetwork.body.data.edges.get().find(item => (item._canonicalFlowIds || []).includes(id));
      return edge ? [edge.from, edge.to] : [];
    })() : [];
    const selectedCenters = selectedGraphIds.map(id => {
      const box = diagramNetwork.getBoundingBox(id);
      if (!box) return null;
      const point = diagramNetwork.canvasToDOM({x: (box.left + box.right) / 2, y: (box.top + box.bottom) / 2});
      return {id, x: point.x, y: point.y};
    }).filter(Boolean);
    const visibleRail = rail && getComputedStyle(rail).visibility !== "hidden" && getComputedStyle(rail).pointerEvents !== "none";
    const intersection = shell && railBox && visibleRail
      ? Math.max(0, Math.min(shell.right, railBox.right) - Math.max(shell.left, railBox.left)) * Math.max(0, Math.min(shell.bottom, railBox.bottom) - Math.max(shell.top, railBox.top))
      : 0;
    return {
      shell: shell ? {top: shell.top, bottom: shell.bottom, height: shell.height, width: shell.width} : null,
      canvas: canvas ? {width: canvas.width, height: canvas.height} : null,
      rail: railBox ? {top: railBox.top, bottom: railBox.bottom, height: railBox.height, state: rail.dataset.mobileState, visibility: getComputedStyle(rail).visibility} : null,
      selection,
      selectedCenters,
      viewport: {width: innerWidth, height: innerHeight},
      canvasRailIntersection: intersection,
      boxes,
      overflow: document.documentElement.scrollWidth > innerWidth + 1,
    };
  });
}

async function main() {
  const options = parseArgs(process.argv);
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const report = fixtureReport(fixture);
  const hierarchy = JSON.parse(fs.readFileSync(HIERARCHY_REPORT_PATH, "utf8"));
  report.dfd_model = hierarchy.model;
  report.dfd_validation = hierarchy.validation;
  const projectId = fixture.project.project_id;
  const playwright = loadPlaywright();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-u2-model-"));
  const dataDir = path.join(tempRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const port = 20300 + Math.floor(Math.random() * 400);
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(port)], {cwd: REPO, env: {...process.env, DATA_DIR: dataDir, PORT: String(port)}, stdio: ["ignore", "pipe", "pipe"]});
  const result = {gate: "UX-M2/H2", project_id: projectId, checks: [], screenshots: [], errors: [], page_errors: [], failed_requests: [], metrics: {}};
  let browser;
  try {
    await waitForServer(`http://127.0.0.1:${port}/api/health`);
    browser = await playwright.chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 1440, height: 900}, hasTouch: true, acceptDownloads: true});
    const page = await context.newPage();
    page.on("pageerror", error => result.page_errors.push(error.message));
    page.on("requestfailed", request => { if (request.url().includes("/api/")) result.failed_requests.push({url: request.url(), failure: request.failure()?.errorText || "failed"}); });
    await installFixtureMock(page, fixture, report);

    await page.goto(pageUrl(port, "model", projectId), {waitUntil: "networkidle", timeout: 20000});
    await waitForModel(page);
    await page.evaluate(() => navigateCanonicalLevel("context"));
    const hierarchyL0 = await page.evaluate(() => {
      const projection = resolveDfdProjection(currentReport.dfd_model, "context");
      const disclosure = document.querySelector("#diagram-text-alternative");
      const wasOpen = disclosure?.open;
      if (disclosure) disclosure.open = true;
      const outline = document.querySelector("#diagram-text-content .diagram-outline-intro")?.innerText || "";
      if (disclosure) disclosure.open = wasOpen;
      return {
        view_id: projection.view.id,
        nodes: projection.nodes.map(item => item.id).sort(),
        flows: projection.flows.map(item => item.id).sort(),
        canonical_flows: projection.flows.flatMap(item => item.canonical_flow_ids || []).sort(),
        canvas_nodes: diagramNetwork.body.data.nodes.getIds().map(String).sort(),
        canvas_flows: diagramNetwork.body.data.edges.getIds().map(String).sort(),
        canvas_flow_constituents: diagramNetwork.body.data.edges.get().map(item => item._canonicalFlowIds || null),
        outline_nodes: [...document.querySelectorAll('#diagram-text-content [data-outline-type="projection-node"]')].map(item => item.dataset.outlineId).sort(),
        outline_flows: [...document.querySelectorAll('#diagram-text-content [data-outline-type="projection-flow"]')].map(item => item.dataset.outlineId).sort(),
        outline,
      };
    });
    assert.equal(hierarchyL0.view_id, "view-context");
    assert.deepEqual(hierarchyL0.canvas_nodes, hierarchyL0.nodes, "L0 canvas node IDs differ from the selected API projection");
    assert.deepEqual(hierarchyL0.canvas_flows, hierarchyL0.flows, "L0 canvas flow mappings differ from the selected API projection");
    assert.deepEqual(hierarchyL0.outline_nodes, hierarchyL0.nodes, "L0 accessible outline nodes differ from the selected API projection");
    assert.deepEqual(hierarchyL0.outline_flows, hierarchyL0.flows, "L0 accessible outline flows differ from the selected API projection");
    assert.deepEqual(hierarchyL0.canvas_flow_constituents.flat().sort(), hierarchyL0.canonical_flows, "L0 canvas lost canonical flow constituents");
    assert.match(hierarchyL0.outline, /3 elements · 2 flows/);
    await page.locator('[data-diagram-level="services"]').click();
    await page.waitForFunction(() => canonicalRenderedViewKind === "system");
    const hierarchyL1 = await page.evaluate(() => {
      const projection = resolveDfdProjection(currentReport.dfd_model, "system");
      const disclosure = document.querySelector("#diagram-text-alternative");
      const wasOpen = disclosure?.open;
      if (disclosure) disclosure.open = true;
      const outline = document.querySelector("#diagram-text-content .diagram-outline-intro")?.innerText || "";
      if (disclosure) disclosure.open = wasOpen;
      return {
        view_id: projection.view.id,
        nodes: projection.nodes.map(item => item.id).sort(),
        flows: projection.flows.map(item => item.id).sort(),
        canonical_flows: projection.flows.flatMap(item => item.canonical_flow_ids || []).sort(),
        canvas_nodes: diagramNetwork.body.data.nodes.getIds().map(String).sort(),
        canvas_flows: diagramNetwork.body.data.edges.getIds().map(String).sort(),
        canvas_flow_constituents: diagramNetwork.body.data.edges.get().map(item => item._canonicalFlowIds || null),
        outline_nodes: [...document.querySelectorAll('#diagram-text-content [data-outline-type="projection-node"]')].map(item => item.dataset.outlineId).sort(),
        outline_flows: [...document.querySelectorAll('#diagram-text-content [data-outline-type="projection-flow"]')].map(item => item.dataset.outlineId).sort(),
        outline,
      };
    });
    assert.equal(hierarchyL1.view_id, "view-system");
    assert.equal(hierarchyL1.nodes.length, 4);
    assert.equal(hierarchyL1.flows.length, 3);
    assert.notDeepEqual(hierarchyL0.nodes, hierarchyL1.nodes, "L0 and L1 projected node sets are identical");
    assert.deepEqual(hierarchyL1.canvas_nodes, hierarchyL1.nodes, "L1 canvas node IDs differ from the selected API projection");
    assert.deepEqual(hierarchyL1.canvas_flows, hierarchyL1.flows, "L1 canvas flow mappings differ from the selected API projection");
    assert.deepEqual(hierarchyL1.outline_nodes, hierarchyL1.nodes, "L1 accessible outline nodes differ from the selected API projection");
    assert.deepEqual(hierarchyL1.outline_flows, hierarchyL1.flows, "L1 accessible outline flows differ from the selected API projection");
    assert.deepEqual(hierarchyL1.canvas_flow_constituents.flat().sort(), hierarchyL1.canonical_flows, "L1 canvas lost canonical flow constituents");
    assert.match(hierarchyL1.outline, /4 elements · 3 flows/);
    await page.locator('[data-diagram-level="scenarios"]').click();
    await page.waitForFunction(() => canonicalRenderedViewKind === "feature");
    const hierarchyL2 = await page.evaluate(() => {
      const projection = resolveDfdProjection(currentReport.dfd_model, canonicalFeatureViewId);
      const disclosure = document.querySelector("#diagram-text-alternative");
      const wasOpen = disclosure?.open;
      if (disclosure) disclosure.open = true;
      const outline = document.querySelector("#diagram-text-content")?.innerText || "";
      if (disclosure) disclosure.open = wasOpen;
      return {
        status: projection.view.decomposition_status,
        issues: projection.view.projection_issues,
        outline,
      };
    });
    assert.equal(hierarchyL2.status, "detail_only", "L2 claims decomposition without child-process evidence");
    assert.ok(hierarchyL2.issues.some(issue => issue.includes("unsupported_decomposition")));
    assert.match(hierarchyL2.outline, /connection detail only; no decomposition evidence/);
    await page.evaluate(() => navigateCanonicalLevel("context"));
    const exportedSvg = await page.evaluate(() => diagramSvgMarkup(diagramExportScene(), projectId));
    assert.match(exportedSvg, /data-view-id="view-context"/);
    assert.match(exportedSvg, /data-validation-status="review"/);
    assert.ok(exportedSvg.includes("flow-checkout-request") && exportedSvg.includes("semantic_hash") && exportedSvg.includes("hidden_internal_node_details"), "current-view SVG export omitted canonical trace, model hash, or aggregation disclosure");
    result.checks.push("L0/L1 projected topology is distinct and matches canvas + accessible outline; evidence-poor L2 stays detail-only");
    result.metrics.hierarchy = {L0: hierarchyL0, L1: hierarchyL1, L2: {status: hierarchyL2.status, issues: hierarchyL2.issues}};
    const desktopBefore = await geometry(page);
    assert.equal(desktopBefore.overflow, false, "desktop Model has horizontal overflow");
    assert.ok(desktopBefore.shell.top < 340 && desktopBefore.shell.height >= 495, `desktop canvas is not canvas-first: ${JSON.stringify(desktopBefore)}`);
    assert.equal(desktopBefore.rail.state, "closed", "desktop boundary review is open by default");
    assert.equal(await page.locator("#btn-model-findings").count(), 0, "duplicate topbar Findings action remains on Model");
    assert.equal(await page.locator("#btn-model-report").count(), 0, "duplicate topbar Report action remains on Model");
    assert.equal(await page.locator("#btn-diagram-fit").count(), 0, "obsolete Fit action remains on Model");
    assert.equal(await page.locator("#btn-diagram-reflow").count(), 1, "Reflow layout action is missing from the Model toolbar");
    assert.equal(await page.locator(".model-more-popover #btn-diagram-reflow").count(), 0, "Reflow layout remains inside More");
    assert.equal(overlapPairs(desktopBefore.boxes).length, 0, "initial canonical DFD has overlapping nodes");
    assert.equal(await page.locator("#model-workspace-title").innerText(), "DFD model", "Model workspace heading is missing or inconsistent");
    assert.deepEqual(await page.locator("[data-diagram-level]").allTextContents(), ["Overview · L0", "Services · L1", "Connection detail · L2"], "DFD L0/L1/L2 labels are not visible or L2 state is overstated");
    assert.equal(await page.locator("#boundary-review-panel").getAttribute("hidden"), null, "Boundary review is unexpectedly hidden before the rail opens");
    const inventorySummary = page.locator("#dfd-inventory-panel > summary");
    const outlineSummary = page.locator("#diagram-text-alternative > summary");
    assert.equal(await inventorySummary.isVisible(), true, "Model inventory disclosure is not visible");
    assert.equal(await outlineSummary.isVisible(), true, "Accessible model outline disclosure is not visible");
    const supportGeometry = await page.evaluate(() => ["#dfd-inventory-panel", "#diagram-text-alternative"].map(selector => {
      const summary = document.querySelector(`${selector} > summary`);
      const label = summary?.firstElementChild?.getBoundingClientRect();
      const state = summary?.querySelector(".model-support-state")?.getBoundingClientRect();
      const summaryBox = summary?.getBoundingClientRect();
      return {selector, labelRight: label?.right, stateLeft: state?.left, stateRight: state?.right, summaryRight: summaryBox?.right};
    }));
    assert.ok(supportGeometry.every(item => item.labelRight != null && item.stateLeft >= item.labelRight + 8 && item.stateRight <= item.summaryRight + 1), `support disclosure state badges are not right-aligned: ${JSON.stringify(supportGeometry)}`);
    await inventorySummary.focus();
    await page.keyboard.press("Enter");
    await page.waitForTimeout(80);
    assert.equal(await page.locator("#dfd-inventory-panel").getAttribute("open"), "", "Model inventory cannot be opened from keyboard");
    assert.equal(await page.locator("#dfd-inventory").isVisible(), true, "Model inventory content is not visible after opening");
    await page.keyboard.press("Enter");
    await outlineSummary.focus();
    await page.keyboard.press("Enter");
    await page.waitForTimeout(80);
    assert.equal(await page.locator("#diagram-text-alternative").getAttribute("open"), "", "Accessible model outline cannot be opened from keyboard");
    assert.ok(await page.locator("#diagram-text-content [data-outline-type]").count() > 0, "Accessible model outline has no semantic elements");
    await page.keyboard.press("Enter");
    result.checks.push("Model heading + L0/L1/L2 terminology + hideable Boundary review + right-aligned keyboard-accessible disclosures");
    result.metrics.desktopBefore = desktopBefore;
    if (options.screenshotDir) {
      fs.mkdirSync(path.resolve(options.screenshotDir), {recursive: true});
      const target = path.resolve(options.screenshotDir, "u2-model-desktop.png");
      await page.screenshot({path: target, fullPage: false});
      result.screenshots.push(target);
    }

    const ids = await page.evaluate(() => ({
      node: diagramNetwork.body.data.nodes.get(diagramNetwork.body.data.nodes.getIds()[0])._canonicalNodeIds[0],
      flow: "flow-checkout-request",
    }));
    await page.evaluate(({node}) => focusModelElement("node", node), ids);
    await page.waitForTimeout(100);
    const selectedBeforeReflow = await page.evaluate(() => window.UIState.read().selection);
    assert.equal(selectedBeforeReflow, `dfd-node:${ids.node}`);
    await page.locator("#btn-diagram-reflow").click();
    await page.waitForTimeout(320);
    const boundaryReviewPanel = page.locator("#boundary-review-panel");
    assert.equal(await boundaryReviewPanel.getAttribute("hidden"), null, "Boundary review is hidden when the rail opens");
    if (options.screenshotDir) {
      const target = path.resolve(options.screenshotDir, "u2-model-desktop-review-visible.png");
      await page.screenshot({path: target, fullPage: false});
      result.screenshots.push(target);
    }
    const reviewCount = page.locator("#model-review-trigger-count");
    await reviewCount.click();
    assert.equal(await boundaryReviewPanel.getAttribute("hidden"), "", "Review count did not hide Boundary review");
    await reviewCount.click();
    await page.waitForTimeout(80);
    assert.equal(await boundaryReviewPanel.getAttribute("hidden"), null, "Review count did not show Boundary review");
    const desktopAfterFit = await geometry(page);
    assert.equal(desktopAfterFit.selection, selectedBeforeReflow, "Reflow lost the selected canonical node");
    assert.equal(overlapPairs(desktopAfterFit.boxes).length, 0, "Reflow produced overlapping canonical nodes");
    assert.ok(desktopAfterFit.selectedCenters.length === 1 && desktopAfterFit.selectedCenters[0].x >= 0 && desktopAfterFit.selectedCenters[0].x <= 1440 && desktopAfterFit.selectedCenters[0].y >= 0 && desktopAfterFit.selectedCenters[0].y <= 900, `Reflow moved selected node out of view: ${JSON.stringify(desktopAfterFit)}`);
    const desktopReviewLayout = await page.evaluate(() => {
      const box = selector => document.querySelector(selector)?.getBoundingClientRect();
      const rail = box("#model-inspector-rail");
      const boundary = box(".model-boundary-queue");
      const selection = box("#node-inspector");
      const cta = box("#start-boundary-guided");
      return {
        rail: rail && {top: rail.top, bottom: rail.bottom, height: rail.height},
        boundary: boundary && {top: boundary.top, bottom: boundary.bottom, right: boundary.right},
        selection: selection && {top: selection.top, bottom: selection.bottom, display: getComputedStyle(document.querySelector("#node-inspector")).display},
        cta: cta && {left: cta.left, right: cta.right},
      };
    });
    assert.ok(desktopReviewLayout.rail?.bottom <= 901, `desktop review rail exceeds viewport: ${JSON.stringify(desktopReviewLayout)}`);
    if (desktopReviewLayout.selection?.display !== "none") assert.ok(desktopReviewLayout.selection.top >= desktopReviewLayout.boundary.bottom - 1, `boundary queue and selection inspector overlap: ${JSON.stringify(desktopReviewLayout)}`);
    assert.ok(desktopReviewLayout.cta?.right >= desktopReviewLayout.boundary?.right - 16, `guided review CTA is not right-aligned: ${JSON.stringify(desktopReviewLayout)}`);
    const firstBoundaryDetails = page.locator(".model-boundary-details").first();
    await firstBoundaryDetails.locator("summary").click();
    const reviewOverflow = await page.evaluate(() => [".model-boundary-list", ".model-selection-inspector .node-inspector-body"].map(selector => {
      const element = document.querySelector(selector);
      const offenders = [...(element?.querySelectorAll("*") || [])].filter(child => child.scrollWidth > child.clientWidth + 1).slice(0, 8).map(child => ({tag: child.tagName, className: String(child.className || ""), clientWidth: child.clientWidth, scrollWidth: child.scrollWidth, text: (child.innerText || "").slice(0, 70)}));
      return {selector, clientWidth: element?.clientWidth || 0, scrollWidth: element?.scrollWidth || 0, clientHeight: element?.clientHeight || 0, scrollHeight: element?.scrollHeight || 0, offenders};
    }));
    assert.ok(reviewOverflow.every(item => item.scrollWidth <= item.clientWidth + 1), `boundary review content overflows horizontally: ${JSON.stringify(reviewOverflow)}`);
    await page.locator("#model-boundary-close").click();
    assert.equal(await boundaryReviewPanel.getAttribute("hidden"), "", "Boundary review close button did not hide the section");
    await reviewCount.click();
    assert.equal(await boundaryReviewPanel.getAttribute("hidden"), null, "Review count could not restore a closed Boundary review");
    result.metrics.desktopAfterFit = desktopAfterFit;
    result.metrics.desktopReviewLayout = desktopReviewLayout;
    result.metrics.reviewOverflow = reviewOverflow;
    if (options.screenshotDir) {
      const target = path.resolve(options.screenshotDir, "u2-model-desktop-review-open.png");
      await page.screenshot({path: target, fullPage: false});
      result.screenshots.push(target);
    }
    result.checks.push("desktop canvas ≥55% viewport + Reflow layout + selected node retained + zero node overlap");

    await page.setViewportSize({width: 390, height: 844});
    await page.goto(pageUrl(port, "model", projectId), {waitUntil: "networkidle", timeout: 20000});
    await waitForModel(page);
    const mobileClosed = await geometry(page);
    assert.equal(mobileClosed.overflow, false, "mobile Model has horizontal overflow");
    assert.ok(mobileClosed.shell.top <= 310, `mobile Model canvas is below the compact first viewport contract: ${JSON.stringify(mobileClosed)}`);
    assert.ok(mobileClosed.canvas.height >= 240, `mobile canvas is below 240px: ${JSON.stringify(mobileClosed)}`);
    assert.equal(mobileClosed.rail.state, "closed", "boundary sheet is open by default");
    assert.equal(mobileClosed.canvasRailIntersection, 0, "closed boundary sheet overlaps the mobile canvas");
    const reviewBox = await page.locator("#model-review-trigger").boundingBox();
    assert.ok(reviewBox, "mobile Review trigger is not visible");
    if (options.screenshotDir) {
      const target = path.resolve(options.screenshotDir, "u2-model-mobile-initial.png");
      await page.screenshot({path: target, fullPage: false});
      result.screenshots.push(target);
    }
    await page.touchscreen.tap(reviewBox.x + reviewBox.width / 2, reviewBox.y + reviewBox.height / 2);
    await page.waitForFunction(() => document.body.classList.contains("model-sheet-open"));
    await page.waitForTimeout(240);
    assert.equal(await page.locator("#boundary-review-panel").getAttribute("hidden"), null, "mobile Boundary review is hidden when the sheet opens");
    const mobileOpen = await geometry(page);
    assert.equal(mobileOpen.rail.state, "open");
    assert.equal(await page.evaluate(() => document.querySelector("#model-inspector-rail")?.getAttribute("role")), "dialog");
    assert.equal(await page.evaluate(() => document.querySelector("#model-inspector-rail")?.getAttribute("aria-modal")), "true");
    assert.ok(await page.evaluate(() => document.querySelector("#model-inspector-rail")?.contains(document.activeElement)), "sheet did not receive focus");
    await page.keyboard.press("Escape");
    assert.deepEqual(await page.evaluate(() => ({open: document.body.classList.contains("model-sheet-open"), focus: document.activeElement?.id})), {open: false, focus: "model-review-trigger"});
    result.metrics.mobileClosed = mobileClosed;
    result.metrics.mobileOpen = mobileOpen;
    result.checks.push("mobile canvas visible before review + closed sheet intersection 0 + touch open + Escape/focus return");

    await page.evaluate(({flow}) => focusModelElement("flow", flow), ids);
    await page.waitForTimeout(240);
    const mobileSelected = await geometry(page);
    assert.equal(mobileSelected.selection, `dfd-flow:${ids.flow}`, "flow selection was not preserved on mobile");
    assert.ok(mobileSelected.selectedCenters.every(point => point.y < mobileSelected.rail.top), `selected flow is hidden under review sheet: ${JSON.stringify(mobileSelected)}`);
    await page.locator("#model-inspector-close").click();
    await page.locator("#btn-diagram-reflow").click();
    await page.waitForTimeout(220);
    assert.equal(await page.evaluate(() => window.UIState.read().selection), `dfd-flow:${ids.flow}`, "closing sheet or Reflow lost selected flow");
    result.checks.push("mobile flow selection remains canonical after sheet close and Reflow");

    await page.setViewportSize({width: 1440, height: 900});
    await page.goto(pageUrl(port, "model", projectId, `&selected=${encodeURIComponent(`dfd-flow:${ids.flow}`)}`), {waitUntil: "networkidle", timeout: 20000});
    await waitForModel(page);
    await page.waitForSelector("#node-inspector .model-finding-link", {state: "visible", timeout: 10000});
    const evidenceHref = await page.locator("#node-inspector .model-evidence-link").first().getAttribute("href");
    assert.ok(evidenceHref && new URL(evidenceHref, page.url()).pathname.endsWith("/evidence.html"), "DFD flow has no evidence workspace trace");
    const findingId = fixture.expected_trace[0].finding_id;
    await page.locator("#node-inspector .model-finding-link").filter({hasText: findingId}).click();
    await page.waitForSelector(`#findings-list [data-finding-id="${findingId}"]`, {timeout: 15000});
    assert.equal(new URL(page.url()).pathname, "/findings.html");
    assert.equal(await page.evaluate(() => window.UIState.read().selection), `threat:${findingId}`);
    const exactDfdLink = page.locator("#findings-inspector a.finding-dfd-link").first();
    assert.equal(await exactDfdLink.count(), 1, "finding did not expose exact DFD interaction");
    assert.equal(new URL(await exactDfdLink.getAttribute("href"), page.url()).searchParams.get("selected"), `dfd-flow:${ids.flow}`, "finding DFD target is not the exact canonical flow");
    await exactDfdLink.click();
    await page.waitForSelector("#node-inspector", {state: "visible", timeout: 15000});
    assert.equal(await page.evaluate(() => window.UIState.read().selection), `dfd-flow:${ids.flow}`);
    await page.locator(".model-more-menu > summary").click();
    assert.equal(await page.locator("#btn-diagram-export").isVisible(), true);
    await page.locator("#btn-diagram-fullscreen").click();
    await page.waitForFunction(() => Boolean(document.fullscreenElement), {timeout: 5000});
    assert.equal(await page.evaluate(() => window.UIState.read().selection), `dfd-flow:${ids.flow}`, "fullscreen lost the selected flow");
    await page.keyboard.press("Escape");
    // Headless Chromium may reserve Escape for the browser fullscreen layer;
    // use the same exit API as the app's toggle to make the test deterministic.
    await page.evaluate(async () => { if (document.fullscreenElement) await document.exitFullscreen(); });
    await page.waitForFunction(() => !document.fullscreenElement, {timeout: 5000});
    result.checks.push("exact reverse trace DFD flow ↔ finding and DFD → evidence workspace; advanced commands grouped in More; fullscreen preserves selection");

    const scopeCandidate = await page.evaluate(() => {
      for (const node of currentReport.dfd_model.nodes) node.scope = "unknown";
      const context = currentReport.dfd_model.views.find(view => view.kind === "context");
      context.projection_nodes = [];
      context.projection_flows = [];
      context.projection_mappings = {};
      context.element_refs = [];
      context.projection_issues = ["context_scope_unknown: no canonical node is explicitly marked in scope"];
      navigateCanonicalLevel("context");
      const candidate = canonicalScopeReviewTargets(currentReport.dfd_model)[0];
      return {
        candidate_id: candidate?.id,
        candidate_type: candidate?.type,
        canvas_links: document.querySelectorAll("#threat-diagram-canvas [data-context-scope-review-id]").length,
        canvas_explains_save: document.querySelector("#threat-diagram-canvas")?.textContent.includes("Save semantic metadata") || false,
        outline_scope_review: document.querySelector("#diagram-text-content")?.textContent.includes("Set system scope") || false,
        outline_explains_save: document.querySelector("#diagram-text-content")?.textContent.includes("Save semantic metadata") || false,
        outline_links: document.querySelectorAll("#diagram-text-content [data-context-scope-review-id]").length,
      };
    });
    assert.ok(scopeCandidate.candidate_id, "scope blocker did not offer a canonical element to review");
    assert.ok(scopeCandidate.canvas_links > 0, "L0 scope blocker has no direct review actions");
    assert.equal(scopeCandidate.canvas_explains_save, true, "L0 scope blocker does not say that the explicit scope choice must be saved");
    assert.equal(scopeCandidate.outline_scope_review, true, "accessible outline omitted scope review guidance");
    assert.equal(scopeCandidate.outline_explains_save, true, "accessible outline does not explain how to persist the scope decision");
    assert.ok(scopeCandidate.outline_links > 0, "accessible outline has no direct scope review actions");
    await page.locator(`#threat-diagram-canvas [data-context-scope-review-id="${scopeCandidate.candidate_id}"]`).click();
    await page.waitForFunction(() => canonicalRenderedViewKind === "system" && Boolean(document.querySelector("#node-inspector [data-dfd-field=scope]")));
    const scopeInspector = await page.evaluate(() => ({
      level: canonicalRenderedViewKind,
      selected_scope: document.querySelector("#node-inspector [data-dfd-field=scope]")?.value,
      selected_node_id: document.querySelector("#node-inspector [data-dfd-field=scope]")?.closest("form")?.querySelector("input[data-dfd-field=name]")?.value,
      scope_guidance: document.querySelector(".diagram-toolbar-sub")?.textContent || "",
    }));
    assert.equal(scopeInspector.level, "system", "scope review action did not open L1");
    assert.equal(scopeInspector.selected_scope, "unknown", "scope review silently changed classification before the user decision");
    assert.match(scopeInspector.scope_guidance, /No system scope is saved yet/, "L1 does not explain why its components remain in review");
    result.metrics.scope_review = {...scopeCandidate, inspector: scopeInspector};
    result.checks.push("unknown context scope has direct canvas and accessible-outline actions to the L1 scope editor without inferred classification");

    const readableApiErrors = await page.evaluate(() => ({
      validation: formatApiErrorPayload({detail: {message: "DFD graph validation failed", errors: ["l2_scope_unknown: explicitly classify parent and child as in_scope before claiming L2 decomposition"]}}, 422),
      conflict: formatApiErrorPayload({detail: {message: "DFD revision conflict", current_revision: 4}}, 409),
    }));
    assert.match(readableApiErrors.validation, /l2_scope_unknown.*explicitly classify parent and child/);
    assert.doesNotMatch(readableApiErrors.validation, /\[object Object\]/);
    assert.match(readableApiErrors.conflict, /DFD revision conflict.*current revision 4/);
    result.metrics.api_errors = readableApiErrors;
    result.checks.push("DFD API validation and revision-conflict objects are shown as readable errors with retry signal");

    await page.close();
    await context.close();
  } catch (error) {
    result.errors.push({message: error.message, stack: error.stack});
  } finally {
    if (browser) await browser.close();
    server.kill("SIGTERM");
    fs.rmSync(tempRoot, {recursive: true, force: true});
  }
  result.summary = {check_count: result.checks.length, error_count: result.errors.length, page_error_count: result.page_errors.length, failed_request_count: result.failed_requests.length, screenshot_count: result.screenshots.length};
  if (options.output) {
    const output = path.resolve(options.output);
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
  }
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.errors.length, 0, "UX-M2 Chromium gate failed");
  assert.equal(result.page_errors.length, 0, `UX-M2 found page errors: ${result.page_errors.join(" | ")}`);
  assert.equal(result.failed_requests.length, 0, "UX-M2 found failed API requests");
    assert.equal(result.checks.length, 8, "UX-M2 did not complete all checks");
}

main().catch(error => { console.error(`UX-M2 gate error: ${error.message}`); process.exitCode = 1; });
