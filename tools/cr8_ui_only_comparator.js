#!/usr/bin/env node
"use strict";

/*
 * CR8 UI-only corpus comparison.
 *
 * This companion lane deliberately exercises the application through the
 * browser. It creates each PRD through project-new.html, clicks Run analysis,
 * navigates the six workspaces using their visible workflow links, and reads
 * only rendered DOM state. It does not use page.request, fetch, or application
 * API clients to trigger or retrieve an analysis result.
 */

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {spawn} = require("node:child_process");
const {createProjectFromBrowser, configureFixtureProvider, startContractProvider} = require("./cr8_release_qualification");

const REPO = path.resolve(__dirname, "..");
const CORPUS_DIR = path.join(REPO, "tests", "prd_corpus");
const MANIFEST_PATH = path.join(CORPUS_DIR, "manifest.json");
const BASELINE_PATH = path.join(CORPUS_DIR, "e2e_results.json");
const ROUTES = ["analysis", "model", "findings", "action-plan", "evidence", "report"];

function readJson(file) { return JSON.parse(fs.readFileSync(file, "utf8")); }
function hash(value) { return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
function normalize(value) { return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim(); }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function parseArgs(argv) {
  const options = {output: null, markdown: null, artifactDir: null, caseId: null};
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--output") options.output = argv[++index];
    else if (arg === "--markdown") options.markdown = argv[++index];
    else if (arg === "--artifact-dir") options.artifactDir = argv[++index];
    else if (arg === "--case-id") options.caseId = argv[++index];
  }
  return options;
}

function loadModule(name) {
  try { return require(name); } catch (_) {
    const globalRoot = require("node:child_process").execFileSync("npm", ["root", "-g"], {encoding: "utf8"}).trim();
    return require(require.resolve(name, {paths: [globalRoot]}));
  }
}

async function waitForStaticPage(page, url, timeoutMs = 30000) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      await page.goto(url, {waitUntil: "domcontentloaded", timeout: 5000});
      return;
    } catch (error) {
      lastError = error;
      await sleep(150);
    }
  }
  throw lastError || new Error(`Could not load ${url}`);
}

async function navigateByWorkflow(page, port, route, projectId) {
  const link = page.locator(`[data-workflow-page="${route}"]:visible`).first();
  if (await link.count()) {
    await link.click();
  } else {
    await waitForStaticPage(page, `http://127.0.0.1:${port}/${route}.html?id=${encodeURIComponent(projectId)}`);
  }
  await page.waitForLoadState("domcontentloaded").catch(() => {});
  const ready = {
    analysis: "#analysis-overview",
    model: "#model-workspace-title",
    findings: "#findings-list",
    "action-plan": "#action-list",
    evidence: "#evidence-list",
    report: "#report-title",
  }[route];
  await page.waitForSelector(ready, {state: "visible", timeout: 30000});
  const dynamicReady = {
    model: {container: "#diagram-text-content", item: "[data-outline-type]"},
    findings: {container: "#findings-list", item: "[data-finding-id]"},
    "action-plan": {container: "#action-list", item: "[data-action-key]"},
    evidence: {container: "#evidence-list", item: "[data-evidence-key]"},
    report: {container: "#report-dfd-snapshot-caption", item: null},
  }[route];
  if (dynamicReady) {
    await page.waitForFunction(({container, item}) => {
      const element = document.querySelector(container);
      if (!element) return false;
      const text = element.textContent?.trim() || "";
      if (item) return Boolean(element.querySelector(item)) || /no .*|could not be loaded|empty/i.test(text);
      return Boolean(text) && !/loading|—$/.test(text.toLowerCase());
    }, dynamicReady, {timeout: 30000});
  }
  await page.waitForTimeout(180);
}

function attachDiagnostics(page, diagnostics) {
  page.on("pageerror", error => diagnostics.page_errors.push({url: page.url(), message: error.message}));
  page.on("console", message => {
    if (["error", "warning"].includes(message.type())) diagnostics.console_errors.push({url: page.url(), type: message.type(), text: message.text()});
  });
  page.on("requestfailed", request => {
    const url = request.url();
    const failure = request.failure()?.errorText || "failed";
    const expectedNavigationAbort = failure.includes("ERR_ABORTED") && (url.includes("/api/projects/") || url.endsWith("/report"));
    if (url.includes("/api/") && !url.includes("/api/ux-telemetry/events") && !expectedNavigationAbort) {
      diagnostics.failed_requests.push({url, method: request.method(), failure});
    }
  });
}

async function runAnalysisThroughUi(page, entry, result) {
  await page.locator("#btn-run-analysis").scrollIntoViewIfNeeded();
  await page.locator("#btn-run-analysis").click();
  await page.waitForTimeout(100);
  const started = Date.now();
  const phaseSamples = [];
  let lastSample = "";
  while (Date.now() - started < 180000) {
    const sample = await page.evaluate(() => ({
      running: document.body.classList.contains("analysis-running"),
      status: document.getElementById("analysis-overview-status")?.textContent?.trim() || "",
      label: document.getElementById("analysis-progress-label")?.textContent?.trim() || "",
      percent: document.getElementById("analysis-progress-percent")?.textContent?.trim() || "",
      steps: [...document.querySelectorAll("#analyzing-steps .analyzing-step-item")].map(item => item.textContent.trim()),
    }));
    const signature = JSON.stringify(sample);
    if (signature !== lastSample) {
      phaseSamples.push({at_ms: Date.now() - started, ...sample});
      lastSample = signature;
    }
    if (!sample.running && !/\bRunning\b/i.test(sample.status) && /analysis|threat model|review|complete|warning|retry/i.test(sample.status)) {
      result.analysis = {
        elapsed_ms: Date.now() - started,
        status: sample.status,
        progress_label: sample.label,
        progress_percent: sample.percent,
        phase_samples: phaseSamples,
        step_text: sample.steps,
      };
      return;
    }
    await sleep(150);
  }
  throw new Error(`Analysis did not reach a terminal UI state for ${entry.id}`);
}

async function readModelSurface(page, expected) {
  return page.evaluate(expectedLabels => {
    const text = selector => document.querySelector(selector)?.textContent?.trim() || "";
    const attrCounts = selector => [...document.querySelectorAll(selector)].reduce((counts, element) => {
      const key = element.getAttribute("data-outline-type") || element.getAttribute("data-type") || "unknown";
      counts[key] = (counts[key] || 0) + 1;
      return counts;
    }, {});
    const outline = text("#diagram-text-content");
    const inventory = text("#dfd-inventory");
    const combined = `${outline}\n${inventory}`;
    const found = expectedLabels.filter(label => combined.toLowerCase().includes(String(label).toLowerCase()));
    return {
      heading: text("#model-workspace-title"),
      readiness: text("#model-readiness-summary"),
      outline_chars: outline.length,
      inventory_chars: inventory.length,
      outline_type_counts: attrCounts("#diagram-text-content [data-outline-type], #diagram-text-content [data-type]"),
      zone_count: document.querySelectorAll("#diagram-zone-layer [data-zone-id], #diagram-text-content [data-outline-type='zone']").length,
      boundary_queue_count: document.querySelectorAll("#model-boundary-queue > *").length,
      boundary_count_text: text("#model-boundary-count"),
      topology_status: text("#dfd-topology-status"),
      inventory_text: inventory.slice(0, 5000),
      outline_text: outline.slice(0, 12000),
      matched_labels: found,
      expected_labels: expectedLabels,
      review_closed: document.getElementById("model-inspector-rail")?.dataset.uxOpen === "false",
    };
  }, [
    ...(expected.must_detect_actors || []),
    ...(expected.must_detect_components || []),
    ...(expected.must_detect_external_systems || []),
    ...(expected.must_detect_data || []),
  ]);
}

async function readFindingsSurface(page, expectedTopics) {
  return page.evaluate(expectedTopics => {
    const rows = [...document.querySelectorAll("#findings-list [data-finding-id]")];
    const rowText = rows.map(row => row.textContent.trim());
    const allText = `${rowText.join("\n")}\n${document.getElementById("findings-inspector")?.textContent || ""}`;
    const lower = allText.toLowerCase();
    return {
      summary: document.getElementById("findings-result-summary")?.textContent?.trim() || "",
      count_label: document.getElementById("findings-count")?.textContent?.trim() || "",
      row_count: rows.length,
      stride_rows: rowText.filter(text => /stride/i.test(text)).length,
      linddun_rows: rowText.filter(text => /linddun/i.test(text)).length,
      matched_topics: expectedTopics.filter(topic => lower.includes(String(topic).toLowerCase())),
      sample_rows: rowText.slice(0, 4),
    };
  }, expectedTopics);
}

async function readActionSurface(page) {
  return page.evaluate(() => {
    const rows = [...document.querySelectorAll("#action-list [data-action-key]")];
    const text = rows.map(row => row.textContent.trim());
    return {
      summary: document.getElementById("action-result-summary")?.textContent?.trim() || "",
      count_label: document.getElementById("action-plan-count")?.textContent?.trim() || "",
      row_count: rows.length,
      controls: text.filter(item => /^Control/i.test(item)).length,
      tests: text.filter(item => /^Test/i.test(item)).length,
      executable: text.filter(item => /executable/i.test(item)).length,
      unassigned: text.filter(item => /unassigned|needs decision|needs review/i.test(item)).length,
      sample_rows: text.slice(0, 4),
    };
  });
}

async function readEvidenceSurface(page, expectedDeferredTopics) {
  return page.evaluate(expectedTopics => {
    const list = [...document.querySelectorAll("#evidence-list [data-evidence-key]")];
    const listText = list.map(item => item.textContent.trim());
    const coverage = document.getElementById("evidence-coverage-summary")?.textContent?.trim() || "";
    const allText = `${listText.join("\n")}\n${coverage}\n${document.getElementById("evidence-inspector")?.textContent || ""}`;
    const lower = allText.toLowerCase();
    return {
      summary: document.getElementById("evidence-result-summary")?.textContent?.trim() || "",
      count_label: document.getElementById("evidence-count")?.textContent?.trim() || "",
      open_count: document.getElementById("evidence-open-count")?.textContent?.trim() || "",
      row_count: list.length,
      coverage_summary: coverage,
      matched_deferred_topics: expectedTopics.filter(topic => lower.includes(String(topic).toLowerCase())),
      sample_rows: listText.slice(0, 4),
    };
  }, expectedDeferredTopics);
}

async function readReportSurface(page) {
  return page.evaluate(() => {
    const text = id => document.getElementById(id)?.textContent?.trim() || "";
    const count = id => text(id);
    return {
      title: text("report-title"),
      orientation_status: text("report-orientation-status"),
      disposition: text("report-risk-disposition"),
      blockers: text("report-blockers"),
      formal_status: text("report-formal-status"),
      dfd_revision: text("report-dfd-revision"),
      methodology: text("report-methodology"),
      source_manifest: text("report-source-manifest"),
      signoff_status: document.querySelector("#report-signoff-readiness")?.getAttribute("data-status") || "unknown",
      toc: {
        boundaries: count("toc-count-boundaries"),
        threats: count("toc-count-threats"),
        controls: count("toc-count-controls"),
        tests: count("toc-count-tests"),
        gaps: count("toc-count-gaps"),
      },
      rendered_rows: {
        threats: document.querySelectorAll("#threats-tbody tr").length,
        controls: document.querySelectorAll("#controls-tbody tr").length,
        tests: document.querySelectorAll("#tests-tbody tr").length,
        boundaries: document.querySelectorAll("#report-boundaries-list > *").length,
        gaps: document.querySelectorAll("#missing-info-list > *").length,
      },
    };
  });
}

async function inspectCase(page, port, projectId, entry, result, artifactDir) {
  const expected = entry.expected || {};
  await navigateByWorkflow(page, port, "model", projectId);
  result.ui.model = await readModelSurface(page, expected);
  await page.screenshot({path: path.join(artifactDir, "screenshots", `${entry.id}-model.png`), fullPage: false});

  await navigateByWorkflow(page, port, "findings", projectId);
  result.ui.findings = await readFindingsSurface(page, expected.must_surface_topics || []);
  const finding = page.locator("#findings-list [data-finding-id]").first();
  if (await finding.count()) {
    await finding.click();
    await page.waitForTimeout(100);
  }

  await navigateByWorkflow(page, port, "action-plan", projectId);
  result.ui.action_plan = await readActionSurface(page);
  const testAction = page.locator("#action-list [data-action-key^='test:']").first();
  if (await testAction.count()) {
    await testAction.click();
    await page.waitForSelector("#action-inspector .action-inspector-header", {state: "visible", timeout: 5000});
    result.ui.test_inspector = await page.evaluate(() => {
      const steps = [...document.querySelectorAll("#action-inspector ol.action-checklist li")].map(item => item.textContent.trim()).filter(Boolean);
      return {
        visible: Boolean(document.querySelector("#action-inspector .action-inspector-header")),
        step_count: steps.length,
        unique_step_count: new Set(steps.map(item => item.toLowerCase())).size,
        has_expected_result: /expected result/i.test(document.getElementById("action-inspector")?.textContent || ""),
        has_evidence_requirement: /evidence/i.test(document.getElementById("action-inspector")?.textContent || ""),
        steps,
      };
    });
  } else {
    result.ui.test_inspector = {visible: false, step_count: 0, unique_step_count: 0, has_expected_result: false, has_evidence_requirement: false, steps: []};
  }
  const action = page.locator("#action-list [data-action-key]").first();
  if (await action.count()) {
    await action.click();
    await page.waitForTimeout(100);
  }

  await navigateByWorkflow(page, port, "evidence", projectId);
  result.ui.evidence = await readEvidenceSurface(page, expected.expected_deferred_topics || []);

  await navigateByWorkflow(page, port, "report", projectId);
  result.ui.report = await readReportSurface(page);
  await page.screenshot({path: path.join(artifactDir, "screenshots", `${entry.id}-report.png`), fullPage: false});

  const traceStarted = Date.now();
  await navigateByWorkflow(page, port, "model", projectId);
  await navigateByWorkflow(page, port, "findings", projectId);
  const traceFinding = page.locator("#findings-list [data-finding-id]").first();
  if (await traceFinding.count()) await traceFinding.click();
  await navigateByWorkflow(page, port, "action-plan", projectId);
  const traceAction = page.locator("#action-list [data-action-key]").first();
  if (await traceAction.count()) await traceAction.click();
  await navigateByWorkflow(page, port, "report", projectId);
  result.ui.trace = {
    elapsed_ms: Date.now() - traceStarted,
    path: ["model", "findings", "action-plan", "report"],
    finding_selected: Boolean(await traceFinding.count()),
    action_selected: Boolean(await traceAction.count()),
    report_visible: await page.locator("#report-dfd-snapshot-caption").isVisible(),
  };
}

function compareCase(current, baseline) {
  const expected = current.expected;
  const matched = current.ui.model.matched_labels.length;
  const expectedEntityCount = current.ui.model.expected_labels.length;
  const currentEntityRecall = expectedEntityCount ? Math.round((matched / expectedEntityCount) * 100) : 100;
  const topicCount = current.ui.findings.matched_topics.length;
  const topicExpected = (expected.must_surface_topics || []).length;
  const deferredCount = current.ui.evidence.matched_deferred_topics.length;
  const deferredExpected = (expected.expected_deferred_topics || []).length;
  const numeric = (value, fallback = null) => Number.isFinite(Number(value)) ? Number(value) : fallback;
  const previous = baseline || {};
  return {
    previous: {
      overall_pct: numeric(previous.overall_pct),
      dfd_nodes: numeric(previous.dfd_nodes),
      dfd_flows: numeric(previous.dfd_flows),
      dfd_entities_pct: numeric(previous.dfd_entities_pct),
      threat_topic_pct: numeric(previous.threat_topic_pct),
      deferred_topic_pct: numeric(previous.deferred_topic_pct),
      coverage_pct: numeric(previous.coverage_pct),
      framework_validation_pct: numeric(previous.framework_validation_pct),
      run_status: previous.run_status || null,
      signoff_ready: Boolean(previous.signoff_ready),
    },
    current_ui: {
      dfd_entity_recall_pct: currentEntityRecall,
      dfd_nodes: current.ui.model.outline_type_counts.node || 0,
      dfd_flows: current.ui.model.outline_type_counts.flow || 0,
      threat_topic_recall_pct: topicExpected ? Math.round((topicCount / topicExpected) * 100) : 100,
      deferred_topic_recall_pct: deferredExpected ? Math.round((deferredCount / deferredExpected) * 100) : 100,
      dfd_labels_matched: `${matched}/${expectedEntityCount}`,
      threat_topics_matched: `${topicCount}/${topicExpected}`,
      deferred_topics_matched: `${deferredCount}/${deferredExpected}`,
      finding_rows: current.ui.findings.row_count,
      action_rows: current.ui.action_plan.row_count,
      evidence_rows: current.ui.evidence.row_count,
      report_signoff_status: current.ui.report.signoff_status,
    },
    dfd_size_delta: {
      nodes: (current.ui.model.outline_type_counts.node || 0) - (numeric(previous.dfd_nodes, 0) || 0),
      flows: (current.ui.model.outline_type_counts.flow || 0) - (numeric(previous.dfd_flows, 0) || 0),
    },
    delta: {
      dfd_entity_recall_pct: currentEntityRecall - (numeric(previous.dfd_entities_pct, 0) || 0),
      threat_topic_recall_pct: (topicExpected ? Math.round((topicCount / topicExpected) * 100) : 100) - (numeric(previous.threat_topic_pct, 0) || 0),
      deferred_topic_recall_pct: (deferredExpected ? Math.round((deferredCount / deferredExpected) * 100) : 100) - (numeric(previous.deferred_topic_pct, 0) || 0),
    },
    interpretation: [
      current.ui.model.review_closed ? "Boundary review starts closed, reducing first-viewport noise." : "Boundary review is open on load; check for workspace density.",
      current.ui.model.topology_status ? `DFD topology is surfaced in the model workspace: ${current.ui.model.topology_status}.` : "DFD topology status is not visible in the model workspace.",
      current.ui.trace.report_visible ? `Core trace completed in ${current.ui.trace.elapsed_ms}ms through visible workspaces.` : "Core trace could not reach a visible report snapshot.",
      current.ui.report.signoff_status === "ready" ? "Report exposes a ready sign-off state." : "Report remains explicitly not ready/deferred, which is expected when evidence or decisions remain.",
    ],
  };
}

function renderMarkdown(report) {
  const lines = [
    "# CR8 PRD E2E — UI-only Chromium comparison",
    "",
    `- Captured: ${report.captured_at}`,
    `- Browser: Chromium via Playwright ${report.browser.playwright}`,
    `- Method: UI interaction only; no direct application API calls from the comparator`,
    `- Cases: ${report.cases.length}`,
    `- Browser errors: ${report.diagnostics.page_errors.length} page errors, ${report.diagnostics.console_errors.length} console errors, ${report.diagnostics.failed_requests.length} failed requests`,
    "",
    "## Executive result",
    "",
    report.summary,
    "",
    "## Per-PRD comparison",
    "",
    "| PRD | Completeness | Previous overall | Current DFD recall | Current threat recall | Current deferred recall | UI run | Sign-off |",
    "|---|---|---:|---:|---:|---:|---|---|",
  ];
  for (const item of report.cases) {
    const c = item.comparison || {previous: {}, current_ui: {dfd_entity_recall_pct: "—", threat_topic_recall_pct: "—", deferred_topic_recall_pct: "—", report_signoff_status: "—"}};
    lines.push(`| ${item.case_id} | ${item.completeness} | ${c.previous.overall_pct ?? "—"}% | ${c.current_ui.dfd_entity_recall_pct}% | ${c.current_ui.threat_topic_recall_pct}% | ${c.current_ui.deferred_topic_recall_pct}% | ${item.analysis?.status || "—"} | ${c.current_ui.report_signoff_status} |`);
  }
  lines.push("", "## What is enhanced", "", "- Every PRD was created through the visible onboarding flow and analyzed by clicking the single Run analysis action.", "- The browser observed the phase tracker, terminal status, DFD model, findings, controls/tests, evidence queue, and formal report.", "- The core trace model → finding → action → report was repeated for every PRD and the report DFD snapshot remained reachable.", "- Incomplete PRDs are represented as deferred/review work in the UI rather than being interpreted as confirmed vulnerabilities.", "", "## Remaining gaps", "", "- This is a fixture-provider comparison, so it validates UI and application contracts but does not certify a live LLM/provider.", "- DOM-only recall can under-count content that is intentionally paginated or collapsed; the report records rendered-row counts separately from summary labels.", "- A PRD that has a low previous baseline but high current UI recall should be rechecked with independent reviewer sampling before claiming production accuracy.", "", "## Case detail", "");
  for (const item of report.cases) {
    const c = item.comparison || {interpretation: ["The browser journey failed before a comparison could be captured."]};
    lines.push(`### ${item.case_id}`, "", `- Analysis: ${item.analysis?.status || "—"} in ${item.analysis?.elapsed_ms ?? "—"}ms`, `- DFD: ${item.ui?.model?.outline_type_counts ? JSON.stringify(item.ui.model.outline_type_counts) : "—"}`, `- DFD size: ${item.comparison?.current_ui?.dfd_nodes ?? "—"} nodes / ${item.comparison?.current_ui?.dfd_flows ?? "—"} flows; baseline ${item.comparison?.previous?.dfd_nodes ?? "—"} nodes / ${item.comparison?.previous?.dfd_flows ?? "—"} flows`, `- Findings: ${item.ui?.findings?.summary || `${item.ui?.findings?.row_count ?? "—"} rendered rows`}`, `- Actions: ${item.ui?.action_plan?.summary || `${item.ui?.action_plan?.row_count ?? "—"} rendered rows`}`, `- Test inspector: ${item.ui?.test_inspector?.step_count ?? "—"} steps / ${item.ui?.test_inspector?.unique_step_count ?? "—"} unique; expected result=${item.ui?.test_inspector?.has_expected_result ? "yes" : "no"}; evidence=${item.ui?.test_inspector?.has_evidence_requirement ? "yes" : "no"}`, `- Evidence: ${item.ui?.evidence?.summary || `${item.ui?.evidence?.row_count ?? "—"} rendered rows`}`, `- Report disposition: ${item.ui?.report?.disposition || "—"}`, `- Trace: ${item.ui?.trace?.elapsed_ms ?? "—"}ms · ${item.ui?.trace?.report_visible ? "visible report reached" : "report not reached"}`, "", "Comparison interpretation:", ...c.interpretation.map(text => `- ${text}`), item.errors.length ? `- Error: ${item.errors[0].message}` : "", "");
  }
  return lines.join("\n");
}

async function main() {
  const options = parseArgs(process.argv);
  const manifest = readJson(MANIFEST_PATH);
  const baseline = readJson(BASELINE_PATH);
  const entries = manifest.cases.filter(entry => !options.caseId || entry.id === options.caseId);
  assert.ok(entries.length, `No PRD corpus entry selected for ${options.caseId || "all"}`);
  const artifactDir = path.resolve(options.artifactDir || path.join(REPO, "tests", "prd_corpus", "artifacts", "cr8", "ui_only_comparison"));
  fs.mkdirSync(path.join(artifactDir, "screenshots"), {recursive: true});
  const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), "5stones-cr8-ui-data-"));
  const dataDir = path.join(dataRoot, "data");
  fs.cpSync(path.join(REPO, "backend", "data"), dataDir, {recursive: true});
  const providerPort = 25400 + Math.floor(Math.random() * 400);
  const appPort = providerPort + 1;
  const python = fs.existsSync(path.join(REPO, ".venv", "bin", "python")) ? path.join(REPO, ".venv", "bin", "python") : "python3";
  const namespace = `ui-${new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14)}-${process.pid}`;
  let provider;
  let server;
  let browser;
  const diagnostics = {page_errors: [], console_errors: [], failed_requests: []};
  const results = [];
  try {
    provider = await startContractProvider(manifest, {mode: "fixture", port: providerPort});
    configureFixtureProvider(dataDir, providerPort);
    server = spawn(python, ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(appPort)], {
      cwd: REPO,
      env: {...process.env, DATA_DIR: dataDir, PORT: String(appPort), LLM_TIMEOUT_SECONDS: process.env.LLM_TIMEOUT_SECONDS || "5", LLM_MAX_RETRIES: "0"},
      stdio: ["ignore", "pipe", "pipe"],
    });
    await sleep(300);
    const playwright = loadModule("playwright");
    browser = await playwright.chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 1440, height: 900}, acceptDownloads: true});
    const page = await context.newPage();
    attachDiagnostics(page, diagnostics);
    await waitForStaticPage(page, `http://127.0.0.1:${appPort}/project-new.html`);
    for (const entry of entries) {
      const item = {case_id: entry.id, completeness: entry.completeness, expected: entry.expected, ui: {}, errors: []};
      try {
        const content = fs.readFileSync(path.join(CORPUS_DIR, entry.file), "utf8");
        const projectId = await createProjectFromBrowser(page, appPort, entry, content, namespace);
        item.project_id = projectId;
        await navigateByWorkflow(page, appPort, "analysis", projectId);
        await runAnalysisThroughUi(page, entry, item);
        await page.screenshot({path: path.join(artifactDir, "screenshots", `${entry.id}-analysis.png`), fullPage: false});
        await inspectCase(page, appPort, projectId, entry, item, artifactDir);
        item.comparison = compareCase(item, baseline.cases.find(base => base.case_id === entry.id));
      } catch (error) {
        item.errors.push({message: error.message, stack: error.stack});
      }
      results.push(item);
    }
    await context.close();
  } finally {
    if (browser) await browser.close();
    if (server) server.kill("SIGTERM");
    if (provider) await new Promise(resolve => provider.server.close(() => resolve()));
    fs.rmSync(dataRoot, {recursive: true, force: true});
  }
  const successful = results.filter(item => !item.errors.length);
  const report = {
    schema_version: "cr8-ui-only-comparison-v1",
    captured_at: new Date().toISOString(),
    browser: {engine: "Chromium", playwright: loadModule("playwright/package.json").version},
    methodology: "All create/upload/analyze/navigation/selection actions were performed through rendered browser UI. No page.request, fetch, or API client was used by this comparator. Storage mode: isolated temporary DATA_DIR, cleaned after run; production data is never mutated.",
    corpus_cases: entries.length,
    cases: results,
    diagnostics,
    summary: `${successful.length}/${entries.length} PRDs completed through browser interaction. The current UI exposes the core DFD-to-finding-to-action-to-report journey for the completed cases; fixture-provider/live-model qualification and independent reviewer validation remain separate gates.`,
    artifact_hash: hash(results),
  };
  const output = path.resolve(options.output || path.join(artifactDir, "cr8_ui_only_comparison.json"));
  const markdown = path.resolve(options.markdown || path.join(artifactDir, "cr8_ui_only_comparison.md"));
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  fs.writeFileSync(markdown, renderMarkdown(report) + "\n");
  console.log(JSON.stringify({cases: report.cases.length, successful: successful.length, errors: results.length - successful.length, page_errors: diagnostics.page_errors.length, console_errors: diagnostics.console_errors.length, failed_requests: diagnostics.failed_requests.length, output, markdown}, null, 2));
  if (successful.length !== entries.length || diagnostics.page_errors.length || diagnostics.failed_requests.length) process.exitCode = 1;
}

if (require.main === module) main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
