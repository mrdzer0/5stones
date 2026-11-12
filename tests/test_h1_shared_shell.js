#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO = path.resolve(__dirname, "..");
const workspaceRoutes = ["analysis", "model", "findings", "action-plan", "evidence", "report"];
const sidebarSource = fs.readFileSync(path.join(REPO, "frontend", "js", "sidebar.js"), "utf8");

assert.match(sidebarSource, /function renderCanonicalSidebar/);
assert.match(sidebarSource, /function installProjectWorkflowNavigation/);
assert.match(sidebarSource, /Dashboard/);
assert.match(sidebarSource, /New project/);
assert.match(sidebarSource, /Settings & BYOK/);
assert.match(sidebarSource, /Overview/);
assert.match(sidebarSource, /DFD model/);
assert.match(sidebarSource, /Report & sign-off/);
assert.match(sidebarSource, /project-workflow-stage/);

for (const route of workspaceRoutes) {
  const html = fs.readFileSync(path.join(REPO, "frontend", `${route}.html`), "utf8");
  assert.match(html, /<script src="\/static\/js\/sidebar\.js"><\/script>/, `${route}: shared sidebar script missing`);
  assert.match(html, /<aside class="sidebar">/, `${route}: sidebar fallback missing`);
}

const analysis = fs.readFileSync(path.join(REPO, "frontend", "analysis.html"), "utf8");
const analysisJs = fs.readFileSync(path.join(REPO, "frontend", "js", "analysis.js"), "utf8");
assert.match(analysis, /id="overview-scored"/, "analysis: scored total metric missing");
assert.match(analysis, /id="overview-critical"/, "analysis: critical detail metric missing");
assert.match(analysis, /id="overview-high"/, "analysis: high detail metric missing");
assert.match(analysisJs, /setText\('overview-scored', scored\)/, "analysis: scored total is not rendered separately");
assert.match(analysisJs, /setText\('overview-critical', critical\)/, "analysis: critical detail is not rendered separately");
assert.match(analysisJs, /setText\('overview-high', high\)/, "analysis: high detail is not rendered separately");

console.log(JSON.stringify({contract: "H1-shared-shell", routes: workspaceRoutes.length, status: "pass"}));
