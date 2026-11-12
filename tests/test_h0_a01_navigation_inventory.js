#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const REPO = path.resolve(__dirname, "..");
const inventory = JSON.parse(fs.readFileSync(path.join(REPO, "fixtures", "h0_a01_navigation_inventory.json"), "utf8"));
const assertTarget = process.argv.includes("--assert-target");

function decodeHtml(value) {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function textContent(value) {
  return decodeHtml(value.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
}

function attr(tag, name) {
  return tag.match(new RegExp(`${name}=["']([^"']*)["']`))?.[1] || "";
}

function readSidebar(html) {
  const aside = html.match(/<aside\s+class=["']sidebar["'][\s\S]*?<\/aside>/i)?.[0] || "";
  const result = [];
  const sections = [...aside.matchAll(/<div\s+class=["'][^"']*sidebar-section[^"']*["'][\s\S]*?<div\s+class=["'][^"']*sidebar-section-label[^"']*["'][^>]*>([\s\S]*?)<\/div>[\s\S]*?<ul\s+class=["'][^"']*sidebar-nav[^"']*["']>([\s\S]*?)<\/ul>/gi)];
  for (const match of sections) {
    const sectionLabel = textContent(match[1]);
    const nav = match[2];
    const links = [...nav.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)].map(link => ({
      id: attr(link[1], "id"),
      href: attr(link[1], "href"),
      label: textContent(link[2]),
      section: sectionLabel,
      active: /\bactive\b/.test(attr(link[1], "class")),
    }));
    result.push(...links);
  }
  return result;
}

function readWorkflow(html) {
  return [...html.matchAll(/<[^>]*class=["'][^"']*analysis-workflow-step[^"']*["'][^>]*>([\s\S]*?)<\/(?:button|a)>/gi)]
    .map(match => textContent(match[1].match(/<strong[^>]*>([\s\S]*?)<\/strong>/i)?.[1] || match[1]));
}

function extractDivByClass(html, className) {
  const start = html.search(new RegExp(`<div\\b[^>]*class=["'][^"']*\\b${className}\\b[^"']*["'][^>]*>`, "i"));
  if (start < 0) return "";
  const tokenPattern = /<\/?div\b[^>]*>/gi;
  tokenPattern.lastIndex = start;
  let depth = 0;
  let end = html.length;
  let token;
  while ((token = tokenPattern.exec(html))) {
    if (/^<div\b/i.test(token[0])) depth += 1;
    else depth -= 1;
    if (depth === 0) {
      end = tokenPattern.lastIndex;
      break;
    }
  }
  return html.slice(start, end);
}

function readTopbarActionIds(html) {
  const block = extractDivByClass(html, "topbar-actions");
  return [...block.matchAll(/<(?:a|button)\b([^>]*)>/gi)]
    .map(match => attr(match[1], "id"))
    .filter(Boolean);
}

function readIds(html, ids) {
  return ids.filter(id => new RegExp(`\\bid=["']${id}["']`).test(html));
}

function readBackLabel(html) {
  const match = html.match(/<(?:a|button)\b([^>]*)aria-label=["']([^"']*?)['"][^>]*>/i);
  return match?.[2] || "";
}

const expectedRouteKeys = Object.keys(inventory.routes);
assert.deepEqual(expectedRouteKeys, ["analysis", "model", "findings", "action-plan", "evidence", "report"]);

for (const [route, expected] of Object.entries(inventory.routes)) {
  const filePath = path.join(REPO, expected.file);
  assert.equal(fs.existsSync(filePath), true, `${route}: route file is missing`);
  const html = fs.readFileSync(filePath, "utf8");
  const sidebar = readSidebar(html);
  if (assertTarget) {
    assert.deepEqual(sidebar.map(item => ({label: item.label, section: item.section})), [
      {label: "Dashboard", section: "Workspace"},
      {label: "New project", section: "Workspace"},
      {label: "Settings & BYOK", section: "Configuration"},
    ], `${route}: canonical static sidebar drift`);
    assert.deepEqual(readWorkflow(html), [], `${route}: legacy workflow navigation must be removed from static markup`);
    assert.equal(/\bCurrent Project\b/i.test(html), false, `${route}: legacy Current Project section remains`);
  }
  const expectedSidebar = expected.sidebar.map(item => ({
    label: item.label,
    section: item.section,
  }));
  if (!assertTarget) {
    assert.deepEqual(sidebar.map(item => ({ label: item.label, section: item.section })), expectedSidebar, `${route}: sidebar matrix drift`);
    assert.deepEqual([...new Set(sidebar.map(item => item.section))], expected.sidebarSections, `${route}: sidebar section drift`);
  }

  const workflow = readWorkflow(html);
  if (!assertTarget) assert.deepEqual(workflow, expected.workflow.map(item => item.label), `${route}: workflow matrix drift`);
  assert.equal(/\bbreadcrumb\b/i.test(html), expected.breadcrumb.present, `${route}: breadcrumb presence drift`);
  assert.equal(readBackLabel(html), expected.back.label, `${route}: back control drift`);

  const actionIds = expected.topbarActions.map(item => item.id);
  if (!assertTarget) assert.deepEqual(readTopbarActionIds(html), actionIds, `${route}: topbar action inventory drift`);
  assert.equal((html.match(/<h1\b/gi) || []).length, 1, `${route}: page title must have exactly one h1`);
  assert.equal((html.match(/class=["']sidebar-footer["']/g) || []).length, 1, `${route}: branding footer drift`);
  const sidebarFooter = html.match(/<div\s+class=["']sidebar-footer["'][^>]*>([\s\S]*?)<\/div>/i)?.[1] || "";
  assert.equal(/<(?:a|button|nav)\b/i.test(sidebarFooter), false, `${route}: footer navigation is not classified`);
  assert.deepEqual(expected.footerNavigation, [], `${route}: footer navigation must remain explicitly empty`);
}

const analysis = inventory.routes.analysis;
if (assertTarget) {
  console.log(JSON.stringify({contract: inventory.contract, mode: "assert-target", routes: expectedRouteKeys.length, status: "pass"}));
  process.exit(0);
}
assert.equal(analysis.workflow.length, 6, "analysis must retain the current six-step baseline for H0-A01");
assert.equal(inventory.findings.some(item => item.id === "NAV-C01" && item.priority === "P0"), true);
assert.equal(inventory.findings.some(item => item.id === "NAV-C02" && item.priority === "P0"), true);
console.log(JSON.stringify({
  contract: inventory.contract,
  routes: expectedRouteKeys.length,
  sidebarItems: expectedRouteKeys.map(route => ({ route, count: inventory.routes[route].sidebar.length })),
  workflowRoutes: expectedRouteKeys.filter(route => inventory.routes[route].workflow.length > 0),
  breadcrumbRoutes: expectedRouteKeys.filter(route => inventory.routes[route].breadcrumb.present),
  footerNavigationRoutes: expectedRouteKeys.filter(route => inventory.routes[route].footerNavigation.length > 0),
  findings: inventory.findings.length,
}));
