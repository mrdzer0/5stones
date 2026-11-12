/*
 * U7 release-gate smoke test.
 *
 * This intentionally stays dependency-light: the repository does not vendor
 * axe-core, so it performs the high-value critical/serious checks locally
 * (names, references, duplicate ids, keyboard focus, overflow, and overlays)
 * and captures a visual matrix for manual diffing.
 *
 * Run with: node tests/test_u7_accessibility.js
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');

let chromium;
try { ({ chromium } = require('playwright')); }
catch (_) { ({ chromium } = require(path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'playwright'))); }

const host = '127.0.0.1';
const projectId = process.env.U7_PROJECT_ID || '9b3aeb5d-1e7b-4f62-809c-0f74b33a1510';
const viewports = [390, 768, 1280, 1440];
const routes = [
  ['analysis', '#analysis-next-actions-list'],
  ['model', '#threat-diagram-canvas'],
  ['findings', '#findings-list'],
  ['action-plan', '#action-list'],
  ['evidence', '#evidence-list'],
  ['report', '#report-title'],
];

async function availablePort() {
  const probe = http.createServer();
  await new Promise(resolve => probe.listen(0, host, resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  return port;
}

async function waitForApp(base, child) {
  for (let i = 0; i < 100; i += 1) {
    if (child.exitCode !== null) throw new Error(`App exited early: ${child.exitCode}`);
    try { if ((await fetch(`${base}/analysis.html`)).ok) return; } catch (_) {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('App did not start');
}

function visible(element) {
  const style = getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  return style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
}

async function auditPage(page, route, width) {
  await page.waitForSelector(route[1], { timeout: 15000 });
  await page.waitForTimeout(350);
  const result = await page.evaluate(() => {
    const isVisible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const name = (element) => {
      const labelledBy = element.getAttribute('aria-labelledby');
      if (labelledBy) return labelledBy.split(/\s+/).map(id => document.getElementById(id)?.textContent || '').join(' ').trim();
      const aria = element.getAttribute('aria-label');
      if (aria) return aria.trim();
      if (element.labels?.length) return [...element.labels].map(label => label.textContent || '').join(' ').trim();
      if (element.title) return element.title.trim();
      return (element.textContent || '').replace(/\s+/g, ' ').trim();
    };
    const violations = [];
    const duplicateIds = [...document.querySelectorAll('[id]')].map(e => e.id).filter((id, i, ids) => ids.indexOf(id) !== i);
    if (duplicateIds.length) violations.push({ rule: 'duplicate-id', nodes: [...new Set(duplicateIds)] });
    for (const element of document.querySelectorAll('button, a[href], input, select, textarea, summary, [role="button"], [role="option"], [role="tab"]')) {
      if (!isVisible(element) || element.disabled || element.getAttribute('aria-hidden') === 'true') continue;
      if (!name(element) && element.getAttribute('type') !== 'hidden') violations.push({ rule: 'interactive-name', node: element.outerHTML.slice(0, 180) });
    }
    for (const element of document.querySelectorAll('[aria-labelledby], [aria-describedby], [aria-controls]')) {
      for (const id of (element.getAttribute('aria-labelledby') || element.getAttribute('aria-describedby') || element.getAttribute('aria-controls')).split(/\s+/)) {
        if (id && !document.getElementById(id)) violations.push({ rule: 'aria-reference', id, node: element.outerHTML.slice(0, 180) });
      }
    }
    const overflow = { scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth };
    if (overflow.scrollWidth > overflow.clientWidth + 1) violations.push({ rule: 'horizontal-overflow', ...overflow });
    return { violations, overflow };
  });
  assert.deepEqual(result.violations, [], `${route[0]} @ ${width}px accessibility/layout violations: ${JSON.stringify(result.violations)}`);

  const focusReport = await page.evaluate(async () => {
    const actionable = [...document.querySelectorAll('button, a[href], input, select, textarea, summary, [tabindex]:not([tabindex="-1"])')]
      .filter(element => {
        const style = getComputedStyle(element); const rect = element.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0 && !element.disabled;
      }).slice(0, 80);
    const issues = [];
    const intersects = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
    for (const element of actionable) {
      element.scrollIntoView({ block: 'center', inline: 'nearest' });
      element.focus({ preventScroll: true });
      const focused = document.activeElement;
      const rect = focused?.getBoundingClientRect();
      if (!rect || rect.bottom <= 0 || rect.top >= innerHeight || rect.right <= 0 || rect.left >= innerWidth) {
        issues.push({ rule: 'focused-item-out-of-viewport', node: element.id || element.textContent?.trim().slice(0, 50) });
        continue;
      }
      const centerTarget = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      // Geometry can overlap without visual occlusion when the focused item
      // belongs to a higher stacking context (for example the open sidebar
      // over the sticky topbar). Check the actual hit-test target first.
      if (centerTarget && (centerTarget === focused || focused.contains(centerTarget))) continue;
      const overlay = centerTarget && centerTarget.closest('*') && [...document.querySelectorAll('body *')].find(candidate => {
        if (candidate === focused || candidate.contains(focused) || !candidate.contains(centerTarget) || !intersects(rect, candidate.getBoundingClientRect())) return false;
        const style = getComputedStyle(candidate);
        return (style.position === 'fixed' || style.position === 'sticky') && Number(style.zIndex || 0) >= 20 && style.pointerEvents !== 'none' && Number(style.opacity || 1) > .1 && candidate.getBoundingClientRect().width > 0 && candidate.getBoundingClientRect().height > 0;
      });
      if (overlay) issues.push({ rule: 'sticky-overlay-covers-focus', focused: element.id || element.textContent?.trim().slice(0, 50), overlay: overlay.className || overlay.id || overlay.tagName });
    }
    return issues;
  });
  assert.deepEqual(focusReport, [], `${route[0]} @ ${width}px focus/overlay violations: ${JSON.stringify(focusReport)}`);
}

async function keyboardJourney(page, base) {
  await page.goto(`${base}/model.html?id=${projectId}`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#threat-diagram-canvas', { timeout: 15000 });
  await page.keyboard.press('Tab');
  const firstFocus = await page.evaluate(() => ({ tag: document.activeElement?.tagName, name: document.activeElement?.getAttribute('aria-label') || document.activeElement?.textContent?.trim().slice(0, 80) }));
  assert.ok(firstFocus.tag, 'keyboard journey did not move focus');
  await page.locator('#model-boundary-queue .model-boundary-title').first().focus().catch(() => {});
  await page.keyboard.press('Enter');
  assert.ok(await page.locator('#node-inspector, #model-inspector-rail').first().isVisible(), 'novice boundary review did not expose inspector');

  const noviceStart = Date.now();
  await page.locator('#nav-findings').click();
  await page.waitForURL(/findings\.html/);
  await page.waitForSelector('#findings-list [data-finding-id]', { timeout: 15000 });
  await page.locator('#findings-list [data-finding-id]').first().focus();
  await page.keyboard.press('Enter');
  await page.waitForSelector('.findings-inspector-header', { timeout: 5000 });
  assert.ok((await page.locator('.findings-inspector').innerText()).length > 40, 'novice finding review did not expose readable detail');
  const noviceMs = Date.now() - noviceStart;

  const expertStart = Date.now();
  await page.locator('.finding-dfd-link').first().click();
  await page.waitForURL(/model\.html/);
  await page.waitForSelector('#threat-diagram-canvas', { timeout: 15000 });
  await page.waitForFunction(() => document.querySelector('#nav-findings')?.getAttribute('href')?.includes('id='), null, { timeout: 15000 });
  const findingsHref = await page.locator('#nav-findings').getAttribute('href');
  const modelRouteState = await page.evaluate(() => ({ url: location.href, state: window.UIState?.read(), projectName: document.querySelector('#page-project-name')?.textContent, revision: document.querySelector('#model-revision-status')?.textContent }));
  assert.match(findingsHref || '', new RegExp(`id=${projectId}`), `model navigation lost project id: ${findingsHref}; state=${JSON.stringify(modelRouteState)}`);
  await page.locator('#nav-findings').click();
  await page.waitForURL(/findings\.html/);
  try {
    await page.waitForSelector('#findings-list [data-finding-id]', { timeout: 15000 });
  } catch (error) {
    throw new Error(`expert findings route did not load rows at ${page.url()}: ${await page.locator('body').innerText().then(text => text.slice(0, 500))}`, { cause: error });
  }
  await page.locator('.finding-action-link, .finding-control-link').first().click().catch(async () => { await page.locator('#nav-action-plan').click(); });
  await page.waitForURL(/action-plan\.html/);
  await page.waitForSelector('#action-list [data-action-key]', { timeout: 15000 });
  await page.locator('#action-list [data-action-key]').first().focus();
  await page.keyboard.press('Enter');
  await page.waitForSelector('.action-inspector-header', { timeout: 5000 });
  const controlInspector = await page.locator('.action-inspector').innerText();
  assert.match(controlInspector, /Traceability/i, 'expert control inspector did not expose traceability');
  assert.match(controlInspector, /Linked findings/i, 'expert control inspector did not expose finding link');
  assert.match(controlInspector, /Canonical DFD targets/i, 'expert control inspector did not expose DFD link');
  const relatedTest = page.locator('.action-inspector [data-open-action^="test:"]').first();
  assert.ok(await relatedTest.count(), 'expert control inspector did not expose a linked verification test');
  await relatedTest.click();
  await page.waitForSelector('.action-inspector-header', { timeout: 5000 });
  const testInspector = await page.locator('.action-inspector').innerText();
  assert.match(testInspector, /Test detail/i, 'expert test inspector did not open');
  assert.match(testInspector, /Canonical DFD targets/i, 'expert test inspector did not preserve DFD trace');
  assert.match(testInspector, /Finding/i, 'expert test inspector did not preserve finding trace');
  const expertMs = Date.now() - expertStart;
  return { noviceMs, expertMs };
}

async function main() {
  const appPort = await availablePort();
  const base = `http://${host}:${appPort}`;
  const child = spawn('./.venv/bin/uvicorn', ['backend.main:app', '--host', host, '--port', String(appPort)], { cwd: process.cwd(), env: { ...process.env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let appLog = '';
  child.stderr.on('data', chunk => { appLog += chunk.toString().slice(0, 2000); });
  let browser;
  const visualDir = fs.mkdtempSync(path.join(os.tmpdir(), 'u7-visual-'));
  try {
    await waitForApp(base, child);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const pageErrors = []; const consoleErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
    for (const width of viewports) {
      await page.setViewportSize({ width, height: 900 });
      for (const route of routes) {
        await page.goto(`${base}/${route[0]}.html?id=${projectId}`, { waitUntil: 'domcontentloaded' });
        await auditPage(page, route, width);
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.waitForTimeout(50);
        await page.screenshot({ path: path.join(visualDir, `${route[0]}-${width}.png`), fullPage: false });
      }
    }
    const journey = await keyboardJourney(page, base);
    assert.deepEqual(pageErrors, [], `page errors: ${JSON.stringify(pageErrors)}`);
    assert.deepEqual(consoleErrors, [], `console errors: ${JSON.stringify(consoleErrors)}`);
    assert.ok(journey.expertMs <= 60000, `expert trace took ${journey.expertMs}ms`);
    console.log(JSON.stringify({ visualDir, viewports, journey, pageErrors, consoleErrors }, null, 2));
  } catch (error) {
    console.error(appLog);
    throw error;
  } finally {
    await browser?.close();
    child.kill('SIGTERM');
  }
}

main().catch(error => { console.error(error.stack || error); process.exitCode = 1; });
