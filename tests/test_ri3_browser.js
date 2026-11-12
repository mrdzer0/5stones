const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (_) {
  ({ chromium } = require(path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'playwright')));
}

const id = 'ri3-browser-fixture';
const base = 'http://127.0.0.1:8765';
const project = { id, name: 'RI3 fixture', environment: 'Test', artifact_sources: [], artifact_inventory: {},
  completeness: { score: 92, level: 'Ready' }, signoff_ready: false };
const report = {
  generated_at: '2026-09-21T00:00:00', completeness: { score: 92, level: 'Ready' },
  quality_gate: { signoff_ready: false, status: 'not_ready', summary: 'Sign-off blocked by 2 quality gates',
    blocking_reasons: ['Canonical DFD topology is incomplete', 'One active threat still requires reviewer disposition'],
    components: {
      input_context: { status: 'ready', reasons: [] },
      dfd: { status: 'not_ready', reasons: ['Canonical DFD topology is incomplete'] },
      threat_review: { status: 'not_ready', reasons: ['One active threat still requires reviewer disposition'] },
    } },
  formal_report: { status: 'signed', release_decision_status: 'not_ready' },
  release_decision: { status: 'not_ready', blockers: [{ code: 'enterprise_release_authority',
    message: 'Enterprise release requires OIDC/JWT identity.' }] },
  trust_boundaries: [{ boundary_id: 'b', source: 'API', destination: 'DB', boundary_label: 'Internal', status: 'Rejected' }],
  threats: [
    { threat_id: 'same', framework: 'STRIDE', risk_level: 'High', threat_category: 'Tampering',
      threat_description: 'Same-zone audit tampering', source: 'API', destination: 'DB', trust_boundary: 'Internal' },
    { threat_id: 'cross', framework: 'LINDDUN', risk_level: 'Critical', threat_category: 'Disclosure',
      threat_description: 'Rejected-boundary disclosure', trust_boundary_ids: ['b'] },
  ],
  controls: [{ control_id: 'c', name: 'Audit integrity', threat_ids: ['same'] }],
  test_scenarios: [{ test_id: 't', scenario_name: 'Verify audit integrity', threat_id: 'same' }],
  assumptions: [], missing_info: [{ area: 'Deployment', question: 'Where are audit logs stored?' }],
  risk_summary: { total: 2, critical: 1, high: 1 },
};

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route(`**/api/projects/${id}`, route => route.fulfill({ json: project }));
  await page.route(`**/api/projects/${id}/report`, route => route.fulfill({ json: report }));
  try {
    await page.goto(`${base}/report.html?id=${id}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelector('#toc-count-threats')?.textContent === '1');
    assert.equal(await page.locator('#toc-count-controls').textContent(), '1');
    assert.equal(await page.locator('#toc-count-tests').textContent(), '1');
    assert.equal(await page.locator('#toc-count-gaps').textContent(), '1');
    assert.equal(await page.locator('#rp-high').textContent(), '1');
    assert.equal(await page.locator('#rp-critical').textContent(), '0');
    assert.match(await page.locator('body').innerText(), /Same-zone audit tampering/);
    assert.doesNotMatch(await page.locator('body').innerText(), /Rejected-boundary disclosure/);
    assert.match(await page.locator('#report-readiness').innerText(), /Input Context Completeness/);
    assert.match(await page.locator('#report-signoff-readiness').innerText(), /Sign-off Readiness/);
    assert.match(await page.locator('#report-signoff-readiness').innerText(), /Not ready/);
    assert.match(await page.locator('#report-signoff-readiness').innerText(), /Input: Ready/);
    assert.match(await page.locator('#report-signoff-readiness').innerText(), /DFD: Not ready/);
    assert.match(await page.locator('#report-signoff-readiness').innerText(), /Canonical DFD topology is incomplete/);
    assert.doesNotMatch(await page.locator('#report-readiness').innerText(), /Threat Model Readiness/);
    assert.equal(await page.locator('#report-formal-status').textContent(), 'signed');
    assert.equal(await page.locator('#report-release-decision').getAttribute('data-status'), 'not_ready');
    assert.match(await page.locator('#report-release-decision').innerText(), /Enterprise release decision/);
    assert.match(await page.locator('#report-release-decision').innerText(), /NOT_READY/);
    assert.match(await page.locator('#report-release-decision').innerText(), /enterprise_release_authority/);

    await page.goto(`${base}/analysis.html?id=${id}`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof renderArtifactImportResult === 'function');
    await page.evaluate(() => renderArtifactImportResult({
      message: 'Parsed with unresolved source ranges.',
      parsed: { stats: {}, warnings: [], coverage_manifest: {
        status: 'partial', chunk_count: 1, processed_chunk_count: 1,
        unread_sections: [{ locator: 'tables 21-21', reason: 'DOCX table extraction limit' }],
      } }, reconciliation: {},
    }, { name: 'requirements.docx' }));
    assert.match(await page.locator('#artifact-import-result').innerText(), /tables 21-21/);
    assert.match(await page.locator('#artifact-import-result').innerText(), /DOCX table extraction limit/);
    assert.doesNotMatch(await page.locator('#artifact-import-result').innerText(), /All source ranges have grounded extraction/);
    assert.deepEqual(errors, []);
    console.log('RI3 Playwright report visibility and ingestion coverage: ok');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
