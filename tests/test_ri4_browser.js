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
let appPort;
let base;
const prd = [
  '# Registration PRD',
  'Customer submits registration to Public API over HTTPS.',
  'Public API stores customer email in Accounts Database.',
  'Public API sends verification email through Mail Gateway.',
  'Only verified customers can activate an account. Audit records are retained for thirty days.',
].join('\n');
const calls = [];
const simulateTruncation = process.argv.includes('--truncated');
const simulateSlowStride = process.argv.includes('--slow');
const simulateQuality = process.argv.includes('--quality');

function responseFor(request) {
  const system = String(request.messages?.[0]?.content || '');
  const prompt = String(request.messages?.[1]?.content || '');
  let kind = 'other';
  let payload;
  if (prompt.includes('ARTIFACT CONTENT CHUNK:')) {
    kind = 'ingestion';
    payload = {
      actors: ['Customer'], components: ['Public API', 'Accounts Database', 'Mail Gateway'],
      data_flows: [
        { source: 'Customer', destination: 'Public API', data: ['registration'], protocol: 'HTTPS' },
        { source: 'Public API', destination: 'Accounts Database', data: ['customer email'], protocol: 'SQL' },
        { source: 'Public API', destination: 'Mail Gateway', data: ['verification email'], protocol: 'HTTPS' },
      ],
      endpoints: ['POST /register'], data_fields: ['customer email'], external_systems: ['Mail Gateway'],
      auth_methods: [], critical_actions: ['activate account'], existing_controls: [],
      evidence_items: [{ snippet: 'Customer submits registration to Public API over HTTPS.', locator: 'Registration PRD', topics: ['registration'] }],
      has_pii: true, summary: 'Customer registration and email verification.',
    };
  } else if (system.includes('STRIDE') || system.includes('LINDDUN')) {
    kind = system.includes('STRIDE') ? 'stride' : 'linddun';
    const match = prompt.match(/CANONICAL DFD INTERACTION [^:]+:\n([^\n]+)/);
    assert.ok(match, `Missing canonical DFD interaction for ${kind}`);
    const context = JSON.parse(match[1]);
    const target = context.flows?.[0]?.id || context.nodes?.[0]?.id;
    assert.ok(target, `Missing target for ${kind}`);
    const category = kind === 'stride' ? 'Tampering' : 'Data Disclosure';
    payload = { threats: [{
      framework: kind === 'stride' ? 'STRIDE' : 'LINDDUN', threat_category: category,
      title: `${category} on registration interaction`,
      threat_description: kind === 'stride'
        ? 'An attacker changes a registration request before the Public API validates it.'
        : 'The registration flow may disclose customer email beyond the intended recipient.',
      scenario: 'A caller alters or reads customer registration data across this interaction.',
      affected_refs: [target], analysis_revision: context.revision, dfd_semantic_hash: context.semantic_hash,
      evidence_refs: [], assumption: 'Authentication and authorization details require review.',
      confidence: 'Medium', risk_level: 'High',
      recommended_control: kind === 'stride' ? 'Server-side validation and integrity checks' : 'Data minimization and recipient scoping',
      preconditions: ['A caller can reach the registration flow'],
      validation_steps: ['Test the registration flow with altered input and verify rejection'],
    }], coverage: [] };
    if (simulateQuality && kind === 'linddun') {
      const baseThreat = { ...payload.threats[0], framework: 'LINDDUN',
        scenario: 'A controlled caller observes customer registration data on this interaction.',
        recommended_control: 'Apply data minimization and recipient scoping.' };
      payload.threats = prompt.includes('batch-1:') ? [
        { ...baseThreat, title: 'Customer email reaches unintended recipient',
          threat_description: 'Customer email is exposed in a registration response to an unintended recipient.' },
        { ...baseThreat, title: 'Customer email appears in application logs',
          threat_description: 'Customer email is written to application logs and can be read by unintended staff.',
          recommended_control: 'Redact customer email from application logs.' },
      ] : [{ ...baseThreat, title: 'Unresolved cross-session linkage', threat_category: 'Linking',
        threat_description: 'Registration records can be combined across sessions in an unspecified way.',
        recommended_control: 'Requires design review.' }];
    }
  } else if (prompt.includes('Return one JSON object with an "items" array')) {
    kind = 'missing_info';
    payload = { items: [{ area: 'Authorization', question: 'Which callers can register accounts?',
      why_it_matters: 'Authorization requirements affect registration threats.', priority: 'High',
      target_team: 'Dev/Tech Lead', question_to_ask: 'Which callers can register accounts?' }] };
  } else {
    payload = {};
  }
  calls.push({ kind, prompt_chars: prompt.length, max_tokens: request.max_tokens });
  const truncated = simulateTruncation && kind === 'stride' && prompt.includes('CANONICAL DFD INTERACTION batch-1:');
  return { id: `fixture-${calls.length}`, object: 'chat.completion', created: 0, model: 'ri4-fixture',
    choices: [{ index: 0, finish_reason: truncated ? 'length' : 'stop',
      message: { role: 'assistant', content: truncated ? '{"threats": [' : JSON.stringify(payload) } }],
    usage: { prompt_tokens: Math.ceil(prompt.length / 4), completion_tokens: 100, total_tokens: Math.ceil(prompt.length / 4) + 100 } };
}

async function startProvider() {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = responseFor(JSON.parse(body));
        const kind = calls.at(-1)?.kind;
        const send = () => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(payload));
        };
        if (simulateSlowStride && kind === 'stride') setTimeout(send, 1200);
        else send();
      } catch (error) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: error.message, type: 'fixture_error' } }));
      }
    });
  });
  await new Promise(resolve => server.listen(0, host, resolve));
  return server;
}

async function availablePort() {
  const probe = http.createServer();
  await new Promise(resolve => probe.listen(0, host, resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  return port;
}

async function waitForApp(child) {
  for (let index = 0; index < 100; index += 1) {
    if (child.exitCode !== null) throw new Error(`App exited early: ${child.exitCode}`);
    try { const response = await fetch(`${base}/analysis.html`); if (response.ok) return; }
    catch (_) {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('App did not start');
}

async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ri4-threat-e2e-'));
  appPort = await availablePort();
  base = `http://${host}:${appPort}`;
  const provider = await startProvider();
  const providerPort = provider.address().port;
  const child = spawn('./.venv/bin/uvicorn', ['backend.main:app', '--host', host, '--port', String(appPort)], {
    cwd: process.cwd(), env: { ...process.env, DATA_DIR: temp,
      OPENAI_BASE_URL: `http://${host}:${providerPort}/v1`, OPENAI_API_KEY: 'fixture',
      OPENAI_MODEL: 'ri4-fixture', LLM_TIMEOUT_SECONDS: '12', LLM_MAX_RETRIES: '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let appLog = '';
  child.stderr.on('data', chunk => { appLog += chunk.toString().slice(0, 2000); });
  let browser;
  try {
    await waitForApp(child);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const pageErrors = [];
    const consoleErrors = [];
    const failedResources = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
    page.on('response', response => { if (response.status() >= 400) failedResources.push(`${response.status()} ${response.url()}`); });
    const created = await page.request.post(`${base}/api/projects`, { data: {
      name: 'RI4 Registration fixture', description: 'Synthetic PRD for threat-modeling E2E',
      environment: 'Test', data_policy: 'byok_allowed',
    } });
    assert.equal(created.status(), 200, await created.text());
    const projectId = (await created.json()).project_id;
    await page.goto(`${base}/analysis.html?id=${projectId}`, { waitUntil: 'domcontentloaded' });
    await page.locator('#artifact-upload-card summary').click();
    await page.locator('#artifact-type-select').selectOption('prd');
    await page.locator('#artifact-file-inline').setInputFiles({ name: 'registration.md', mimeType: 'text/markdown', buffer: Buffer.from(prd) });
    const uploaded = page.waitForResponse(response => response.url().endsWith(`/api/projects/${projectId}/artifact/file`) && response.request().method() === 'POST');
    await page.locator('#btn-upload-artifact').click();
    const uploadResponse = await uploaded;
    assert.equal(uploadResponse.status(), 200, await uploadResponse.text());
    await page.waitForFunction(() => document.querySelector('#artifact-import-result')?.textContent?.includes('Context updated'));
    const analysisResponse = page.waitForResponse(response => response.url().endsWith(`/api/projects/${projectId}/analyze`) && response.request().method() === 'POST', { timeout: 120000 });
    const startedAt = Date.now();
    await page.locator('#btn-run-analysis').click();
    if (simulateSlowStride) {
      await page.waitForFunction(() => document.querySelector('#as-stride')?.classList.contains('active'), null, { timeout: 5000 });
      assert.equal(await page.locator('#as-linddun').evaluate(element => element.classList.contains('active')), false,
        'LINDDUN remains queued while STRIDE is active');
    }
    const completed = await analysisResponse;
    assert.equal(completed.status(), 200, await completed.text());
    const report = await completed.json();
    await page.waitForFunction(() => {
      const overview = document.querySelector('#analysis-overview');
      const scored = document.querySelector('#overview-scored')?.textContent?.trim();
      return overview && overview.style.display !== 'none' && scored && scored !== '—';
    });
    const current = (report.threats || []).filter(item => item.analysis_state !== 'historical');
    const controls = (report.controls || []).filter(item => item.analysis_state !== 'historical');
    const tests = (report.test_scenarios || []).filter(item => item.analysis_state !== 'historical');
    assert.ok(report.dfd_model?.flows?.length >= 1, 'DFD has grounded flows');
    assert.ok(current.some(item => item.framework === 'STRIDE'), 'Current STRIDE threat exists');
    assert.ok(current.some(item => item.framework === 'LINDDUN'), 'Current LINDDUN threat exists');
    assert.ok(current.every(item => item.risk_methodology_version === 'dfd-risk-v1.0'), 'Every threat uses the versioned risk method');
    assert.ok(current.every(item => item.provider_risk_level === 'High'), 'Provider severity is retained only for audit');
    assert.ok(current.every(item => item.risk_level === 'Unknown' && item.risk_status !== 'assessed'), 'Ungrounded or context-deferred scenarios have no final risk');
    assert.ok(current.every(item => item.risk_score > 0 && item.risk_assessment_fingerprint), 'Scenario calculations are auditable');
    if (simulateTruncation) {
      assert.equal(report.ai_status?.stride?.assessment_status, 'partial');
      assert.equal(report.ai_status?.stride?.previous_results_preserved, false);
      assert.equal(report.ai_status?.stride?.response_metadata?.generation_manifest?.deferred_refs?.length > 0, true);
    }
    if (simulateQuality) {
      const email = current.find(item => item.title === 'Customer email reaches unintended recipient');
      const logs = current.find(item => item.title === 'Customer email appears in application logs');
      const unresolved = current.find(item => item.title === 'Unresolved cross-session linkage');
      assert.ok(email && logs && unresolved, 'All quality fixture threats remain current');
      const emailTest = tests.find(item => item.threat_id === email.threat_id);
      const logTest = tests.find(item => item.threat_id === logs.threat_id);
      const unresolvedTest = tests.find(item => item.threat_id === unresolved.threat_id);
      assert.ok(emailTest && logTest && unresolvedTest, 'Every quality threat has a scenario');
      assert.notDeepEqual(emailTest.steps, logTest.steps, 'Same-category threats have distinct test steps');
      assert.match(logTest.steps.join(' '), /logs|telemetry/i);
      assert.match(emailTest.steps.join(' '), /recipient/i);
      assert.equal(unresolvedTest.applicability_status, 'blocked');
      assert.equal(unresolvedTest.related_control_id, undefined);
      assert.ok(controls.some(item => item.mapping_status === 'unassigned' && item.threat_ids.includes(unresolved.threat_id)));
      assert.equal(report.ai_status?.controls?.assessment_status, 'partial');
      assert.equal(report.ai_status?.tests?.assessment_status, 'partial');
    }
    assert.ok(controls.some(item => item.threat_ids?.some(id => current.some(threat => threat.threat_id === id))), 'Controls link to current threats');
    assert.ok(tests.some(item => current.some(threat => threat.threat_id === item.threat_id)), 'Tests link to current threats');
    assert.ok(controls.every(item => item.priority_source === 'deterministic_threat_risk' && item.risk_methodology_version === 'dfd-risk-v1.0'), 'Control priority follows deterministic threat risk');
    assert.ok(tests.every(item => item.priority_source === 'deterministic_threat_risk' && item.risk_methodology_version === 'dfd-risk-v1.0'), 'Test priority follows deterministic threat risk');
    assert.ok(tests.every(item => item.applicability_status === 'blocked' || (item.related_control_id && controls.some(control =>
      control.control_id === item.related_control_id && control.mapping_status !== 'unassigned' && control.threat_ids?.includes(item.threat_id)))),
      'Every scenario links to a mapped control');
    assert.ok(tests.some(item => item.scenario_name.includes('—')), 'Scenario names include a canonical DFD target');
    assert.ok(controls.every(item => !/Webhook|Amount\/Value|Nonce/i.test(item.name)), 'Unrelated webhook/payment controls are excluded');
    assert.equal(calls.filter(call => call.kind === 'controls' || call.kind === 'tests').length, 0);
    assert.deepEqual(
      await page.locator('#project-workflow-nav .project-workflow-link > span:last-child').allTextContents(),
      ['Overview', 'DFD model', 'Findings', 'Action plan', 'Evidence', 'Report & sign-off'],
      'Primary navigation follows the canonical project workflow',
    );
    assert.equal(await page.locator('#analysis-workflow').count(), 0, 'Legacy duplicate analysis workflow remains in the DOM');
    const routeJourneys = [
      {id: 'nav-model', route: 'model', ready: '#threat-diagram-canvas canvas'},
      {id: 'nav-findings', route: 'findings', ready: '#findings-list [data-finding-id]'},
      {id: 'nav-action-plan', route: 'action-plan', ready: '#action-list [data-action-key]'},
      {id: 'nav-evidence', route: 'evidence', ready: '#evidence-list [data-evidence-key]'},
      {id: 'nav-report', route: 'report', ready: '#report-dfd-snapshot-caption'},
    ];
    for (const journey of routeJourneys) {
      await page.goto(`${base}/analysis.html?id=${projectId}`, {waitUntil: 'networkidle'});
      await page.locator(`#${journey.id}`).click();
      await page.waitForURL(new RegExp(`/${journey.route}\\.html\\?`));
      assert.equal(new URL(page.url()).searchParams.get('id'), projectId, `${journey.route} navigation lost project identity`);
      await page.waitForSelector(journey.ready, {state: 'visible', timeout: 10000});
    }
    await page.goto(`${base}/analysis.html?id=${projectId}`, {waitUntil: 'networkidle'});
    assert.deepEqual(pageErrors, []);
    const unexpectedResources = failedResources.filter(value => !/404 .*\/report$/.test(value));
    const unexpectedConsoleErrors = consoleErrors.filter(value =>
      !(failedResources.some(resource => /404 .*\/report$/.test(resource)) && /Failed to load resource.*404/.test(value)));
    assert.deepEqual(unexpectedResources, []);
    assert.deepEqual(unexpectedConsoleErrors, []);
    const summary = {
      status: report.analysis_run?.status, dfd_flows: report.dfd_model.flows.length,
      current_threats: current.length, controls: controls.length, tests: tests.length,
      control_mapping: controls.map(item => ({ name: item.name, status: item.mapping_status })),
      elapsed_ms: Date.now() - startedAt,
      stage_status: Object.fromEntries(['stride', 'linddun', 'controls', 'tests'].map(stage =>
        [stage, { status: report.ai_status?.[stage]?.assessment_status, engine: report.ai_status?.[stage]?.engine,
          ok: report.ai_status?.[stage]?.ok }])),
      provider_calls: Object.fromEntries(['ingestion', 'stride', 'linddun', 'missing_info', 'other'].map(kind => [kind, calls.filter(call => call.kind === kind).length])),
      max_prompt_chars: Math.max(...calls.map(call => call.prompt_chars)),
    };
    console.log(`RI4 Playwright Analyze click E2E: ${JSON.stringify(summary)}`);
  } catch (error) {
    console.error(appLog.slice(-2500));
    throw error;
  } finally {
    if (browser) await browser.close();
    if (child.exitCode === null) {
      child.kill('SIGINT');
      await new Promise(resolve => child.once('exit', resolve));
    }
    await new Promise(resolve => provider.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
