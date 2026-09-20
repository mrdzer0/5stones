const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (_) {
  const globalModules = execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim();
  ({ chromium } = require(path.join(globalModules, 'playwright')));
}

const projectId = process.env.RI2_PROJECT_ID || '81a087d2-b46b-40f7-ba58-bdc315a6ae0c';
const base = `http://127.0.0.1:8765/analysis.html?id=${projectId}`;

async function visualState(page) {
  return page.evaluate(() => {
    const ids = diagramNetwork.body.data.nodes.getIds();
    const boxes = ids.map(id => ({ id, ...diagramNetwork.getBoundingBox(id) }));
    const overlaps = [];
    for (let i = 0; i < boxes.length; i += 1) {
      for (let j = i + 1; j < boxes.length; j += 1) {
        const width = Math.min(boxes[i].right, boxes[j].right) - Math.max(boxes[i].left, boxes[j].left);
        const height = Math.min(boxes[i].bottom, boxes[j].bottom) - Math.max(boxes[i].top, boxes[j].top);
        if (width > 2 && height > 2) overlaps.push([boxes[i].id, boxes[j].id]);
      }
    }
    const zones = [...document.querySelectorAll('#diagram-zone-layer .diagram-zone')].map(element => ({
      id: element.dataset.zoneId,
      visible: getComputedStyle(element).display !== 'none',
      width: element.getBoundingClientRect().width,
      height: element.getBoundingClientRect().height,
    }));
    return { nodes: ids.length, flows: diagramNetwork.body.data.edges.length,
      expectedZones: currentReport.dfd_model.zones.length, zones, overlaps };
  });
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const errors = [];
  const savedModels = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route(`**/api/projects/${projectId}/dfd`, async route => {
    if (route.request().method() !== 'PUT') return route.continue();
    const body = JSON.parse(route.request().postData() || '{}');
    savedModels.push(body.model);
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      model: body.model, validation: { valid: true }, semantic_changed: false,
    }) });
  });
  try {
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof diagramNetwork !== 'undefined' && !!diagramNetwork && !!currentReport?.dfd_model);
    await page.waitForTimeout(700);
    const initial = await visualState(page);
    await page.locator('#btn-diagram-fit').click();
    await page.waitForTimeout(450);
    const fitted = await visualState(page);
    await page.locator('#btn-diagram-reflow').click();
    await page.waitForTimeout(950);
    const reflowed = await visualState(page);
    const beforePan = await page.locator('#diagram-zone-layer [data-zone-id="zone-application"]').evaluate(element => element.style.left);
    await page.evaluate(() => {
      const position = diagramNetwork.getViewPosition();
      diagramNetwork.moveTo({ position: { x: position.x + 120, y: position.y + 60 }, scale: diagramNetwork.getScale() * 1.2, animation: false });
    });
    await page.waitForTimeout(120);
    const afterPan = await page.locator('#diagram-zone-layer [data-zone-id="zone-application"]').evaluate(element => element.style.left);
    assert.notEqual(beforePan, afterPan);
    await page.locator('#btn-diagram-fit').click();
    await page.waitForTimeout(350);
    await page.locator('#diagram-canvas-shell').screenshot({ path: path.join(os.tmpdir(), 'ri2-dfd-reflow.png') });

    const pngEvent = page.waitForEvent('download');
    await page.locator('#btn-diagram-export').click();
    const png = await pngEvent;
    const pngBytes = fs.readFileSync(await png.path());
    assert.equal(pngBytes.subarray(1, 4).toString(), 'PNG');

    const svgEvent = page.waitForEvent('download');
    await page.locator('#btn-diagram-export-svg').click();
    const svg = await svgEvent;
    const svgText = fs.readFileSync(await svg.path(), 'utf8');
    assert.equal((svgText.match(/data-zone-id=/g) || []).length, reflowed.zones.filter(zone => zone.visible).length);
    assert.match(svgText, /semantic_hash/);
    assert.match(svgText, /flow_refs/);

    await page.evaluate(async () => { await toggleDfdZone('zone-application'); });
    await page.waitForFunction(() => !!diagramNetwork?.body?.data?.nodes?.get('dfd-group-zone-application'));
    const collapsed = await page.evaluate(() => {
      const group = diagramNetwork.body.data.nodes.get('dfd-group-zone-application');
      diagramNetwork.emit('click', { nodes: [group.id], edges: [] });
      return { groupZone: group._collapsedZoneId, memberCount: group._collapsedNodeIds.length,
        inspector: document.querySelector('#inspector-title')?.textContent,
        visualNodeCount: diagramNetwork.body.data.nodes.length };
    });
    assert.equal(collapsed.groupZone, 'zone-application');
    assert.ok(collapsed.memberCount > 1);
    assert.match(collapsed.inspector, /Application/i);
    await page.locator('.dfd-zone-interactions summary').click();
    assert.ok(await page.locator('[data-zone-flow-id]').count() > 0);
    await page.locator('[data-zone-flow-id]').first().click();
    assert.equal(await page.locator('#inspector-body [data-dfd-flow-editor]').count(), 1);
    await page.locator('#btn-diagram-reflow').click();
    await page.waitForTimeout(700);
    const latestView = savedModels.at(-1)?.views?.find(view => view.kind === 'context');
    assert.ok(latestView);
    assert.equal(Object.keys(latestView.positions || {}).some(id => id.startsWith('dfd-group-')), false);
    await page.evaluate(async () => { await toggleDfdZone('zone-application'); });
    await page.waitForFunction(() => !diagramNetwork?.body?.data?.nodes?.get('dfd-group-zone-application'));

    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(400);
    const mobile = await visualState(page);
    assert.equal(mobile.zones.filter(zone => zone.visible).length, mobile.expectedZones);
    assert.equal(mobile.overlaps.length, 0);

    const parallel = await page.evaluate(() => {
      const model = JSON.parse(JSON.stringify(currentReport.dfd_model));
      const original = model.flows[0];
      const duplicate = { ...original, id: 'ri2-parallel-test', display_id: 'RI2',
        name: 'Parallel test flow', protocol: original.protocol === 'HTTP' ? 'HTTPS' : 'HTTP' };
      model.flows.push(duplicate);
      renderCanonicalDiagram({ ...currentReport, dfd_model: model }, 'context');
      const rows = diagramNetwork.body.data.edges.get().filter(edge =>
        edge.from === original.source_id && edge.to === original.target_id);
      const details = rows.map(row => {
        diagramNetwork.emit('click', { nodes: [], edges: [row.id] });
        return document.querySelector('#inspector-body')?.textContent || '';
      });
      renderCanonicalDiagram(currentReport, 'context');
      return { ids: rows.map(row => row.id), curves: rows.map(row => row.smooth?.type),
        protocols: rows.map(row => row._flowDetails.find(item => item.startsWith('Interaction:'))),
        inspectorOpened: details.map(text => text.includes('Protocol:')) };
    });
    assert.ok(parallel.ids.includes('ri2-parallel-test'));
    assert.notEqual(parallel.curves[0], parallel.curves[1]);
    assert.notEqual(parallel.protocols[0], parallel.protocols[1]);
    assert.deepEqual(parallel.inspectorOpened, [true, true]);

    const result = { initial, fitted, reflowed, panMovedZone: beforePan !== afterPan, collapsed, mobile, parallel, pngBytes: pngBytes.length, svgBytes: svgText.length, errors };
    console.log(JSON.stringify(result));
    assert.equal(initial.zones.filter(zone => zone.visible).length, initial.expectedZones);
    assert.equal(fitted.overlaps.length, 0);
    assert.equal(reflowed.overlaps.length, 0);
    assert.equal(errors.length, 0);
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
