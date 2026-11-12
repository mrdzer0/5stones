const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const layer = { querySelectorAll: () => [] };
const context = {
  console, URL, URLSearchParams,
  localStorage: { getItem: () => null },
  document: { addEventListener: () => {}, getElementById: () => layer },
  window: {},
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('frontend/js/analysis.js', 'utf8'), context);

const zones = [
  { id: 'zone-parent', name: 'Application', parent_zone_id: null },
  { id: 'zone-child', name: 'Identity', parent_zone_id: 'zone-parent' },
  { id: 'zone-external', name: 'External', parent_zone_id: null },
];
const nodes = [
  { id: 'source', display_id: 'N1', name: 'A customer with a very long descriptive label for the public request', zone_ids: ['zone-external'] },
  { id: 'target', display_id: 'N2', name: 'The authentication service with another very long descriptive label', zone_ids: ['zone-child'] },
  { id: 'sibling', display_id: 'N3', name: 'A second internal process whose label wraps over several lines', zone_ids: ['zone-parent'] },
  { id: 'store', display_id: 'N4', name: 'Identity and session record storage with lifecycle metadata', zone_ids: ['zone-child'] },
];
const flows = [
  { id: 'flow-https', source_id: 'source', target_id: 'target', name: 'Read profile', protocol: 'HTTPS', boundary_crossings: ['boundary-1'], evidence_refs: ['EV-1'] },
  { id: 'flow-http', source_id: 'source', target_id: 'target', name: 'Write profile', protocol: 'HTTP', boundary_crossings: ['boundary-2'], evidence_refs: ['EV-2'] },
];
const model = { zones, nodes, flows, views: [] };

const expanded = context.canonicalVisualProjection(model, nodes, flows, new Set());
assert.deepEqual(Array.from(expanded.flows, item => item.id), ['flow-https', 'flow-http']);
assert.deepEqual(Array.from(expanded.flows, item => item.protocol), ['HTTPS', 'HTTP']);
assert.notEqual(context.canonicalFlowSmooth(0, 2).type, context.canonicalFlowSmooth(1, 2).type);

const collapsed = context.canonicalVisualProjection(model, nodes, flows, new Set(['zone-child']));
assert.equal(collapsed.flows.length, 1);
assert.equal(collapsed.flows[0]._collapsedFlows.length, 2);
assert.equal(collapsed.flows[0].protocol, 'mixed');
assert.deepEqual(Array.from(collapsed.flows[0].boundary_crossings), ['boundary-1', 'boundary-2']);
assert.deepEqual(Array.from(collapsed.flows[0]._collapsedFlowIds), ['flow-https', 'flow-http']);
assert.equal(collapsed.nodes.find(node => node._collapsedZoneId === 'zone-child')._collapsedNodeIds.length, 2);

const layout = context.canonicalLayoutPositions(model, nodes, flows, 'context');
for (let i = 0; i < nodes.length; i += 1) {
  for (let j = i + 1; j < nodes.length; j += 1) {
    const a = layout.positions[nodes[i].id];
    const b = layout.positions[nodes[j].id];
    const aSize = context.canonicalEstimatedNodeSize(nodes[i]);
    const bSize = context.canonicalEstimatedNodeSize(nodes[j]);
    const overlapX = Math.abs(a.x - b.x) < (aSize.width + bSize.width) / 2;
    const overlapY = Math.abs(a.y - b.y) < (aSize.height + bSize.height) / 2;
    assert.equal(overlapX && overlapY, false, `${nodes[i].id} overlaps ${nodes[j].id}`);
  }
}
const savedModel = { ...model, views: [{ kind: 'context', positions: Object.fromEntries(nodes.map(node => [node.id, { x: 0, y: 0 }])) }] };
assert.equal(context.canonicalLayoutPositions(savedModel, nodes, flows, 'context').positions.source.x, 0);
assert.notEqual(context.canonicalLayoutPositions(savedModel, nodes, flows, 'context', null, true).positions.source.x, 0);

const elements = zones.map(zone => ({ dataset: { zoneId: zone.id, zoneDepth: zone.id === 'zone-child' ? '1' : '0' }, style: {} }));
layer.querySelectorAll = () => elements;
context.__network = {
  getPositions: () => Object.fromEntries(nodes.map((node, index) => [node.id, { x: 200 + index * 200, y: 150 + index * 120 }])),
  getBoundingBox: id => {
    const index = nodes.findIndex(node => node.id === id);
    return { left: 150 + index * 200, right: 280 + index * 200, top: 110 + index * 120, bottom: 190 + index * 120 };
  },
  canvasToDOM: point => point,
};
vm.runInContext('diagramNetwork = __network', context);
context.updateCanonicalZoneLayer(model, nodes);
assert.equal(elements.every(element => element.style.display === ''), true);
const parent = elements[0].style;
const child = elements[1].style;
assert.ok(parseFloat(parent.left) < parseFloat(child.left));
assert.ok(parseFloat(parent.top) < parseFloat(child.top));

const svg = context.diagramSvgMarkup({
  width: 1000, height: 600, revision: 3, semanticHash: 'hash-3', viewKind: 'system',
  zones: [{ id: 'zone-<&', label: 'Z1 · Internal <zone>', x: 10, y: 20, width: 300, height: 200, stroke: '#457B9D', fill: '#F3F8FC' }],
  nodeRefs: ['source'], flowRefs: ['flow-https', 'flow-http'], canvas: { toDataURL: () => 'data:image/png;base64,AAA' },
}, 'project-1');
assert.match(svg, /data-zone-id="zone-&lt;&amp;"/);
assert.match(svg, /Internal &lt;zone&gt;/);
assert.match(svg, /flow-https/);
assert.match(svg, /revision 3/);

console.log('RI2 DFD projection, layout, zone geometry, and SVG regression: ok');
