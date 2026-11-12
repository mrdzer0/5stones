const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const context = { console, URL, URLSearchParams };
vm.createContext(context);
vm.runInContext(fs.readFileSync('frontend/js/api.js', 'utf8'), context);

const report = {
  trust_boundaries: [{
    boundary_id: 'boundary-1',
    source: 'User',
    destination: 'API Gateway',
    boundary_label: 'External → Application',
    status: 'Rejected',
  }],
  threats: [{
    threat_id: 'threat-1',
    framework: 'STRIDE',
    trust_boundary: 'User → API Gateway',
    trust_boundary_ids: ['boundary-1'],
  }],
  controls: [{ control_id: 'control-1', threat_ids: ['threat-1'] }],
  test_scenarios: [{ test_id: 'test-1', threat_id: 'threat-1' }],
  assumptions: [{ area: 'Auth', related_threat_id: 'threat-1' }],
  missing_info: [{ area: 'Deployment' }],
};

let visibility = context.analysisVisibility(report);
assert.equal(visibility.allRejected, true);
assert.equal(visibility.threats.length, 0);
assert.equal(visibility.controls.length, 0);
assert.equal(visibility.tests.length, 0);
assert.equal(visibility.assumptions.length, 0);
assert.equal(visibility.missingInfo.length, 1, 'unlinked review question must remain visible');

report.trust_boundaries[0].status = 'Candidate';
visibility = context.analysisVisibility(report);
assert.equal(visibility.allRejected, false);
assert.equal(visibility.threats.length, 1);
assert.equal(visibility.controls.length, 1);
assert.equal(visibility.tests.length, 1);
assert.equal(visibility.assumptions.length, 1);
assert.equal(visibility.missingInfo.length, 1);

report.trust_boundaries[0].status = 'Confirmed';
visibility = context.analysisVisibility(report);
assert.equal(visibility.threats.length, 1);

// RG12: same-zone threats (no trust_boundary_ids) must remain visible even when all boundaries are rejected.
const sameZoneReport = {
  trust_boundaries: [{
    boundary_id: 'boundary-2',
    source: 'ServiceA',
    destination: 'ServiceB',
    boundary_label: 'Internal → Internal',
    status: 'Rejected',
  }],
  threats: [
    // Similar text is not an explicit boundary dependency.
    { threat_id: 'tz-1', framework: 'STRIDE', source: 'ServiceA', destination: 'ServiceB',
      trust_boundary: 'Internal → Internal', trust_boundary_ids: [] },
    // Boundary-linked threat: explicit link to rejected boundary
    { threat_id: 'tz-2', framework: 'STRIDE', trust_boundary_ids: ['boundary-2'] },
  ],
  controls: [
    { control_id: 'ctrl-tz-1', threat_ids: ['tz-1'] },
    { control_id: 'ctrl-tz-2', threat_ids: ['tz-2'] },
    { control_id: 'ctrl-unlinked', threat_ids: [] },
  ],
  test_scenarios: [
    { test_id: 'tst-tz-1', threat_id: 'tz-1' },
    { test_id: 'tst-tz-2', threat_id: 'tz-2' },
  ],
};

const sameZoneVis = context.analysisVisibility(sameZoneReport);
assert.equal(sameZoneVis.allRejected, true, 'allRejected should be true');
// Same-zone threat has no boundary dependency → must be visible
assert.equal(sameZoneVis.threats.length, 1, 'same-zone threat must remain visible when allRejected');
assert.equal(sameZoneVis.threats[0].threat_id, 'tz-1', 'visible threat should be the same-zone one');
// Controls and tests of the visible same-zone threat must also be visible
assert.equal(sameZoneVis.controls.length, 2, 'same-zone and unlinked controls must be visible');
assert.equal(sameZoneVis.tests.length, 1, 'test of same-zone threat must be visible');
// Hidden counts must reflect the boundary-linked items
assert.equal(sameZoneVis.hidden.threats, 1, 'boundary-linked threat should be hidden');
assert.equal(sameZoneVis.hidden.controls, 1, 'boundary-linked control should be hidden');
assert.equal(sameZoneVis.hidden.tests, 1, 'boundary-linked test should be hidden');

console.log('RI3 same-zone visibility regression: ok');
console.log('analysis visibility regression: ok');
