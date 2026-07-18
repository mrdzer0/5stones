/**
 * Analysis page — loads project context, runs analysis, renders results tabs
 * Includes: interactive vis-network diagram, LINDDUN fix (unique IDs), LINDDUN filter
 */
let projectId = null;
let currentReport = null;
let diagramNetwork = null;   // vis-network instance
const MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const ARTIFACT_ACCEPT = {
  prd: '.pdf,.docx,.md,.markdown,.txt',
  openapi: '.json,.yaml,.yml',
  postman: '.json',
  markdown: '.md,.markdown,.txt',
  database_schema: '.sql,.txt',
  csv: '.csv,.txt',
  har: '.har,.json',
  text: '.txt,.md,.markdown',
};

document.addEventListener('DOMContentLoaded', async () => {
  projectId = getProjectId();
  if (!projectId) {
    showToast('No project ID specified', 'error');
    return;
  }

  await loadProject();
  await tryLoadExistingReport();

  // Tab navigation
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Analysis actions
  document.getElementById('btn-run-analysis').addEventListener('click', runFullAnalysis);
  document.getElementById('btn-run-analysis-empty')?.addEventListener('click', runFullAnalysis);
  document.getElementById('btn-stride')?.addEventListener('click', () => runAnalysis(['trust_boundary', 'stride', 'controls', 'tests']));
  document.getElementById('btn-linddun')?.addEventListener('click', () => runAnalysis(['trust_boundary', 'linddun', 'controls', 'tests']));
  document.getElementById('btn-upload-artifact')?.addEventListener('click', uploadArtifact);
  document.getElementById('artifact-type-select')?.addEventListener('change', (e) => updateArtifactFileAccept(e.target.value));
  updateArtifactFileAccept(document.getElementById('artifact-type-select')?.value || 'prd');

  // Diagram toolbar
  document.getElementById('btn-diagram-fit')?.addEventListener('click', () => diagramNetwork?.fit());
  document.getElementById('btn-diagram-export')?.addEventListener('click', exportDiagramPng);

  // Report nav links
  const reportLink = document.getElementById('nav-report');
  if (reportLink) reportLink.href = `/report.html?id=${projectId}`;
  const reportBtn = document.getElementById('btn-view-report');
  if (reportBtn) reportBtn.href = `/report.html?id=${projectId}`;
});

// ── Project loading ────────────────────────────────────────────────────────────
async function loadProject() {
  try {
    const project = await API.projects.get(projectId);
    document.getElementById('page-project-name').textContent = project.name;
    renderProjectContext(project);
  } catch (err) {
    showToast('Could not load project: ' + err.message, 'error');
  }
}

function updateArtifactFileAccept(type) {
  const input = document.getElementById('artifact-file-inline');
  const hint = document.getElementById('artifact-file-inline-hint');
  if (input) {
    input.value = '';
    input.accept = ARTIFACT_ACCEPT[type] || '';
  }
  if (hint) {
    hint.textContent = `Max 5 MB. Allowed: ${ARTIFACT_ACCEPT[type] || 'selected artifact formats'}. Upload only PRD/API/schema/collection evidence needed for threat modeling.`;
  }
}

function renderProjectContext(p) {
  const el = document.getElementById('project-context-list');
  if (!el) return;
  const score = p.completeness_score ?? p.completeness?.score ?? 0;
  const level = p.completeness_level || p.completeness?.level || 'Not scored';
  const completeness = p.completeness || {};
  const color = score >= 85 ? 'var(--green)' : score >= 65 ? 'var(--orange)' : 'var(--accent)';
  const items = [
    ['Environment', p.environment || '—'],
    ['Actors', (p.actors || []).join(', ') || '—'],
    ['Entry Points', (p.entry_points || []).join(', ') || '—'],
    ['Data', (p.data_involved || []).join(', ') || '—'],
    ['Auth', p.auth_method || '—'],
    ['External', (p.external_systems || []).join(', ') || '—'],
    ['Artifacts', (p.artifacts || []).length + ' uploaded'],
  ];
  const contextHtml = items.map(([label, val]) => `
    <div style="margin-bottom:6px;">
      <span style="color:var(--text-faint);font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${label}</span><br>
      <span>${escHtml(String(val))}</span>
    </div>`).join('');

  const blockers = (completeness.blockers || []).slice(0, 4);
  const artifactTypes = completeness.artifact_types || [];
  el.innerHTML = `
    <div style="padding:var(--space-3);border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface-2);margin-bottom:var(--space-4);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span style="font-size:0.76rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Readiness</span>
        <span style="font-size:0.78rem;color:var(--text);font-weight:600;">${score}/100</span>
      </div>
      <div style="height:7px;background:var(--surface-3);border-radius:999px;overflow:hidden;margin-bottom:6px;">
        <div style="height:100%;width:${Math.max(0, Math.min(100, score))}%;background:${color};"></div>
      </div>
      <div style="font-size:0.75rem;color:var(--text-muted);">${escHtml(level)}</div>
      <div style="margin-top:6px;font-size:0.74rem;color:var(--text-muted);">
        ${completeness.artifact_count || 0} artifacts${artifactTypes.length ? ` · ${artifactTypes.map(escHtml).join(', ')}` : ''}
      </div>
      ${blockers.length ? `<div style="margin-top:var(--space-3);font-size:0.74rem;color:var(--text-muted);">
        <strong>Top gaps:</strong>
        <ul style="margin:6px 0 0;padding-left:16px;">${blockers.map(b => `<li>${escHtml(b.area)}</li>`).join('')}</ul>
      </div>` : ''}
    </div>
    ${contextHtml}`;
}

async function tryLoadExistingReport() {
  try {
    const report = await API.analysis.report(projectId);
    currentReport = report;
    renderResults(report);
    document.getElementById('btn-view-report').style.display = '';
  } catch {
    // No report yet — show empty state
  }
}

// ── Analysis pipeline ──────────────────────────────────────────────────────────
async function runFullAnalysis() {
  await runAnalysis(['trust_boundary', 'stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions']);
}

async function runAnalysis(types) {
  document.getElementById('empty-analysis-card').style.display = 'none';
  document.getElementById('results-tabs').style.display = 'none';
  document.getElementById('analyzing-card').style.display = '';

  const stepIds = ['as-trust', 'as-stride', 'as-linddun', 'as-controls', 'as-tests', 'as-gaps'];
  let stepIndex = 0;
  const stepInterval = setInterval(() => {
    if (stepIndex > 0) {
      document.getElementById(stepIds[stepIndex - 1])?.classList.replace('active', 'done');
    }
    if (stepIndex < stepIds.length) {
      document.getElementById(stepIds[stepIndex])?.classList.add('active');
      stepIndex++;
    }
  }, 1800);

  try {
    const report = await API.analysis.run(projectId, types);
    clearInterval(stepInterval);
    stepIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.classList.remove('active'); el.classList.add('done'); }
    });
    await new Promise(r => setTimeout(r, 400));
    currentReport = report;
    document.getElementById('analyzing-card').style.display = 'none';
    renderResults(report);
    document.getElementById('btn-view-report').style.display = '';
    showToast(`Analysis complete — ${report.risk_summary?.total || 0} threats identified`, 'success');
  } catch (err) {
    clearInterval(stepInterval);
    document.getElementById('analyzing-card').style.display = 'none';
    document.getElementById('empty-analysis-card').style.display = '';
    showToast('Analysis failed: ' + err.message, 'error');
  }
}

// ── Result rendering ───────────────────────────────────────────────────────────
function renderResults(report) {
  document.getElementById('results-tabs').style.display = '';

  const threats = report.threats || [];
  const stride = threats.filter(t => t.framework === 'STRIDE');
  const linddun = threats.filter(t => t.framework === 'LINDDUN');
  const completeness = report.completeness || {};

  document.getElementById('count-trust').textContent = (report.trust_boundaries || []).length;
  document.getElementById('count-stride').textContent = stride.length;
  document.getElementById('count-linddun').textContent = linddun.length;
  document.getElementById('count-controls').textContent = (report.controls || []).length;
  document.getElementById('count-tests').textContent = (report.test_scenarios || []).length;
  document.getElementById('count-gaps').textContent = (report.missing_info || []).length + (report.assumptions || []).length;
  document.getElementById('stride-summary').textContent = `STRIDE threats — ${stride.length} generated · readiness ${completeness.score || 0}/100 · ${report.risk_summary?.needs_review || 0} need review`;
  document.getElementById('tests-summary').textContent = `Security test backlog — ${(report.test_scenarios || []).length} scenarios mapped to current threats`;

  renderTrustBoundaries(report.trust_boundaries || []);
  renderDiagram(report);                                // ← interactive diagram
  renderThreats('stride-threats-list', 'st', stride);  // ← unique prefix 'st'
  renderThreats('linddun-threats-list', 'ln', linddun);// ← unique prefix 'ln'
  renderControls(report.controls || []);
  renderTests(report.test_scenarios || []);
  renderGaps(report.missing_info || [], report.assumptions || []);

  // STRIDE filter
  const strideFilter = document.getElementById('stride-filter');
  if (strideFilter) {
    strideFilter.onchange = (e) => {
      const filtered = e.target.value ? stride.filter(t => t.threat_category === e.target.value) : stride;
      renderThreats('stride-threats-list', 'st', filtered);
    };
  }
  // LINDDUN filter
  const linddunFilter = document.getElementById('linddun-filter');
  if (linddunFilter) {
    linddunFilter.onchange = (e) => {
      const filtered = e.target.value ? linddun.filter(t => t.threat_category === e.target.value) : linddun;
      renderThreats('linddun-threats-list', 'ln', filtered);
    };
  }
  // Tests filter
  const testsFilter = document.getElementById('tests-filter');
  if (testsFilter) {
    testsFilter.onchange = (e) => {
      const filtered = e.target.value ? (report.test_scenarios || []).filter(t => t.priority === e.target.value) : report.test_scenarios || [];
      renderTests(filtered);
    };
  }
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.tab-btn[data-tab="${tabId}"]`)?.classList.add('active');
  document.getElementById(`tab-${tabId}`)?.classList.add('active');

  // Re-fit diagram when switching to diagram tab
  if (tabId === 'diagram' && diagramNetwork) {
    setTimeout(() => diagramNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } }), 100);
  }
}

// ── Trust Boundaries list ─────────────────────────────────────────────────────
function renderTrustBoundaries(boundaries) {
  const el = document.getElementById('trust-boundaries-list');
  if (!boundaries.length) {
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><h3>No trust boundaries detected</h3></div>`;
    return;
  }
  el.innerHTML = `
    <div style="margin-bottom:var(--space-4);">
      <p class="text-sm text-muted">Trust boundaries represent points where data crosses between different trust zones — each is a potential attack surface.</p>
    </div>
    <div style="display:flex;flex-direction:column;gap:var(--space-3);">
      ${boundaries.map(b => `
        <div style="border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface);overflow:hidden;">
          <div style="display:flex;align-items:center;gap:var(--space-4);padding:var(--space-4) var(--space-5);">
            <div style="flex:1;">
              <div style="display:flex;align-items:center;gap:var(--space-3);margin-bottom:var(--space-2);">
                <div style="font-weight:600;font-size:0.875rem;">${escHtml(b.source)}</div>
                <span style="color:var(--text-faint);font-size:0.8rem;">→</span>
                <div style="font-weight:600;font-size:0.875rem;">${escHtml(b.destination)}</div>
                <span class="tb-boundary-label">${escHtml(b.boundary_label)}</span>
              </div>
              <div style="display:flex;gap:var(--space-3);font-size:0.78rem;color:var(--text-muted);">
                <span>${escHtml(b.source_trust_level || '')} → ${escHtml(b.destination_trust_level || '')}</span>
              </div>
              ${b.risk_note ? `<div style="font-size:0.78rem;color:var(--text-muted);margin-top:var(--space-1);">${escHtml(b.risk_note)}</div>` : ''}
            </div>
          </div>
        </div>
      `).join('')}
    </div>`;
}

// ── INTERACTIVE DIAGRAM (vis-network) ─────────────────────────────────────────
const TRUST_COLORS = {
  'untrusted':        { bg: '#FEF2F4', border: '#DC2626', font: '#DC2626' },
  'external':         { bg: '#FFF7ED', border: '#D97706', font: '#D97706' },
  'low':              { bg: '#FFF7ED', border: '#D97706', font: '#D97706' },
  'internal':         { bg: '#EFF6FF', border: '#2563EB', font: '#2563EB' },
  'privileged':       { bg: '#F0FDF4', border: '#15803D', font: '#15803D' },
  'highly privileged':{ bg: '#F0FDF4', border: '#15803D', font: '#15803D' },
  'sensitive':        { bg: '#F5F3FF', border: '#6D28D9', font: '#6D28D9' },
  'default':          { bg: '#F3F4F6', border: '#6B7280', font: '#374151' },
};

function getTrustColor(trustLevel) {
  const k = (trustLevel || '').toLowerCase().trim();
  return TRUST_COLORS[k] || TRUST_COLORS.default;
}

function getNodeShape(label) {
  const l = label.toLowerCase();
  if (l.includes('database') || l.includes('db') || l.includes('storage') || l.includes('store')) return 'database';
  if (l.includes('user') || l.includes('customer') || l.includes('actor') || l.includes('merchant') || l.includes('admin')) return 'ellipse';
  if (l.includes('service') || l.includes('api') || l.includes('server') || l.includes('gateway') || l.includes('proxy')) return 'box';
  return 'box';
}

function renderDiagram(report) {
  const container = document.getElementById('threat-diagram-canvas');
  if (!container) return;

  const boundaries = report.trust_boundaries || [];
  const threats = report.threats || [];

  // Build node map from trust boundaries + project context
  const nodeMap = new Map();
  let nodeIdCounter = 1;

  function getOrCreateNode(label, trustLevel) {
    const key = label.toLowerCase().trim();
    if (!nodeMap.has(key)) {
      const color = getTrustColor(trustLevel);
      nodeMap.set(key, {
        id: nodeIdCounter++,
        label: label,
        trustLevel: trustLevel || 'default',
        color: { background: color.bg, border: color.border, highlight: { background: color.bg, border: '#1A1917' } },
        font: { color: color.font, size: 13, face: 'Inter, sans-serif', bold: true },
        shape: getNodeShape(label),
        borderWidth: 2,
        borderWidthSelected: 3,
        shadow: { enabled: true, size: 6, x: 2, y: 2, color: 'rgba(0,0,0,0.08)' },
        margin: 12,
        // store related threats for inspector
        relatedThreats: [],
      });
    }
    return nodeMap.get(key);
  }

  // Process trust boundaries to create nodes and edges
  const edges = [];
  let edgeId = 1;

  boundaries.forEach(b => {
    const srcNode = getOrCreateNode(b.source, b.source_trust_level);
    const dstNode = getOrCreateNode(b.destination, b.destination_trust_level);
    edges.push({
      id: edgeId++,
      from: srcNode.id,
      to: dstNode.id,
      label: b.boundary_label || '',
      arrows: { to: { enabled: true, scaleFactor: 0.8 } },
      color: { color: '#C8C5BF', highlight: '#1A1917', hover: '#1A1917' },
      font: { size: 10, color: '#726E68', face: 'Inter, sans-serif', background: '#FFFFFF', strokeWidth: 0 },
      dashes: b.is_trust_crossing !== false,
      width: 1.5,
      smooth: { type: 'curvedCW', roundness: 0.15 },
    });
  });

  // Attach threats to nodes for inspector
  threats.forEach(t => {
    const comp = (t.component || t.asset || '').toLowerCase().trim();
    nodeMap.forEach((node, key) => {
      if (comp && (comp.includes(key) || key.includes(comp))) {
        node.relatedThreats.push(t);
      }
    });
  });

  // Add threat count badges to nodes
  nodeMap.forEach(node => {
    const count = node.relatedThreats.length;
    if (count > 0) {
      const critical = node.relatedThreats.filter(t => t.risk_level === 'Critical').length;
      const high = node.relatedThreats.filter(t => t.risk_level === 'High').length;
      let badge = '';
      if (critical > 0) badge += `⚠ ${critical}C `;
      if (high > 0) badge += `${high}H`;
      if (badge) node.label = node.label + '\n' + badge.trim();
    }
  });

  const nodes = Array.from(nodeMap.values()).map(n => ({
    id: n.id,
    label: n.label,
    color: n.color,
    font: n.font,
    shape: n.shape,
    borderWidth: n.borderWidth,
    borderWidthSelected: n.borderWidthSelected,
    shadow: n.shadow,
    margin: n.margin,
    // keep ref
    _trustLevel: n.trustLevel,
    _threats: n.relatedThreats,
    _origLabel: n.label,
  }));

  // If no boundaries, show placeholder nodes from project
  if (nodes.length === 0) {
    const placeholders = ['Internet', 'Web Application', 'API Server', 'Database'];
    placeholders.forEach((label, i) => {
      const levels = ['untrusted', 'external', 'internal', 'privileged'];
      const color = getTrustColor(levels[i]);
      nodes.push({
        id: i + 1, label, shape: getNodeShape(label),
        color: { background: color.bg, border: color.border, highlight: { background: color.bg, border: '#1A1917' } },
        font: { color: color.font, size: 13, face: 'Inter, sans-serif', bold: true },
        borderWidth: 2, margin: 12,
        _threats: [],
      });
    });
    [1,2,3].forEach(i => {
      edges.push({ id: i, from: i, to: i+1, arrows: { to: { enabled: true, scaleFactor: 0.8 } }, color: { color: '#C8C5BF' }, dashes: true, width: 1.5, label: 'trust boundary' + i, font: { size: 10, color: '#726E68', background: '#FFFFFF' } });
    });
  }

  const data = {
    nodes: new vis.DataSet(nodes),
    edges: new vis.DataSet(edges),
  };

  const options = {
    physics: {
      enabled: true,
      solver: 'barnesHut',
      barnesHut: { gravitationalConstant: -8000, springConstant: 0.04, springLength: 200, damping: 0.3 },
      stabilization: { iterations: 150, updateInterval: 10 },
    },
    layout: { randomSeed: 42 },
    interaction: {
      hover: true,
      tooltipDelay: 200,
      navigationButtons: false,
      zoomView: true,
      dragView: true,
    },
    nodes: { widthConstraint: { minimum: 80, maximum: 160 } },
    edges: { selectionWidth: 2 },
  };

  // Destroy existing instance
  if (diagramNetwork) { diagramNetwork.destroy(); diagramNetwork = null; }
  diagramNetwork = new vis.Network(container, data, options);

  // Stop physics after stabilization (for manual drag)
  diagramNetwork.once('stabilizationIterationsDone', () => {
    diagramNetwork.setOptions({ physics: { enabled: false } });
    diagramNetwork.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
  });

  // Click to inspect node
  diagramNetwork.on('click', (params) => {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const node = data.nodes.get(nodeId);
      showNodeInspector(node);
    } else {
      document.getElementById('node-inspector').style.display = 'none';
    }
  });

  // Re-enable physics on drag start (for snapping), disable on drag end
  diagramNetwork.on('dragStart', () => diagramNetwork.setOptions({ physics: { enabled: false } }));
}

function showNodeInspector(node) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;

  const threats = node._threats || [];
  const origLabel = (node._origLabel || node.label || '').split('\n')[0];
  title.textContent = origLabel;

  if (!threats.length) {
    body.innerHTML = `<div style="font-size:0.82rem;color:var(--text-muted);padding:var(--space-3) 0;">No threats mapped to this component.</div>`;
  } else {
    body.innerHTML = threats.map(t => `
      <div style="border-bottom:1px solid var(--border);padding:var(--space-3) 0;">
        <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:4px;">
          ${badgeHtml(t.risk_level, 'risk')}
          ${badgeHtml(t.framework, 'framework')}
          <span style="font-size:0.78rem;font-weight:500;">${escHtml(t.threat_category)}</span>
        </div>
        <div style="font-size:0.8rem;color:var(--text-2);">${escHtml((t.threat_description || '').substring(0, 120))}…</div>
        ${t.recommended_control ? `<div style="font-size:0.75rem;color:var(--green);margin-top:2px;">→ ${escHtml(t.recommended_control)}</div>` : ''}
      </div>
    `).join('');
  }

  inspector.style.display = 'block';
}

function exportDiagramPng() {
  if (!diagramNetwork) return;
  try {
    const canvas = diagramNetwork.canvas.frame.canvas;
    const link = document.createElement('a');
    link.download = `threat-diagram-${projectId}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
    showToast('Diagram exported as PNG', 'success');
  } catch {
    showToast('Could not export diagram', 'error');
  }
}

// ── Threats (FIXED: unique prefix to avoid ID conflicts) ──────────────────────
/**
 * @param {string} containerId  - DOM element ID
 * @param {string} prefix       - unique prefix: 'st' for STRIDE, 'ln' for LINDDUN
 * @param {Array}  threats
 */
function renderThreats(containerId, prefix, threats) {
  const el = document.getElementById(containerId);
  if (!el) return;

  if (!threats.length) {
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><h3>No threats generated</h3><p>Run the analysis to generate threats.</p></div>`;
    return;
  }

  el.innerHTML = threats.map((t, i) => {
    const uid = `${prefix}-${i}`;   // unique: 'st-0', 'ln-0', etc.
    return `
    <div class="threat-item" id="threat-${uid}">
      <div class="threat-item-header" onclick="toggleThreat('${uid}')">
        ${badgeHtml(t.risk_level, 'risk')}
        ${badgeHtml(t.framework, 'framework')}
        <div style="flex:1;font-size:0.845rem;font-weight:500;color:var(--text);">${escHtml(t.threat_category)} — ${escHtml((t.threat_description || '').substring(0, 90))}${(t.threat_description || '').length > 90 ? '…' : ''}</div>
        ${confidenceDots(t.confidence)}
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;color:var(--text-faint);flex-shrink:0;" id="chevron-${uid}"><polyline points="6 9 12 15 18 9"/></svg>
      </div>
      <div class="threat-item-body" id="threat-body-${uid}" style="display:none;">
        <div class="threat-meta-grid">
          <div class="threat-meta-item"><div class="threat-meta-label">Asset</div><div class="threat-meta-value">${escHtml(t.asset || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Component</div><div class="threat-meta-value">${escHtml(t.component || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Trust Boundary</div><div class="threat-meta-value">${escHtml(t.trust_boundary || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Classification</div><div class="threat-meta-value">${escHtml(t.data_classification || '—')}</div></div>
        </div>
        <div style="margin-top:var(--space-3);display:grid;grid-template-columns:1fr 1fr;gap:var(--space-3);">
          <div class="threat-meta-item"><div class="threat-meta-label">Evidence Source</div><div class="threat-meta-value">${escHtml(t.evidence_source || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Review Status</div><div class="threat-meta-value">${statusSelectHtml(t)}</div></div>
        </div>
        ${t.evidence_snippet ? `<div style="margin-top:var(--space-3);font-size:0.78rem;color:var(--text-muted);"><strong>Evidence:</strong> ${escHtml(t.evidence_snippet)}</div>` : ''}
        ${t.confidence_reason ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--text-muted);"><strong>Confidence reason:</strong> ${escHtml(t.confidence_reason)}</div>` : ''}
        ${t.abuse_case ? `<div style="margin-top:var(--space-4);padding:var(--space-3) var(--space-4);background:var(--accent-light);border:1px solid var(--accent-border);border-radius:var(--r-md);"><div class="threat-meta-label" style="color:var(--accent);">Abuse Case</div><div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(t.abuse_case)}</div></div>` : ''}
        ${t.recommended_control ? `<div style="margin-top:var(--space-3);padding:var(--space-3) var(--space-4);background:var(--green-light);border:1px solid var(--green-border);border-radius:var(--r-md);"><div class="threat-meta-label" style="color:var(--green);">Recommended Control</div><div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(t.recommended_control)}</div></div>` : ''}
        ${t.assumption ? `<div style="margin-top:var(--space-3);font-size:0.78rem;color:var(--text-muted);"><strong>Assumption:</strong> ${escHtml(t.assumption)}</div>` : ''}
        ${t.missing_info ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--orange);"><strong>Missing Info:</strong> ${escHtml(t.missing_info)}</div>` : ''}
      </div>
    </div>`;
  }).join('');
}

function statusSelectHtml(t) {
  const statuses = ['Open', 'Needs Info', 'Reviewed', 'Accepted', 'Mitigation Planned', 'Mitigated', 'Verified'];
  return `<select class="form-select" style="height:30px;font-size:0.76rem;" onchange="updateThreatStatus('${escHtml(t.threat_id)}', this.value)">
    ${statuses.map(s => `<option value="${s}" ${t.status === s ? 'selected' : ''}>${s}</option>`).join('')}
  </select>`;
}

// Exposed globally — called via inline onclick
window.toggleThreat = function(uid) {
  const body = document.getElementById(`threat-body-${uid}`);
  const chevron = document.getElementById(`chevron-${uid}`);
  if (!body) return;
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (chevron) chevron.style.transform = isOpen ? '' : 'rotate(180deg)';
};

window.updateThreatStatus = async function(threatId, status) {
  try {
    await API.analysis.updateThreat(projectId, threatId, { status });
    showToast('Threat status updated', 'success');
  } catch (err) {
    showToast('Could not update status: ' + err.message, 'error');
  }
};

// ── Controls ───────────────────────────────────────────────────────────────────
function renderControls(controls) {
  const el = document.getElementById('controls-list');
  if (!controls.length) {
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><h3>No controls mapped yet</h3></div>`;
    return;
  }
  const statusColor = { Implemented: 'badge-mitigated', Partial: 'badge-medium', Missing: 'badge-critical', Unknown: 'badge-neutral' };
  el.innerHTML = `<div style="display:flex;flex-direction:column;gap:var(--space-3);">
    ${controls.map(c => `
      <div style="border:1px solid var(--border);border-radius:var(--r-md);padding:var(--space-4) var(--space-5);background:var(--surface);">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:var(--space-4);margin-bottom:var(--space-2);">
          <div style="font-weight:600;font-size:0.875rem;">${escHtml(c.name)}</div>
          <span class="badge ${statusColor[c.status] || 'badge-neutral'}">${escHtml(c.review_status || c.status)}</span>
        </div>
        ${c.implementation_guidance ? `<div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:var(--space-2);">${escHtml(c.implementation_guidance)}</div>` : ''}
        ${c.checklist_items?.length ? `<ul style="margin:var(--space-3) 0;padding-left:18px;font-size:0.8rem;color:var(--text-2);">${c.checklist_items.map(item => `<li style="margin-bottom:4px;">${escHtml(item)}</li>`).join('')}</ul>` : ''}
        ${c.verification_method ? `<div style="font-size:0.78rem;color:var(--green);margin-bottom:var(--space-2);"><strong>Verify:</strong> ${escHtml(c.verification_method)}</div>` : ''}
        <div style="display:flex;gap:var(--space-4);font-size:0.75rem;color:var(--text-faint);">
          <span>Owner: <strong>${escHtml(c.owner || '—')}</strong></span>
          <span>Priority: <strong>${escHtml(c.priority || 'Medium')}</strong></span>
          ${c.evidence ? `<span>Evidence: ${escHtml(c.evidence)}</span>` : ''}
        </div>
      </div>
    `).join('')}
  </div>`;
}

// ── Tests ──────────────────────────────────────────────────────────────────────
function renderTests(tests) {
  const el = document.getElementById('tests-list');
  if (!tests.length) {
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><h3>No test scenarios yet</h3></div>`;
    return;
  }
  el.innerHTML = tests.map((t, i) => {
    const uid = `ts-${i}`;
    return `
    <div class="threat-item" style="margin-bottom:var(--space-3);">
      <div class="threat-item-header" onclick="toggleTest('${uid}')">
        <span class="mono text-xs" style="color:var(--text-faint);">${escHtml(t.test_id || '')}</span>
        ${badgeHtml(t.priority, 'risk')}
        <div style="flex:1;font-size:0.845rem;font-weight:500;">${escHtml(t.scenario_name || '')}</div>
        <span style="font-size:0.75rem;color:var(--text-muted);">${escHtml(t.owner || '')}</span>
      </div>
      <div class="threat-item-body" id="test-body-${uid}" style="display:none;">
        <div style="margin-bottom:var(--space-3);"><div class="threat-meta-label">Preconditions</div><div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(t.preconditions || '—')}</div></div>
        ${t.steps?.length ? `<div style="margin-bottom:var(--space-3);"><div class="threat-meta-label">Steps</div><ol style="margin-top:var(--space-2);padding-left:var(--space-5);font-size:0.82rem;color:var(--text-2);">${t.steps.map(s => `<li style="margin-bottom:4px;">${escHtml(s)}</li>`).join('')}</ol></div>` : ''}
        <div><div class="threat-meta-label">Expected Result</div><div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(t.expected_result || '—')}</div></div>
        ${t.related_control ? `<div style="margin-top:var(--space-3);font-size:0.78rem;color:var(--green);"><strong>Tests control:</strong> ${escHtml(t.related_control)}</div>` : ''}
      </div>
    </div>`;
  }).join('');
}

window.toggleTest = function(uid) {
  const body = document.getElementById(`test-body-${uid}`);
  if (body) body.style.display = body.style.display === 'none' ? 'block' : 'none';
};

// ── Gaps ───────────────────────────────────────────────────────────────────────
function renderGaps(missing, assumptions) {
  const el = document.getElementById('gaps-list');
  let html = '';
  if (missing.length) {
    html += `<h3 style="font-size:0.875rem;margin-bottom:var(--space-4);">Missing Information</h3>
      <div style="display:flex;flex-direction:column;gap:var(--space-3);margin-bottom:var(--space-6);">
        ${missing.map(m => `
          <div style="border:1px solid var(--orange-border);border-radius:var(--r-md);padding:var(--space-4) var(--space-5);background:var(--orange-light);">
            <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:4px;">
              ${badgeHtml(m.priority || 'Medium', 'risk')}
              <div style="font-weight:600;font-size:0.845rem;color:var(--orange);">${escHtml(m.area)}</div>
              <span class="text-xs text-muted">${escHtml(m.target_team || 'Dev/Tech Lead')}</span>
            </div>
            <div style="font-size:0.82rem;color:var(--text-2);margin-top:4px;">${escHtml(m.question_to_ask || m.question)}</div>
            <div style="font-size:0.75rem;color:var(--text-muted);margin-top:4px;"><em>Why it matters: ${escHtml(m.why_it_matters)}</em></div>
          </div>
        `).join('')}
      </div>`;
  }
  if (assumptions.length) {
    html += `<h3 style="font-size:0.875rem;margin-bottom:var(--space-4);">Assumption Register</h3>
      <div style="display:flex;flex-direction:column;gap:var(--space-3);">
        ${assumptions.map(a => `
          <div style="border:1px solid var(--border);border-radius:var(--r-md);padding:var(--space-4) var(--space-5);background:var(--surface);">
            <div style="display:flex;align-items:flex-start;gap:var(--space-4);">
              <div style="flex:1;">
                <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:4px;">
                  <div style="font-weight:600;font-size:0.82rem;color:var(--text);">${escHtml(a.area)}</div>
                  <span class="text-xs text-muted">${escHtml(a.owner || 'Dev/Tech Lead')}</span>
                </div>
                <div style="font-size:0.82rem;color:var(--text-2);">${escHtml(a.assumption)}</div>
              </div>
              ${confidenceDots(a.confidence)}
              <span class="text-xs text-muted">${escHtml(a.confidence)}</span>
            </div>
            ${a.evidence ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:8px;"><strong>Evidence:</strong> ${escHtml(a.evidence)}</div>` : ''}
            ${a.impact_if_wrong ? `<div style="font-size:0.75rem;color:var(--orange);margin-top:6px;"><strong>Impact if wrong:</strong> ${escHtml(a.impact_if_wrong)}</div>` : ''}
            ${a.verification_question ? `<div style="font-size:0.75rem;color:var(--text-2);margin-top:6px;"><strong>Ask dev:</strong> ${escHtml(a.verification_question)}</div>` : ''}
            ${a.recommended_validation ? `<div style="font-size:0.75rem;color:var(--green);margin-top:6px;"><strong>Validate:</strong> ${escHtml(a.recommended_validation)}</div>` : ''}
          </div>
        `).join('')}
      </div>`;
  }
  if (!html) html = `<div class="empty-state" style="padding:var(--space-8);"><h3>No gaps identified</h3></div>`;
  el.innerHTML = html;
}

// ── Artifact upload ────────────────────────────────────────────────────────────
async function uploadArtifact() {
  const type = document.getElementById('artifact-type-select')?.value;
  const file = document.getElementById('artifact-file-inline')?.files?.[0];
  const btn = document.getElementById('btn-upload-artifact');
  if (!file) { showToast('Upload an artifact file first', 'warn'); return; }
  if (file && file.size > MAX_ARTIFACT_BYTES) { showToast('File exceeds 5 MB limit', 'warn'); return; }

  btn.disabled = true;
  btn.innerHTML = '<div class="loading-spinner"></div> Parsing…';
  try {
    await API.artifacts.uploadFile(projectId, type, file);
    const project = await API.projects.get(projectId);
    renderProjectContext(project);
    const fileInput = document.getElementById('artifact-file-inline');
    if (fileInput) fileInput.value = '';
    showToast('Artifact parsed and context updated', 'success');
  } catch (err) {
    showToast('Upload failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg> Parse &amp; Add Context';
  }
}
