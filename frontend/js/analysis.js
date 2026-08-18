/**
 * Analysis page — loads project context, runs analysis, renders results tabs
 * Includes: interactive vis-network diagram, LINDDUN fix (unique IDs), LINDDUN filter
 */
let projectId = null;
let currentReport = null;
let currentProject = null;
let diagramNetwork = null;   // vis-network instance
let diagramResizeTimer = null;
let diagramViewMode = loadDiagramViewMode();
let diagramLevel = loadDiagramLevel();
let analysisIsRunning = false;
let pendingArtifactAnalysisTypes = [];
const VALID_ANALYSIS_TABS = ['diagram', 'trust-boundaries', 'stride', 'linddun', 'controls', 'tests', 'gaps'];
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

  setupAnalysisProgressCollapse();
  setupContextCollapse();
  setupAnalysisTabs();
  setupOverviewActions();
  setupDiagramUtilities();

  await loadProject();
  await tryLoadExistingReport();
  restoreAnalysisTab();

  // Analysis actions
  document.getElementById('btn-run-analysis').addEventListener('click', runFullAnalysis);
  document.getElementById('btn-run-analysis-empty')?.addEventListener('click', runFullAnalysis);
  document.getElementById('btn-stride')?.addEventListener('click', () => runAnalysis(['trust_boundary', 'stride', 'controls', 'tests']));
  document.getElementById('btn-linddun')?.addEventListener('click', () => runAnalysis(['trust_boundary', 'linddun', 'controls', 'tests']));
  document.getElementById('btn-run-affected')?.addEventListener('click', () => {
    runAnalysis(pendingArtifactAnalysisTypes.length ? pendingArtifactAnalysisTypes : fullAnalysisTypes());
  });
  document.getElementById('btn-upload-artifact')?.addEventListener('click', uploadArtifact);
  document.getElementById('artifact-type-select')?.addEventListener('change', (e) => updateArtifactFileAccept(e.target.value));
  document.getElementById('artifact-file-inline')?.addEventListener('change', (e) => updateArtifactSelection(e.target.files?.[0]));
  updateArtifactFileAccept(document.getElementById('artifact-type-select')?.value || 'prd');
  const artifactError = new URLSearchParams(window.location.search).get('artifact_error');
  if (artifactError) {
    setArtifactImportStatus('error', `
      <div class="artifact-result-title">The initial artifact was not added</div>
      <div>${escHtml(artifactError)}</div>
      <div style="margin-top:6px;">Select the matching artifact type and retry here. The project itself was created successfully.</div>
    `);
  }

  // Diagram toolbar
  document.getElementById('btn-diagram-fit')?.addEventListener('click', () => diagramNetwork?.fit());
  document.getElementById('btn-diagram-export')?.addEventListener('click', exportDiagramPng);
  setupDiagramModeSwitch();
  setupDiagramLevelSwitch();
  window.addEventListener('resize', () => {
    window.clearTimeout(diagramResizeTimer);
    diagramResizeTimer = window.setTimeout(() => {
      diagramNetwork?.fit({ animation: false });
      updateTabScrollControls();
    }, 180);
  });

  // Report nav links
  const reportLink = document.getElementById('nav-report');
  if (reportLink) reportLink.href = `/report.html?id=${projectId}`;
  const reportBtn = document.getElementById('btn-view-report');
  if (reportBtn) reportBtn.href = `/report.html?id=${projectId}`;

  document.getElementById('btn-proceed-results')?.addEventListener('click', () => {
    document.getElementById('analyzing-card').style.display = 'none';
    setAnalysisRunning(false);
    if (currentReport) {
      renderResults(currentReport);
      restoreAnalysisTab();
    }
  });
});

function fullAnalysisTypes() {
  return ['trust_boundary', 'stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions'];
}

function setupContextCollapse() {
  const toggle = document.getElementById('context-collapse-toggle');
  if (!toggle) return;

  let stored = null;
  try { stored = localStorage.getItem('5stones-analysis-context-collapsed'); } catch (_) {}
  const collapsed = stored === null
    ? window.matchMedia('(max-width: 1050px)').matches
    : stored === 'true';
  setContextCollapsed(collapsed, false);

  toggle.addEventListener('click', () => {
    const card = document.getElementById('project-context-card');
    setContextCollapsed(!card?.classList.contains('is-collapsed'));
  });
}

function setContextCollapsed(collapsed, persist = true) {
  const card = document.getElementById('project-context-card');
  const toggle = document.getElementById('context-collapse-toggle');
  const label = document.getElementById('context-collapse-label');
  if (!card || !toggle) return;
  card.classList.toggle('is-collapsed', collapsed);
  toggle.setAttribute('aria-expanded', String(!collapsed));
  toggle.title = collapsed ? 'Expand project context' : 'Collapse project context';
  if (label) label.textContent = collapsed ? 'Show details' : 'Hide details';
  if (persist) {
    try { localStorage.setItem('5stones-analysis-context-collapsed', String(collapsed)); } catch (_) {}
  }
}

function setupAnalysisTabs() {
  const buttons = [...document.querySelectorAll('.tab-btn[data-tab]')];
  const nav = document.querySelector('.analysis-tabs-toolbar .tab-nav');
  const select = document.getElementById('analysis-tab-select');

  buttons.forEach((button, index) => {
    button.addEventListener('click', () => switchTab(button.dataset.tab));
    button.addEventListener('keydown', event => {
      let nextIndex = null;
      if (event.key === 'ArrowRight') nextIndex = (index + 1) % buttons.length;
      if (event.key === 'ArrowLeft') nextIndex = (index - 1 + buttons.length) % buttons.length;
      if (event.key === 'Home') nextIndex = 0;
      if (event.key === 'End') nextIndex = buttons.length - 1;
      if (nextIndex === null) return;
      event.preventDefault();
      switchTab(buttons[nextIndex].dataset.tab, { focus: true });
    });
  });

  select?.addEventListener('change', event => switchTab(event.target.value));
  document.getElementById('tab-scroll-prev')?.addEventListener('click', () => {
    nav?.scrollBy({ left: -Math.max(220, nav.clientWidth * .7), behavior: 'smooth' });
  });
  document.getElementById('tab-scroll-next')?.addEventListener('click', () => {
    nav?.scrollBy({ left: Math.max(220, nav.clientWidth * .7), behavior: 'smooth' });
  });
  nav?.addEventListener('scroll', updateTabScrollControls, { passive: true });
  window.addEventListener('hashchange', () => {
    const tab = location.hash.replace(/^#analysis-/, '');
    if (VALID_ANALYSIS_TABS.includes(tab)) switchTab(tab, { persist: false });
  });
  requestAnimationFrame(updateTabScrollControls);
}

function updateTabScrollControls() {
  const nav = document.querySelector('.analysis-tabs-toolbar .tab-nav');
  const prev = document.getElementById('tab-scroll-prev');
  const next = document.getElementById('tab-scroll-next');
  if (!nav || !prev || !next) return;
  const maxScroll = Math.max(0, nav.scrollWidth - nav.clientWidth);
  prev.disabled = nav.scrollLeft <= 2;
  next.disabled = nav.scrollLeft >= maxScroll - 2;
  document.getElementById('analysis-tabs-toolbar')?.classList.toggle('has-overflow', maxScroll > 2);
}

function preferredAnalysisTab() {
  if (!currentReport) return 'diagram';
  const threats = analysisVisibility(currentReport).threats;
  const priority = threats.find(item => ['Critical', 'High'].includes(item.risk_level)) || threats[0];
  if (priority?.framework === 'LINDDUN') return 'linddun';
  if (priority?.framework === 'STRIDE') return 'stride';
  return 'diagram';
}

function restoreAnalysisTab() {
  if (!currentReport) return;
  const hashTab = location.hash.replace(/^#analysis-/, '');
  let storedTab = null;
  try { storedTab = localStorage.getItem(`5stones-analysis-tab:${projectId}`); } catch (_) {}
  const tab = [hashTab, storedTab, preferredAnalysisTab()].find(item => VALID_ANALYSIS_TABS.includes(item));
  switchTab(tab || 'diagram', { persist: false });
}

function setupOverviewActions() {
  document.querySelectorAll('[data-overview-action]').forEach(button => {
    button.addEventListener('click', () => openOverviewAction(button.dataset.overviewAction));
  });
  document.getElementById('overview-context-action')?.addEventListener('click', () => {
    setContextCollapsed(false);
    document.getElementById('project-context-card')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
  });
}

function openOverviewAction(action) {
  if (!currentReport) return;
  if (action === 'boundaries') {
    switchTab('trust-boundaries');
    document.getElementById('tab-trust-boundaries')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
    return;
  }
  if (['controls', 'tests'].includes(action)) {
    switchTab(action);
    document.getElementById(`tab-${action}`)?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
    return;
  }
  if (action === 'gaps') {
    switchTab('gaps');
    document.getElementById('tab-gaps')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
    return;
  }

  const threats = analysisVisibility(currentReport).threats;
  const target = action === 'review'
    ? threats.find(item => ['Open', 'Needs Info', 'Needs Review'].includes(item.status || 'Open'))
    : threats.find(item => String(item.risk_level).toLowerCase() === action);
  if (!target) {
    switchTab(threats[0]?.framework === 'LINDDUN' ? 'linddun' : 'stride');
    return;
  }

  const tab = target.framework === 'LINDDUN' ? 'linddun' : 'stride';
  switchTab(tab);
  requestAnimationFrame(() => {
    const item = [...document.querySelectorAll(`#tab-${tab} .threat-item`)]
      .find(element => element.dataset.threatId === String(target.threat_id || ''));
    item?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'center' });
    item?.querySelector('.threat-item-header')?.focus({ preventScroll: true });
  });
}

function reducedMotionBehavior() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
}

function setupDiagramUtilities() {
  const fullscreenButton = document.getElementById('btn-diagram-fullscreen');
  fullscreenButton?.addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.getElementById('tab-diagram')?.requestFullscreen();
    } catch (_) {
      showToast('Fullscreen is not available in this browser', 'warn');
    }
  });
  document.addEventListener('fullscreenchange', () => {
    const active = document.fullscreenElement?.id === 'tab-diagram';
    const fullscreenLabel = document.getElementById('diagram-fullscreen-label');
    if (fullscreenButton) {
      fullscreenButton.setAttribute('aria-label', active ? 'Exit diagram fullscreen' : 'Open diagram fullscreen');
      fullscreenButton.title = active ? 'Exit diagram fullscreen' : 'Open diagram fullscreen';
    }
    if (fullscreenLabel) fullscreenLabel.textContent = active ? 'Exit fullscreen' : 'Fullscreen';
    setTimeout(() => diagramNetwork?.fit({ animation: false }), 100);
  });

  const shell = document.getElementById('diagram-canvas-shell');
  document.querySelectorAll('[data-diagram-zone-index]').forEach(button => {
    button.addEventListener('click', () => {
      const index = Number(button.dataset.diagramZoneIndex || 0);
      const max = Math.max(0, shell.scrollWidth - shell.clientWidth);
      shell.scrollTo({ left: max * (index / 3), behavior: reducedMotionBehavior() });
    });
  });
  shell?.addEventListener('scroll', () => {
    const max = Math.max(1, shell.scrollWidth - shell.clientWidth);
    const index = Math.round((shell.scrollLeft / max) * 3);
    document.querySelectorAll('[data-diagram-zone-index]').forEach(button => {
      button.classList.toggle('active', Number(button.dataset.diagramZoneIndex) === index);
    });
  }, { passive: true });
}

function setupAnalysisProgressCollapse() {
  const panel = document.querySelector('.analysis-progress-panel');
  const toggle = document.getElementById('analysis-progress-toggle');
  if (!panel || !toggle) return;

  const applyState = (collapsed) => {
    panel.classList.toggle('is-collapsed', collapsed);
    toggle.setAttribute('aria-expanded', String(!collapsed));
    toggle.setAttribute('aria-label', collapsed ? 'Expand progress details' : 'Collapse progress details');
    toggle.title = collapsed ? 'Expand progress details' : 'Collapse progress details';
  };

  let collapsed = false;
  try {
    collapsed = localStorage.getItem('5stones-progress-collapsed') === 'true';
  } catch (_) {
    // Preference persistence is optional.
  }
  applyState(collapsed);

  toggle.addEventListener('click', () => {
    collapsed = !panel.classList.contains('is-collapsed');
    applyState(collapsed);
    try {
      localStorage.setItem('5stones-progress-collapsed', String(collapsed));
    } catch (_) {
      // Keep the interaction functional even when storage is unavailable.
    }
  });
}

function loadDiagramViewMode() {
  try {
    return localStorage.getItem('5stones-dfd-mode') === 'classic' ? 'classic' : 'improved';
  } catch (_) {
    return 'improved';
  }
}

function loadDiagramLevel() {
  try {
    const value = localStorage.getItem('5stones-dfd-level');
    return ['context', 'services', 'scenarios'].includes(value) ? value : 'context';
  } catch (_) {
    return 'context';
  }
}

function syncDiagramLevelUi() {
  document.querySelectorAll('[data-diagram-level]').forEach(button => {
    const active = button.dataset.diagramLevel === diagramLevel;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const shell = document.getElementById('diagram-canvas-shell');
  shell?.classList.toggle('is-service', diagramLevel === 'services');
  shell?.classList.toggle('is-scenario', diagramLevel === 'scenarios');
  const modeSwitch = document.querySelector('.diagram-mode-switch');
  if (modeSwitch) modeSwitch.hidden = diagramLevel !== 'context';
  const trustLegend = document.getElementById('diagram-trust-legend');
  if (trustLegend) trustLegend.style.display = diagramLevel === 'context' && diagramViewMode === 'classic' ? '' : 'none';
  const mobileMap = document.getElementById('diagram-mobile-map');
  if (mobileMap) mobileMap.classList.toggle('is-level-hidden', diagramLevel !== 'context');
  const title = document.querySelector('.diagram-toolbar-title');
  if (title) title.textContent = diagramLevel === 'context' ? 'Context Data Flow Diagram' : diagramLevel === 'services' ? 'Service-level Model' : 'Scenario Flows & API Operations';
  ['btn-diagram-fit', 'btn-diagram-export'].forEach(id => {
    const button = document.getElementById(id);
    if (button) button.hidden = diagramLevel === 'scenarios';
  });
  const subtitle = document.querySelector('.diagram-toolbar-sub');
  if (subtitle) {
    if (diagramLevel === 'services') {
      subtitle.textContent = 'Evidence readiness determines whether this is a logical service map, architecture candidate, or insufficient model';
    } else if (diagramLevel === 'scenarios') {
      subtitle.textContent = 'Business activities and API operations remain separate · Shapes preserve actor, action, decision, store, and external semantics';
    }
  }
}

function setupDiagramLevelSwitch() {
  syncDiagramLevelUi();
  document.querySelectorAll('[data-diagram-level]').forEach(button => {
    button.addEventListener('click', () => {
      const nextLevel = button.dataset.diagramLevel;
      if (!['context', 'services', 'scenarios'].includes(nextLevel) || nextLevel === diagramLevel) return;
      diagramLevel = nextLevel;
      try { localStorage.setItem('5stones-dfd-level', diagramLevel); } catch (_) {}
      document.getElementById('node-inspector').style.display = 'none';
      if (currentReport) {
        renderDiagram(currentReport);
        renderDiagramTextAlternative(currentReport);
      }
    });
  });
}

function syncDiagramModeUi() {
  document.querySelectorAll('[data-diagram-mode]').forEach(button => {
    const active = button.dataset.diagramMode === diagramViewMode;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const shell = document.getElementById('diagram-canvas-shell');
  shell?.classList.toggle('is-classic', diagramViewMode === 'classic');
  const trustLegend = document.getElementById('diagram-trust-legend');
  if (trustLegend) trustLegend.style.display = diagramViewMode === 'classic' ? '' : 'none';
  const subtitle = document.querySelector('.diagram-toolbar-sub');
  if (subtitle && diagramLevel === 'context') {
    subtitle.textContent = diagramViewMode === 'classic'
      ? 'Classic relationship view · Drag nodes · Scroll to zoom · Click node to inspect threats'
      : 'Trust zones flow left to right · Pan or swipe to explore · Click nodes or flows for details';
  }
}

function setupDiagramModeSwitch() {
  syncDiagramModeUi();
  document.querySelectorAll('[data-diagram-mode]').forEach(button => {
    button.addEventListener('click', () => {
      const nextMode = button.dataset.diagramMode;
      if (!['classic', 'improved'].includes(nextMode) || nextMode === diagramViewMode) return;
      diagramViewMode = nextMode;
      try {
        localStorage.setItem('5stones-dfd-mode', diagramViewMode);
      } catch (_) {
        // The mode switch remains usable when preference storage is unavailable.
      }
      syncDiagramModeUi();
      document.getElementById('node-inspector').style.display = 'none';
      if (currentReport) renderDiagram(currentReport);
      showToast(`${diagramViewMode === 'classic' ? 'Classic' : 'Improved'} DFD view enabled`, 'success');
    });
  });
}

// ── Project loading ────────────────────────────────────────────────────────────
async function loadProject() {
  try {
    const project = await API.projects.get(projectId);
    currentProject = project;
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
  updateArtifactSelection(null);
}

function formatArtifactBytes(bytes) {
  if (!Number.isFinite(bytes)) return 'unknown size';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function updateArtifactSelection(file) {
  const status = document.getElementById('artifact-file-selection');
  if (!status) return;
  status.classList.toggle('is-ready', Boolean(file));
  if (!file) {
    status.textContent = 'Choose a file to inspect before upload.';
    return;
  }
  const tooLarge = file.size > MAX_ARTIFACT_BYTES;
  status.textContent = tooLarge
    ? `${file.name} · ${formatArtifactBytes(file.size)} · exceeds the 5 MB limit`
    : `${file.name} · ${formatArtifactBytes(file.size)} · ready to parse`;
}

function setArtifactImportStatus(kind, html) {
  const result = document.getElementById('artifact-import-result');
  if (!result) return;
  result.className = `artifact-import-result is-visible is-${kind}`;
  result.innerHTML = html;
}

function renderArtifactImportResult(response, file) {
  const parsedStats = response.parsed?.stats || {};
  const inventory = response.reconciliation || {};
  const warnings = response.parsed?.warnings || [];
  const duplicate = Boolean(response.duplicate);
  const conflictCount = inventory.conflict_count || 0;
  const operationCount = parsedStats.operation_count ?? inventory.operation_count ?? 0;
  const scenarioCount = parsedStats.request_count ?? parsedStats.operation_count ?? 0;
  const businessScenarioCount = inventory.business_scenario_count ?? response.parsed?.use_cases?.length ?? 0;
  const statusKind = conflictCount || warnings.length ? 'warning' : 'success';
  setArtifactImportStatus(statusKind, `
    <div class="artifact-result-title">${duplicate ? 'Already included' : 'Context updated'} · ${escHtml(file.name)}</div>
    <div>${escHtml(response.message || (duplicate ? 'No duplicate context was added.' : 'The artifact was parsed and reconciled.'))}</div>
    <div class="artifact-result-metrics">
      <div class="artifact-result-metric"><strong>${operationCount}</strong><span>operations in this file</span></div>
      <div class="artifact-result-metric"><strong>${inventory.operation_count || operationCount}</strong><span>canonical operations total</span></div>
      <div class="artifact-result-metric"><strong>${inventory.overlap_count || 0}</strong><span>matched across sources</span></div>
      <div class="artifact-result-metric"><strong>${scenarioCount}</strong><span>request scenarios inspected</span></div>
      <div class="artifact-result-metric"><strong>${businessScenarioCount}</strong><span>evidence-backed business flows</span></div>
    </div>
    ${conflictCount ? `<div style="margin-top:8px;"><strong>${conflictCount} conflict${conflictCount === 1 ? '' : 's'}</strong> retained for review; no source was silently overwritten.</div>` : ''}
    ${warnings.length ? `<div style="margin-top:8px;">${warnings.map(warning => escHtml(warning)).join('<br>')}</div>` : ''}
  `);
}

function renderProjectContext(p) {
  const el = document.getElementById('project-context-list');
  if (!el) return;
  const score = p.completeness_score ?? p.completeness?.score ?? 0;
  const level = p.completeness_level || p.completeness?.level || 'Not scored';
  const completeness = p.completeness || {};
  const color = score >= 85 ? 'var(--green)' : score >= 65 ? 'var(--orange)' : 'var(--accent)';
  const inventory = p.artifact_inventory || {};
  const contextSummary = document.getElementById('context-header-summary');
  if (contextSummary) {
    const artifactCount = inventory.artifact_count ?? completeness.artifact_count ?? (p.artifacts || []).length;
    contextSummary.textContent = `${score}/100 · ${level} · ${artifactCount} artifact${artifactCount === 1 ? '' : 's'}`;
  }
  const operationCount = inventory.operation_count || (p.canonical_operations || []).length;
  const businessScenarioCount = inventory.business_scenario_count || (p.business_scenarios || []).length;
  const previewList = (values, limit = 5) => {
    const items = Array.isArray(values) ? values.filter(Boolean) : [];
    if (!items.length) return '—';
    const visible = items.slice(0, limit).join(', ');
    return items.length > limit ? `${visible} · +${items.length - limit} more` : visible;
  };
  const entryPointLabel = operationCount
    ? `${operationCount} canonical API operation${operationCount === 1 ? '' : 's'}`
    : businessScenarioCount
      ? `${businessScenarioCount} evidence-backed business scenario${businessScenarioCount === 1 ? '' : 's'}`
      : ((p.entry_points || []).join(', ') || '—');
  const items = [
    ['Environment', p.environment || '—'],
    ['Actors', previewList(p.actors)],
    ['Entry Points', entryPointLabel],
    ['Use Cases', businessScenarioCount ? `${businessScenarioCount} candidate business flow${businessScenarioCount === 1 ? '' : 's'}` : '—'],
    ['Data', previewList(p.data_involved)],
    ['Auth', p.auth_method || '—'],
    ['External', previewList(p.external_systems)],
    ['Artifacts', (inventory.artifact_count ?? (p.artifacts || []).length) + ' active'],
  ];
  const contextHtml = items.map(([label, val]) => `
    <div style="margin-bottom:6px;">
      <span style="color:var(--text-faint);font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;">${label}</span><br>
      <span>${escHtml(String(val))}</span>
    </div>`).join('');

  const blockers = (completeness.blockers || []).slice(0, 4);
  const artifactTypes = completeness.artifact_types || [];
  const inventoryHtml = (inventory.artifact_count || operationCount || businessScenarioCount) ? `
    <div class="artifact-inventory-summary">
      <strong>${operationCount} canonical operations · ${businessScenarioCount} business flows</strong><br>
      ${inventory.overlap_count || 0} matched across API sources · ${inventory.scenario_count || 0} request scenarios
      ${inventory.conflict_count ? ` · <strong>${inventory.conflict_count} conflict${inventory.conflict_count === 1 ? '' : 's'} to review</strong>` : ' · no source conflicts'}
      <div class="artifact-source-list">
        ${(p.artifact_sources || []).filter(source => source?.active !== false).map(source => `
          <div class="artifact-source-item">
            <span>${escHtml(source.filename || source.artifact_type || 'Artifact')}</span>
            <small>${escHtml(String(source.artifact_type || 'source').toUpperCase())} · ${source.stats?.operation_count || 0} operations</small>
          </div>`).join('')}
      </div>
    </div>` : '';
  el.innerHTML = `
    ${inventoryHtml}
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
        ${completeness.artifact_count || 0} artifact${completeness.artifact_count === 1 ? '' : 's'}${artifactTypes.length ? ` · ${artifactTypes.map(escHtml).join(', ')}` : ''}
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
    document.body.classList.add('analysis-has-report');
    renderResults(report);
    document.getElementById('btn-view-report').style.display = '';
  } catch {
    // No report yet — show empty state
    document.body.classList.remove('analysis-has-report');
  }
}

// ── Analysis pipeline ──────────────────────────────────────────────────────────
const originalLabels = {
  'as-trust': 'Mapping trust boundaries',
  'as-stride': 'Evaluating STRIDE threat scenarios',
  'as-linddun': 'Reviewing LINDDUN privacy risks',
  'as-controls': 'Mapping security controls',
  'as-tests': 'Preparing verification scenarios',
  'as-gaps': 'Checking evidence gaps and assumptions'
};

const stageProfiles = {
  'as-trust': {
    seconds: 50,
    shortLabel: 'Boundary mapping',
    note: 'Reviewing actors, entry points, data flows, and changes in trust level.'
  },
  'as-stride': {
    seconds: 95,
    shortLabel: 'STRIDE evaluation',
    note: 'Evaluating six STRIDE categories against the mapped attack surface.'
  },
  'as-linddun': {
    seconds: 75,
    shortLabel: 'Privacy review',
    note: 'Reviewing personal-data flows against the LINDDUN privacy categories.'
  },
  'as-controls': {
    seconds: 60,
    shortLabel: 'Control mapping',
    note: 'Matching identified risks to relevant controls and implementation guidance.'
  },
  'as-tests': {
    seconds: 75,
    shortLabel: 'Verification planning',
    note: 'Preparing actionable test scenarios from the current threat catalog.'
  },
  'as-gaps': {
    seconds: 45,
    shortLabel: 'Evidence review',
    note: 'Checking unresolved assumptions and evidence needed for human validation.'
  }
};

let analysisTimer = null;
let analysisStartedAt = 0;
let phaseStartedAt = 0;
let activeStageId = null;
let selectedStageIds = [];
let completedStageIds = new Set();

function loadStageDurations() {
  try {
    return JSON.parse(localStorage.getItem('5stones-stage-durations') || '{}');
  } catch (_) {
    return {};
  }
}

function expectedStageSeconds(stageId) {
  const history = loadStageDurations()[stageId];
  return history?.average || stageProfiles[stageId]?.seconds || 60;
}

function rememberStageDuration(stageId, seconds) {
  try {
    const history = loadStageDurations();
    const previous = history[stageId] || { average: seconds, samples: 0 };
    const samples = Math.min((previous.samples || 0) + 1, 8);
    const weight = 1 / samples;
    history[stageId] = {
      average: Math.round((previous.average * (1 - weight)) + (seconds * weight)),
      samples
    };
    localStorage.setItem('5stones-stage-durations', JSON.stringify(history));
  } catch (_) {
    // Timing history is optional; analysis must continue if storage is unavailable.
  }
}

function formatClock(totalSeconds) {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

function formatRemainingRange(seconds) {
  if (seconds < 25) return '< 1 min';
  const low = Math.max(1, Math.ceil((seconds * .75) / 60));
  const high = Math.max(low, Math.ceil((seconds * 1.35) / 60));
  return low === high ? `~${low} min` : `~${low}–${high} min`;
}

function userFacingAnalysisError(error) {
  const message = String(error || 'No response');
  if (/expecting value|structured json|structured data|jsondecode/i.test(message)) {
    return 'The selected analysis engine returned an unstructured response.';
  }
  if (/timed out|timeout/i.test(message)) {
    return 'The selected analysis engine did not respond within the configured time limit.';
  }
  if (/connection|connecterror|network/i.test(message)) {
    return 'The analysis engine could not be reached.';
  }
  return message;
}

function stageIdsForTypes(types) {
  const ids = [];
  if (types.includes('trust_boundary')) ids.push('as-trust');
  if (types.includes('stride')) ids.push('as-stride');
  if (types.includes('linddun')) ids.push('as-linddun');
  if (types.includes('controls')) ids.push('as-controls');
  if (types.includes('tests')) ids.push('as-tests');
  if (types.includes('missing_info') || types.includes('assumptions')) ids.push('as-gaps');
  return ids;
}

function updateAnalysisProgress() {
  if (!analysisStartedAt || !selectedStageIds.length) return;

  const now = performance.now();
  const totalElapsed = (now - analysisStartedAt) / 1000;
  const phaseElapsed = phaseStartedAt ? (now - phaseStartedAt) / 1000 : 0;
  const completedCount = completedStageIds.size;
  const currentIndex = activeStageId
    ? selectedStageIds.indexOf(activeStageId)
    : completedCount - 1;
  const expected = activeStageId ? expectedStageSeconds(activeStageId) : 60;
  const estimatedPhaseFraction = activeStageId
    ? Math.min(.88, 1 - Math.exp(-(phaseElapsed / expected) * 1.25))
    : 0;
  const percent = Math.min(99, Math.round(((completedCount + estimatedPhaseFraction) / selectedStageIds.length) * 100));

  let remaining = activeStageId
    ? Math.max(expected - phaseElapsed, expected * .22)
    : 0;
  for (let i = currentIndex + 1; i < selectedStageIds.length; i += 1) {
    remaining += expectedStageSeconds(selectedStageIds[i]);
  }

  const label = document.getElementById('analysis-progress-label');
  const percentEl = document.getElementById('analysis-progress-percent');
  const fill = document.getElementById('analysis-progress-fill');
  const track = document.getElementById('analysis-progress-track');
  const elapsedEl = document.getElementById('analysis-elapsed');
  const phaseElapsedEl = document.getElementById('phase-elapsed');
  const etaEl = document.getElementById('analysis-eta');
  const noteEl = document.getElementById('analysis-progress-note');

  if (label && activeStageId) {
    label.textContent = `Phase ${currentIndex + 1} of ${selectedStageIds.length} · ${stageProfiles[activeStageId].shortLabel}`;
  }
  if (percentEl) percentEl.textContent = `${percent}% est.`;
  if (fill) fill.style.width = `${percent}%`;
  if (track) {
    track.setAttribute('aria-valuenow', String(percent));
    track.setAttribute('aria-valuetext', `${completedCount} of ${selectedStageIds.length} phases confirmed complete`);
  }
  if (elapsedEl) elapsedEl.textContent = formatClock(totalElapsed);
  if (phaseElapsedEl) phaseElapsedEl.textContent = formatClock(phaseElapsed);
  if (etaEl) etaEl.textContent = formatRemainingRange(remaining);
  if (noteEl && activeStageId) {
    noteEl.textContent = phaseElapsed > expected * 1.25
      ? `This phase is taking longer than usual, but it is still running. ${stageProfiles[activeStageId].note}`
      : stageProfiles[activeStageId].note;
  }
}

function startAnalysisProgress(types) {
  if (analysisTimer) clearInterval(analysisTimer);
  selectedStageIds = stageIdsForTypes(types);
  completedStageIds = new Set();
  activeStageId = null;
  analysisStartedAt = performance.now();
  phaseStartedAt = 0;
  updateAnalysisProgress();
  analysisTimer = setInterval(updateAnalysisProgress, 1000);
}

function startStageProgress(stageId) {
  activeStageId = stageId;
  phaseStartedAt = performance.now();
  const title = document.querySelector('#analyzing-card h3');
  if (title) title.textContent = `${originalLabels[stageId]}…`;
  updateAnalysisProgress();
}

function completeStageProgress(stageId) {
  const seconds = stageId === activeStageId && phaseStartedAt
    ? Math.max(1, Math.round((performance.now() - phaseStartedAt) / 1000))
    : 0;
  if (seconds) rememberStageDuration(stageId, seconds);
  completedStageIds.add(stageId);
  activeStageId = null;
  phaseStartedAt = 0;
  updateAnalysisProgress();
  return seconds ? formatClock(seconds) : '';
}

function finishAnalysisProgress(message) {
  if (analysisTimer) clearInterval(analysisTimer);
  analysisTimer = null;
  const fill = document.getElementById('analysis-progress-fill');
  const track = document.getElementById('analysis-progress-track');
  const percentEl = document.getElementById('analysis-progress-percent');
  const label = document.getElementById('analysis-progress-label');
  const etaEl = document.getElementById('analysis-eta');
  if (fill) fill.style.width = '100%';
  if (track) track.setAttribute('aria-valuenow', '100');
  if (percentEl) percentEl.textContent = '100%';
  if (label) label.textContent = message;
  if (etaEl) etaEl.textContent = 'Complete';
}

async function runFullAnalysis() {
  await runAnalysis(fullAnalysisTypes());
}

function setRunControlsBusy(busy) {
  document.querySelectorAll('[data-analysis-run]').forEach(button => {
    if (busy) {
      if (!button.dataset.idleHtml) button.dataset.idleHtml = button.innerHTML;
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
      button.innerHTML = '<span class="loading-spinner" aria-hidden="true"></span><span>Running…</span>';
    } else {
      button.disabled = false;
      button.removeAttribute('aria-busy');
      if (button.dataset.idleHtml) button.innerHTML = button.dataset.idleHtml;
    }
  });
}

function setAnalysisRunning(running) {
  analysisIsRunning = running;
  document.body.classList.toggle('analysis-running', running);
  if (currentReport) document.body.classList.add('analysis-has-report');
  setRunControlsBusy(running);
}

async function runAnalysis(types) {
  if (analysisIsRunning) return;
  setAnalysisRunning(true);
  document.getElementById('empty-analysis-card').style.display = 'none';
  document.getElementById('results-tabs').style.display = 'none';
  document.getElementById('analyzing-card').style.display = '';
  document.getElementById('analyzing-actions').style.display = 'none';
  document.getElementById('analysis-stale-notice').style.display = 'none';
  requestAnimationFrame(() => {
    document.getElementById('analyzing-card')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
  });
  
  const titleEl = document.querySelector('#analyzing-card h3');
  if (titleEl) titleEl.textContent = 'Studying your system context…';
  startAnalysisProgress(types);

  const stepIds = ['as-trust', 'as-stride', 'as-linddun', 'as-controls', 'as-tests', 'as-gaps'];
  stepIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.className = 'analyzing-step-item';
      el.style.opacity = '';
      el.innerHTML = `
        <div class="step-dot"></div>
        <span>${originalLabels[id]}</span>
      `;
    }
  });

  const setActiveStep = (id) => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('done', 'skipped'); el.classList.add('active'); }
    startStageProgress(id);
  };

  const setStepDone = (id, aiStatus = { ok: true }) => {
    const el = document.getElementById(id);
    if (!el) return;
    const duration = completeStageProgress(id);

    if (aiStatus && aiStatus.ok === false) {
      el.className = 'analyzing-step-item error';
      el.innerHTML = `
        <div class="step-dot" style="background:#DC2626;box-shadow:none;"></div>
        <div style="flex:1;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);width:100%;">
            <span style="color:#DC2626;font-weight:500;">${originalLabels[id]}</span>
            ${duration ? `<span class="stage-duration">${duration}</span>` : ''}
            <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); retryStage('${id}')" style="color:#2563EB;padding:2px 8px;font-size:0.72rem;border:1px solid var(--border);border-radius:var(--r-sm);background:var(--surface);">
              ↻ Retry stage
            </button>
          </div>
          <div class="step-subtext" style="font-size:0.72rem;color:var(--orange);margin-top:2px;line-height:1.2;">
            Baseline framework results used. ${escHtml(userFacingAnalysisError(aiStatus.error))}
          </div>
        </div>
      `;
    } else {
      el.className = 'analyzing-step-item done';
      el.innerHTML = `
        <div class="step-dot" style="background:var(--green);box-shadow:none;"></div>
        <span style="color:var(--green);">${originalLabels[id]}</span>
        ${duration ? `<span class="stage-duration">${duration}</span>` : ''}
      `;
    }
  };

  const setStepSkipped = (id) => {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove('active', 'done');
      el.classList.add('skipped');
      el.style.opacity = '0.5';
      el.innerHTML = `
        <div class="step-dot" style="background:var(--border);box-shadow:none;"></div>
        <span style="color:var(--text-muted);">${originalLabels[id]} (skipped)</span>
      `;
    }
  };

  let anyFailed = false;

  // 1. Trust Boundaries
  if (types.includes('trust_boundary')) {
    setActiveStep('as-trust');
    try {
      await API.analysis.run(projectId, ['trust_boundary']);
      const report = await API.analysis.report(projectId);
      const aiStatus = report.ai_status?.trust_boundary || { ok: true };
      if (!aiStatus.ok) anyFailed = true;
      setStepDone('as-trust', aiStatus);
    } catch (err) {
      anyFailed = true;
      setStepDone('as-trust', { ok: false, error: err.message });
    }
  } else {
    setStepSkipped('as-trust');
  }

  // 2. STRIDE
  if (types.includes('stride')) {
    setActiveStep('as-stride');
    try {
      await API.analysis.run(projectId, ['stride']);
      const report = await API.analysis.report(projectId);
      const aiStatus = report.ai_status?.stride || { ok: true };
      if (!aiStatus.ok) anyFailed = true;
      setStepDone('as-stride', aiStatus);
    } catch (err) {
      anyFailed = true;
      setStepDone('as-stride', { ok: false, error: err.message });
    }
  } else {
    setStepSkipped('as-stride');
  }

  // 3. LINDDUN
  if (types.includes('linddun')) {
    setActiveStep('as-linddun');
    try {
      await API.analysis.run(projectId, ['linddun']);
      const report = await API.analysis.report(projectId);
      const aiStatus = report.ai_status?.linddun || {
        ok: false,
        error: 'The privacy review completed without a stage status. Please retry this phase.'
      };
      if (!aiStatus.ok) anyFailed = true;
      setStepDone('as-linddun', aiStatus);
    } catch (err) {
      anyFailed = true;
      setStepDone('as-linddun', { ok: false, error: err.message });
    }
  } else {
    setStepSkipped('as-linddun');
  }

  // 4. Controls
  if (types.includes('controls')) {
    setActiveStep('as-controls');
    try {
      await API.analysis.run(projectId, ['controls']);
      const report = await API.analysis.report(projectId);
      const aiStatus = report.ai_status?.controls || { ok: true };
      if (!aiStatus.ok) anyFailed = true;
      setStepDone('as-controls', aiStatus);
    } catch (err) {
      anyFailed = true;
      setStepDone('as-controls', { ok: false, error: err.message });
    }
  } else {
    setStepSkipped('as-controls');
  }

  // 5. Test Scenarios
  if (types.includes('tests')) {
    setActiveStep('as-tests');
    try {
      await API.analysis.run(projectId, ['tests']);
      const report = await API.analysis.report(projectId);
      const aiStatus = report.ai_status?.tests || { ok: true };
      if (!aiStatus.ok) anyFailed = true;
      setStepDone('as-tests', aiStatus);
    } catch (err) {
      anyFailed = true;
      setStepDone('as-tests', { ok: false, error: err.message });
    }
  } else {
    setStepSkipped('as-tests');
  }

  // 6. Gaps (missing info + assumptions)
  const gapTypes = [];
  if (types.includes('missing_info')) gapTypes.push('missing_info');
  if (types.includes('assumptions')) gapTypes.push('assumptions');

  if (gapTypes.length > 0) {
    setActiveStep('as-gaps');
    try {
      await API.analysis.run(projectId, gapTypes);
      const report = await API.analysis.report(projectId);
      const aiStatus = report.ai_status?.missing_info || { ok: true };
      if (!aiStatus.ok) anyFailed = true;
      setStepDone('as-gaps', aiStatus);
    } catch (err) {
      anyFailed = true;
      setStepDone('as-gaps', { ok: false, error: err.message });
    }
  } else {
    setStepSkipped('as-gaps');
  }

  try {
    const report = await API.analysis.report(projectId);
    currentReport = report;

    if (anyFailed) {
      finishAnalysisProgress('Review ready · baseline results used');
      if (titleEl) titleEl.textContent = 'Analysis prepared with baseline results';
      document.getElementById('analyzing-actions').style.display = 'block';
      document.body.classList.add('analysis-has-report');
      pendingArtifactAnalysisTypes = [];
      setAnalysisRunning(false);
      showToast('Some stages used baseline framework results and still require review.', 'warn');
    } else {
      finishAnalysisProgress('All phases complete');
      document.getElementById('analyzing-card').style.display = 'none';
      document.body.classList.add('analysis-has-report');
      pendingArtifactAnalysisTypes = [];
      setAnalysisRunning(false);
      renderResults(report);
      restoreAnalysisTab();
      document.getElementById('btn-view-report').style.display = '';
      showToast(`Analysis complete — ${report.risk_summary?.total || 0} threats identified`, 'success');
    }
  } catch (err) {
    if (analysisTimer) clearInterval(analysisTimer);
    document.getElementById('analyzing-card').style.display = 'none';
    if (currentReport) renderResults(currentReport);
    else document.getElementById('empty-analysis-card').style.display = '';
    setAnalysisRunning(false);
    if (pendingArtifactAnalysisTypes.length && currentReport) {
      document.getElementById('analysis-stale-notice').style.display = 'flex';
    }
    showToast('Analysis failed to load report: ' + err.message, 'error');
  }
}

window.retryStage = async function(stepId) {
  const stepToTypes = {
    'as-trust': ['trust_boundary'],
    'as-stride': ['stride'],
    'as-linddun': ['linddun'],
    'as-controls': ['controls'],
    'as-tests': ['tests'],
    'as-gaps': ['missing_info', 'assumptions']
  };

  const types = stepToTypes[stepId];
  if (!types) return;

  const el = document.getElementById(stepId);
  if (el) {
    el.className = 'analyzing-step-item active';
    el.innerHTML = `
      <div class="step-dot"></div>
      <span style="font-weight:500;">${originalLabels[stepId]} (Retrying…)</span>
    `;
  }

  try {
    await API.analysis.run(projectId, types);
    const report = await API.analysis.report(projectId);
    currentReport = report;

    const statusMap = {
      'as-trust': 'trust_boundary',
      'as-stride': 'stride',
      'as-linddun': 'linddun',
      'as-controls': 'controls',
      'as-tests': 'tests',
      'as-gaps': 'missing_info'
    };
    const key = statusMap[stepId];
    const aiStatus = report.ai_status?.[key] || { ok: true };

    const originalSetStepDone = (id, aiStat) => {
      const targetEl = document.getElementById(id);
      if (!targetEl) return;
      if (aiStat && aiStat.ok === false) {
        targetEl.className = 'analyzing-step-item error';
        targetEl.innerHTML = `
          <div class="step-dot" style="background:#DC2626;box-shadow:none;"></div>
          <div style="flex:1;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);width:100%;">
              <span style="color:#DC2626;font-weight:500;">${originalLabels[id]}</span>
              <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); retryStage('${id}')" style="color:#2563EB;padding:2px 8px;font-size:0.72rem;border:1px solid var(--border);border-radius:var(--r-sm);background:var(--surface);">
                ↻ Retry stage
              </button>
            </div>
            <div class="step-subtext" style="font-size:0.72rem;color:var(--orange);margin-top:2px;line-height:1.2;">
              Baseline framework results used. ${escHtml(userFacingAnalysisError(aiStat.error))}
            </div>
          </div>
        `;
      } else {
        targetEl.className = 'analyzing-step-item done';
        targetEl.innerHTML = `
          <div class="step-dot" style="background:var(--green);box-shadow:none;"></div>
          <span style="color:var(--green);">${originalLabels[id]}</span>
        `;
      }
    };

    originalSetStepDone(stepId, aiStatus);
    renderResults(report);

    if (aiStatus.ok) {
      showToast('Stage evaluation completed successfully.', 'success');
      
      // Auto-proceed if all active/non-skipped steps are now green/done
      const anyRemainingFailed = Object.keys(statusMap).some(sid => {
        const k = statusMap[sid];
        const itemEl = document.getElementById(sid);
        if (!itemEl || itemEl.classList.contains('skipped')) return false;
        return report.ai_status?.[k]?.ok === false;
      });
      if (!anyRemainingFailed) {
        document.getElementById('analyzing-card').style.display = 'none';
        document.getElementById('btn-view-report').style.display = '';
      }
    } else {
      showToast('Stage evaluation could not complete; baseline results remain available.', 'warn');
    }
  } catch (err) {
    showToast('Stage evaluation failed: ' + err.message, 'error');
    // Restore error state
    const originalSetStepDone = (id, aiStat) => {
      const targetEl = document.getElementById(id);
      if (!targetEl) return;
      targetEl.className = 'analyzing-step-item error';
      targetEl.innerHTML = `
        <div class="step-dot" style="background:#DC2626;box-shadow:none;"></div>
        <div style="flex:1;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);width:100%;">
            <span style="color:#DC2626;font-weight:500;">${originalLabels[id]}</span>
            <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); retryStage('${id}')" style="color:#2563EB;padding:2px 8px;font-size:0.72rem;border:1px solid var(--border);border-radius:var(--r-sm);background:var(--surface);">
              ↻ Retry stage
            </button>
          </div>
          <div class="step-subtext" style="font-size:0.72rem;color:var(--orange);margin-top:2px;line-height:1.2;">
            Baseline framework results used. ${escHtml(userFacingAnalysisError(err.message))}
          </div>
        </div>
      `;
    };
    originalSetStepDone(stepId, { ok: false, error: err.message });
  }
};

// ── Result rendering ───────────────────────────────────────────────────────────
function renderResults(report) {
  currentReport = report;
  document.body.classList.add('analysis-has-report');
  document.getElementById('empty-analysis-card').style.display = 'none';
  document.getElementById('results-tabs').style.display = '';

  const visibility = analysisVisibility(report);
  const threats = visibility.threats;
  const stride = threats.filter(t => t.framework === 'STRIDE');
  const linddun = threats.filter(t => t.framework === 'LINDDUN');
  const completeness = report.completeness || {};

  document.getElementById('count-trust').textContent = activeTrustBoundaries(report).length;
  document.getElementById('count-stride').textContent = stride.length;
  document.getElementById('count-linddun').textContent = linddun.length;
  document.getElementById('count-controls').textContent = visibility.controls.length;
  document.getElementById('count-tests').textContent = visibility.tests.length;
  document.getElementById('count-gaps').textContent = visibility.missingInfo.length + visibility.assumptions.length;
  const visibleNeedsReview = threats.filter(item => ['Open', 'Needs Info', 'Needs Review'].includes(item.status || 'Open')).length;
  document.getElementById('stride-summary').textContent = `STRIDE threats — ${stride.length} visible · readiness ${completeness.score || 0}/100 · ${visibleNeedsReview} need review`;
  document.getElementById('tests-summary').textContent = `Security test backlog — ${visibility.tests.length} scenarios mapped to visible threats`;
  updateAnalysisTabOptions(report, stride.length, linddun.length, visibility);
  renderAnalysisOverview(report, visibility);

  renderTrustBoundaries(report.trust_boundaries || []);
  renderDiagram(report);                                // ← interactive diagram
  renderDiagramTextAlternative(report);
  renderThreats('stride-threats-list', 'st', stride);  // ← unique prefix 'st'
  renderThreats('linddun-threats-list', 'ln', linddun);// ← unique prefix 'ln'
  renderControls(visibility.controls);
  renderTests(visibility.tests);
  renderGaps(visibility.missingInfo, visibility.assumptions);
  syncAnalysisStaleness(report);

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
      const filtered = e.target.value ? visibility.tests.filter(t => t.priority === e.target.value) : visibility.tests;
      renderTests(filtered);
    };
  }
  requestAnimationFrame(updateTabScrollControls);
}

function updateAnalysisTabOptions(report, strideCount, linddunCount, visibility = analysisVisibility(report)) {
  const counts = {
    diagram: '',
    'trust-boundaries': (report.trust_boundaries || []).length,
    stride: strideCount,
    linddun: linddunCount,
    controls: visibility.controls.length,
    tests: visibility.tests.length,
    gaps: visibility.missingInfo.length + visibility.assumptions.length,
  };
  const labels = {
    diagram: 'Diagram',
    'trust-boundaries': 'Trust Boundaries',
    stride: 'STRIDE',
    linddun: 'LINDDUN',
    controls: 'Controls',
    tests: 'Tests',
    gaps: 'Gaps & Assumptions',
  };
  const select = document.getElementById('analysis-tab-select');
  Object.entries(labels).forEach(([value, label]) => {
    const option = select?.querySelector(`option[value="${value}"]`);
    if (option) option.textContent = counts[value] === '' ? label : `${label} (${counts[value]})`;
  });
}

function renderAnalysisOverview(report, visibility = analysisVisibility(report)) {
  const threats = visibility.threats;
  const critical = threats.filter(item => item.risk_level === 'Critical').length;
  const high = threats.filter(item => item.risk_level === 'High').length;
  const statusReviewCount = threats.filter(item => ['Open', 'Needs Info', 'Needs Review'].includes(item.status || 'Open')).length;
  const boundaryCandidates = (report.trust_boundaries || []).filter(item => item.status === 'Candidate').length;
  const threatNeedsReview = threats.some(item => item.status) ? statusReviewCount : (report.risk_summary?.needs_review ?? statusReviewCount);
  const needsReview = threatNeedsReview + boundaryCandidates;
  const gaps = visibility.missingInfo.length + visibility.assumptions.length;
  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = String(value); };
  setText('overview-critical', critical);
  setText('overview-high', high);
  setText('overview-review', needsReview);
  setText('overview-gaps', gaps);

  const guidance = document.getElementById('analysis-overview-guidance');
  const primary = document.getElementById('overview-primary-action');
  let action = 'gaps';
  let label = 'Review evidence gaps';
  if (visibility.allRejected) {
    action = 'boundaries';
    label = 'Review rejected boundary';
    if (guidance) guidance.textContent = 'Dependent findings are safely retained but hidden while every grounded boundary is rejected.';
  } else if (boundaryCandidates) {
    action = 'boundaries';
    label = `Review ${boundaryCandidates} boundary candidate${boundaryCandidates === 1 ? '' : 's'}`;
    if (guidance) guidance.textContent = 'Confirm or reject grounded boundary candidates before relying on downstream threat results.';
  } else if (critical) {
    action = 'critical';
    label = `Review ${critical} critical threat${critical === 1 ? '' : 's'}`;
    if (guidance) guidance.textContent = 'Critical findings need an explicit review before controls and test coverage are finalized.';
  } else if (high) {
    action = 'high';
    label = `Review ${high} high-risk threat${high === 1 ? '' : 's'}`;
    if (guidance) guidance.textContent = 'No critical findings remain. Continue with high-risk threats and validate mapped controls.';
  } else if (needsReview) {
    action = 'review';
    label = `Resolve ${needsReview} review item${needsReview === 1 ? '' : 's'}`;
    if (guidance) guidance.textContent = 'Resolve pending review decisions, then verify controls and test scenarios.';
  } else if (gaps) {
    if (guidance) guidance.textContent = 'Threat review is clear. Close remaining evidence gaps to improve confidence.';
  } else {
    action = 'controls';
    label = 'Review mapped controls';
    if (guidance) guidance.textContent = 'Threat review is clear. Continue with controls, tests, and report validation.';
  }
  if (primary) {
    primary.dataset.overviewAction = action;
    primary.textContent = label;
  }
}

function syncAnalysisStaleness(report) {
  const notice = document.getElementById('analysis-stale-notice');
  const message = document.getElementById('analysis-stale-message');
  const stale = report?.analysis_stale;
  const stages = Array.isArray(stale?.stages) ? stale.stages : [];
  pendingArtifactAnalysisTypes = stages;
  if (!notice) return;
  if (!stages.length) {
    notice.style.display = 'none';
    return;
  }
  if (message) {
    message.textContent = `${stale.reason || 'Analysis inputs changed.'} Pending: ${stages.join(', ')}.`;
  }
  notice.style.display = 'flex';
}

function switchTab(tabId, { persist = true, focus = false } = {}) {
  if (!VALID_ANALYSIS_TABS.includes(tabId)) return;
  document.querySelectorAll('.tab-btn').forEach(button => {
    const active = button.dataset.tab === tabId;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    const active = panel.id === `tab-${tabId}`;
    panel.classList.toggle('active', active);
    panel.hidden = !active;
  });
  const activeButton = document.querySelector(`.tab-btn[data-tab="${tabId}"]`);
  if (focus) activeButton?.focus();
  activeButton?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'nearest', inline: 'center' });
  const select = document.getElementById('analysis-tab-select');
  if (select) select.value = tabId;
  if (persist) {
    try { localStorage.setItem(`5stones-analysis-tab:${projectId}`, tabId); } catch (_) {}
    history.replaceState(null, '', `${location.pathname}${location.search}#analysis-${tabId}`);
  }

  // Re-fit diagram when switching to diagram tab
  if (tabId === 'diagram' && diagramNetwork) {
    setTimeout(() => diagramNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } }), 100);
  }
  requestAnimationFrame(updateTabScrollControls);
}

// ── Trust Boundaries list ─────────────────────────────────────────────────────
function activeTrustBoundaries(report = currentReport) {
  return (report?.trust_boundaries || []).filter(item => item.status !== 'Rejected');
}

function activeDiagramFlows(report = currentReport) {
  const boundaries = report?.trust_boundaries || [];
  const activeFlowIds = new Set(activeTrustBoundaries(report).flatMap(item => item.crossing_flow_ids || []));
  const rejectedFlowIds = new Set(
    boundaries.filter(item => item.status === 'Rejected').flatMap(item => item.crossing_flow_ids || [])
  );
  const flows = report?.trust_model
    ? (report.data_flows || [])
    : (currentProject?.extracted_data_flows || report?.data_flows || []);
  return flows.filter(flow => !rejectedFlowIds.has(flow.flow_id) || activeFlowIds.has(flow.flow_id));
}

function formatReviewTimestamp(value) {
  if (!value) return '';
  const normalized = /(?:Z|[+-]\d\d:\d\d)$/.test(String(value)) ? String(value) : `${value}Z`;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

function renderTrustBoundaries(boundaries) {
  const el = document.getElementById('trust-boundaries-list');
  const groundingWarnings = currentReport?.trust_model?.warnings || [];
  if (!boundaries.length) {
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><h3>No grounded trust boundaries</h3><p>Confirm an actor, ingress point, and cross-zone data flow before treating a relationship as a boundary.</p>${groundingWarnings.length ? `<div class="trust-grounding-notes">${groundingWarnings.map(item => `<div>${escHtml(item)}</div>`).join('')}</div>` : ''}</div>`;
    return;
  }
  const statusCounts = {
    Candidate: boundaries.filter(item => item.status === 'Candidate').length,
    Confirmed: boundaries.filter(item => item.status === 'Confirmed').length,
    Rejected: boundaries.filter(item => item.status === 'Rejected').length,
  };
  const hidden = analysisVisibility(currentReport).hidden;
  const hiddenTotal = hidden.threats + hidden.controls + hidden.tests + hidden.missingInfo + hidden.assumptions;
  const statusClass = status => status === 'Confirmed' ? 'badge-low' : status === 'Rejected' ? 'badge-high' : 'badge-medium';
  el.innerHTML = `
    <div style="margin-bottom:var(--space-4);">
      <div class="trust-review-summary" aria-label="Trust boundary review summary">
        <span><strong>${statusCounts.Candidate}</strong> pending review</span>
        <span><strong>${statusCounts.Confirmed}</strong> confirmed</span>
        <span><strong>${statusCounts.Rejected}</strong> rejected</span>
      </div>
      ${hiddenTotal ? `<div class="trust-visibility-note"><strong>${hiddenTotal} dependent items hidden</strong><span>${hidden.threats} threats · ${hidden.controls} controls · ${hidden.tests} tests · ${hidden.missingInfo + hidden.assumptions} review notes. Restore a rejected boundary to show them again.</span></div>` : ''}
      <p class="text-sm text-muted">Only grounded relationships are proposed. Confirmed and pending candidates remain eligible for analysis; rejected relationships are excluded from the DFD and downstream modeling.</p>
      ${groundingWarnings.length ? `<div class="trust-grounding-notes"><strong>Grounding notes</strong>${groundingWarnings.map(item => `<div>${escHtml(item)}</div>`).join('')}</div>` : ''}
    </div>
    <div style="display:flex;flex-direction:column;gap:var(--space-3);">
      ${boundaries.map(b => `
        <div class="trust-boundary-review-card ${b.status === 'Rejected' ? 'is-rejected' : ''}" data-boundary-id="${escHtml(b.boundary_id || '')}">
          <div style="display:flex;align-items:center;gap:var(--space-4);padding:var(--space-4) var(--space-5);">
            <div style="flex:1;">
              <div style="display:flex;align-items:center;gap:var(--space-3);margin-bottom:var(--space-2);">
                <div style="font-weight:600;font-size:0.875rem;">${escHtml(b.source)}</div>
                <span style="color:var(--text-faint);font-size:0.8rem;">→</span>
                <div style="font-weight:600;font-size:0.875rem;">${escHtml(b.destination)}</div>
                <span class="tb-boundary-label">${escHtml(b.boundary_label)}</span>
                <span class="badge ${statusClass(b.status)}">${escHtml(b.status || 'Candidate')}</span>
                ${b.review_stale ? '<span class="badge badge-high">Review expired</span>' : ''}
              </div>
              <div style="display:flex;gap:var(--space-3);font-size:0.78rem;color:var(--text-muted);">
                <span>${escHtml(b.source_trust_level || '')} → ${escHtml(b.destination_trust_level || '')}</span>
                <span>${escHtml(b.confidence || 'Low')} confidence</span>
              </div>
              ${b.risk_note ? `<div style="font-size:0.78rem;color:var(--text-muted);margin-top:var(--space-1);">${escHtml(b.risk_note)}</div>` : ''}
              ${b.basis ? `<div class="trust-boundary-basis"><strong>Basis:</strong> ${escHtml(b.basis)}</div>` : ''}
              ${(b.evidence_refs || []).length ? `<details class="trust-boundary-evidence"><summary>${b.evidence_refs.length} supporting reference${b.evidence_refs.length === 1 ? '' : 's'}</summary><ul>${b.evidence_refs.map(ref => `<li>${escHtml(ref)}</li>`).join('')}</ul></details>` : ''}
              <div class="trust-boundary-review-controls">
                <label for="boundary-note-${escHtml(b.boundary_id || '')}">Reviewer note <span>(optional)</span></label>
                <textarea id="boundary-note-${escHtml(b.boundary_id || '')}" class="form-input" rows="2" maxlength="1000" placeholder="Record who validated this relationship or why it was rejected.">${escHtml(b.review_note || '')}</textarea>
                <div class="trust-boundary-review-actions">
                  ${b.status !== 'Confirmed' ? `<button type="button" class="btn btn-primary btn-sm" data-boundary-review="Confirmed">Confirm boundary</button>` : ''}
                  ${b.status !== 'Rejected' ? `<button type="button" class="btn btn-secondary btn-sm" data-boundary-review="Rejected">Reject</button>` : ''}
                  ${b.status !== 'Candidate' ? `<button type="button" class="btn btn-ghost btn-sm" data-boundary-review="Candidate">Reset to candidate</button>` : ''}
                  ${b.reviewed_at ? `<span class="trust-boundary-reviewed-at">Reviewed ${escHtml(formatReviewTimestamp(b.reviewed_at))}</span>` : ''}
                </div>
              </div>
            </div>
          </div>
        </div>
      `).join('')}
    </div>`;
  el.querySelectorAll('[data-boundary-review]').forEach(button => {
    button.addEventListener('click', () => updateTrustBoundaryReview(
      button.closest('[data-boundary-id]')?.dataset.boundaryId,
      button.dataset.boundaryReview,
    ));
  });
}

async function updateTrustBoundaryReview(boundaryId, status) {
  if (!boundaryId || !['Candidate', 'Confirmed', 'Rejected'].includes(status)) return;
  const card = document.querySelector(`[data-boundary-id="${boundaryId}"]`);
  const reviewNote = card?.querySelector('textarea')?.value.trim() || '';
  card?.querySelectorAll('button').forEach(button => { button.disabled = true; });
  try {
    await API.analysis.updateTrustBoundary(projectId, boundaryId, { status, review_note: reviewNote });
    const report = await API.analysis.report(projectId);
    currentReport = report;
    renderResults(report);
    switchTab('trust-boundaries', { focus: false });
    showToast(`Trust boundary marked ${status.toLowerCase()}.`, status === 'Rejected' ? 'warn' : 'success');
  } catch (err) {
    card?.querySelectorAll('button').forEach(button => { button.disabled = false; });
    showToast('Could not update trust boundary: ' + err.message, 'error');
  }
}

// ── INTERACTIVE DIAGRAM (vis-network) ─────────────────────────────────────────
const TRUST_COLORS = {
  'untrusted':        { bg: '#FEF2F4', border: '#DC2626', font: '#DC2626' },
  'low trust':        { bg: '#FEF2F4', border: '#DC2626', font: '#DC2626' },
  'external':         { bg: '#FFF7ED', border: '#D97706', font: '#D97706' },
  'external dependency': { bg: '#FFF7ED', border: '#D97706', font: '#D97706' },
  'low':              { bg: '#FFF7ED', border: '#D97706', font: '#D97706' },
  'internal':         { bg: '#EFF6FF', border: '#2563EB', font: '#2563EB' },
  'internal trusted': { bg: '#EFF6FF', border: '#2563EB', font: '#2563EB' },
  'privileged':       { bg: '#F0FDF4', border: '#15803D', font: '#15803D' },
  'privileged external': { bg: '#F0FDF4', border: '#15803D', font: '#15803D' },
  'highly privileged':{ bg: '#F0FDF4', border: '#15803D', font: '#15803D' },
  'sensitive':        { bg: '#F5F3FF', border: '#6D28D9', font: '#6D28D9' },
  'sensitive internal store': { bg: '#F5F3FF', border: '#6D28D9', font: '#6D28D9' },
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
  syncDiagramModeUi();
  syncDiagramLevelUi();
  renderDiagramMappingSummary(report);
  if (diagramLevel === 'services') {
    renderServiceDiagram(report);
  } else if (diagramLevel === 'scenarios') {
    renderScenarioExplorer(report);
  } else if (diagramViewMode === 'classic') {
    renderClassicDiagram(report);
  } else {
    renderImprovedDiagram(report);
  }
}

function modelViews(report) {
  return report?.trust_model?.views || {};
}

function targetRefs(item, type = null, modelLevel = null) {
  return (item?.target_refs || []).filter(ref =>
    ref && (!type || ref.type === type) && (!modelLevel || ref.model_level === modelLevel)
  );
}

function targetMatches(item, ids, types = null) {
  const idSet = ids instanceof Set ? ids : new Set([ids].flat().filter(Boolean).map(String));
  const typeSet = types ? new Set([types].flat()) : null;
  return targetRefs(item).some(ref => idSet.has(String(ref.id)) && (!typeSet || typeSet.has(ref.type)));
}

function uniqueThreats(items) {
  const seen = new Set();
  return (items || []).filter((item, index) => {
    const key = item?.threat_id || `${item?.framework || ''}:${item?.threat_category || ''}:${index}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderDiagramMappingSummary(report) {
  const el = document.getElementById('diagram-mapping-summary');
  if (!el) return;
  const threats = analysisVisibility(report).threats;
  const mapped = threats.filter(item => item.mapping_status === 'mapped' || targetRefs(item).length);
  const unmapped = threats.filter(item => item.mapping_status === 'unmapped' || !targetRefs(item).length);
  const typeByLevel = {
    context: ['external_entity', 'external_system', 'process', 'data_store', 'data_flow', 'trust_boundary'],
    services: ['process', 'data_store', 'external_system'],
    scenarios: ['scenario'],
  };
  const levelMapped = threats.filter(item => targetRefs(item).some(ref =>
    typeByLevel[diagramLevel].includes(ref.type) &&
    (diagramLevel === 'context' ? ref.model_level === 'context' : ref.model_level === diagramLevel.slice(0, -1))
  ));
  el.innerHTML = `
    <span class="diagram-mapping-label">Finding coverage</span>
    <span class="diagram-mapping-chip"><strong>${levelMapped.length}</strong> on this level</span>
    <span class="diagram-mapping-chip"><strong>${mapped.length}</strong> mapped overall</span>
    <span class="diagram-mapping-chip ${unmapped.length ? 'is-warning' : 'is-complete'}"><strong>${unmapped.length}</strong> unmapped</span>
    <span class="diagram-mapping-help">Counts are unique findings; one finding may target more than one model element.</span>`;
}

function renderDiagramTextAlternative(report) {
  const content = document.getElementById('diagram-text-content');
  const canvas = document.getElementById('threat-diagram-canvas');
  if (!content) return;
  const views = modelViews(report);
  const threats = analysisVisibility(report).threats;
  if (diagramLevel === 'services') {
    const nodes = views.services?.nodes || [];
    const items = nodes.map(node => {
      const count = threats.filter(item => targetMatches(item, node.element_id, node.element_type || 'process')).length;
      return `<li><strong>${escHtml(node.label)}</strong> — ${node.operation_count || 0} operation${node.operation_count === 1 ? '' : 's'}, ${count} mapped finding${count === 1 ? '' : 's'}${node.topology_status === 'logical' ? ' (logical group)' : ''}</li>`;
    }).join('');
    content.innerHTML = `<p>${nodes.length} service-level elements derived from canonical operations. Logical groups do not assert a deployment boundary.</p><ul>${items || '<li>No service elements are available.</li>'}</ul>`;
    if (canvas) canvas.setAttribute('aria-label', `Service model with ${nodes.length} elements`);
    return;
  }
  if (diagramLevel === 'scenarios') {
    const business = views.scenarios?.business_items || [];
    const operations = views.scenarios?.operation_items || (views.scenarios?.items || []).filter(item => item.scenario_kind !== 'business_flow');
    const businessItems = business.map(item => {
      const count = threats.filter(threat => targetMatches(threat, item.element_id, 'scenario')).length;
      return `<li><strong>${escHtml(item.label)}</strong> — actor ${escHtml(item.actor)}, ${(item.steps || []).length - 1} activities, ${count} direct finding${count === 1 ? '' : 's'}</li>`;
    }).join('');
    const operationItems = operations.map(item => {
      const count = threats.filter(threat => targetMatches(threat, item.element_id, 'scenario')).length;
      return `<li><strong>${escHtml(item.method)} ${escHtml(item.path)}</strong> — ${escHtml(item.service)}, ${count} direct finding${count === 1 ? '' : 's'}</li>`;
    }).join('');
    content.innerHTML = `<p>${business.length} business flows and ${operations.length} canonical API operations are available.</p><h3>Business flows</h3><ul>${businessItems || '<li>No evidence-backed business flows are available.</li>'}</ul><h3>API operations</h3><ul>${operationItems || '<li>No canonical operations are available.</li>'}</ul>`;
    if (canvas) canvas.setAttribute('aria-label', `Scenario model with ${business.length} business flows and ${operations.length} API operations`);
    return;
  }
  const boundaries = activeTrustBoundaries(report);
  const flows = activeDiagramFlows(report);
  const nodes = new Set();
  boundaries.forEach(item => { if (item.source) nodes.add(item.source); if (item.destination) nodes.add(item.destination); });
  flows.forEach(item => { if (item.source) nodes.add(item.source); if (item.destination) nodes.add(item.destination); });
  const nodeItems = [...nodes].map(node => {
    const contextNode = (views.context?.nodes || []).find(item => item.label === node);
    const count = threats.filter(item => contextNode
      ? targetMatches(item, contextNode.element_id, ['process', 'external_entity'])
      : String(item.component || item.asset || '').toLowerCase().includes(String(node).toLowerCase())).length;
    return `<li><strong>${escHtml(node)}</strong> — ${count} mapped threat${count === 1 ? '' : 's'}</li>`;
  }).join('');
  const flowItems = (flows.length ? flows : boundaries).map(item => {
    const data = Array.isArray(item.data) ? item.data.join(', ') : (item.data || item.boundary_label || 'interaction');
    return `<li>${escHtml(item.source || 'Unknown source')} → ${escHtml(item.destination || 'Unknown destination')}: ${escHtml(data)}</li>`;
  }).join('');
  content.innerHTML = `
    <p>${nodes.size} components and ${(flows.length || boundaries.length)} flows are represented in the diagram.</p>
    <h3>Components</h3>
    <ul>${nodeItems || '<li>No components are available.</li>'}</ul>
    <h3>Data flows</h3>
    <ul>${flowItems || '<li>No data flows are available.</li>'}</ul>`;
  if (canvas) canvas.setAttribute('aria-label', `Interactive data flow diagram with ${nodes.size} components and ${threats.length} mapped threats`);
}

const ENHANCED_TRUST_ZONES = [
  { key: 'untrusted', label: 'Untrusted', level: 0 },
  { key: 'external', label: 'External dependency', level: 1 },
  { key: 'internal', label: 'Internal application', level: 2 },
  { key: 'privileged', label: 'Privileged / sensitive', level: 3 },
];

function normalizeEnhancedTrustLevel(value, label = '') {
  const trust = `${value || ''} ${label || ''}`.toLowerCase();
  if (/sensitive|database|data store|storage|privileged|admin/.test(trust)) return 'privileged';
  if (/untrusted|low trust|public internet|anonymous|\buser\b|\bcustomer\b|\bactor\b|\bclient\b/.test(trust)) return 'untrusted';
  if (/external|third.?party|dependency|vendor/.test(trust)) return 'external';
  if (/internal|trusted|frontend|backend|ci\/cd/.test(trust)) return 'internal';
  return 'internal';
}

function canonicalNodeLabel(value) {
  const label = String(value || '').replace(/\s+/g, ' ').trim();
  if (/^backend api\b/i.test(label)) return 'Backend API';
  if (/^(react|web) frontend\b/i.test(label)) return 'Web Frontend';
  if (/vllm|ai\/ml service/i.test(label)) return 'VLLM Service';
  if (/postgres|postgis|database/i.test(label)) return 'PostgreSQL / PostGIS';
  if (/planet data api/i.test(label)) return 'Planet Data API';
  if (/external developer/i.test(label)) return 'External Developer';
  if (/github actions/i.test(label)) return 'GitHub Actions CI/CD';
  return label || 'Unknown component';
}

function compactFlowText(value, maxLength = 42) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 1).trim()}…` : text;
}

function inferredFlowDescription(source, destination) {
  const pair = `${source} ${destination}`.toLowerCase();
  if (pair.includes('admin')) return 'Administrative access';
  if (pair.includes('github actions')) return 'Deployment changes';
  if (pair.includes('developer')) return 'Development pipeline';
  if (pair.includes('user')) return 'User interaction';
  return 'Service interaction';
}

function renderServiceDiagram(report) {
  const container = document.getElementById('threat-diagram-canvas');
  if (!container) return;
  if (diagramNetwork) { diagramNetwork.destroy(); diagramNetwork = null; }
  container.innerHTML = '';
  const view = modelViews(report).services || {};
  const readiness = view.readiness || { state: 'insufficient', label: 'Insufficient architecture evidence', message: '' };
  const sourceNodes = view.nodes || [];
  const sourceFlows = view.flows || [];
  const threats = analysisVisibility(report).threats;
  if (!sourceNodes.length) {
    container.innerHTML = `<div class="diagram-grounded-empty"><strong>${escHtml(readiness.label || 'No service model available')}</strong><span>${escHtml(readiness.message || 'Add explicit internal components and data flows, or a structured API artifact, then refresh threat modeling.')}</span></div>`;
    return;
  }
  const toolbarTitle = document.querySelector('.diagram-toolbar-title');
  const toolbarSubtitle = document.querySelector('.diagram-toolbar-sub');
  if (toolbarTitle) toolbarTitle.textContent = view.label || 'Service-level Model';
  if (toolbarSubtitle) toolbarSubtitle.textContent = view.description || '';

  const ingress = sourceNodes.find(item => item.role === 'ingress');
  const services = sourceNodes.filter(item => item.role !== 'ingress');
  const nodeRows = sourceNodes.map((node, index) => {
    const mapped = uniqueThreats(threats.filter(item => targetMatches(item, node.element_id, node.element_type || 'process')));
    const critical = mapped.filter(item => item.risk_level === 'Critical').length;
    const high = mapped.filter(item => item.risk_level === 'High').length;
    const isIngress = node.role === 'ingress';
    const trustKey = node.element_type === 'data_store' ? 'privileged' : node.element_type === 'external_system' ? 'external' : normalizeEnhancedTrustLevel(node.trust_level, node.label);
    const color = getTrustColor(isIngress ? normalizeEnhancedTrustLevel(node.trust_level, node.label) : trustKey);
    const serviceIndex = Math.max(0, services.indexOf(node));
    return {
      id: node.element_id,
      label: `${node.label}${node.operation_count ? `\n${node.operation_count} operations` : ''}${mapped.length ? `\n${mapped.length} findings` : ''}`,
      title: `${node.label}\n${node.operation_count || 0} canonical operations\n${mapped.length} mapped findings${node.topology_status === 'logical' ? '\nLogical grouping — not a deployment boundary' : ''}`,
      x: isIngress ? -360 : 80 + (serviceIndex % 2) * 300,
      y: isIngress ? 0 : (serviceIndex - ((services.length - 1) / 2)) * 125,
      fixed: false,
      shape: node.element_type === 'data_store' ? 'database' : 'box',
      color: { background: color.bg, border: critical ? '#DC2626' : high ? '#D97706' : color.border, highlight: { background: color.bg, border: '#1D3557' } },
      font: { color: color.font, size: 13, face: 'Space Grotesk, sans-serif', bold: true },
      borderWidth: critical ? 3 : 2,
      margin: 14,
      shadow: { enabled: true, size: 6, x: 2, y: 3, color: 'rgba(29,53,87,.10)' },
      widthConstraint: { minimum: 145, maximum: 220 },
      _trustLevel: normalizeEnhancedTrustLevel(node.trust_level, node.label),
      _threats: mapped,
      _origLabel: node.label,
      _modelMeta: node.topology_status === 'logical'
        ? `${node.operation_count || 0} canonical operations · Logical service group, not a deployment boundary`
        : node.topology_status === 'candidate'
          ? `${node.element_type || 'process'} · Architecture candidate from narrative evidence; review required`
          : 'Grounded ingress process',
    };
  });
  const knownNodes = new Set(nodeRows.map(item => item.id));
  const edgeRows = sourceFlows.filter(flow => knownNodes.has(flow.source_id) && knownNodes.has(flow.destination_id)).map(flow => ({
    id: flow.element_id,
    from: flow.source_id,
    to: flow.destination_id,
    label: `${flow.operation_count || 0} operations`,
    title: `${flow.label}\n${flow.topology_status === 'candidate' ? 'Candidate relationship extracted from narrative evidence; review required.' : 'Logical API routing; it does not represent a trust crossing.'}`,
    arrows: { to: { enabled: true, scaleFactor: .75 } },
    dashes: [5, 5],
    color: { color: '#6C91AA', highlight: '#1D3557', hover: '#1D3557' },
    width: 1.6,
    font: { size: 10, color: '#526777', face: 'JetBrains Mono, monospace', background: 'rgba(255,255,255,.94)', strokeWidth: 0 },
    smooth: { enabled: true, type: 'cubicBezier', forceDirection: 'horizontal', roundness: .22 },
    _sourceLabel: flow.source,
    _destinationLabel: flow.destination,
    _flowDetails: [`${flow.operation_count || 0} canonical operations routed to ${flow.destination}`],
    _crossing: false,
    _logical: flow.topology_status !== 'candidate',
    _threats: [],
  }));
  const data = { nodes: new vis.DataSet(nodeRows), edges: new vis.DataSet(edgeRows) };
  diagramNetwork = new vis.Network(container, data, {
    physics: false,
    interaction: { hover: true, tooltipDelay: 180, zoomView: true, dragView: true, keyboard: { enabled: true, bindToWindow: false } },
    edges: { selectionWidth: 2.4, hoverWidth: 2.1 },
  });
  diagramNetwork.once('afterDrawing', () => diagramNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } }));
  diagramNetwork.on('click', params => {
    if (params.nodes.length) showNodeInspector(data.nodes.get(params.nodes[0]));
    else if (params.edges.length) showFlowInspector(data.edges.get(params.edges[0]));
    else document.getElementById('node-inspector').style.display = 'none';
  });
}

function scenarioMethodClass(method) {
  const value = String(method || '').toLowerCase();
  return ['get', 'post', 'put', 'patch', 'delete'].includes(value) ? `is-${value}` : '';
}

function activityNodeHtml(step) {
  const type = ['actor', 'action', 'decision', 'data_store', 'external_system'].includes(step.element_type)
    ? step.element_type : 'action';
  const labels = { actor: 'Actor', action: 'Action', decision: 'Decision', data_store: 'Data store', external_system: 'External system' };
  const actorIcon = type === 'actor' ? '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="3"/><path d="M12 8v7m-5-3h10m-8 9 3-6 3 6"/></svg>' : '';
  const data = (step.data || []).length ? `<small>${escHtml(step.data.slice(0, 3).join(', '))}</small>` : '';
  return `<div class="activity-node is-${type}">${actorIcon}<span>${labels[type]}</span><strong>${escHtml(step.label || type)}</strong>${step.target ? `<em>${escHtml(step.target)}</em>` : ''}${data}</div>`;
}

function renderScenarioExplorer(report) {
  const container = document.getElementById('threat-diagram-canvas');
  if (!container) return;
  if (diagramNetwork) { diagramNetwork.destroy(); diagramNetwork = null; }
  const view = modelViews(report).scenarios || {};
  const businessScenarios = view.business_items || [];
  const operations = view.operation_items || (view.items || []).filter(item => item.scenario_kind !== 'business_flow');
  const threats = analysisVisibility(report).threats;
  if (!businessScenarios.length && !operations.length) {
    container.innerHTML = '<div class="diagram-grounded-empty"><strong>Insufficient scenario evidence</strong><span>Add a PRD with explicit actor, use-case steps, and supporting text—or OpenAPI/Postman operations—then refresh threat modeling.</span></div>';
    return;
  }
  const services = [...new Set(operations.map(item => item.service).filter(Boolean))].sort();
  const serviceOptions = services.map(service => `<option value="${escHtml(service)}">${escHtml(service)}</option>`).join('');
  const operationCards = operations.map((item, index) => {
    const direct = uniqueThreats(threats.filter(threat => targetMatches(threat, item.element_id, 'scenario')));
    const serviceRelated = uniqueThreats(threats.filter(threat => targetRefs(threat, 'process', 'service').some(ref => ref.label === item.service)));
    const evidence = (item.evidence_refs || []).slice(0, 2);
    const searchText = `${item.method} ${item.path} ${item.label} ${item.service}`.toLowerCase();
    return `<article class="scenario-card" data-scenario-index="${index}" data-scenario-service="${escHtml(item.service || '')}" data-scenario-search="${escHtml(searchText)}">
      <div class="scenario-card-head">
        <span class="scenario-method ${scenarioMethodClass(item.method)}">${escHtml(item.method || 'API')}</span>
        <code>${escHtml(item.path || 'Unknown path')}</code>
        <span class="scenario-security ${String(item.security_status).toLowerCase() === 'secured' ? 'is-secured' : ''}">${escHtml(item.security_status || 'unknown')}</span>
      </div>
      <div class="scenario-card-body">
        <strong>${escHtml(item.label || `${item.method} ${item.path}`)}</strong>
        <span>${escHtml(item.service || 'Application API')}</span>
        <div class="scenario-stats"><span><b>${direct.length}</b> direct findings</span><span><b>${serviceRelated.length}</b> service-related</span><span><b>${item.scenario_count || 0}</b> artifact examples</span></div>
        ${evidence.length ? `<details><summary>Evidence trace</summary><ul>${evidence.map(ref => `<li><code>${escHtml(ref)}</code></li>`).join('')}</ul></details>` : ''}
      </div>
    </article>`;
  }).join('');
  const businessCards = businessScenarios.map((item, index) => {
    const direct = uniqueThreats(threats.filter(threat => targetMatches(threat, item.element_id, 'scenario')));
    const flow = (item.steps || []).map((step, stepIndex) => `${stepIndex ? '<span class="activity-arrow" aria-hidden="true">→</span>' : ''}${activityNodeHtml(step)}`).join('');
    const searchText = `${item.label} ${item.actor} ${item.trigger || ''} ${(item.steps || []).map(step => step.label).join(' ')}`.toLowerCase();
    return `<article class="scenario-flow-card" data-business-index="${index}" data-business-search="${escHtml(searchText)}">
      <div class="scenario-flow-head">
        <div><span class="scenario-flow-kicker">Business scenario · ${escHtml(item.status || 'Candidate')}</span><strong>${escHtml(item.label)}</strong></div>
        <div class="scenario-stats"><span><b>${direct.length}</b> direct findings</span><span><b>${(item.steps || []).length - 1}</b> activities</span></div>
      </div>
      ${item.trigger ? `<div class="scenario-trigger"><b>Trigger</b>${escHtml(item.trigger)}</div>` : ''}
      <div class="activity-flow" aria-label="Activity flow for ${escHtml(item.label)}">${flow}</div>
      <div class="scenario-flow-foot">
        ${(item.preconditions || []).length ? `<span><b>Preconditions:</b> ${escHtml(item.preconditions.join(' · '))}</span>` : ''}
        <details><summary>Evidence trace</summary><div><code>${escHtml(item.evidence_refs?.[0] || item.evidence_locator || 'Evidence reference unavailable')}</code>${item.evidence_snippet ? `<p>${escHtml(item.evidence_snippet)}</p>` : ''}</div></details>
      </div>
    </article>`;
  }).join('');
  const initialKind = businessScenarios.length ? 'business' : 'operations';
  container.innerHTML = `<div class="scenario-explorer">
    <div class="scenario-kind-switch" role="group" aria-label="Scenario view">
      <button type="button" data-scenario-kind="business" class="${initialKind === 'business' ? 'active' : ''}" aria-pressed="${initialKind === 'business'}" ${businessScenarios.length ? '' : 'disabled'}>Business flows <b>${businessScenarios.length}</b></button>
      <button type="button" data-scenario-kind="operations" class="${initialKind === 'operations' ? 'active' : ''}" aria-pressed="${initialKind === 'operations'}" ${operations.length ? '' : 'disabled'}>API operations <b>${operations.length}</b></button>
    </div>
    <section class="scenario-kind-panel" data-scenario-panel="business" ${initialKind === 'business' ? '' : 'hidden'}>
      <div class="activity-legend" aria-label="Activity shape legend">
        <span><i class="legend-shape is-actor"></i>Actor</span><span><i class="legend-shape is-action"></i>Action</span><span><i class="legend-shape is-decision"></i>Decision</span><span><i class="legend-shape is-store"></i>Data store</span><span><i class="legend-shape is-external"></i>External system</span>
      </div>
      <div class="scenario-explorer-toolbar is-business"><label class="scenario-search"><span>Find scenario or activity</span><input class="form-input" id="business-scenario-search" type="search" placeholder="Actor, action, use case…" /></label><span class="scenario-result-count" id="business-result-count">${businessScenarios.length} business flows</span></div>
      <div class="scenario-model-note"><strong>Evidence-backed activity view.</strong> Candidate steps come from exact PRD excerpts; unknown architecture is left unstated.</div>
      <div class="scenario-flow-list" id="business-scenario-list">${businessCards}</div>
      <div class="scenario-empty-filter" id="business-empty-filter" hidden>No business scenario matches this search.</div>
    </section>
    <section class="scenario-kind-panel" data-scenario-panel="operations" ${initialKind === 'operations' ? '' : 'hidden'}>
      <div class="scenario-explorer-toolbar">
        <label><span>Service</span><select class="form-select" id="scenario-service-filter"><option value="">All services</option>${serviceOptions}</select></label>
        <label class="scenario-search"><span>Find operation</span><input class="form-input" id="scenario-search-input" type="search" placeholder="Method, path, summary…" /></label>
        <span class="scenario-result-count" id="scenario-result-count">${operations.length} operations</span>
      </div>
      <div class="scenario-model-note"><strong>Canonical operation catalog.</strong> Operations come from normalized API artifacts and do not create deployment boundaries.</div>
      <div class="scenario-card-grid" id="scenario-card-grid">${operationCards}</div>
      <div class="scenario-empty-filter" id="scenario-empty-filter" hidden>No operation matches this filter.</div>
      <div class="scenario-load-more-row"><button type="button" class="btn btn-secondary btn-sm" id="scenario-load-more">Show more operations</button></div>
    </section>
  </div>`;
  container.querySelectorAll('[data-scenario-kind]').forEach(button => button.addEventListener('click', () => {
    const kind = button.dataset.scenarioKind;
    container.querySelectorAll('[data-scenario-kind]').forEach(item => {
      const active = item === button;
      item.classList.toggle('active', active);
      item.setAttribute('aria-pressed', String(active));
    });
    container.querySelectorAll('[data-scenario-panel]').forEach(panel => { panel.hidden = panel.dataset.scenarioPanel !== kind; });
  }));
  const applyBusinessFilter = () => {
    const query = (document.getElementById('business-scenario-search')?.value || '').trim().toLowerCase();
    let visible = 0;
    container.querySelectorAll('.scenario-flow-card').forEach(card => {
      const show = !query || card.dataset.businessSearch.includes(query);
      card.hidden = !show;
      if (show) visible += 1;
    });
    const count = document.getElementById('business-result-count');
    if (count) count.textContent = `${visible} of ${businessScenarios.length} business flows`;
    const empty = document.getElementById('business-empty-filter');
    if (empty) empty.hidden = visible !== 0;
  };
  document.getElementById('business-scenario-search')?.addEventListener('input', applyBusinessFilter);
  let visibleLimit = 12;
  const applyFilter = () => {
    const service = document.getElementById('scenario-service-filter')?.value || '';
    const query = (document.getElementById('scenario-search-input')?.value || '').trim().toLowerCase();
    let matched = 0;
    let visible = 0;
    container.querySelectorAll('.scenario-card').forEach(card => {
      const matchesFilter = (!service || card.dataset.scenarioService === service) && (!query || card.dataset.scenarioSearch.includes(query));
      if (matchesFilter) matched += 1;
      const show = matchesFilter && matched <= visibleLimit;
      card.hidden = !show;
      if (show) visible += 1;
    });
    const resultCount = document.getElementById('scenario-result-count');
    if (resultCount) resultCount.textContent = `${visible} shown · ${matched} matches · ${operations.length} total`;
    const empty = document.getElementById('scenario-empty-filter');
    if (empty) empty.hidden = matched !== 0;
    const more = document.getElementById('scenario-load-more');
    if (more) {
      more.hidden = visible >= matched;
      more.textContent = `Show ${Math.min(12, matched - visible)} more operations`;
    }
  };
  document.getElementById('scenario-service-filter')?.addEventListener('change', () => { visibleLimit = 12; applyFilter(); });
  document.getElementById('scenario-search-input')?.addEventListener('input', () => { visibleLimit = 12; applyFilter(); });
  document.getElementById('scenario-load-more')?.addEventListener('click', () => { visibleLimit += 12; applyFilter(); });
  if (operations.length) applyFilter();
}

function renderImprovedDiagram(report) {
  const container = document.getElementById('threat-diagram-canvas');
  if (!container) return;

  const boundaries = activeTrustBoundaries(report);
  const flows = activeDiagramFlows(report);
  const threats = analysisVisibility(report).threats;
  const contextView = modelViews(report).context || {};
  const contextNodeByLabel = new Map((contextView.nodes || []).map(item => [canonicalNodeLabel(item.label).toLowerCase(), item]));
  const contextFlowByPair = new Map((contextView.flows || []).map(item => [`${canonicalNodeLabel(item.source).toLowerCase()}::${canonicalNodeLabel(item.destination).toLowerCase()}`, item]));
  const nodeMap = new Map();
  const connectionMap = new Map();
  let nodeId = 1;

  function ensureNode(rawLabel, rawTrust) {
    const label = canonicalNodeLabel(rawLabel);
    const key = label.toLowerCase();
    const zoneKey = normalizeEnhancedTrustLevel(rawTrust, label);
    const contextElement = contextNodeByLabel.get(key);
    if (!nodeMap.has(key)) {
      nodeMap.set(key, {
        id: nodeId++,
        key,
        label,
        aliases: new Set([String(rawLabel || '').toLowerCase().trim()]),
        zoneKey,
        threats: [],
        elementId: contextElement?.element_id || null,
        elementType: contextElement?.element_type || 'process',
      });
    } else {
      nodeMap.get(key).aliases.add(String(rawLabel || '').toLowerCase().trim());
    }
    return nodeMap.get(key);
  }

  function connectionFor(sourceNode, destinationNode) {
    const pair = [sourceNode.key, destinationNode.key].sort();
    const key = pair.join('::');
    if (!connectionMap.has(key)) {
      connectionMap.set(key, { key, nodes: new Map(), boundaries: [], flows: [] });
    }
    const connection = connectionMap.get(key);
    connection.nodes.set(sourceNode.key, sourceNode);
    connection.nodes.set(destinationNode.key, destinationNode);
    return connection;
  }

  boundaries.forEach(boundary => {
    const source = ensureNode(boundary.source, boundary.source_trust_level);
    const destination = ensureNode(boundary.destination, boundary.destination_trust_level);
    connectionFor(source, destination).boundaries.push({
      source: source.key,
      destination: destination.key,
      label: boundary.boundary_label || '',
      boundaryId: boundary.boundary_id || null,
    });
  });

  flows.forEach(flow => {
    const source = ensureNode(flow.source, '');
    const destination = ensureNode(flow.destination, '');
    connectionFor(source, destination).flows.push({
      source: source.key,
      destination: destination.key,
      protocol: flow.protocol || '',
      data: Array.isArray(flow.data) ? flow.data : [flow.data].filter(Boolean),
      flowId: flow.flow_id || contextFlowByPair.get(`${source.key}::${destination.key}`)?.element_id || null,
    });
  });

  if (!nodeMap.size && report.trust_model) {
    if (diagramNetwork) { diagramNetwork.destroy(); diagramNetwork = null; }
    container.innerHTML = '<div class="diagram-grounded-empty"><strong>No active grounded relationships</strong><span>All boundary candidates were rejected or no evidenced cross-zone flow is available.</span></div>';
    document.getElementById('node-inspector').style.display = 'none';
    return;
  }

  if (!nodeMap.size) {
    [
      ['User', 'untrusted'],
      ['Web Frontend', 'internal'],
      ['Backend API', 'internal'],
      ['Database', 'privileged'],
    ].forEach(([label, trust]) => ensureNode(label, trust));
  }

  threats.forEach(threat => {
    const candidates = [threat.component, threat.source, threat.destination]
      .filter(Boolean)
      .map(canonicalNodeLabel)
      .map(value => value.toLowerCase());
    nodeMap.forEach(node => {
      const component = String(threat.component || threat.asset || '').toLowerCase();
      const typedMatch = node.elementId && targetMatches(threat, node.elementId, [node.elementType, 'process', 'external_entity']);
      const matches = typedMatch || candidates.includes(node.key)
        || [...node.aliases].some(alias => alias && component.includes(alias))
        || (component && (component.includes(node.key) || node.key.includes(component)));
      const alreadyMapped = threat.threat_id
        ? node.threats.some(item => item.threat_id === threat.threat_id)
        : node.threats.includes(threat);
      if (matches && !alreadyMapped) {
        node.threats.push(threat);
      }
    });
  });

  const nodesByZone = new Map(ENHANCED_TRUST_ZONES.map(zone => [zone.key, []]));
  nodeMap.forEach(node => (nodesByZone.get(node.zoneKey) || nodesByZone.get('internal')).push(node));
  const zoneX = { untrusted: -480, external: -160, internal: 160, privileged: 480 };
  nodesByZone.forEach(zoneNodes => {
    zoneNodes.sort((a, b) => a.label.localeCompare(b.label));
    zoneNodes.forEach((node, index) => {
      node.x = zoneX[node.zoneKey];
      node.y = (index - ((zoneNodes.length - 1) / 2)) * 145;
    });
  });

  const visNodes = [...nodeMap.values()].map(node => {
    const color = getTrustColor(node.zoneKey);
    const critical = node.threats.filter(t => t.risk_level === 'Critical').length;
    const high = node.threats.filter(t => t.risk_level === 'High').length;
    const threatLabel = [critical ? `${critical} Critical` : '', high ? `${high} High` : ''].filter(Boolean).join(' · ');
    const zone = ENHANCED_TRUST_ZONES.find(item => item.key === node.zoneKey);
    return {
      id: node.id,
      label: threatLabel ? `${node.label}\n${threatLabel}` : node.label,
      title: `${node.label}\nTrust zone: ${zone?.label || node.zoneKey}\n${node.threats.length} mapped threats`,
      x: node.x,
      y: node.y,
      shape: getNodeShape(node.label),
      color: { background: color.bg, border: color.border, highlight: { background: color.bg, border: '#1D3557' } },
      font: { color: color.font, size: 14, face: 'Space Grotesk, sans-serif', bold: true, multi: false },
      borderWidth: critical ? 3 : 2,
      borderWidthSelected: 3,
      margin: 14,
      shadow: { enabled: true, size: 7, x: 2, y: 3, color: 'rgba(29,53,87,.10)' },
      widthConstraint: { minimum: 110, maximum: 190 },
      _trustLevel: node.zoneKey,
      _threats: node.threats,
      _origLabel: node.label,
      _elementId: node.elementId,
    };
  });

  let edgeId = 1;
  const visEdges = [...connectionMap.values()].map(connection => {
    const connectedNodes = [...connection.nodes.values()];
    const first = connectedNodes[0];
    const second = connectedNodes[1];
    const forward = connection.flows.filter(flow => flow.source === first.key && flow.destination === second.key);
    const reverse = connection.flows.filter(flow => flow.source === second.key && flow.destination === first.key);
    const boundaryDirection = connection.boundaries[0];
    const source = forward.length || reverse.length
      ? (forward.length ? first : second)
      : nodeMap.get(boundaryDirection?.source) || first;
    const destination = source.key === first.key ? second : first;
    const hasForward = connection.flows.some(flow => flow.source === source.key && flow.destination === destination.key)
      || connection.boundaries.some(item => item.source === source.key && item.destination === destination.key);
    const hasReverse = connection.flows.some(flow => flow.source === destination.key && flow.destination === source.key)
      || connection.boundaries.some(item => item.source === destination.key && item.destination === source.key);
    const protocols = [...new Set(connection.flows.map(flow => flow.protocol).filter(Boolean))];
    const dataItems = [...new Set(connection.flows.flatMap(flow => flow.data).filter(Boolean))];
    const dataLabel = dataItems.length
      ? `${compactFlowText(dataItems[0], 25)}${dataItems.length > 1 ? ` +${dataItems.length - 1}` : ''}`
      : inferredFlowDescription(source.label, destination.label);
    const label = [protocols.join('/'), dataLabel].filter(Boolean).join(' · ');
    const crossing = source.zoneKey !== destination.zoneKey;
    const details = connection.flows.map(flow => {
      const from = nodeMap.get(flow.source)?.label || flow.source;
      const to = nodeMap.get(flow.destination)?.label || flow.destination;
      return `${from} → ${to}: ${flow.data.join(', ') || 'data'}${flow.protocol ? ` [${flow.protocol}]` : ''}`;
    });
    const boundaryIds = new Set(connection.boundaries.map(item => item.boundaryId).filter(Boolean));
    const flowIds = new Set(connection.flows.map(item => item.flowId).filter(Boolean));
    const edgeThreats = uniqueThreats(threats.filter(threat =>
      targetMatches(threat, boundaryIds, 'trust_boundary') || targetMatches(threat, flowIds, 'data_flow')
    ));
    const edgeLabel = `${label}${edgeThreats.length ? `${label ? '\n' : ''}${edgeThreats.length} findings` : ''}`;
    return {
      id: edgeId++,
      from: source.id,
      to: destination.id,
      label: edgeLabel,
      title: `${details.join('\n') || `${source.label} → ${destination.label}`}\n${edgeThreats.length} mapped findings`,
      arrows: {
        to: { enabled: hasForward, scaleFactor: .75 },
        from: { enabled: hasReverse, scaleFactor: .75 },
      },
      dashes: crossing ? [8, 6] : false,
      color: { color: crossing ? '#D06B55' : '#6C91AA', highlight: '#1D3557', hover: '#1D3557' },
      width: crossing ? 2 : 1.7,
      font: { size: 10, color: '#526777', face: 'JetBrains Mono, monospace', background: 'rgba(255,255,255,.92)', strokeWidth: 0, align: 'middle' },
      smooth: { enabled: true, type: 'cubicBezier', forceDirection: 'horizontal', roundness: .28 },
      _sourceLabel: source.label,
      _destinationLabel: destination.label,
      _flowDetails: details,
      _crossing: crossing,
      _threats: edgeThreats,
    };
  });

  const data = { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) };
  const options = {
    physics: false,
    interaction: { hover: true, tooltipDelay: 180, zoomView: true, dragView: true, keyboard: { enabled: true, bindToWindow: false } },
    nodes: { chosen: true },
    edges: { selectionWidth: 2.5, hoverWidth: 2.2 },
  };

  if (diagramNetwork) diagramNetwork.destroy();
  diagramNetwork = new vis.Network(container, data, options);
  diagramNetwork.once('afterDrawing', () => {
    diagramNetwork.fit({ animation: { duration: 450, easingFunction: 'easeInOutQuad' } });
  });
  diagramNetwork.on('click', params => {
    if (params.nodes.length) {
      showNodeInspector(data.nodes.get(params.nodes[0]));
    } else if (params.edges.length) {
      showFlowInspector(data.edges.get(params.edges[0]));
    } else {
      document.getElementById('node-inspector').style.display = 'none';
    }
  });
}

function showFlowInspector(edge) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;
  title.textContent = `${edge._sourceLabel || 'Source'} ↔ ${edge._destinationLabel || 'Destination'}`;
  const crossing = edge._crossing
    ? '<div class="flow-boundary-note">This flow crosses a trust boundary and should be reviewed for authentication, authorization, validation, and transport protection.</div>'
    : `<div class="flow-internal-note">${edge._logical ? 'Logical routing relationship; this does not assert a deployment or trust boundary.' : 'This flow stays within one trust zone.'}</div>`;
  const details = (edge._flowDetails || []).length
    ? edge._flowDetails.map(item => `<li>${escHtml(item)}</li>`).join('')
    : `<li>${escHtml(edge.label || 'Service interaction')}</li>`;
  const threats = uniqueThreats(edge._threats || []);
  const findings = threats.length
    ? `<div class="inspector-findings"><strong>${threats.length} mapped findings</strong>${threats.map(t => `
        <div class="inspector-finding-row">${badgeHtml(t.risk_level, 'risk')}${badgeHtml(t.framework, 'framework')}<span>${escHtml(t.threat_category || 'Finding')}</span></div>`).join('')}</div>`
    : '<div class="inspector-empty-note">No finding is directly targeted to this flow.</div>';
  body.innerHTML = `${crossing}<ul class="flow-detail-list">${details}</ul>${findings}`;
  inspector.style.display = 'block';
  inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderClassicDiagram(report) {
  const container = document.getElementById('threat-diagram-canvas');
  if (!container) return;

  const boundaries = activeTrustBoundaries(report);
  const threats = analysisVisibility(report).threats;
  const contextNodes = modelViews(report).context?.nodes || [];

  // Build node map from trust boundaries + project context
  const nodeMap = new Map();
  let nodeIdCounter = 1;

  function getOrCreateNode(label, trustLevel) {
    const key = label.toLowerCase().trim();
    const modelNode = contextNodes.find(item => String(item.label || '').toLowerCase().trim() === key);
    if (!nodeMap.has(key)) {
      const color = getTrustColor(trustLevel);
      nodeMap.set(key, {
        id: nodeIdCounter++,
        label: label,
        trustLevel: trustLevel || 'default',
        color: { background: color.bg, border: color.border, highlight: { background: color.bg, border: '#1A1917' } },
        font: { color: color.font, size: 13, face: 'Space Grotesk, sans-serif', bold: true },
        shape: getNodeShape(label),
        borderWidth: 2,
        borderWidthSelected: 3,
        shadow: { enabled: true, size: 6, x: 2, y: 2, color: 'rgba(0,0,0,0.08)' },
        margin: 12,
        // store related threats for inspector
        relatedThreats: [],
        elementId: modelNode?.element_id || null,
        elementType: modelNode?.element_type || 'process',
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
    const edgeThreats = uniqueThreats(threats.filter(item => targetMatches(item, b.boundary_id, 'trust_boundary')));
    edges.push({
      id: edgeId++,
      from: srcNode.id,
      to: dstNode.id,
      label: `${b.boundary_label || ''}${edgeThreats.length ? `\n${edgeThreats.length} findings` : ''}`,
      arrows: { to: { enabled: true, scaleFactor: 0.8 } },
      color: { color: '#C8C5BF', highlight: '#1A1917', hover: '#1A1917' },
      font: { size: 10, color: '#726E68', face: 'JetBrains Mono, monospace', background: '#FFFFFF', strokeWidth: 0 },
      dashes: b.is_trust_crossing !== false,
      width: 1.5,
      smooth: { type: 'curvedCW', roundness: 0.15 },
      _sourceLabel: b.source,
      _destinationLabel: b.destination,
      _flowDetails: b.data_flows || [],
      _crossing: b.is_trust_crossing !== false,
      _threats: edgeThreats,
    });
  });

  // Attach threats to nodes for inspector
  threats.forEach(t => {
    const comp = (t.component || t.asset || '').toLowerCase().trim();
    nodeMap.forEach((node, key) => {
      if ((node.elementId && targetMatches(t, node.elementId, [node.elementType, 'process', 'external_entity'])) || (comp && (comp.includes(key) || key.includes(comp)))) {
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
    _elementId: n.elementId,
  }));

  // Grounded reports must never replace an empty model with invented nodes.
  if (nodes.length === 0 && report.trust_model) {
    if (diagramNetwork) { diagramNetwork.destroy(); diagramNetwork = null; }
    container.innerHTML = '<div class="diagram-grounded-empty"><strong>No active grounded relationships</strong><span>All boundary candidates were rejected or no evidenced cross-zone flow is available.</span></div>';
    document.getElementById('node-inspector').style.display = 'none';
    return;
  }

  // Legacy reports without a grounded model keep their previous placeholders.
  if (nodes.length === 0) {
    const placeholders = ['Internet', 'Web Application', 'API Server', 'Database'];
    placeholders.forEach((label, i) => {
      const levels = ['untrusted', 'external', 'internal', 'privileged'];
      const color = getTrustColor(levels[i]);
      nodes.push({
        id: i + 1, label, shape: getNodeShape(label),
        color: { background: color.bg, border: color.border, highlight: { background: color.bg, border: '#1A1917' } },
        font: { color: color.font, size: 13, face: 'Space Grotesk, sans-serif', bold: true },
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
      keyboard: { enabled: true, bindToWindow: false },
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
    } else if (params.edges.length > 0) {
      showFlowInspector(data.edges.get(params.edges[0]));
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
  const zone = ENHANCED_TRUST_ZONES.find(item => item.key === node._trustLevel);
  const zoneSummary = diagramViewMode === 'improved' && zone
    ? `<div class="node-trust-summary"><span class="legend-dot" style="background:${getTrustColor(zone.key).border};"></span>${escHtml(zone.label)} trust zone</div>`
    : '';
  const modelMeta = node._modelMeta ? `<div class="node-model-meta">${escHtml(node._modelMeta)}</div>` : '';

  if (!threats.length) {
    body.innerHTML = `${zoneSummary}${modelMeta}<div style="font-size:0.82rem;color:var(--text-muted);padding:var(--space-3) 0;">No threats mapped to this component.</div>`;
  } else {
    body.innerHTML = zoneSummary + modelMeta + threats.map(t => `
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
    const hidden = analysisVisibility(currentReport).hidden.threats > 0;
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><h3>${hidden ? 'Threats hidden by boundary review' : 'No threats identified'}</h3><p>${hidden ? 'The findings remain stored. Restore the rejected boundary to Candidate or Confirmed to show them again.' : 'Run the structured review to evaluate potential threats.'}</p></div>`;
    return;
  }

  el.innerHTML = threats.map((t, i) => {
    const uid = `${prefix}-${i}`;   // unique: 'st-0', 'ln-0', etc.
    return `
    <div class="threat-item" id="threat-${uid}" data-threat-id="${escHtml(t.threat_id || '')}" data-risk="${escHtml(t.risk_level || '')}" data-status="${escHtml(t.status || 'Open')}">
      <button type="button" class="threat-item-header threat-review-header" id="threat-trigger-${uid}"
        aria-expanded="false" aria-controls="threat-body-${uid}" onclick="toggleThreat('${uid}')">
        <span class="threat-header-badges">
          ${badgeHtml(t.risk_level, 'risk')}
          ${badgeHtml(t.framework, 'framework')}
        </span>
        <span class="threat-item-title">${escHtml(t.threat_category)} — ${escHtml((t.threat_description || '').substring(0, 90))}${(t.threat_description || '').length > 90 ? '…' : ''}</span>
        <span class="threat-header-signals">
          ${confidenceDots(t.confidence)}
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" id="chevron-${uid}" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>
        </span>
      </button>
      <div class="threat-item-body" id="threat-body-${uid}" role="region" aria-labelledby="threat-trigger-${uid}" hidden>
        <div class="threat-meta-grid">
          <div class="threat-meta-item"><div class="threat-meta-label">Asset</div><div class="threat-meta-value">${escHtml(t.asset || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Component</div><div class="threat-meta-value">${escHtml(t.component || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Trust Boundary</div><div class="threat-meta-value">${escHtml(t.trust_boundary || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Classification</div><div class="threat-meta-value">${escHtml(t.data_classification || '—')}</div></div>
        </div>
        <div class="threat-review-grid">
          <div class="threat-meta-item"><div class="threat-meta-label">Evidence strength</div><div class="threat-meta-value">${evidenceBadgeHtml(t)}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Review Status</div><div class="threat-meta-value">${statusSelectHtml(t)}</div></div>
        </div>
        ${evidenceCardHtml(t)}
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
  const trigger = document.getElementById(`threat-trigger-${uid}`);
  if (!body) return;
  const isOpen = !body.hidden;
  body.hidden = isOpen;
  trigger?.setAttribute('aria-expanded', String(!isOpen));
  if (chevron) chevron.style.transform = isOpen ? '' : 'rotate(180deg)';
};

window.updateThreatStatus = async function(threatId, status) {
  try {
    await API.analysis.updateThreat(projectId, threatId, { status });
    const threat = currentReport?.threats?.find(item => String(item.threat_id) === String(threatId));
    if (threat) threat.status = status;
    document.querySelector(`[data-threat-id="${CSS.escape(String(threatId))}"]`)?.setAttribute('data-status', status);
    if (currentReport) renderAnalysisOverview(currentReport);
    showToast('Threat status updated', 'success');
  } catch (err) {
    showToast('Could not update status: ' + err.message, 'error');
  }
};

// ── Controls ───────────────────────────────────────────────────────────────────
function renderControls(controls) {
  const el = document.getElementById('controls-list');
  if (!controls.length) {
    const hidden = analysisVisibility(currentReport).hidden.controls > 0;
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><h3>${hidden ? 'Controls hidden by boundary review' : 'No controls mapped yet'}</h3>${hidden ? '<p>Restore the rejected boundary to show the retained control mappings.</p>' : ''}</div>`;
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
    const hidden = analysisVisibility(currentReport).hidden.tests > 0;
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><h3>${hidden ? 'Tests hidden by boundary review' : 'No test scenarios yet'}</h3>${hidden ? '<p>Restore the rejected boundary to show the retained verification backlog.</p>' : ''}</div>`;
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
  if (!html) {
    const visibility = analysisVisibility(currentReport);
    const hidden = visibility.hidden.missingInfo + visibility.hidden.assumptions > 0;
    html = `<div class="empty-state" style="padding:var(--space-8);"><h3>${hidden ? 'Review notes hidden by boundary review' : 'No gaps identified'}</h3>${hidden ? '<p>Restore the rejected boundary to show retained gaps and assumptions.</p>' : ''}</div>`;
  }
  el.innerHTML = html;
}

// ── Artifact upload ────────────────────────────────────────────────────────────
function analysisTypesForArtifact(type) {
  const modelingStages = ['trust_boundary', 'stride', 'linddun', 'controls', 'tests'];
  if (['prd', 'markdown', 'text'].includes(type)) return fullAnalysisTypes();
  return modelingStages;
}

async function uploadArtifact() {
  const type = document.getElementById('artifact-type-select')?.value;
  const file = document.getElementById('artifact-file-inline')?.files?.[0];
  const btn = document.getElementById('btn-upload-artifact');
  if (!file) { showToast('Upload an artifact file first', 'warn'); return; }
  if (file && file.size > MAX_ARTIFACT_BYTES) { showToast('File exceeds 5 MB limit', 'warn'); return; }

  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  btn.innerHTML = '<div class="loading-spinner"></div> Parsing…';
  setArtifactImportStatus('working', `
    <div class="artifact-result-title">Parsing ${escHtml(file.name)}…</div>
    <div>Reading the complete structured file, normalizing operations, and reconciling it with active artifacts.</div>
  `);
  try {
    const response = await API.artifacts.uploadFile(projectId, type, file);
    const project = response.project || await API.projects.get(projectId);
    if (response.completeness) project.completeness = response.completeness;
    currentProject = project;
    renderProjectContext(project);
    renderArtifactImportResult(response, file);
    const fileInput = document.getElementById('artifact-file-inline');
    if (fileInput) fileInput.value = '';
    updateArtifactSelection(null);
    if (response.duplicate) {
      showToast('This artifact is already included — no duplicate context was added.', 'info');
    } else if (currentReport) {
      pendingArtifactAnalysisTypes = analysisTypesForArtifact(type);
      const notice = document.getElementById('analysis-stale-notice');
      const message = document.getElementById('analysis-stale-message');
      if (message) message.textContent = `${file.name} updated the project context. Refresh the affected analysis stages before relying on the current findings.`;
      if (notice) notice.style.display = 'flex';
      document.body.classList.add('analysis-has-report');
      notice?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'nearest' });
      showToast('Artifact added — refresh affected stages to update the findings', 'success');
    } else {
      showToast('Artifact parsed and context updated. The project is ready for analysis.', 'success');
    }
  } catch (err) {
    setArtifactImportStatus('error', `
      <div class="artifact-result-title">Could not parse ${escHtml(file.name)}</div>
      <div>${escHtml(err.message)}</div>
      <div style="margin-top:6px;">Check the selected artifact type and validate the file structure, then try again.</div>
    `);
    document.getElementById('artifact-import-result')?.focus();
    showToast('Upload failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg> Parse &amp; Add Context';
  }
}
