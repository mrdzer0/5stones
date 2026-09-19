/**
 * Analysis page — loads project context, runs analysis, renders results tabs
 * Includes: interactive vis-network diagram, LINDDUN fix (unique IDs), LINDDUN filter
 */
let projectId = null;
let currentReport = null;
let currentProject = null;
let diagramNetwork = null;   // vis-network instance
let diagramResizeTimer = null;
let canonicalLayoutSaveTimer = null;
let canonicalUndoStack = [];
let canonicalRedoStack = [];
let canonicalFeatureViewId = null;
let canonicalRenderedViewKind = 'context';
let canonicalShowUnconnected = false;
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
  document.getElementById('btn-retry-persisted-analysis')?.addEventListener('click', retryPersistedAnalysis);
  document.getElementById('btn-apply-dfd-proposal')?.addEventListener('click', applyDfdProposal);
  document.getElementById('btn-dismiss-dfd-proposal')?.addEventListener('click', dismissDfdProposal);
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
  document.getElementById('btn-diagram-fit')?.addEventListener('click', () => {
    if (!diagramNetwork) return;
    diagramNetwork.fit({ animation: { duration: 250, easingFunction: 'easeInOutQuad' } });
    if (currentReport?.dfd_model) scheduleCanonicalLayoutSave();
  });
  document.getElementById('btn-diagram-unconnected')?.addEventListener('click', () => {
    canonicalShowUnconnected = !canonicalShowUnconnected;
    if (currentReport) renderDiagram(currentReport);
  });
  document.getElementById('btn-dfd-undo')?.addEventListener('click', () => restoreCanonicalDfdHistory('undo'));
  document.getElementById('btn-dfd-redo')?.addEventListener('click', () => restoreCanonicalDfdHistory('redo'));
  document.getElementById('btn-diagram-export')?.addEventListener('click', exportDiagramPng);
  document.getElementById('btn-diagram-export-svg')?.addEventListener('click', exportDiagramSvg);
  document.getElementById('btn-diagram-export-json')?.addEventListener('click', exportDiagramJson);
  document.getElementById('btn-diagram-import-json')?.addEventListener('click', () => document.getElementById('dfd-json-import')?.click());
  document.getElementById('dfd-json-import')?.addEventListener('change', event => importDiagramJson(event.target.files?.[0]));
  setupDiagramModeSwitch();
  setupDiagramLevelSwitch();
  window.addEventListener('resize', () => {
    window.clearTimeout(diagramResizeTimer);
    diagramResizeTimer = window.setTimeout(() => {
      if (currentReport?.dfd_model && diagramNetwork) {
        if (!restoreCanonicalViewport(currentReport.dfd_model)) diagramNetwork.fit({ animation: false });
      } else diagramNetwork?.fit({ animation: false });
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
  const canonical = Boolean(currentReport?.dfd_model?.nodes?.length);
  const levelLabels = canonical
    ? { context: 'L0 Context', services: 'L1 System DFD', scenarios: 'L2 Feature DFD' }
    : { context: 'L0 Context', services: 'L1 Services', scenarios: 'L2 Scenarios' };
  document.querySelectorAll('[data-diagram-level]').forEach(button => {
    if (levelLabels[button.dataset.diagramLevel]) button.textContent = levelLabels[button.dataset.diagramLevel];
  });
  const trustLegend = document.getElementById('diagram-trust-legend');
  if (trustLegend) trustLegend.style.display = diagramLevel === 'context' && diagramViewMode === 'classic' ? '' : 'none';
  const mobileMap = document.getElementById('diagram-mobile-map');
  if (mobileMap) mobileMap.classList.toggle('is-level-hidden', diagramLevel !== 'context');
  const title = document.querySelector('.diagram-toolbar-title');
  if (title) title.textContent = canonical
    ? (diagramLevel === 'context' ? 'Context DFD' : diagramLevel === 'services' ? 'System DFD' : 'Feature DFD')
    : (diagramLevel === 'context' ? 'Context Data Flow Diagram' : diagramLevel === 'services' ? 'Service-level Model' : 'Scenario Flows & API Operations');
  const featureSelect = document.getElementById('canonical-feature-select');
  if (featureSelect) featureSelect.style.display = canonical && diagramLevel === 'scenarios' ? '' : 'none';
  const unconnectedButton = document.getElementById('btn-diagram-unconnected');
  if (unconnectedButton) unconnectedButton.hidden = !canonical || diagramLevel !== 'services';
  ['btn-diagram-fit', 'btn-diagram-export', 'btn-diagram-export-svg', 'btn-diagram-export-json', 'btn-diagram-import-json'].forEach(id => {
    const button = document.getElementById(id);
    if (button) button.hidden = diagramLevel === 'scenarios';
  });
  const subtitle = document.querySelector('.diagram-toolbar-sub');
  if (subtitle) {
    if (diagramLevel === 'services') {
      subtitle.textContent = canonical
        ? 'Connected data flows are shown first; review unconnected elements in the inventory or toggle Show unconnected.'
        : 'Evidence readiness determines whether this is a logical service map, architecture candidate, or insufficient model';
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
  document.getElementById('canonical-feature-select')?.addEventListener('change', event => {
    canonicalFeatureViewId = event.target.value || null;
    if (currentReport) {
      renderDiagram(currentReport);
      renderDiagramTextAlternative(currentReport);
    }
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
    canonicalUndoStack = [];
    canonicalRedoStack = [];
    document.body.classList.add('analysis-has-report');
    renderResults(report);
    document.getElementById('btn-view-report').style.display = '';
  } catch {
    // No report yet — show empty state
    document.body.classList.remove('analysis-has-report');
  }
}

function renderAnalysisRunState(report) {
  const panel = document.getElementById('analysis-run-state');
  const title = document.getElementById('analysis-run-state-title');
  const message = document.getElementById('analysis-run-state-message');
  const retry = document.getElementById('btn-retry-persisted-analysis');
  if (!panel || !title || !message) return;
  const run = report?.analysis_run;
  if (!run?.status || run.status === 'completed') {
    panel.style.display = 'none';
    return;
  }
  const status = String(run.status);
  const failed = status === 'failed';
  const warning = status === 'completed_with_warnings';
  const running = status === 'running';
  panel.style.display = 'flex';
  panel.classList.toggle('is-error', failed);
  title.textContent = failed ? 'Analysis failed safely' : warning ? 'Analysis completed with review warnings' : 'Analysis run was interrupted';
  const detail = run.error || (run.warning_stages?.length ? `Stages using baseline results: ${run.warning_stages.join(', ')}.` : 'The saved model remains available.');
  message.textContent = `${detail} ${running || failed ? 'The previous saved model was preserved.' : ''}`.trim();
  if (retry) {
    retry.style.display = failed || running || warning ? '' : 'none';
    retry.disabled = analysisIsRunning;
  }
}

async function retryPersistedAnalysis() {
  if (analysisIsRunning) return;
  setAnalysisRunning(true);
  const button = document.getElementById('btn-retry-persisted-analysis');
  if (button) button.disabled = true;
  try {
    const report = await API.analysis.retry(projectId);
    currentReport = report;
    renderResults(report);
    showToast(report.analysis_run?.status === 'completed_with_warnings' ? 'Analysis retried with review warnings.' : 'Analysis retry completed.', 'success');
  } catch (err) {
    showToast(`Analysis retry failed: ${userFacingAnalysisError(err.message)}`, 'error');
    try { await tryLoadExistingReport(); } catch (_) {}
  } finally {
    setAnalysisRunning(false);
    if (button) button.disabled = false;
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
  renderGraphCoverageSummary(report);
  renderDfdInventory(report);
  renderDiagramTextAlternative(report);
  renderThreats('stride-threats-list', 'st', stride);  // ← unique prefix 'st'
  renderThreats('linddun-threats-list', 'ln', linddun);// ← unique prefix 'ln'
  renderControls(visibility.controls);
  renderTests(visibility.tests);
  renderGaps(visibility.missingInfo, visibility.assumptions);
  renderAnalysisRunState(report);
  syncAnalysisStaleness(report);
  renderDfdProposal(report);
  syncDfdHistoryButtons();

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

function renderDfdProposal(report) {
  const panel = document.getElementById('dfd-proposal-panel');
  const summary = document.getElementById('dfd-proposal-summary');
  const sectionList = document.getElementById('dfd-proposal-sections');
  if (!panel) return;
  const proposal = report?.dfd_proposal;
  if (!proposal?.candidate_model) {
    panel.style.display = 'none';
    if (sectionList) sectionList.innerHTML = '';
    return;
  }
  const labels = {
    nodes: 'Nodes', data_objects: 'Data objects', flows: 'Flows', stores: 'Store metadata',
    zones: 'Zones', boundaries: 'Boundaries', questions: 'Questions',
  };
  const changedSections = Object.entries(proposal.sections || {})
    .filter(([, section]) => (section.added || []).length || (section.removed || []).length || (section.changed || []).length)
    .map(([name]) => name);
  const sections = changedSections.map(name => proposal.sections[name]);
  const changes = sections.reduce((total, section) => total
    + (section.added || []).length
    + (section.removed || []).length
    + (section.changed || []).length, 0);
  if (summary) {
    summary.textContent = `${changes} semantic change${changes === 1 ? '' : 's'} are ready for explicit review. Human edits remain active until applied.`;
  }
  if (sectionList) {
    sectionList.innerHTML = changedSections.map(name => `
      <label class="text-xs" style="display:inline-flex;align-items:center;gap:4px;">
        <input type="checkbox" value="${escHtml(name)}" checked /> ${escHtml(labels[name] || name)}
      </label>`).join('');
  }
  panel.style.display = 'flex';
}

async function applyDfdProposal() {
  if (!currentReport?.dfd_model?.revision || !currentReport?.dfd_proposal?.candidate_model) return;
  const previous = cloneCanonicalDfdModel(currentReport.dfd_model);
  const sections = [...document.querySelectorAll('#dfd-proposal-sections input[type="checkbox"]:checked')]
    .map(input => input.value);
  const availableSections = [...document.querySelectorAll('#dfd-proposal-sections input[type="checkbox"]')]
    .map(input => input.value);
  if (!sections.length) {
    showToast('Select at least one proposal section to apply', 'error');
    return;
  }
  const button = document.getElementById('btn-apply-dfd-proposal');
  if (button) {
    button.disabled = true;
    button.textContent = 'Applying…';
  }
  try {
    const response = await API.dfd.applyProposal(projectId, {
      expected_revision: currentReport.dfd_model.revision,
      ...(sections.length === availableSections.length ? { accept_all: true } : { sections }),
    });
    currentReport.dfd_model = response.model;
    currentReport.dfd_validation = response.validation;
    currentReport.dfd_proposal = response.proposal || null;
    canonicalUndoStack.push(previous);
    canonicalRedoStack = [];
    if (response.semantic_changed) {
      currentReport.analysis_stale = {
        stages: ['stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions'],
        reason: 'A reviewed DFD regeneration proposal changed the canonical semantic model. Refresh dependent analysis stages.',
        changed_at: new Date().toISOString(),
      };
    }
    renderResults(currentReport);
    syncDfdHistoryButtons();
    showToast('Reviewed DFD source changes applied. Refresh dependent analysis stages.', 'success');
  } catch (err) {
    showToast('Could not apply DFD proposal: ' + err.message, 'error');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Apply reviewed source changes';
    }
  }
}

async function dismissDfdProposal() {
  if (!currentReport?.dfd_model?.revision || !currentReport?.dfd_proposal?.candidate_model) return;
  if (!window.confirm('Dismiss this source regeneration proposal? The reviewed canonical DFD will remain authoritative.')) return;
  const button = document.getElementById('btn-dismiss-dfd-proposal');
  if (button) {
    button.disabled = true;
    button.textContent = 'Dismissing…';
  }
  try {
    const response = await API.dfd.dismissProposal(projectId, {
      expected_revision: currentReport.dfd_model.revision,
      action: 'dismiss',
    });
    currentReport.dfd_proposal = null;
    currentReport.dfd_proposal_resolution = response.resolution;
    if (currentReport.analysis_stale?.reason?.startsWith('Source context changed while a human-edited DFD exists')) {
      delete currentReport.analysis_stale;
    }
    renderResults(currentReport);
    showToast('DFD regeneration proposal dismissed; reviewed model remains active.', 'success');
  } catch (err) {
    showToast('Could not dismiss DFD proposal: ' + err.message, 'error');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Dismiss proposal';
    }
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
  if (report?.dfd_model?.flows?.length) {
    const nodes = new Map((report.dfd_model.nodes || []).map(node => [String(node.id), node]));
    const data = new Map((report.dfd_model.data_objects || []).map(item => [String(item.id), item]));
    return report.dfd_model.flows.map(flow => ({
      flow_id: flow.id,
      source: nodes.get(String(flow.source_id))?.name || flow.source_id,
      destination: nodes.get(String(flow.target_id))?.name || flow.target_id,
      source_id: flow.source_id,
      destination_id: flow.target_id,
      protocol: flow.protocol,
      data: (flow.data_object_ids || []).map(id => data.get(String(id))?.name || id),
      interaction_kind: flow.interaction_kind,
      boundary_crossings: flow.boundary_crossings || [],
      crossing_status: flow.crossing_status,
      evidence_refs: flow.evidence_refs || [],
    }));
  }
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
  const canonicalAvailable = Boolean(report?.dfd_model?.nodes?.length);
  document.getElementById('diagram-canvas-shell')?.classList.toggle('is-canonical', canonicalAvailable);
  // The canonical semantic model is the source of truth for the context DFD.
  // Legacy trust-model projections remain available for service/scenario views
  // until their feature decomposition editor is migrated.
  if (report?.dfd_model?.nodes?.length && ['context', 'services', 'scenarios'].includes(diagramLevel)) {
    renderCanonicalDiagram(report, diagramLevel === 'scenarios' ? 'feature' : diagramLevel === 'services' ? 'system' : 'context');
    return;
  }
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
  const model = report?.dfd_model;
  if (!model?.nodes?.length) return report?.trust_model?.views || {};
  const zones = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const nodes = (model.nodes || []).map(node => ({
    element_id: node.id,
    label: `${node.display_id || ''} ${node.name || ''}`.trim(),
    element_type: node.type === 'entity' ? 'external_entity' : node.type,
    trust_zone_id: node.zone_ids?.[0] || 'unknown',
    trust_level: node.knowledge_status || 'unknown',
    scope: node.scope,
    ownership: node.ownership,
    exposure: node.exposure,
    zone_label: (node.zone_ids || []).map(id => zones.get(id)?.name || id).join(' / '),
    evidence_refs: node.evidence_refs || [],
    model_level: 'context',
  }));
  const nodeById = new Map((model.nodes || []).map(node => [String(node.id), node]));
  const dataById = new Map((model.data_objects || []).map(item => [String(item.id), item]));
  const flows = (model.flows || []).map(flow => ({
    element_id: flow.id,
    flow_id: flow.id,
    label: `${flow.display_id || ''} ${flow.name || ''}`.trim(),
    element_type: 'data_flow',
    source_id: flow.source_id,
    destination_id: flow.target_id,
    source: nodeById.get(String(flow.source_id))?.name || flow.source_id,
    destination: nodeById.get(String(flow.target_id))?.name || flow.target_id,
    protocol: flow.protocol,
    data: (flow.data_object_ids || []).map(id => dataById.get(String(id))?.name || id),
    interaction_kind: flow.interaction_kind,
    boundary_crossings: flow.boundary_crossings || [],
    crossing_status: flow.crossing_status,
    evidence_refs: flow.evidence_refs || [],
    model_level: 'context',
  }));
  const boundaries = (model.boundaries || []).map(boundary => ({
    element_id: boundary.id,
    boundary_id: boundary.id,
    label: `${boundary.display_id || ''} ${boundary.name || ''}`.trim(),
    boundary_label: boundary.name,
    source: (boundary.source_zone_ids || []).map(id => zones.get(id)?.name || id).join(' / '),
    destination: (boundary.target_zone_ids || []).map(id => zones.get(id)?.name || id).join(' / '),
    crossing_flow_ids: boundary.crossing_flow_ids || [],
    status: boundary.status,
    types: boundary.types || [],
    model_level: 'context',
  }));
  return {
    context: { label: 'Canonical Context DFD', nodes, flows, boundaries },
    system: { label: 'Canonical System DFD', nodes, flows, boundaries },
    services: report?.trust_model?.views?.services || {},
    scenarios: report?.trust_model?.views?.scenarios || {},
    assets: { items: (model.data_objects || []).map(item => ({ element_id: item.id, label: item.name, ...item })) },
  };
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
    context: ['entity', 'external_entity', 'external_system', 'process', 'data_store', 'data_flow', 'trust_boundary'],
    services: ['process', 'data_store', 'external_system'],
    scenarios: ['scenario'],
  };
  const canonicalIds = report?.dfd_model?.nodes?.length && diagramLevel !== 'context'
    ? new Set((report.dfd_model.views || []).find(view =>
      diagramLevel === 'scenarios'
        ? view.id === (canonicalFeatureViewId || (report.dfd_model.views || []).find(item => item.kind === 'feature')?.id)
        : view.kind === 'system'
    )?.element_refs || [])
    : null;
  const levelMapped = threats.filter(item => canonicalIds
    ? targetRefs(item).some(ref => canonicalIds.has(String(ref.id)))
    : targetRefs(item).some(ref =>
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

function renderGraphCoverageSummary(report) {
  const el = document.getElementById('analysis-coverage-summary');
  if (!el) return;
  const summaries = Object.entries(report?.analysis_coverage_summary || {});
  if (!summaries.length) {
    el.style.display = 'none';
    el.innerHTML = '';
    return;
  }
  el.style.display = '';
  const privacy = report?.privacy_assessment;
  el.innerHTML = summaries.map(([framework, summary]) => `
    <span class="diagram-mapping-label">${escHtml(framework)} graph coverage</span>
    <span class="diagram-mapping-chip"><strong>${Number(summary.candidate_identified || 0)}</strong> candidate</span>
    <span class="diagram-mapping-chip"><strong>${Number(summary.reviewed_no_candidate || 0)}</strong> reviewed no candidate</span>
    <span class="diagram-mapping-chip ${summary.insufficient_information ? 'is-warning' : 'is-complete'}"><strong>${Number(summary.insufficient_information || 0)}</strong> insufficient information</span>
    <span class="diagram-mapping-help">Missing coverage is reviewable and is not treated as no threat.</span>
  `).join('') + (privacy ? `<span class="diagram-mapping-label">Privacy metadata</span><span class="diagram-mapping-chip ${privacy.status === 'documented' ? 'is-complete' : 'is-warning'}"><strong>${escHtml(privacy.status)}</strong> · ${Number(privacy.unresolved_count || 0)} unresolved</span><span class="diagram-mapping-help">Unknown privacy/lifecycle metadata remains reviewable context.</span>` : '');
}

function canonicalNodeVisualZone(node) {
  if (node.exposure === 'internet_facing') return 'untrusted';
  if (node.ownership === 'vendor' || node.scope === 'external_dependency') return 'external';
  if (node.type === 'data_store' || node.sensitivity) return 'privileged';
  if (node.exposure === 'unknown' || node.ownership === 'unknown' || node.scope === 'unknown') return 'unknown';
  return 'internal';
}

function renderDfdInventory(report) {
  const panel = document.getElementById('dfd-inventory-panel');
  const container = document.getElementById('dfd-inventory');
  const topologyStatus = document.getElementById('dfd-topology-status');
  const model = report?.dfd_model;
  if (topologyStatus) {
    const validation = report?.dfd_validation;
    const issues = validation?.semantic_issues || [];
    topologyStatus.hidden = !model || !issues.length;
    topologyStatus.innerHTML = issues.length ? `
      <strong>DFD topology needs review (${issues.length}):</strong>
      <ul>${issues.map(issue => `<li>${escHtml(issue)}</li>`).join('')}</ul>` : '';
  }
  if (!panel || !container) return;
  if (!model) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = '';
  const nodeById = new Map((model.nodes || []).map(node => [String(node.id), node]));
  const rows = [
    ...(model.nodes || []).map(node => ({
      type: 'node', id: node.id, displayId: node.display_id, name: node.name,
      detail: `${node.type} · ${node.scope} · ${node.ownership} · ${node.exposure}`,
    })),
    ...(model.flows || []).map(flow => ({
      type: 'flow', id: flow.id, displayId: flow.display_id, name: flow.name,
      detail: `${nodeById.get(String(flow.source_id))?.name || flow.source_id} → ${nodeById.get(String(flow.target_id))?.name || flow.target_id}`,
    })),
    ...(model.data_objects || []).map(item => ({
      type: 'data_object', id: item.id, displayId: item.display_id, name: item.name,
      detail: `data object · ${item.knowledge_status} · ${item.sensitivity || 'sensitivity unknown'} · ${privacyReadinessLabel(report, item.id)}`,
    })),
    ...(model.zones || []).map(zone => ({
      type: 'zone', id: zone.id, displayId: zone.display_id, name: zone.name,
      detail: `${zone.parent_zone_id ? `child of ${zone.parent_zone_id}` : 'top-level'} · ${zone.knowledge_status}`,
    })),
    ...(model.boundaries || []).map(boundary => ({
      type: 'boundary', id: boundary.id, displayId: boundary.display_id, name: boundary.name,
      detail: `${boundary.status} · ${(boundary.types || []).join(', ') || 'type unknown'}`,
    })),
    ...(model.questions || []).map(question => ({
      type: 'question', id: question.id, displayId: 'Q', name: question.question,
      detail: `${question.status} · ${(question.affected_refs || []).length} affected ref${(question.affected_refs || []).length === 1 ? '' : 's'}`,
    })),
  ];
  if (!rows.length) {
    container.innerHTML = '<p class="text-sm text-muted">The canonical model has no inventory elements yet.</p>';
    return;
  }
  container.innerHTML = `
    <div class="dfd-inventory-actions" role="group" aria-label="Add canonical DFD element">
      <button type="button" class="btn btn-secondary btn-sm" data-dfd-add-type="node">Add node</button>
      <button type="button" class="btn btn-secondary btn-sm" data-dfd-add-type="flow">Add flow</button>
      <button type="button" class="btn btn-secondary btn-sm" data-dfd-add-type="data_object">Add data object</button>
      <button type="button" class="btn btn-secondary btn-sm" data-dfd-add-type="zone">Add zone</button>
      <button type="button" class="btn btn-secondary btn-sm" data-dfd-add-type="boundary">Add boundary</button>
    </div>
    <div class="table-wrap" style="overflow:auto;">
      <table class="data-table" aria-label="Canonical DFD inventory">
        <thead><tr><th scope="col">ID</th><th scope="col">Element</th><th scope="col">Detail</th></tr></thead>
        <tbody>${rows.map(row => `
          <tr>
            <td><button type="button" class="btn btn-ghost btn-sm mono" data-dfd-select-type="${escHtml(row.type)}" data-dfd-select-id="${escHtml(row.id)}">${escHtml(row.displayId || row.id)}</button>${row.type === 'zone' ? `<button type="button" class="btn btn-secondary btn-sm" data-dfd-toggle-zone="${escHtml(row.id)}">${canonicalCollapsedZoneIds(model, canonicalRenderedViewKind).has(String(row.id)) ? 'Expand' : 'Collapse'}</button>` : ''}</td>
            <td>${escHtml(row.name)}</td>
            <td class="text-sm text-muted">${escHtml(row.detail)}</td>
          </tr>`).join('')}</tbody>
      </table>
    </div>`;
  container.querySelectorAll('[data-dfd-select-id]').forEach(button => {
    button.addEventListener('click', () => focusDfdElement(button.dataset.dfdSelectType, button.dataset.dfdSelectId));
  });
  container.querySelectorAll('[data-dfd-add-type]').forEach(button => {
    button.addEventListener('click', () => showDfdCreateInspector(button.dataset.dfdAddType));
  });
  container.querySelectorAll('[data-dfd-toggle-zone]').forEach(button => {
    button.addEventListener('click', () => toggleDfdZone(button.dataset.dfdToggleZone));
  });
}

function privacyReadinessRecord(report, dataObjectId) {
  return (report?.privacy_assessment?.data_objects || []).find(item => String(item.element_id) === String(dataObjectId));
}

function privacyReadinessLabel(report, dataObjectId) {
  const record = privacyReadinessRecord(report, dataObjectId);
  return record ? `privacy ${record.status}` : 'privacy context unknown';
}

function canonicalCollapsedZoneIds(model, viewKind) {
  const view = canonicalViewFor(model, viewKind);
  return new Set((view?.collapsed_groups || []).map(value => String(value)));
}

async function toggleDfdZone(zoneId) {
  const model = cloneCanonicalDfdModel(currentReport?.dfd_model);
  if (!model) return;
  const view = canonicalViewFor(model, canonicalRenderedViewKind);
  if (!view) return;
  const collapsed = canonicalCollapsedZoneIds(model, canonicalRenderedViewKind);
  if (collapsed.has(String(zoneId))) collapsed.delete(String(zoneId));
  else collapsed.add(String(zoneId));
  view.collapsed_groups = [...collapsed].sort();
  await persistCanonicalDfdModel(model, {
    message: collapsed.has(String(zoneId)) ? 'DFD zone collapsed' : 'DFD zone expanded',
  });
}

function focusDfdElement(type, id) {
  const model = currentReport?.dfd_model;
  if (!model) return;
  switchTab('diagram');
  window.setTimeout(() => {
    if (type === 'node') {
      const node = diagramNetwork?.body?.data?.nodes?.get(id);
      if (node) {
        diagramNetwork.selectNodes([id]);
        showNodeInspector(node);
      }
      return;
    }
    if (type === 'flow') {
      const edge = diagramNetwork?.body?.data?.edges?.get(id);
      if (edge) {
        diagramNetwork.selectEdges([id]);
        showFlowInspector(edge);
      }
      return;
    }
    if (type === 'boundary') {
      const boundary = (model.boundaries || []).find(item => String(item.id) === String(id));
      if (boundary) showBoundaryInspector(boundary);
      return;
    }
    if (type === 'zone') {
      const zone = (model.zones || []).find(item => String(item.id) === String(id));
      if (zone) showZoneInspector(zone);
      return;
    }
    if (type === 'data_object') {
      const dataObject = (model.data_objects || []).find(item => String(item.id) === String(id));
      if (dataObject) showDataObjectInspector(dataObject);
      return;
    }
    const question = (model.questions || []).find(item => String(item.id) === String(id));
    if (question) showDfdQuestionInspector(question);
  }, 120);
}

function dfdRandomId(prefix) {
  const uuid = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${uuid}`;
}

function nextDfdDisplayId(items, prefix) {
  const max = (items || []).reduce((highest, item) => {
    const match = String(item.display_id || '').match(new RegExp(`^${prefix}(\\d+)$`, 'i'));
    return Math.max(highest, match ? Number(match[1]) : 0);
  }, 0);
  return `${prefix}${max + 1}`;
}

function lineValues(value) {
  return String(value || '').split('\n').map(item => item.trim()).filter(Boolean);
}

function dfdZoneOptions(model, selected = null, includeBlank = false) {
  const selectedSet = new Set(Array.isArray(selected) ? selected : selected ? [selected] : []);
  return `${includeBlank ? '<option value="">Top-level / none</option>' : ''}${(model.zones || []).map(zone =>
    `<option value="${escHtml(zone.id)}" ${selectedSet.has(zone.id) ? 'selected' : ''}>${escHtml(`${zone.display_id} ${zone.name}`)}</option>`
  ).join('')}`;
}

function syncDfdViews(model) {
  const semanticIds = [
    ...(model.nodes || []).map(item => item.id),
    ...(model.data_objects || []).map(item => item.id),
    ...(model.flows || []).map(item => item.id),
    ...(model.boundaries || []).map(item => item.id),
  ];
  (model.views || []).forEach(view => {
    if (view.kind === 'context' || view.kind === 'system') {
      const refs = new Set(view.element_refs || []);
      semanticIds.forEach(id => refs.add(id));
      view.element_refs = [...refs];
      view.projection_mappings = { ...(view.projection_mappings || {}) };
      semanticIds.forEach(id => { view.projection_mappings[id] = view.projection_mappings[id] || [id]; });
    }
    if (view.kind === 'feature' && view.parent_process_id) {
      const relatedFlows = (model.flows || []).filter(flow => flow.source_id === view.parent_process_id || flow.target_id === view.parent_process_id);
      const relatedNodes = new Set([view.parent_process_id, ...relatedFlows.flatMap(flow => [flow.source_id, flow.target_id])]);
      const relatedData = new Set(relatedFlows.flatMap(flow => flow.data_object_ids || []));
      const refs = [...new Set([...relatedNodes, ...relatedFlows.map(flow => flow.id), ...relatedData])];
      view.element_refs = refs;
      view.projection_mappings = Object.fromEntries(refs.map(id => [id, [id]]));
      view.input_flow_ids = relatedFlows.filter(flow => flow.target_id === view.parent_process_id).map(flow => flow.id).sort();
      view.output_flow_ids = relatedFlows.filter(flow => flow.source_id === view.parent_process_id).map(flow => flow.id).sort();
      view.port_mappings = { input: [...view.input_flow_ids], output: [...view.output_flow_ids] };
    }
  });
}

function showDfdCreateInspector(type) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  const model = currentReport?.dfd_model;
  if (!inspector || !title || !body || !model) return;
  const nodeOptions = (model.nodes || []).map(node => `<option value="${escHtml(node.id)}">${escHtml(`${node.display_id} ${node.name}`)}</option>`).join('');
  const dataOptions = (model.data_objects || []).map(item => `<option value="${escHtml(item.id)}">${escHtml(`${item.display_id} ${item.name}`)}</option>`).join('');
  const typeForms = {
    node: `<label class="form-label">Node type<select class="form-select" data-dfd-create-field="type"><option value="process">process</option><option value="entity">entity</option><option value="data_store">data_store</option></select></label>
      <label class="form-label">Name<input class="form-input" data-dfd-create-field="name" maxlength="240" required /></label>
      <div class="dfd-editor-grid"><label class="form-label">Scope<select class="form-select" data-dfd-create-field="scope"><option>in_scope</option><option>external_dependency</option><option selected>unknown</option></select></label><label class="form-label">Ownership<select class="form-select" data-dfd-create-field="ownership"><option>organization</option><option>customer</option><option>vendor</option><option>shared</option><option selected>unknown</option></select></label><label class="form-label">Exposure<select class="form-select" data-dfd-create-field="exposure"><option>internet_facing</option><option>private</option><option>local</option><option selected>unknown</option></select></label></div>
      <label class="form-label">Trust zones<select class="form-select" data-dfd-create-field="zone_ids" multiple size="${Math.min(4, Math.max(2, (model.zones || []).length))}">${dfdZoneOptions(model)}</select></label>
      <label class="form-label">Evidence references<textarea class="form-input" data-dfd-create-field="evidence_refs" rows="2" placeholder="One evidence reference per line"></textarea></label>`,
    flow: `<label class="form-label">Source<select class="form-select" data-dfd-create-field="source_id">${nodeOptions}</select></label><label class="form-label">Destination<select class="form-select" data-dfd-create-field="target_id">${nodeOptions}</select></label><label class="form-label">Data flow name<input class="form-input" data-dfd-create-field="name" maxlength="240" required /></label><div class="dfd-editor-grid"><label class="form-label">Interaction<select class="form-select" data-dfd-create-field="interaction_kind">${['request', 'response', 'event', 'read', 'write', 'replication', 'unknown'].map(value => `<option value="${value}">${value}</option>`).join('')}</select></label><label class="form-label">Protocol<input class="form-input" data-dfd-create-field="protocol" maxlength="120" /></label></div><label class="form-label">Data objects<select class="form-select" data-dfd-create-field="data_object_ids" multiple size="${Math.min(5, Math.max(2, (model.data_objects || []).length))}">${dataOptions}</select></label><label class="form-label">Evidence references<textarea class="form-input" data-dfd-create-field="evidence_refs" rows="2" placeholder="One evidence reference per line"></textarea></label>`,
    data_object: `<label class="form-label">Data object name<input class="form-input" data-dfd-create-field="name" maxlength="240" required /></label><label class="form-label">Fields<textarea class="form-input" data-dfd-create-field="fields" rows="2" placeholder="One field per line"></textarea></label><div class="dfd-editor-grid"><label class="form-label">Classification<input class="form-input" data-dfd-create-field="classification" /></label><label class="form-label">Sensitivity<input class="form-input" data-dfd-create-field="sensitivity" /></label></div><label class="form-label">Data subjects<textarea class="form-input" data-dfd-create-field="data_subjects" rows="2" placeholder="One subject per line"></textarea></label><label class="form-label">Direct identifiers<textarea class="form-input" data-dfd-create-field="direct_identifiers" rows="2" placeholder="One identifier per line"></textarea></label><label class="form-label">Indirect identifiers / linkability<textarea class="form-input" data-dfd-create-field="indirect_identifiers" rows="2" placeholder="One identifier per line"></textarea></label><label class="form-label">Purpose<textarea class="form-input" data-dfd-create-field="purpose" rows="2"></textarea></label><label class="form-label">Recipients<textarea class="form-input" data-dfd-create-field="recipients" rows="2" placeholder="One recipient per line"></textarea></label><label class="form-label">Linkability<input class="form-input" data-dfd-create-field="linkability" placeholder="unknown / bounded / cross-context" /></label><label class="form-label">Notice<textarea class="form-input" data-dfd-create-field="notice" rows="2"></textarea></label><label class="form-label">Individual control<textarea class="form-input" data-dfd-create-field="individual_control" rows="2"></textarea></label><label class="form-label">Documented legal basis<textarea class="form-input" data-dfd-create-field="legal_basis" rows="2"></textarea></label><label class="form-label">Evidence references<textarea class="form-input" data-dfd-create-field="evidence_refs" rows="2" placeholder="One evidence reference per line"></textarea></label>`,
    zone: `<label class="form-label">Zone name<input class="form-input" data-dfd-create-field="name" maxlength="180" required /></label><label class="form-label">Parent zone<select class="form-select" data-dfd-create-field="parent_zone_id">${dfdZoneOptions(model, null, true)}</select></label><label class="form-label">Trust assumptions<textarea class="form-input" data-dfd-create-field="trust_assumptions" rows="2" placeholder="One assumption per line"></textarea></label><label class="form-label">Evidence references<textarea class="form-input" data-dfd-create-field="evidence_refs" rows="2" placeholder="One evidence reference per line"></textarea></label>`,
    boundary: `<label class="form-label">Boundary name<input class="form-input" data-dfd-create-field="name" maxlength="180" required /></label><label class="form-label">Boundary types<select class="form-select" data-dfd-create-field="types" multiple size="5">${['network', 'identity', 'privilege', 'tenant', 'organization'].map(value => `<option value="${value}">${value}</option>`).join('')}</select></label><label class="form-label">Source zones<select class="form-select" data-dfd-create-field="source_zone_ids" multiple size="4">${dfdZoneOptions(model)}</select></label><label class="form-label">Target zones<select class="form-select" data-dfd-create-field="target_zone_ids" multiple size="4">${dfdZoneOptions(model)}</select></label><label class="form-label">Rationale<textarea class="form-input" data-dfd-create-field="rationale" rows="2"></textarea></label><label class="form-label">Evidence references<textarea class="form-input" data-dfd-create-field="evidence_refs" rows="2" placeholder="One evidence reference per line"></textarea></label>`,
  };
  if (!typeForms[type]) return;
  title.textContent = `Add DFD ${type.replace('_', ' ')}`;
  body.innerHTML = `<form class="dfd-node-editor" data-dfd-create-editor><div class="node-model-meta">New semantic element · unknown values remain reviewable</div>${typeForms[type]}<button type="button" class="btn btn-primary btn-sm" data-save-dfd-create>Create element</button></form>`;
  body.querySelector('[data-save-dfd-create]')?.addEventListener('click', () => saveDfdCreate(type, body));
  inspector.style.display = 'block';
  inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function saveDfdCreate(type, body) {
  const model = cloneCanonicalDfdModel(currentReport?.dfd_model);
  if (!model) return;
  const read = field => body.querySelector(`[data-dfd-create-field="${field}"]`);
  const selected = field => [...(read(field)?.selectedOptions || [])].map(option => option.value);
  const name = read('name')?.value.trim();
  if (!name) { showToast('Name is required', 'error'); return; }
  if (type === 'node') {
    const nodeType = read('type')?.value || 'process';
    const node = {
      id: dfdRandomId('node'), display_id: nextDfdDisplayId(model.nodes, nodeType === 'entity' ? 'E' : nodeType === 'data_store' ? 'D' : 'P'), type: nodeType, name,
      description: null, scope: read('scope')?.value || 'unknown', ownership: read('ownership')?.value || 'unknown', operator_control_party: null,
      exposure: read('exposure')?.value || 'unknown', zone_ids: selected('zone_ids'), parent_process_id: null, knowledge_status: 'unknown', implementation_status: 'unknown', evidence_refs: lineValues(read('evidence_refs')?.value), assertions: [],
      process_metadata: nodeType === 'process' ? { purpose: null, execution_identity: null, privileges: [], input_flow_ids: [], output_flow_ids: [], transformations: [], control_refs: [] } : null,
    };
    model.nodes.push(node);
    if (nodeType === 'data_store') model.stores[node.id] = { data_object_ids: [], readers: [], writers: [], retention: null, deletion: null, backup: null, protection_controls: [], evidence_refs: [] };
    if (nodeType === 'process') model.views.push({ id: `view-feature-${node.id}`, kind: 'feature', parent_process_id: node.id, element_refs: [node.id], projection_mappings: { [node.id]: [node.id] }, input_flow_ids: [], output_flow_ids: [], port_mappings: { input: [], output: [] }, positions: {}, collapsed_groups: [], viewport: {} });
  } else if (type === 'flow') {
    const sourceId = read('source_id')?.value;
    const targetId = read('target_id')?.value;
    if (!sourceId || !targetId || sourceId === targetId) { showToast('Select distinct source and destination nodes', 'error'); return; }
    model.flows.push({ id: dfdRandomId('flow'), display_id: nextDfdDisplayId(model.flows, 'F'), source_id: sourceId, target_id: targetId, name, data_object_ids: selected('data_object_ids'), protocol: read('protocol')?.value.trim() || null, interaction_kind: read('interaction_kind')?.value || 'unknown', authn: null, authz: null, boundary_crossings: [], crossing_rationales: {}, crossing_origins: {}, crossing_status: 'resolved', evidence_refs: lineValues(read('evidence_refs')?.value), knowledge_status: 'unknown', implementation_status: 'unknown' });
  } else if (type === 'data_object') {
    model.data_objects.push({ id: dfdRandomId('data-object'), display_id: nextDfdDisplayId(model.data_objects, 'DO'), name, fields: lineValues(read('fields')?.value), classification: read('classification')?.value.trim() || null, data_subjects: lineValues(read('data_subjects')?.value), identifiers: [], direct_identifiers: lineValues(read('direct_identifiers')?.value), indirect_identifiers: lineValues(read('indirect_identifiers')?.value), sensitivity: read('sensitivity')?.value.trim() || null, purpose: read('purpose')?.value.trim() || null, recipients: lineValues(read('recipients')?.value), linkability: read('linkability')?.value.trim() || null, notice: read('notice')?.value.trim() || null, individual_control: read('individual_control')?.value.trim() || null, legal_basis: read('legal_basis')?.value.trim() || null, transformation_refs: [], lineage_refs: [], knowledge_status: 'unknown', evidence_refs: lineValues(read('evidence_refs')?.value), assertions: [] });
  } else if (type === 'zone') {
    model.zones.push({ id: dfdRandomId('zone'), display_id: nextDfdDisplayId(model.zones, 'Z'), name, description: null, parent_zone_id: read('parent_zone_id')?.value || null, ownership_group_id: null, trust_assumptions: lineValues(read('trust_assumptions')?.value), knowledge_status: 'unknown', evidence_refs: lineValues(read('evidence_refs')?.value) });
  } else if (type === 'boundary') {
    model.boundaries.push({ id: dfdRandomId('boundary'), display_id: nextDfdDisplayId(model.boundaries, 'TB'), name, types: selected('types'), rationale: read('rationale')?.value.trim() || null, source_zone_ids: selected('source_zone_ids'), target_zone_ids: selected('target_zone_ids'), crossing_flow_ids: [], transition_scope: 'zone', controls: [], assertions: [], status: 'unresolved', derived: false, evidence_refs: lineValues(read('evidence_refs')?.value) });
  }
  syncDfdViews(model);
  await persistCanonicalDfdModel(model, { message: `DFD ${type.replace('_', ' ')} added` });
}

function dfdDeleteButtonHtml(type, id) {
  return `<button type="button" class="btn btn-danger btn-sm" data-delete-dfd-element data-delete-type="${escHtml(type)}" data-delete-id="${escHtml(id)}">Delete ${escHtml(type.replace('_', ' '))}</button>`;
}

function wireDfdDeleteButton(body) {
  body.querySelector('[data-delete-dfd-element]')?.addEventListener('click', event => {
    const button = event.currentTarget;
    deleteDfdElement(button.dataset.deleteType, button.dataset.deleteId);
  });
}

async function deleteDfdElement(type, id) {
  if (!currentReport?.dfd_model) return;
  try {
    const impact = await API.dfd.impactPreview(projectId, type, id);
    const dependencies = ['dependent_nodes', 'dependent_flows', 'dependent_views', 'dependent_boundaries', 'dependent_zones', 'dependent_questions', 'dependent_threats']
      .map(key => `${key.replace('dependent_', '')}: ${(impact[key] || []).length}`).join(', ');
    const message = `Delete ${impact.label || id}?\n\nImpact preview: ${dependencies}.\n\nThis changes the canonical DFD and marks threat analysis stale.`;
    if (!window.confirm(message)) return;
    const model = cloneCanonicalDfdModel(currentReport.dfd_model);
    if (type === 'node') {
      model.nodes = model.nodes.filter(item => item.id !== id);
      model.flows = model.flows.filter(flow => flow.source_id !== id && flow.target_id !== id);
      Object.keys(model.stores || {}).forEach(key => { if (key === id) delete model.stores[key]; });
      model.nodes.forEach(node => { if (node.parent_process_id === id) node.parent_process_id = null; });
      model.views = (model.views || []).filter(view => view.parent_process_id !== id);
    } else if (type === 'data_object') {
      model.data_objects = model.data_objects.filter(item => item.id !== id);
      model.flows.forEach(flow => { flow.data_object_ids = (flow.data_object_ids || []).filter(value => value !== id); });
      Object.values(model.stores || {}).forEach(store => { store.data_object_ids = (store.data_object_ids || []).filter(value => value !== id); });
    } else if (type === 'flow') {
      model.flows = model.flows.filter(item => item.id !== id);
      model.boundaries.forEach(boundary => { boundary.crossing_flow_ids = (boundary.crossing_flow_ids || []).filter(value => value !== id); });
    } else if (type === 'zone') {
      model.zones = model.zones.filter(item => item.id !== id);
      model.nodes.forEach(node => { node.zone_ids = (node.zone_ids || []).filter(value => value !== id); });
      model.zones.forEach(zone => { if (zone.parent_zone_id === id) zone.parent_zone_id = null; });
      model.boundaries.forEach(boundary => { boundary.source_zone_ids = (boundary.source_zone_ids || []).filter(value => value !== id); boundary.target_zone_ids = (boundary.target_zone_ids || []).filter(value => value !== id); });
    } else if (type === 'boundary') {
      model.boundaries = model.boundaries.filter(item => item.id !== id);
      model.flows.forEach(flow => { flow.boundary_crossings = (flow.boundary_crossings || []).filter(value => value !== id); delete flow.crossing_rationales?.[id]; delete flow.crossing_origins?.[id]; });
    }
    model.questions = (model.questions || []).map(question => ({ ...question, affected_refs: (question.affected_refs || []).filter(value => value !== id) }));
    model.views = (model.views || []).map(view => ({ ...view, element_refs: (view.element_refs || []).filter(value => value !== id), input_flow_ids: (view.input_flow_ids || []).filter(value => value !== id), output_flow_ids: (view.output_flow_ids || []).filter(value => value !== id), port_mappings: Object.fromEntries(Object.entries(view.port_mappings || {}).map(([key, refs]) => [key, (refs || []).filter(value => value !== id)])), projection_mappings: Object.fromEntries(Object.entries(view.projection_mappings || {}).filter(([key]) => key !== id).map(([key, refs]) => [key, (refs || []).filter(value => value !== id)])) }));
    syncDfdViews(model);
    await persistCanonicalDfdModel(model, { message: 'DFD element deleted' });
  } catch (error) {
    showToast(`Could not delete DFD element: ${userFacingAnalysisError(error.message)}`, 'error');
  }
}

function showDataObjectInspector(dataObject) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;
  const privacy = privacyReadinessRecord(currentReport, dataObject.id);
  const privacySummary = privacy ? `<div class="analysis-stale-notice ${privacy.status === 'documented' ? '' : 'is-error'}" style="display:flex;margin-bottom:var(--space-3);"><div><strong>Privacy context: ${escHtml(privacy.status)}</strong><span>${privacy.missing_fields?.length ? `Missing: ${escHtml(privacy.missing_fields.join(', '))}` : 'Required privacy metadata is documented.'}</span></div></div>` : '';
  title.textContent = `${dataObject.display_id || dataObject.id} ${dataObject.name}`;
  body.innerHTML = `${privacySummary}<form class="dfd-node-editor" data-dfd-data-editor>
    <div class="node-model-meta">${escHtml(dataObject.id)} · data object · ${escHtml(dataObject.knowledge_status)}</div>
    <label class="form-label">Name<input class="form-input" data-dfd-data-field="name" value="${escHtml(dataObject.name)}" maxlength="240" required /></label>
    <label class="form-label">Fields<textarea class="form-input" data-dfd-data-field="fields" rows="3">${escHtml((dataObject.fields || []).join('\n'))}</textarea></label>
    <div class="dfd-editor-grid"><label class="form-label">Classification<input class="form-input" data-dfd-data-field="classification" value="${escHtml(dataObject.classification || '')}" /></label><label class="form-label">Sensitivity<input class="form-input" data-dfd-data-field="sensitivity" value="${escHtml(dataObject.sensitivity || '')}" /></label></div>
    <label class="form-label">Data subjects<textarea class="form-input" data-dfd-data-field="data_subjects" rows="2">${escHtml((dataObject.data_subjects || []).join('\n'))}</textarea></label>
    <label class="form-label">Identifiers<textarea class="form-input" data-dfd-data-field="identifiers" rows="2">${escHtml((dataObject.identifiers || []).join('\n'))}</textarea></label>
    <div class="dfd-editor-grid"><label class="form-label">Direct identifiers<textarea class="form-input" data-dfd-data-field="direct_identifiers" rows="2">${escHtml((dataObject.direct_identifiers || []).join('\n'))}</textarea></label><label class="form-label">Indirect identifiers<textarea class="form-input" data-dfd-data-field="indirect_identifiers" rows="2">${escHtml((dataObject.indirect_identifiers || []).join('\n'))}</textarea></label></div>
    <label class="form-label">Purpose<textarea class="form-input" data-dfd-data-field="purpose" rows="2">${escHtml(dataObject.purpose || '')}</textarea></label>
    <label class="form-label">Recipients<textarea class="form-input" data-dfd-data-field="recipients" rows="2">${escHtml((dataObject.recipients || []).join('\n'))}</textarea></label>
    <label class="form-label">Linkability<input class="form-input" data-dfd-data-field="linkability" value="${escHtml(dataObject.linkability || '')}" placeholder="unknown / bounded / cross-context" /></label>
    <label class="form-label">Notice<textarea class="form-input" data-dfd-data-field="notice" rows="2">${escHtml(dataObject.notice || '')}</textarea></label>
    <label class="form-label">Individual control<textarea class="form-input" data-dfd-data-field="individual_control" rows="2">${escHtml(dataObject.individual_control || '')}</textarea></label>
    <label class="form-label">Documented legal basis<textarea class="form-input" data-dfd-data-field="legal_basis" rows="2">${escHtml(dataObject.legal_basis || '')}</textarea></label>
    <label class="form-label">Evidence references<textarea class="form-input" data-dfd-data-field="evidence_refs" rows="2" placeholder="One evidence reference per line">${escHtml((dataObject.evidence_refs || []).join('\n'))}</textarea></label>
    <button type="button" class="btn btn-primary btn-sm" data-save-dfd-data>Save data metadata</button>
    ${dfdDeleteButtonHtml('data_object', dataObject.id)}
  </form>`;
  body.querySelector('[data-save-dfd-data]')?.addEventListener('click', () => saveDataObject(dataObject.id, body));
  wireDfdDeleteButton(body);
  inspector.style.display = 'block';
  inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function saveDataObject(dataObjectId, body) {
  const model = cloneCanonicalDfdModel(currentReport?.dfd_model);
  const item = (model?.data_objects || []).find(value => String(value.id) === String(dataObjectId));
  if (!item) return;
  const read = field => body.querySelector(`[data-dfd-data-field="${field}"]`);
  item.name = read('name')?.value.trim();
  if (!item.name) { showToast('Data object name is required', 'error'); return; }
  item.fields = lineValues(read('fields')?.value); item.classification = read('classification')?.value.trim() || null; item.sensitivity = read('sensitivity')?.value.trim() || null; item.data_subjects = lineValues(read('data_subjects')?.value); item.identifiers = lineValues(read('identifiers')?.value); item.direct_identifiers = lineValues(read('direct_identifiers')?.value); item.indirect_identifiers = lineValues(read('indirect_identifiers')?.value); item.purpose = read('purpose')?.value.trim() || null; item.recipients = lineValues(read('recipients')?.value); item.linkability = read('linkability')?.value.trim() || null; item.notice = read('notice')?.value.trim() || null; item.individual_control = read('individual_control')?.value.trim() || null; item.legal_basis = read('legal_basis')?.value.trim() || null; item.evidence_refs = lineValues(read('evidence_refs')?.value);
  const button = body.querySelector('[data-save-dfd-data]'); if (button) button.disabled = true;
  await persistCanonicalDfdModel(model, { message: 'DFD data metadata saved' });
}

function showBoundaryInspector(boundary) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;
  const threats = uniqueThreats(analysisVisibility(currentReport).threats.filter(threat =>
    targetMatches(threat, boundary.id, 'trust_boundary')
  ));
  title.textContent = `${boundary.display_id || boundary.id} ${boundary.name}`;
  const types = ['network', 'identity', 'privilege', 'tenant', 'organization', 'unknown'];
  body.innerHTML = `
    <form class="dfd-node-editor" data-dfd-boundary-editor>
      <div class="node-model-meta">${escHtml(boundary.display_id || boundary.id)} · ${escHtml(boundary.source_zone_ids.join(' → ') || 'zone transition unknown')}</div>
      <label class="form-label">Boundary name<input class="form-input" data-dfd-boundary-field="name" value="${escHtml(boundary.name)}" maxlength="180" required /></label>
      <div class="dfd-editor-grid">
        <label class="form-label">Status<select class="form-select" data-dfd-boundary-field="status">${['candidate', 'confirmed', 'rejected', 'unresolved'].map(value => `<option value="${value}" ${boundary.status === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label>
        <label class="form-label">Transition<select class="form-select" data-dfd-boundary-field="transition_scope">${['zone', 'logical', 'mixed', 'unknown'].map(value => `<option value="${value}" ${boundary.transition_scope === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label>
      </div>
      <label class="form-label">Boundary types<select class="form-select" data-dfd-boundary-field="types" multiple size="4">${types.map(value => `<option value="${value}" ${(boundary.types || []).includes(value) ? 'selected' : ''}>${value}</option>`).join('')}</select></label>
      <label class="form-label">Rationale<textarea class="form-input" data-dfd-boundary-field="rationale" rows="3" maxlength="1000">${escHtml(boundary.rationale || '')}</textarea></label>
      <label class="form-label">Evidence references<textarea class="form-input" data-dfd-boundary-field="evidence_refs" rows="2" placeholder="One evidence reference per line">${escHtml((boundary.evidence_refs || []).join('\n'))}</textarea></label>
      <div class="dfd-editor-actions"><button type="button" class="btn btn-primary btn-sm" data-save-dfd-boundary>Save boundary metadata</button>${dfdDeleteButtonHtml('boundary', boundary.id)}</div>
    </form>
    <div class="inspector-findings"><strong>${threats.length} mapped finding${threats.length === 1 ? '' : 's'}</strong></div>`;
  body.querySelector('[data-save-dfd-boundary]')?.addEventListener('click', () => saveCanonicalBoundary(boundary.id, body));
  wireDfdDeleteButton(body);
  inspector.style.display = 'block';
  inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function saveCanonicalBoundary(boundaryId, body) {
  const model = cloneCanonicalDfdModel(currentReport.dfd_model);
  const boundary = (model.boundaries || []).find(item => String(item.id) === String(boundaryId));
  if (!boundary) return;
  const read = field => body.querySelector(`[data-dfd-boundary-field="${field}"]`);
  boundary.name = read('name')?.value.trim();
  boundary.status = read('status')?.value || 'unresolved';
  boundary.transition_scope = read('transition_scope')?.value || 'unknown';
  boundary.types = [...(read('types')?.selectedOptions || [])].map(option => option.value);
  boundary.rationale = read('rationale')?.value.trim() || null;
  boundary.evidence_refs = lineValues(read('evidence_refs')?.value);
  const button = body.querySelector('[data-save-dfd-boundary]');
  if (button) button.disabled = true;
  await persistCanonicalDfdModel(model, { message: 'DFD boundary metadata saved' });
}

function showZoneInspector(zone) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;
  const model = currentReport?.dfd_model;
  const parentOptions = (model?.zones || []).filter(item => item.id !== zone.id).map(item =>
    `<option value="${escHtml(item.id)}" ${item.id === zone.parent_zone_id ? 'selected' : ''}>${escHtml(`${item.display_id} ${item.name}`)}</option>`
  ).join('');
  title.textContent = `${zone.display_id || zone.id} ${zone.name}`;
  body.innerHTML = `
    <form class="dfd-node-editor" data-dfd-zone-editor>
      <div class="node-model-meta">${escHtml(zone.id)} · ${zone.parent_zone_id ? `parent ${escHtml(zone.parent_zone_id)}` : 'top-level zone'}</div>
      <label class="form-label">Zone name<input class="form-input" data-dfd-zone-field="name" value="${escHtml(zone.name)}" maxlength="180" required /></label>
      <label class="form-label">Parent zone<select class="form-select" data-dfd-zone-field="parent_zone_id"><option value="">Top-level</option>${parentOptions}</select></label>
      <label class="form-label">Description<textarea class="form-input" data-dfd-zone-field="description" rows="2" maxlength="1000">${escHtml(zone.description || '')}</textarea></label>
      <label class="form-label">Trust assumptions<textarea class="form-input" data-dfd-zone-field="trust_assumptions" rows="2" placeholder="One assumption per line">${escHtml((zone.trust_assumptions || []).join('\n'))}</textarea></label>
      <label class="form-label">Evidence references<textarea class="form-input" data-dfd-zone-field="evidence_refs" rows="2" placeholder="One evidence reference per line">${escHtml((zone.evidence_refs || []).join('\n'))}</textarea></label>
      <div class="dfd-editor-actions"><button type="button" class="btn btn-primary btn-sm" data-save-dfd-zone>Save zone metadata</button>${dfdDeleteButtonHtml('zone', zone.id)}</div>
    </form>`;
  body.querySelector('[data-save-dfd-zone]')?.addEventListener('click', () => saveCanonicalZone(zone.id, body));
  wireDfdDeleteButton(body);
  inspector.style.display = 'block';
  inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function saveCanonicalZone(zoneId, body) {
  const model = cloneCanonicalDfdModel(currentReport.dfd_model);
  const zone = (model.zones || []).find(item => String(item.id) === String(zoneId));
  if (!zone) return;
  const read = field => body.querySelector(`[data-dfd-zone-field="${field}"]`);
  zone.name = read('name')?.value.trim();
  zone.parent_zone_id = read('parent_zone_id')?.value || null;
  zone.description = read('description')?.value.trim() || null;
  zone.trust_assumptions = (read('trust_assumptions')?.value || '').split('\n').map(value => value.trim()).filter(Boolean);
  zone.evidence_refs = lineValues(read('evidence_refs')?.value);
  const button = body.querySelector('[data-save-dfd-zone]');
  if (button) button.disabled = true;
  await persistCanonicalDfdModel(model, { message: 'DFD zone metadata saved' });
}

function showDfdQuestionInspector(question) {
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;
  title.textContent = `Question ${question.id}`;
  body.innerHTML = `
    <form class="dfd-node-editor" data-dfd-question-editor>
      <div class="node-model-meta">affected: ${(question.affected_refs || []).join(', ') || 'none'}</div>
      <p style="font-weight:600;">${escHtml(question.question)}</p>
      <p class="text-sm text-muted">${escHtml(question.reason)}</p>
      ${question.source_refs?.length ? `<div class="text-xs text-muted">Sources: ${question.source_refs.map(escHtml).join(', ')}</div>` : ''}
      <label class="form-label">Review status<select class="form-select" data-dfd-question-field="status">${['open', 'answered', 'deferred'].map(value => `<option value="${value}" ${question.status === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label>
      <label class="form-label">Resolution<textarea class="form-input" data-dfd-question-field="resolution" rows="3" maxlength="1200" placeholder="Record the evidence or decision that resolves this question">${escHtml(question.resolution || '')}</textarea></label>
      <button type="button" class="btn btn-primary btn-sm" data-save-dfd-question>Save question review</button>
    </form>`;
  body.querySelector('[data-save-dfd-question]')?.addEventListener('click', () => saveDfdQuestion(question.id, body));
  inspector.style.display = 'block';
  inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function saveDfdQuestion(questionId, body) {
  const model = cloneCanonicalDfdModel(currentReport?.dfd_model);
  const question = (model?.questions || []).find(item => String(item.id) === String(questionId));
  if (!question) return;
  const read = field => body.querySelector(`[data-dfd-question-field="${field}"]`);
  question.status = read('status')?.value || 'open';
  question.resolution = read('resolution')?.value.trim() || null;
  const button = body.querySelector('[data-save-dfd-question]');
  if (button) button.disabled = true;
  await persistCanonicalDfdModel(model, { message: 'DFD question review saved' });
}

function focusThreatTargets(threatId) {
  const threat = (currentReport?.threats || []).find(item => String(item.threat_id) === String(threatId));
  const model = currentReport?.dfd_model;
  if (!threat || !model) return;
  const refs = targetRefs(threat);
  const nodeIds = new Set();
  const flowIds = new Set();
  const dataObjectIds = new Set();
  const boundaryIds = new Set();
  refs.forEach(ref => {
    if (['entity', 'process', 'data_store'].includes(ref.type)) nodeIds.add(String(ref.id));
    if (ref.type === 'data_flow') flowIds.add(String(ref.id));
    if (ref.type === 'data_object') dataObjectIds.add(String(ref.id));
    if (ref.type === 'trust_boundary') boundaryIds.add(String(ref.id));
  });
  (model.flows || []).forEach(flow => {
    if ((flow.data_object_ids || []).some(id => dataObjectIds.has(String(id)))
      || (flow.boundary_crossings || []).some(id => boundaryIds.has(String(id)))) {
      flowIds.add(String(flow.id));
    }
  });
  switchTab('diagram');
  window.setTimeout(() => {
    if (diagramLevel === 'services' && !canonicalShowUnconnected && [...nodeIds].some(id => !diagramNetwork?.body.data.nodes.get(id))) {
      canonicalShowUnconnected = true;
      renderDiagram(currentReport);
    }
    if (!diagramNetwork) return;
    const visibleNodeIds = [...nodeIds].filter(id => diagramNetwork.body.data.nodes.get(id));
    const visibleFlowIds = [...flowIds].filter(id => diagramNetwork.body.data.edges.get(id));
    diagramNetwork.selectNodes(visibleNodeIds);
    diagramNetwork.selectEdges(visibleFlowIds);
    const firstNode = visibleNodeIds.length ? diagramNetwork.body.data.nodes.get(visibleNodeIds[0]) : null;
    const firstFlow = visibleFlowIds.length ? diagramNetwork.body.data.edges.get(visibleFlowIds[0]) : null;
    if (firstNode) showNodeInspector(firstNode);
    else if (firstFlow) showFlowInspector(firstFlow);
    if (!visibleNodeIds.length && !visibleFlowIds.length) {
      showToast('This threat has no visible canonical target references', 'warn');
    }
  }, 120);
}

function canonicalSortKey(node) {
  return `${node.display_id || ''} ${node.name || ''}`.toLocaleLowerCase();
}

function canonicalLayoutPositions(model, visibleNodes, visibleFlows, viewKind, selectedView = null) {
  const view = selectedView || (model.views || []).find(item => item.kind === viewKind) || (model.views || []).find(item => item.kind === 'context');
  const saved = view?.positions || {};
  const hasCompleteSavedLayout = visibleNodes.length > 0 && visibleNodes.every(node => {
    const position = saved[node.id];
    return Number.isFinite(Number(position?.x)) && Number.isFinite(Number(position?.y));
  });
  if (hasCompleteSavedLayout) {
    const positions = Object.fromEntries(visibleNodes.map(node => [node.id, {
      x: Number(saved[node.id].x),
      y: Number(saved[node.id].y),
    }]));
    const maxX = Math.max(...Object.values(positions).map(position => position.x), 0);
    const maxY = Math.max(...Object.values(positions).map(position => position.y), 0);
    const minX = Math.min(...Object.values(positions).map(position => position.x), 0);
    const minY = Math.min(...Object.values(positions).map(position => position.y), 0);
    return { positions, bounds: { width: maxX - minX + 300, height: maxY - minY + 220 } };
  }
  if (viewKind === 'system' && visibleFlows.length) {
    const systemLayout = canonicalSystemZoneLayout(model, visibleNodes, visibleFlows);
    if (systemLayout) return systemLayout;
  }

  const nodeById = new Map(visibleNodes.map(node => [String(node.id), node]));
  const nodeIds = visibleNodes.map(node => String(node.id));
  const adjacency = new Map(nodeIds.map(id => [id, new Set()]));
  const usableFlows = visibleFlows.filter(flow => nodeById.has(String(flow.source_id)) && nodeById.has(String(flow.target_id)));
  usableFlows.forEach(flow => {
    const source = String(flow.source_id);
    const target = String(flow.target_id);
    adjacency.get(source)?.add(target);
    adjacency.get(target)?.add(source);
  });

  const components = [];
  const remaining = new Set(nodeIds);
  while (remaining.size) {
    const start = [...remaining].sort()[0];
    const queue = [start];
    const component = [];
    remaining.delete(start);
    while (queue.length) {
      const current = queue.shift();
      component.push(current);
      [...(adjacency.get(current) || [])].sort().forEach(next => {
        if (remaining.has(next)) {
          remaining.delete(next);
          queue.push(next);
        }
      });
    }
    components.push(component);
  }

  const componentRecords = components.map(ids => ({
    ids,
    nodes: ids.map(id => nodeById.get(id)).filter(Boolean),
    flows: usableFlows.filter(flow => ids.includes(String(flow.source_id)) && ids.includes(String(flow.target_id))),
  })).sort((a, b) => {
    if (b.flows.length !== a.flows.length) return b.flows.length - a.flows.length;
    if (b.nodes.length !== a.nodes.length) return b.nodes.length - a.nodes.length;
    return canonicalSortKey(a.nodes[0]).localeCompare(canonicalSortKey(b.nodes[0]));
  });

  const positions = {};
  let nextTop = 90;
  const placeConnectedComponent = component => {
    const ranks = new Map(component.ids.map(id => [id, 0]));
    for (let pass = 0; pass < component.ids.length; pass += 1) {
      let changed = false;
      component.flows.forEach(flow => {
        const source = String(flow.source_id);
        const target = String(flow.target_id);
        const nextRank = Math.min(4, (ranks.get(source) || 0) + 1);
        if (nextRank > (ranks.get(target) || 0)) {
          ranks.set(target, nextRank);
          changed = true;
        }
      });
      if (!changed) break;
    }
    const groups = new Map();
    component.nodes.forEach(node => {
      const rank = ranks.get(String(node.id)) || 0;
      if (!groups.has(rank)) groups.set(rank, []);
      groups.get(rank).push(node);
    });
    [...groups.values()].forEach(group => group.sort((a, b) => canonicalSortKey(a).localeCompare(canonicalSortKey(b))));
    const maxRows = Math.max(...[...groups.values()].map(group => group.length), 1);
    const componentHeight = Math.max(190, maxRows * 112 + 78);
    const centerY = nextTop + componentHeight / 2;
    [...groups.entries()].sort((a, b) => a[0] - b[0]).forEach(([rank, group]) => {
      group.forEach((node, index) => {
        positions[node.id] = {
          x: 170 + Number(rank) * 275,
          y: centerY + (index - (group.length - 1) / 2) * 112,
        };
      });
    });
    nextTop += componentHeight;
  };

  componentRecords.filter(component => component.flows.length).forEach(component => {
    placeConnectedComponent(component);
    nextTop += 80;
  });

  const isolatedNodes = componentRecords
    .filter(component => !component.flows.length)
    .flatMap(component => component.nodes)
    .sort((a, b) => canonicalSortKey(a).localeCompare(canonicalSortKey(b)));
  if (isolatedNodes.length) {
    const columns = Math.min(5, Math.max(3, Math.ceil(Math.sqrt(isolatedNodes.length))));
    isolatedNodes.forEach((node, index) => {
      positions[node.id] = {
        x: 170 + (index % columns) * 220,
        y: nextTop + Math.floor(index / columns) * 112,
      };
    });
    nextTop += (Math.ceil(isolatedNodes.length / columns) - 1) * 112 + 180;
  }

  const zoneLayout = canonicalCompactZoneLayout(model, visibleNodes, positions);
  const laidOutPositions = zoneLayout.positions;
  const values = Object.values(laidOutPositions);
  const maxX = Math.max(...values.map(position => position.x), 0);
  const minX = Math.min(...values.map(position => position.x), 0);
  const maxY = Math.max(...values.map(position => position.y), 0);
  const minY = Math.min(...values.map(position => position.y), 0);
  return { positions: laidOutPositions, bounds: { width: maxX - minX + 300, height: maxY - minY + 220 } };
}

function canonicalTopZoneId(zoneId, zonesById) {
  let current = zonesById.get(String(zoneId));
  const visited = new Set();
  while (current?.parent_zone_id && zonesById.has(String(current.parent_zone_id)) && !visited.has(String(current.id))) {
    visited.add(String(current.id));
    current = zonesById.get(String(current.parent_zone_id));
  }
  return current?.id ? String(current.id) : '__unknown__';
}

function canonicalSystemZoneLayout(model, visibleNodes, visibleFlows) {
  const zonesById = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const nodeById = new Map(visibleNodes.map(node => [String(node.id), node]));
  const topZone = node => canonicalTopZoneId(String(node.zone_ids?.[0] || ''), zonesById);
  const zoneGroups = new Map();
  visibleNodes.forEach(node => {
    const id = topZone(node);
    if (!zoneGroups.has(id)) zoneGroups.set(id, []);
    zoneGroups.get(id).push(node);
  });
  const degrees = new Map(visibleNodes.map(node => [String(node.id), 0]));
  const zoneDegrees = new Map([...zoneGroups.keys()].map(id => [id, 0]));
  const connectedIds = new Set();
  visibleFlows.forEach(flow => {
    const source = nodeById.get(String(flow.source_id));
    const target = nodeById.get(String(flow.target_id));
    if (!source || !target) return;
    connectedIds.add(String(source.id));
    connectedIds.add(String(target.id));
    degrees.set(String(source.id), (degrees.get(String(source.id)) || 0) + 1);
    degrees.set(String(target.id), (degrees.get(String(target.id)) || 0) + 1);
    if (topZone(source) !== topZone(target)) {
      zoneDegrees.set(topZone(source), (zoneDegrees.get(topZone(source)) || 0) + 1);
      zoneDegrees.set(topZone(target), (zoneDegrees.get(topZone(target)) || 0) + 1);
    }
  });
  const rankedZones = [...zoneGroups.keys()].sort((a, b) =>
    (zoneDegrees.get(b) || 0) - (zoneDegrees.get(a) || 0)
    || zoneGroups.get(b).length - zoneGroups.get(a).length
    || a.localeCompare(b));
  const hubZone = rankedZones[0];
  if (!hubZone || (zoneDegrees.get(hubZone) || 0) === 0) return null;
  const orderedNodes = nodes => [...nodes].sort((a, b) =>
    Number(connectedIds.has(String(b.id))) - Number(connectedIds.has(String(a.id)))
    || (degrees.get(String(b.id)) || 0) - (degrees.get(String(a.id)) || 0)
    || canonicalSortKey(a).localeCompare(canonicalSortKey(b)));
  const positions = {};
  const hubNodes = orderedNodes(zoneGroups.get(hubZone));
  const hubX = 440;
  positions[hubNodes[0].id] = { x: hubX, y: 130 };
  hubNodes.slice(1).forEach((node, index) => {
    positions[node.id] = { x: hubX + ((index % 3) - 1) * 200, y: 260 + Math.floor(index / 3) * 115 };
  });
  const hubBottom = Math.max(...hubNodes.map(node => positions[node.id].y));
  const satelliteTop = hubBottom + 240;
  const satellites = rankedZones.slice(1).filter(id => (zoneDegrees.get(id) || 0) > 0);
  let satelliteLeft = 80;
  let satelliteBottom = satelliteTop;
  satellites.forEach(id => {
    const nodes = orderedNodes(zoneGroups.get(id));
    const columns = Math.min(2, nodes.length);
    nodes.forEach((node, index) => {
      positions[node.id] = { x: satelliteLeft + (index % columns) * 200, y: satelliteTop + Math.floor(index / columns) * 115 };
    });
    satelliteBottom = Math.max(satelliteBottom, ...nodes.map(node => positions[node.id].y));
    satelliteLeft += columns * 200 + 170;
  });
  const isolatedZones = rankedZones.slice(1).filter(id => (zoneDegrees.get(id) || 0) === 0);
  let isolatedTop = satelliteBottom + 235;
  isolatedZones.forEach(id => {
    const nodes = orderedNodes(zoneGroups.get(id));
    nodes.forEach((node, index) => {
      positions[node.id] = { x: 240 + (index % 3) * 200, y: isolatedTop + Math.floor(index / 3) * 115 };
    });
    isolatedTop += Math.ceil(nodes.length / 3) * 115 + 90;
  });
  return { positions, bounds: { width: Math.max(900, satelliteLeft + 80), height: Math.max(680, isolatedTop + 100) } };
}

function canonicalCompactZoneLayout(model, visibleNodes, basePositions) {
  const zones = model.zones || [];
  const zonesById = new Map(zones.map(zone => [String(zone.id), zone]));
  const topGroups = new Map();
  visibleNodes.forEach(node => {
    const directZone = String(node.zone_ids?.[0] || '__unknown__');
    const topZone = canonicalTopZoneId(directZone, zonesById);
    if (!topGroups.has(topZone)) topGroups.set(topZone, []);
    topGroups.get(topZone).push({ node, directZone });
  });
  const orderedTopZones = [...topGroups.keys()].sort((a, b) => {
    const aIndex = zones.findIndex(zone => String(zone.id) === a);
    const bIndex = zones.findIndex(zone => String(zone.id) === b);
    return (aIndex < 0 ? Number.MAX_SAFE_INTEGER : aIndex) - (bIndex < 0 ? Number.MAX_SAFE_INTEGER : bIndex);
  });
  const positions = {};
  let laneTop = 95;
  let maxWidth = 1100;
  orderedTopZones.forEach(topZoneId => {
    const subGroups = new Map();
    topGroups.get(topZoneId).forEach(record => {
      if (!subGroups.has(record.directZone)) subGroups.set(record.directZone, []);
      subGroups.get(record.directZone).push(record.node);
    });
    let laneWidth = 0;
    let laneHeight = 0;
    [...subGroups.entries()].forEach(([, nodes], groupIndex) => {
      nodes.sort((a, b) => {
        const left = basePositions[a.id] || { x: 0, y: 0 };
        const right = basePositions[b.id] || { x: 0, y: 0 };
        return left.y - right.y || left.x - right.x || canonicalSortKey(a).localeCompare(canonicalSortKey(b));
      });
      const columns = Math.min(5, Math.max(1, Math.ceil(Math.sqrt(nodes.length))));
      const groupLeft = 155 + groupIndex * 270;
      const rows = Math.max(1, Math.ceil(nodes.length / columns));
      nodes.forEach((node, index) => {
        positions[node.id] = {
          x: groupLeft + (index % columns) * 220,
          y: laneTop + 100 + Math.floor(index / columns) * 112,
        };
      });
      laneWidth = Math.max(laneWidth, groupLeft + Math.max(0, columns - 1) * 220 + 220);
      laneHeight = Math.max(laneHeight, rows * 112 + 155);
    });
    maxWidth = Math.max(maxWidth, laneWidth);
    laneTop += laneHeight + 70;
  });
  return { positions, bounds: { width: maxWidth, height: laneTop + 80 } };
}

function canonicalZoneDepth(zoneId, zonesById, memo = new Map()) {
  if (memo.has(zoneId)) return memo.get(zoneId);
  const zone = zonesById.get(String(zoneId));
  if (!zone?.parent_zone_id || !zonesById.has(String(zone.parent_zone_id))) {
    memo.set(zoneId, 0);
    return 0;
  }
  const depth = canonicalZoneDepth(String(zone.parent_zone_id), zonesById, memo) + 1;
  memo.set(zoneId, depth);
  return depth;
}

function canonicalZoneDescendants(zoneId, zonesById, memo = new Map()) {
  if (memo.has(zoneId)) return memo.get(zoneId);
  const descendants = [String(zoneId)];
  [...zonesById.values()].filter(zone => String(zone.parent_zone_id || '') === String(zoneId)).forEach(child => {
    descendants.push(...canonicalZoneDescendants(String(child.id), zonesById, memo));
  });
  memo.set(zoneId, descendants);
  return descendants;
}

function canonicalViewFor(model, viewKind) {
  if (!model) return null;
  if (viewKind === 'feature') {
    return (model.views || []).find(view => view.id === canonicalFeatureViewId)
      || (model.views || []).find(view => view.kind === 'feature');
  }
  return (model.views || []).find(view => view.kind === viewKind)
    || (model.views || []).find(view => view.kind === 'context');
}

function restoreCanonicalViewport(model) {
  if (!diagramNetwork || !model) return false;
  const view = canonicalViewFor(model, canonicalRenderedViewKind);
  const viewport = view?.viewport || {};
  const x = Number(viewport.x);
  const y = Number(viewport.y);
  const scale = Number(viewport.scale);
  if (![x, y, scale].every(Number.isFinite) || scale <= 0) return false;
  diagramNetwork.moveTo({ position: { x, y }, scale, animation: false });
  return true;
}

function renderCanonicalZoneLayer(model, visibleNodes) {
  const layer = document.getElementById('diagram-zone-layer');
  if (!layer) return;
  const zonesById = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const descendantMemo = new Map();
  const depthMemo = new Map();
  const visibleIds = new Set(visibleNodes.map(node => String(node.id)));
  const records = (model.zones || []).map(zone => {
    const zoneIds = new Set(canonicalZoneDescendants(String(zone.id), zonesById, descendantMemo));
    const nodeIds = visibleNodes.filter(node => (node.zone_ids || []).some(id => zoneIds.has(String(id)))).map(node => String(node.id));
    return { zone, nodeIds, depth: canonicalZoneDepth(String(zone.id), zonesById, depthMemo) };
  }).filter(record => record.nodeIds.length);
  layer.innerHTML = records.map(record => `
    <div class="diagram-zone" data-zone-id="${escHtml(record.zone.id)}" data-zone-depth="${record.depth}" style="z-index:${record.depth + 1};">
      <span>${escHtml(`${record.zone.display_id || record.zone.id} · ${record.zone.name}`)}</span>
    </div>`).join('');
  layer.dataset.zoneCount = String(records.length);
  updateCanonicalZoneLayer(model, visibleIds);
}

function updateCanonicalZoneLayer(model, visibleIds = null) {
  if (!diagramNetwork) return;
  const layer = document.getElementById('diagram-zone-layer');
  if (!layer) return;
  const positions = diagramNetwork.getPositions();
  const visualNodes = diagramNetwork.body.data.nodes.get();
  const visible = visibleIds || new Set(Object.keys(positions));
  layer.querySelectorAll('[data-zone-id]').forEach(element => {
    const zoneId = element.dataset.zoneId;
    const zone = (model.zones || []).find(item => String(item.id) === String(zoneId));
    if (!zone) return;
    const zoneIds = new Set(canonicalZoneDescendants(String(zone.id), new Map((model.zones || []).map(item => [String(item.id), item]))));
    const points = visualNodes.filter(node => visible.has(String(node.id)) && (node.zone_ids || []).some(id => zoneIds.has(String(id))))
      .map(node => positions[node.id])
      .filter(Boolean)
      .map(position => diagramNetwork.canvasToDOM(position));
    if (!points.length) {
      element.style.display = 'none';
      return;
    }
    const depth = Number(element.dataset.zoneDepth || 0);
    const paddingX = 105 + depth * 14;
    const paddingTop = 58 + depth * 10;
    const paddingBottom = 55 + depth * 10;
    const left = Math.min(...points.map(point => point.x)) - paddingX;
    const top = Math.min(...points.map(point => point.y)) - paddingTop;
    const right = Math.max(...points.map(point => point.x)) + paddingX;
    const bottom = Math.max(...points.map(point => point.y)) + paddingBottom;
    element.style.display = '';
    element.style.left = `${Math.max(4, left)}px`;
    element.style.top = `${Math.max(4, top)}px`;
    element.style.width = `${Math.max(150, right - left)}px`;
    element.style.height = `${Math.max(110, bottom - top)}px`;
    element.title = `${zone.display_id || zone.id} ${zone.name} · ${points.length} visible node${points.length === 1 ? '' : 's'}`;
  });
}

function canonicalVisualProjection(model, nodes, flows, collapsedGroups) {
  const zonesById = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const groups = new Map();
  const nodeTarget = new Map();
  const collapsedRoot = node => {
    for (const zoneId of node.zone_ids || []) {
      let current = String(zoneId);
      const visited = new Set();
      while (current && !visited.has(current)) {
        if (collapsedGroups.has(current)) return current;
        visited.add(current);
        current = String(zonesById.get(current)?.parent_zone_id || '');
      }
    }
    return null;
  };
  const visualNodes = [];
  nodes.forEach(node => {
    const root = collapsedRoot(node);
    if (!root) {
      visualNodes.push(node);
      nodeTarget.set(String(node.id), String(node.id));
      return;
    }
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(node);
  });
  groups.forEach((members, zoneId) => {
    const zone = zonesById.get(zoneId);
    const groupId = `dfd-group-${zoneId}`;
    visualNodes.push({
      id: groupId,
      display_id: `G${zone?.display_id || zoneId}`,
      type: 'process',
      name: `${zone?.name || zoneId} (${members.length} nodes)`,
      scope: 'unknown',
      ownership: 'unknown',
      exposure: 'unknown',
      zone_ids: [zoneId],
      knowledge_status: 'inferred',
      _collapsedZoneId: zoneId,
      _collapsedNodeIds: members.map(node => node.id),
    });
    members.forEach(node => nodeTarget.set(String(node.id), groupId));
  });
  const projectedFlows = new Map();
  flows.forEach(flow => {
    const sourceId = nodeTarget.get(String(flow.source_id));
    const targetId = nodeTarget.get(String(flow.target_id));
    if (!sourceId || !targetId || sourceId === targetId) return;
    const key = `${sourceId}::${targetId}`;
    const existing = projectedFlows.get(key);
    if (existing) {
      existing._collapsedFlowIds.push(flow.id);
      existing.data_object_ids = [...new Set([...(existing.data_object_ids || []), ...(flow.data_object_ids || [])])];
      existing.name = existing._collapsedFlowIds.length > 1 ? `${existing.name} (+${existing._collapsedFlowIds.length - 1})` : existing.name;
      return;
    }
    projectedFlows.set(key, {
      ...flow,
      source_id: sourceId,
      target_id: targetId,
      _collapsedFlowIds: [flow.id],
    });
  });
  return { nodes: visualNodes, flows: [...projectedFlows.values()] };
}

function renderCanonicalDiagram(report, viewKind = 'context') {
  const container = document.getElementById('threat-diagram-canvas');
  if (!container) return;
  document.getElementById('diagram-canvas-shell')?.classList.add('is-canonical');
  if (diagramNetwork) { diagramNetwork.destroy(); diagramNetwork = null; }
  container.innerHTML = '';
  const model = report.dfd_model;
  const zones = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const dataObjects = new Map((model.data_objects || []).map(item => [String(item.id), item]));
  const threats = analysisVisibility(report).threats;
  const featureViews = (model.views || []).filter(view => view.kind === 'feature' && view.parent_process_id);
  const featureSelect = document.getElementById('canonical-feature-select');
  if (featureSelect) {
    if (!featureViews.some(view => view.id === canonicalFeatureViewId)) canonicalFeatureViewId = featureViews[0]?.id || null;
    featureSelect.innerHTML = featureViews.map(view => {
      const parent = (model.nodes || []).find(node => node.id === view.parent_process_id);
      return `<option value="${escHtml(view.id)}" ${view.id === canonicalFeatureViewId ? 'selected' : ''}>${escHtml(parent?.name || view.parent_process_id)}</option>`;
    }).join('');
  }
  const selectedFeature = viewKind === 'feature'
    ? featureViews.find(view => view.id === canonicalFeatureViewId) || featureViews[0]
    : null;
  const visibleRefs = selectedFeature ? new Set(selectedFeature.element_refs || []) : null;
  const allVisibleNodes = visibleRefs ? (model.nodes || []).filter(node => visibleRefs.has(node.id)) : (model.nodes || []);
  const allVisibleFlows = visibleRefs ? (model.flows || []).filter(flow => visibleRefs.has(flow.id)) : (model.flows || []);
  const connectedNodeIds = new Set(allVisibleFlows.flatMap(flow => [String(flow.source_id), String(flow.target_id)]));
  const hiddenUnconnectedCount = viewKind === 'system' && !canonicalShowUnconnected
    ? allVisibleNodes.filter(node => !connectedNodeIds.has(String(node.id))).length : 0;
  const baseVisibleNodes = hiddenUnconnectedCount
    ? allVisibleNodes.filter(node => connectedNodeIds.has(String(node.id))) : allVisibleNodes;
  const baseNodeIds = new Set(baseVisibleNodes.map(node => String(node.id)));
  const baseVisibleFlows = allVisibleFlows.filter(flow => baseNodeIds.has(String(flow.source_id)) && baseNodeIds.has(String(flow.target_id)));
  const collapsedGroups = canonicalCollapsedZoneIds(model, viewKind);
  const visualProjection = canonicalVisualProjection(model, baseVisibleNodes, baseVisibleFlows, collapsedGroups);
  const visibleNodes = visualProjection.nodes;
  const visibleFlows = visualProjection.flows;
  const unconnectedButton = document.getElementById('btn-diagram-unconnected');
  if (unconnectedButton) {
    unconnectedButton.hidden = viewKind !== 'system' || !allVisibleNodes.some(node => !connectedNodeIds.has(String(node.id)));
    unconnectedButton.textContent = canonicalShowUnconnected ? 'Hide unconnected' : `Show unconnected (${hiddenUnconnectedCount})`;
    unconnectedButton.setAttribute('aria-pressed', String(canonicalShowUnconnected));
  }
  const layout = canonicalLayoutPositions(model, visibleNodes, visibleFlows, viewKind, selectedFeature);
  canonicalRenderedViewKind = viewKind;
  const shell = document.getElementById('diagram-canvas-shell');
  if (shell) shell.style.height = `${Math.max(680, Math.min(1100, Math.ceil(layout.bounds.height)))}px`;
  const nodeRows = visibleNodes.map(node => {
    const zoneId = String(node.zone_ids?.[0] || 'unknown');
    const mapped = uniqueThreats(threats.filter(threat => targetMatches(threat, node.id)));
    const critical = mapped.filter(item => item.risk_level === 'Critical').length;
    const high = mapped.filter(item => item.risk_level === 'High').length;
    const visualZone = canonicalNodeVisualZone(node);
    const color = visualZone === 'unknown' ? getTrustColor('default') : getTrustColor(visualZone);
    const position = layout.positions[node.id];
    const zone = zones.get(zoneId);
    const status = `${node.scope || 'unknown'} · ${node.ownership || 'unknown'} · ${node.exposure || 'unknown'}`;
    return {
      id: node.id,
      label: `${node.display_id || node.id} ${node.name}${mapped.length ? `\n${mapped.length} finding${mapped.length === 1 ? '' : 's'}` : ''}`,
      title: `${node.display_id || node.id} ${node.name}\nType: ${node.type}\nZone: ${zone?.name || 'unknown'}\n${status}`,
      x: position?.x ?? 170,
      y: position?.y ?? 90,
      shape: node.type === 'data_store' ? 'database' : node.type === 'entity' ? 'ellipse' : 'box',
      color: { background: color.bg, border: critical ? '#DC2626' : high ? '#D97706' : color.border, highlight: { background: color.bg, border: '#1D3557' } },
      font: { color: color.font, size: 13, face: 'Space Grotesk, sans-serif', bold: true },
      borderWidth: node.knowledge_status === 'unknown' || visualZone === 'unknown' ? 1 : 2,
      borderDashes: node.knowledge_status === 'unknown' || visualZone === 'unknown',
      margin: 14,
      widthConstraint: { minimum: 150, maximum: 240 },
      _trustLevel: visualZone,
      _threats: mapped,
      _origLabel: `${node.display_id || node.id} ${node.name}`,
      _elementId: node.id,
      _modelMeta: `${node.type} · ${zone?.name || 'zone unknown'} · ${status}${node.knowledge_status ? ` · knowledge=${node.knowledge_status}` : ''}`,
    };
  });
  const nodeById = new Map(visibleNodes.map(node => [String(node.id), node]));
  const edgeRows = visibleFlows.map(flow => {
    const source = nodeById.get(String(flow.source_id));
    const target = nodeById.get(String(flow.target_id));
    const mapped = uniqueThreats(threats.filter(threat =>
      targetMatches(threat, flow.id, 'data_flow')
      || targetMatches(threat, flow.boundary_crossings || [], 'trust_boundary')
    ));
    const data = (flow.data_object_ids || []).map(id => dataObjects.get(String(id))?.name || id);
    const crossing = (flow.boundary_crossings || []).length > 0 || flow.crossing_status === 'unresolved';
    const crossingText = flow.crossing_status === 'unresolved'
      ? 'Boundary crossing unresolved — review zone membership.'
      : `Crossings: ${(flow.boundary_crossings || []).join(', ') || 'none'}`;
    return {
      id: flow.id,
      from: flow.source_id,
      to: flow.target_id,
      label: `${flow.display_id || flow.id} · ${compactFlowText(data[0] || flow.name || 'unknown data', 26)}${mapped.length ? `\n${mapped.length} findings` : ''}`,
      title: `${flow.display_id || flow.id}: ${source?.name || flow.source_id} → ${target?.name || flow.target_id}\n${data.join(', ') || 'Data label unknown'}\nInteraction: ${flow.interaction_kind}\n${crossingText}`,
      arrows: { to: { enabled: true, scaleFactor: .75 } },
      dashes: crossing ? [8, 6] : false,
      color: { color: flow.crossing_status === 'unresolved' ? '#B7791F' : crossing ? '#D06B55' : '#6C91AA', highlight: '#1D3557', hover: '#1D3557' },
      width: crossing ? 2 : 1.7,
      font: { size: 12, color: '#344E5C', face: 'JetBrains Mono, monospace', background: 'rgba(255,255,255,.96)', strokeWidth: 0, align: 'horizontal' },
      smooth: { enabled: true, type: 'cubicBezier', forceDirection: 'horizontal', roundness: .22 },
      _sourceLabel: source?.name || flow.source_id,
      _destinationLabel: target?.name || flow.target_id,
      _flowDetails: [
        `${flow.display_id || flow.id}: ${flow.name || 'unknown data'}`,
        flow._collapsedFlowIds?.length > 1 ? `Aggregated flows: ${flow._collapsedFlowIds.join(', ')}` : null,
        `Interaction: ${flow.interaction_kind}`,
        `Data: ${data.join(', ') || 'unknown'}`,
        `Protocol: ${flow.protocol || 'unknown'}`,
        `AuthN: ${flow.authn || 'unknown'} · AuthZ: ${flow.authz || 'unknown'}`,
        crossingText,
        `Evidence: ${(flow.evidence_refs || []).join(', ') || 'none'}`,
      ],
      _crossing: crossing,
      _logical: flow.crossing_status === 'resolved' && !(flow.boundary_crossings || []).length,
      _threats: mapped,
    };
  });
  if (!nodeRows.length) {
    container.innerHTML = '<div class="diagram-grounded-empty"><strong>Canonical DFD is empty</strong><span>Add or confirm model elements before running threat analysis.</span></div>';
    return;
  }
  const data = { nodes: new vis.DataSet(nodeRows), edges: new vis.DataSet(edgeRows) };
  renderCanonicalZoneLayer(model, visibleNodes);
  const toolbarTitle = document.querySelector('.diagram-toolbar-title');
  const toolbarSubtitle = document.querySelector('.diagram-toolbar-sub');
  if (toolbarTitle) toolbarTitle.textContent = viewKind === 'feature'
    ? `Feature DFD · ${selectedFeature?.parent_process_id || 'process'}`
    : viewKind === 'system' ? 'Canonical System DFD' : 'Canonical Context DFD';
  const visualConnectedNodeIds = new Set(visibleFlows.flatMap(flow => [String(flow.source_id), String(flow.target_id)]));
  const isolatedCount = visibleNodes.filter(node => !visualConnectedNodeIds.has(String(node.id))).length;
  if (toolbarSubtitle) toolbarSubtitle.textContent = `Revision ${model.revision} · ${visibleNodes.length} nodes · ${visibleFlows.length} flows · ${hiddenUnconnectedCount ? `${hiddenUnconnectedCount} unconnected nodes in inventory · ` : isolatedCount ? `${isolatedCount} nodes without grounded flow · ` : ''}unknown values remain reviewable`;
  diagramNetwork = new vis.Network(container, data, {
    physics: false,
    interaction: { hover: true, tooltipDelay: 180, zoomView: true, dragView: true, keyboard: { enabled: true, bindToWindow: false } },
    nodes: { chosen: true },
    edges: { selectionWidth: 2.5, hoverWidth: 2.2 },
  });
  diagramNetwork.once('afterDrawing', () => {
    if (!restoreCanonicalViewport(model)) {
      diagramNetwork.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
    }
    window.requestAnimationFrame(() => updateCanonicalZoneLayer(model, new Set(visibleNodes.map(node => String(node.id)))));
  });
  diagramNetwork.on('zoom', () => updateCanonicalZoneLayer(model, new Set(visibleNodes.map(node => String(node.id)))));
  diagramNetwork.on('dragging', () => updateCanonicalZoneLayer(model, new Set(visibleNodes.map(node => String(node.id)))));
  diagramNetwork.on('click', params => {
    if (params.nodes.length) {
      const selected = data.nodes.get(params.nodes[0]);
      if (selected?._collapsedZoneId) {
        const zone = (model.zones || []).find(item => String(item.id) === String(selected._collapsedZoneId));
        if (zone) showZoneInspector(zone);
      } else showNodeInspector(selected);
    }
    else if (params.edges.length) showFlowInspector(data.edges.get(params.edges[0]));
    else document.getElementById('node-inspector').style.display = 'none';
  });
  diagramNetwork.on('dragEnd', () => {
    updateCanonicalZoneLayer(model, new Set(visibleNodes.map(node => String(node.id))));
    scheduleCanonicalLayoutSave();
  });
}

function scheduleCanonicalLayoutSave() {
  if (!currentReport?.dfd_model || !diagramNetwork) return;
  window.clearTimeout(canonicalLayoutSaveTimer);
  canonicalLayoutSaveTimer = window.setTimeout(async () => {
    const model = JSON.parse(JSON.stringify(currentReport.dfd_model));
    const view = canonicalViewFor(model, canonicalRenderedViewKind);
    if (!view) return;
    const positions = diagramNetwork.getPositions();
    view.positions = {
      ...(view.positions || {}),
      ...Object.fromEntries(Object.entries(positions).map(([id, position]) => [id, {
        x: Number(position.x.toFixed(2)),
        y: Number(position.y.toFixed(2)),
      }])),
    };
    const viewport = diagramNetwork.getViewPosition();
    const scale = diagramNetwork.getScale();
    if (viewport && Number.isFinite(Number(viewport.x)) && Number.isFinite(Number(viewport.y)) && Number.isFinite(Number(scale)) && Number(scale) > 0) {
      view.viewport = {
        x: Number(Number(viewport.x).toFixed(2)),
        y: Number(Number(viewport.y).toFixed(2)),
        scale: Number(Number(scale).toFixed(4)),
      };
    }
    await persistCanonicalDfdModel(model, { render: false, message: 'DFD layout saved' });
  }, 450);
}

function cloneCanonicalDfdModel(model) {
  return model ? JSON.parse(JSON.stringify(model)) : null;
}

function syncDfdHistoryButtons() {
  const hasModel = Boolean(currentReport?.dfd_model);
  const undo = document.getElementById('btn-dfd-undo');
  const redo = document.getElementById('btn-dfd-redo');
  if (undo) undo.disabled = !hasModel || canonicalUndoStack.length === 0;
  if (redo) redo.disabled = !hasModel || canonicalRedoStack.length === 0;
}

async function persistCanonicalDfdModel(model, {
  render = true,
  message = 'Canonical DFD saved',
  recordHistory = true,
} = {}) {
  const previous = cloneCanonicalDfdModel(currentReport?.dfd_model);
  try {
    const response = await API.dfd.save(projectId, model, currentReport.dfd_model.revision);
    currentReport.dfd_model = response.model;
    currentReport.dfd_validation = response.validation;
    if (recordHistory && previous) {
      canonicalUndoStack.push(previous);
      canonicalRedoStack = [];
    }
    if (response.semantic_changed) {
      currentReport.analysis_stale = {
        stages: ['stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions'],
        reason: 'Canonical DFD semantic model edited. Refresh dependent analysis stages.',
        changed_at: new Date().toISOString(),
      };
    }
    if (render) renderResults(currentReport);
    syncDfdHistoryButtons();
    showToast(message, 'success');
    return response;
  } catch (err) {
    showToast('Could not save canonical DFD: ' + err.message, 'error');
    if (/409|conflict/i.test(err.message || '')) await tryLoadExistingReport();
    return null;
  }
}

async function restoreCanonicalDfdHistory(direction) {
  if (!currentReport?.dfd_model) return;
  const source = direction === 'undo' ? canonicalUndoStack : canonicalRedoStack;
  const target = source.pop();
  if (!target) return;
  const current = cloneCanonicalDfdModel(currentReport.dfd_model);
  const response = await persistCanonicalDfdModel(target, {
    message: direction === 'undo' ? 'Canonical DFD change undone' : 'Canonical DFD change redone',
    recordHistory: false,
  });
  if (!response) {
    source.push(target);
    syncDfdHistoryButtons();
    return;
  }
  (direction === 'undo' ? canonicalRedoStack : canonicalUndoStack).push(current);
  syncDfdHistoryButtons();
}

function renderDiagramTextAlternative(report) {
  const content = document.getElementById('diagram-text-content');
  const canvas = document.getElementById('threat-diagram-canvas');
  if (!content) return;
  const views = modelViews(report);
  const threats = analysisVisibility(report).threats;
  if (report?.dfd_model?.nodes?.length && diagramLevel !== 'context') {
    const featureViews = (report.dfd_model.views || []).filter(view => view.kind === 'feature' && view.parent_process_id);
    const selected = diagramLevel === 'scenarios'
      ? featureViews.find(view => view.id === canonicalFeatureViewId) || featureViews[0]
      : null;
    const elementIds = selected ? new Set(selected.element_refs || []) : null;
    const nodes = (report.dfd_model.nodes || []).filter(node => !elementIds || elementIds.has(node.id));
    const flows = (report.dfd_model.flows || []).filter(flow => !elementIds || elementIds.has(flow.id));
    const nodeById = new Map((report.dfd_model.nodes || []).map(node => [node.id, node]));
    const nodeItems = nodes.map(node => `<li><strong>${escHtml(`${node.display_id} ${node.name}`)}</strong> — ${escHtml(`${node.type} · ${node.scope} · ${node.ownership} · ${node.exposure}`)}</li>`).join('');
    const flowItems = flows.map(flow => `<li>${escHtml(`${flow.display_id} ${nodeById.get(flow.source_id)?.name || flow.source_id} → ${nodeById.get(flow.target_id)?.name || flow.target_id}: ${flow.name}`)}</li>`).join('');
    content.innerHTML = `<p>${selected ? `Feature view for ${escHtml(selected.parent_process_id)}.` : 'System DFD projection.'} ${nodes.length} nodes and ${flows.length} flows are represented.</p><h3>Elements</h3><ul>${nodeItems || '<li>No elements are available.</li>'}</ul><h3>Data flows</h3><ul>${flowItems || '<li>No data flows are available.</li>'}</ul>`;
    if (canvas) canvas.setAttribute('aria-label', `${diagramLevel === 'scenarios' ? 'Feature' : 'System'} DFD with ${nodes.length} nodes and ${flows.length} flows`);
    return;
  }
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

function canonicalFlowEditorHtml(flow) {
  const model = currentReport?.dfd_model;
  if (!model) return '';
  const selectedData = new Set(flow.data_object_ids || []);
  const dataOptions = (model.data_objects || []).map(item =>
    `<option value="${escHtml(item.id)}" ${selectedData.has(item.id) ? 'selected' : ''}>${escHtml(`${item.display_id} ${item.name}`)}</option>`
  ).join('');
  const logicalBoundaries = (model.boundaries || []).filter(boundary =>
    ['logical', 'mixed'].includes(boundary.transition_scope) && boundary.status !== 'rejected'
  );
  const selectedLogical = new Set((flow.boundary_crossings || []).filter(id =>
    logicalBoundaries.some(boundary => boundary.id === id)
  ));
  const logicalBoundaryOptions = logicalBoundaries.map(boundary =>
    `<option value="${escHtml(boundary.id)}" ${selectedLogical.has(boundary.id) ? 'selected' : ''}>${escHtml(`${boundary.display_id} ${boundary.name}`)}</option>`
  ).join('');
  return `
    <form class="dfd-node-editor" data-dfd-flow-editor>
      <div class="node-model-meta">${escHtml(flow.display_id || flow.id)} · ${escHtml(flow.source_id)} → ${escHtml(flow.target_id)}</div>
      <label class="form-label">Data flow name<input class="form-input" data-dfd-flow-field="name" value="${escHtml(flow.name)}" maxlength="240" required /></label>
      <div class="dfd-editor-grid">
        <label class="form-label">Interaction<select class="form-select" data-dfd-flow-field="interaction_kind">${['request', 'response', 'event', 'read', 'write', 'replication', 'unknown'].map(value => `<option value="${value}" ${flow.interaction_kind === value ? 'selected' : ''}>${value}</option>`).join('')}</select></label>
        <label class="form-label">Protocol<input class="form-input" data-dfd-flow-field="protocol" value="${escHtml(flow.protocol || '')}" maxlength="120" /></label>
        <label class="form-label">AuthN<input class="form-input" data-dfd-flow-field="authn" value="${escHtml(flow.authn || '')}" maxlength="160" /></label>
        <label class="form-label">AuthZ<input class="form-input" data-dfd-flow-field="authz" value="${escHtml(flow.authz || '')}" maxlength="160" /></label>
      </div>
      <label class="form-label">Data objects<select class="form-select" data-dfd-flow-field="data_object_ids" multiple size="${Math.min(5, Math.max(2, (model.data_objects || []).length))}">${dataOptions}</select></label>
      <label class="form-label">Evidence references<textarea class="form-input" data-dfd-flow-field="evidence_refs" rows="2" placeholder="One evidence reference per line">${escHtml((flow.evidence_refs || []).join('\n'))}</textarea></label>
      ${logicalBoundaries.length ? `<label class="form-label">Logical identity / privilege / tenant crossings<select class="form-select" data-dfd-flow-field="logical_boundary_crossings" multiple size="${Math.min(4, Math.max(2, logicalBoundaries.length))}">${logicalBoundaryOptions}</select></label><label class="form-label">Reviewer crossing rationale<textarea class="form-input" data-dfd-flow-field="crossing_rationale" rows="2" maxlength="1000" placeholder="Why does this same-zone flow cross a logical boundary?">${escHtml((flow.boundary_crossings || []).map(id => flow.crossing_rationales?.[id]).filter(Boolean).join('\n'))}</textarea></label>` : ''}
      <div class="dfd-editor-actions"><button type="button" class="btn btn-primary btn-sm" data-save-dfd-flow>Save flow metadata</button>${dfdDeleteButtonHtml('flow', flow.id)}</div>
    </form>`;
}

async function saveCanonicalFlow(flowId, body) {
  const model = JSON.parse(JSON.stringify(currentReport.dfd_model));
  const flow = (model.flows || []).find(item => String(item.id) === String(flowId));
  if (!flow) return;
  const read = field => body.querySelector(`[data-dfd-flow-field="${field}"]`);
  const name = read('name')?.value.trim();
  if (!name) {
    showToast('Flow name is required', 'error');
    return;
  }
  flow.name = name;
  flow.interaction_kind = read('interaction_kind')?.value || 'unknown';
  flow.protocol = read('protocol')?.value.trim() || null;
  flow.authn = read('authn')?.value.trim() || null;
  flow.authz = read('authz')?.value.trim() || null;
  flow.data_object_ids = [...(read('data_object_ids')?.selectedOptions || [])].map(option => option.value);
  flow.evidence_refs = lineValues(read('evidence_refs')?.value);
  const logicalBoundaryIds = [...(read('logical_boundary_crossings')?.selectedOptions || [])].map(option => option.value);
  const logicalBoundarySet = new Set((model.boundaries || []).filter(boundary => ['logical', 'mixed'].includes(boundary.transition_scope)).map(boundary => boundary.id));
  flow.boundary_crossings = (flow.boundary_crossings || []).filter(id => !logicalBoundarySet.has(id));
  flow.crossing_origins = { ...(flow.crossing_origins || {}) };
  flow.crossing_rationales = { ...(flow.crossing_rationales || {}) };
  logicalBoundaryIds.forEach(id => {
    flow.boundary_crossings.push(id);
    flow.crossing_origins[id] = 'reviewer';
    flow.crossing_rationales[id] = read('crossing_rationale')?.value.trim() || 'Reviewer identified a logical boundary crossing on this flow.';
  });
  const button = body.querySelector('[data-save-dfd-flow]');
  if (button) button.disabled = true;
  await persistCanonicalDfdModel(model, { message: 'DFD flow metadata saved' });
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
  const details = (edge._flowDetails || []).filter(Boolean).length
    ? edge._flowDetails.filter(Boolean).map(item => `<li>${escHtml(item)}</li>`).join('')
    : `<li>${escHtml(edge.label || 'Service interaction')}</li>`;
  const threats = uniqueThreats(edge._threats || []);
  const findings = threats.length
    ? `<div class="inspector-findings"><strong>${threats.length} mapped findings</strong>${threats.map(t => `
        <div class="inspector-finding-row">${badgeHtml(t.risk_level, 'risk')}${badgeHtml(t.framework, 'framework')}<span>${escHtml(t.threat_category || 'Finding')}</span></div>`).join('')}</div>`
    : '<div class="inspector-empty-note">No finding is directly targeted to this flow.</div>';
  const canonicalFlow = currentReport?.dfd_model?.flows?.find(item => String(item.id) === String(edge.id));
  if (canonicalFlow) {
    body.innerHTML = `${crossing}${canonicalFlowEditorHtml(canonicalFlow)}<ul class="flow-detail-list">${details}</ul>${findings}`;
    body.querySelector('[data-save-dfd-flow]')?.addEventListener('click', () => saveCanonicalFlow(canonicalFlow.id, body));
    wireDfdDeleteButton(body);
  } else {
    body.innerHTML = `${crossing}<ul class="flow-detail-list">${details}</ul>${findings}`;
  }
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

function canonicalNodeEditorHtml(node) {
  const model = currentReport?.dfd_model;
  if (!model) return '';
  const options = (name, values, selected) => values.map(value =>
    `<option value="${escHtml(value)}" ${value === selected ? 'selected' : ''}>${escHtml(value)}</option>`
  ).join('');
  const selectedZones = new Set(node.zone_ids || []);
  const zoneOptions = (model.zones || []).map(zone =>
    `<option value="${escHtml(zone.id)}" ${selectedZones.has(zone.id) ? 'selected' : ''}>${escHtml(`${zone.display_id} ${zone.name}`)}</option>`
  ).join('');
  const purpose = node.process_metadata?.purpose || '';
  const processMetadata = node.process_metadata || {};
  const storeMetadata = model.stores?.[node.id] || {};
  const dataObjectOptions = (model.data_objects || []).map(item =>
    `<option value="${escHtml(item.id)}" ${(storeMetadata.data_object_ids || []).includes(item.id) ? 'selected' : ''}>${escHtml(`${item.display_id} ${item.name}`)}</option>`
  ).join('');
  const multiline = values => escHtml((values || []).join('\n'));
  return `
    <form class="dfd-node-editor" data-dfd-node-editor>
      <div class="node-model-meta">${escHtml(node.display_id || node.id)} · ${escHtml(node.type)} · semantic revision ${escHtml(model.revision)}</div>
      <label class="form-label" for="dfd-node-name">Name</label>
      <input class="form-input" id="dfd-node-name" data-dfd-field="name" value="${escHtml(node.name)}" maxlength="240" required />
      <div class="dfd-editor-grid">
        <label class="form-label">Scope<select class="form-select" data-dfd-field="scope">${options('scope', ['in_scope', 'external_dependency', 'unknown'], node.scope)}</select></label>
        <label class="form-label">Ownership<select class="form-select" data-dfd-field="ownership">${options('ownership', ['organization', 'customer', 'vendor', 'shared', 'unknown'], node.ownership)}</select></label>
        <label class="form-label">Exposure<select class="form-select" data-dfd-field="exposure">${options('exposure', ['internet_facing', 'private', 'local', 'unknown'], node.exposure)}</select></label>
        <label class="form-label">Operator / control party<input class="form-input" data-dfd-field="operator_control_party" value="${escHtml(node.operator_control_party || '')}" maxlength="240" /></label>
      </div>
      <label class="form-label">Description<textarea class="form-input" data-dfd-field="description" rows="2" maxlength="1000">${escHtml(node.description || '')}</textarea></label>
      <label class="form-label">Trust zones<select class="form-select" data-dfd-field="zone_ids" multiple size="${Math.min(4, Math.max(2, (model.zones || []).length))}">${zoneOptions}</select></label>
      <label class="form-label">Evidence references<textarea class="form-input" data-dfd-field="evidence_refs" rows="2" placeholder="One evidence reference per line">${escHtml((node.evidence_refs || []).join('\n'))}</textarea></label>
      ${node.type === 'process' ? `
        <label class="form-label">Process purpose<input class="form-input" data-dfd-field="purpose" value="${escHtml(purpose)}" maxlength="500" /></label>
        <label class="form-label">Execution identity<input class="form-input" data-dfd-field="execution_identity" value="${escHtml(processMetadata.execution_identity || '')}" maxlength="240" /></label>
        <label class="form-label">Privileges<textarea class="form-input" data-dfd-field="privileges" rows="2" placeholder="One privilege per line">${multiline(processMetadata.privileges)}</textarea></label>
        <label class="form-label">Transformations<textarea class="form-input" data-dfd-field="transformations" rows="2" placeholder="One transformation per line">${multiline(processMetadata.transformations)}</textarea></label>
        <label class="form-label">Control references<textarea class="form-input" data-dfd-field="control_refs" rows="2" placeholder="One control reference per line">${multiline(processMetadata.control_refs)}</textarea></label>
      ` : ''}
      ${node.type === 'data_store' ? `
        <fieldset class="dfd-editor-fieldset"><legend>Store lifecycle</legend>
          <label class="form-label">Stored data<select class="form-select" data-dfd-store-field="data_object_ids" multiple size="${Math.min(5, Math.max(2, (model.data_objects || []).length))}">${dataObjectOptions}</select></label>
          <label class="form-label">Readers<textarea class="form-input" data-dfd-store-field="readers" rows="2" placeholder="One node ID per line">${multiline(storeMetadata.readers)}</textarea></label>
          <label class="form-label">Writers<textarea class="form-input" data-dfd-store-field="writers" rows="2" placeholder="One node ID per line">${multiline(storeMetadata.writers)}</textarea></label>
          <label class="form-label">Retention<input class="form-input" data-dfd-store-field="retention" value="${escHtml(storeMetadata.retention || '')}" maxlength="240" /></label>
          <label class="form-label">Deletion<input class="form-input" data-dfd-store-field="deletion" value="${escHtml(storeMetadata.deletion || '')}" maxlength="240" /></label>
          <label class="form-label">Backup<input class="form-input" data-dfd-store-field="backup" value="${escHtml(storeMetadata.backup || '')}" maxlength="240" /></label>
          <label class="form-label">Protection controls<textarea class="form-input" data-dfd-store-field="protection_controls" rows="2" placeholder="One control per line">${multiline(storeMetadata.protection_controls)}</textarea></label>
          <label class="form-label">Evidence references<textarea class="form-input" data-dfd-store-field="evidence_refs" rows="2" placeholder="One evidence reference per line">${multiline(storeMetadata.evidence_refs)}</textarea></label>
        </fieldset>
      ` : ''}
      <div class="dfd-editor-actions"><button type="button" class="btn btn-primary btn-sm" data-save-dfd-node>Save semantic metadata</button>${dfdDeleteButtonHtml('node', node.id)}</div>
    </form>`;
}

function canonicalProcessIpoHtml(node) {
  const model = currentReport?.dfd_model;
  if (!model || node.type !== 'process') return '';
  const nodeById = new Map((model.nodes || []).map(item => [String(item.id), item]));
  const dataById = new Map((model.data_objects || []).map(item => [String(item.id), item]));
  const incoming = (model.flows || []).filter(flow => String(flow.target_id) === String(node.id));
  const outgoing = (model.flows || []).filter(flow => String(flow.source_id) === String(node.id));
  const flowRows = (flows, direction) => flows.length ? flows.map(flow => {
    const otherId = direction === 'input' ? flow.source_id : flow.target_id;
    const other = nodeById.get(String(otherId));
    const data = (flow.data_object_ids || []).map(id => dataById.get(String(id))?.name || id).join(', ') || 'unknown data';
    return `<li><button type="button" class="btn btn-link btn-sm" data-dfd-ipo-flow="${escHtml(flow.id)}">${escHtml(`${flow.display_id} ${flow.name}`)}</button><span class="text-sm text-muted">${escHtml(`${direction === 'input' ? other?.name || otherId : other?.name || otherId} · ${data} · ${flow.interaction_kind}`)}</span></li>`;
  }).join('') : '<li class="text-sm text-muted">No grounded flow on this side.</li>';
  const metadata = node.process_metadata || {};
  return `
    <section class="dfd-ipo-summary" aria-labelledby="dfd-ipo-heading">
      <h4 id="dfd-ipo-heading">Input–Process–Output</h4>
      <div class="dfd-ipo-grid">
        <div><strong>Input</strong><ul>${flowRows(incoming, 'input')}</ul></div>
        <div><strong>Process</strong><p class="text-sm">${escHtml(metadata.purpose || 'unknown purpose')}</p><p class="text-sm text-muted">Identity: ${escHtml(metadata.execution_identity || 'unknown')} · Privileges: ${escHtml((metadata.privileges || []).join(', ') || 'unknown')}</p><p class="text-sm text-muted">Transformations: ${escHtml((metadata.transformations || []).join(', ') || 'none documented')}</p></div>
        <div><strong>Output</strong><ul>${flowRows(outgoing, 'output')}</ul></div>
      </div>
    </section>`;
}

async function saveCanonicalNode(nodeId, body) {
  const model = JSON.parse(JSON.stringify(currentReport.dfd_model));
  const node = (model.nodes || []).find(item => String(item.id) === String(nodeId));
  if (!node) return;
  const read = field => body.querySelector(`[data-dfd-field="${field}"]`);
  const name = read('name')?.value.trim();
  if (!name) {
    showToast('Node name is required', 'error');
    return;
  }
  node.name = name;
  node.scope = read('scope')?.value || 'unknown';
  node.ownership = read('ownership')?.value || 'unknown';
  node.exposure = read('exposure')?.value || 'unknown';
  node.operator_control_party = read('operator_control_party')?.value.trim() || null;
  node.description = read('description')?.value.trim() || null;
  node.zone_ids = [...(read('zone_ids')?.selectedOptions || [])].map(option => option.value);
  node.evidence_refs = lineValues(read('evidence_refs')?.value);
  if (node.type === 'process') {
    node.process_metadata = node.process_metadata || {};
    node.process_metadata.purpose = read('purpose')?.value.trim() || null;
    node.process_metadata.execution_identity = read('execution_identity')?.value.trim() || null;
    node.process_metadata.privileges = (read('privileges')?.value || '').split('\n').map(value => value.trim()).filter(Boolean);
    node.process_metadata.transformations = (read('transformations')?.value || '').split('\n').map(value => value.trim()).filter(Boolean);
    node.process_metadata.control_refs = (read('control_refs')?.value || '').split('\n').map(value => value.trim()).filter(Boolean);
    node.process_metadata.input_flow_ids = model.flows.filter(flow => flow.target_id === node.id).map(flow => flow.id).sort();
    node.process_metadata.output_flow_ids = model.flows.filter(flow => flow.source_id === node.id).map(flow => flow.id).sort();
  }
  if (node.type === 'data_store') {
    const readStore = field => body.querySelector(`[data-dfd-store-field="${field}"]`);
    model.stores = model.stores || {};
    model.stores[node.id] = {
      ...(model.stores[node.id] || {}),
      data_object_ids: [...(readStore('data_object_ids')?.selectedOptions || [])].map(option => option.value),
      readers: (readStore('readers')?.value || '').split('\n').map(value => value.trim()).filter(Boolean),
      writers: (readStore('writers')?.value || '').split('\n').map(value => value.trim()).filter(Boolean),
      retention: readStore('retention')?.value.trim() || null,
      deletion: readStore('deletion')?.value.trim() || null,
      backup: readStore('backup')?.value.trim() || null,
      protection_controls: (readStore('protection_controls')?.value || '').split('\n').map(value => value.trim()).filter(Boolean),
      evidence_refs: lineValues(readStore('evidence_refs')?.value),
    };
  }
  const button = body.querySelector('[data-save-dfd-node]');
  if (button) button.disabled = true;
  await persistCanonicalDfdModel(model, { message: 'DFD node metadata saved' });
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

  const canonicalNode = currentReport?.dfd_model?.nodes?.find(item => String(item.id) === String(node._elementId));
  if (canonicalNode) {
    body.innerHTML = `${zoneSummary}${canonicalProcessIpoHtml(canonicalNode)}${canonicalNodeEditorHtml(canonicalNode)}`;
    body.querySelector('[data-save-dfd-node]')?.addEventListener('click', () => saveCanonicalNode(canonicalNode.id, body));
    wireDfdDeleteButton(body);
    body.querySelectorAll('[data-dfd-ipo-flow]').forEach(button => {
      button.addEventListener('click', () => focusDfdElement('flow', button.dataset.dfdIpoFlow));
    });
    if (threats.length) {
      body.insertAdjacentHTML('beforeend', `<div class="inspector-findings"><strong>${threats.length} mapped finding${threats.length === 1 ? '' : 's'}</strong>${threats.map(t => `
        <div class="inspector-finding-row">${badgeHtml(t.risk_level, 'risk')}${badgeHtml(t.framework, 'framework')}<span>${escHtml(t.threat_category || 'Finding')}</span></div>`).join('')}</div>`);
    } else {
      body.insertAdjacentHTML('beforeend', '<div class="inspector-empty-note">No finding is directly targeted to this node.</div>');
    }
    inspector.style.display = 'block';
    return;
  }

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

async function exportDiagramSvg() {
  if (!projectId) return;
  try {
    const response = await API.dfd.exportSvg(projectId);
    if (!response.ok) throw new Error('SVG export failed');
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `dfd-${projectId}.svg`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('Canonical DFD exported as SVG', 'success');
  } catch {
    showToast('Could not export canonical DFD', 'error');
  }
}

async function exportDiagramJson() {
  if (!projectId) return;
  try {
    const response = await API.dfd.exportJson(projectId);
    if (!response.ok) throw new Error('JSON export failed');
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `dfd-${projectId}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    showToast('Canonical DFD exported as JSON', 'success');
  } catch {
    showToast('Could not export canonical DFD JSON', 'error');
  }
}

async function importDiagramJson(file) {
  if (!file || !currentReport?.dfd_model) return;
  const previous = cloneCanonicalDfdModel(currentReport.dfd_model);
  try {
    const parsed = JSON.parse(await file.text());
    const model = parsed?.model && typeof parsed.model === 'object' ? parsed.model : parsed;
    const response = await API.dfd.importJson(projectId, {
      model,
      expected_revision: currentReport.dfd_model.revision,
    });
    currentReport.dfd_model = response.model;
    currentReport.dfd_validation = response.validation;
    canonicalUndoStack.push(previous);
    canonicalRedoStack = [];
    if (response.semantic_changed) {
      currentReport.analysis_stale = {
        stages: ['stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions'],
        reason: 'Canonical DFD JSON import changed the semantic model. Refresh dependent analysis stages.',
        changed_at: new Date().toISOString(),
      };
    }
    renderResults(currentReport);
    syncDfdHistoryButtons();
    showToast('Canonical DFD JSON imported and validated', 'success');
  } catch (err) {
    showToast('Could not import canonical DFD JSON: ' + err.message, 'error');
  } finally {
    const input = document.getElementById('dfd-json-import');
    if (input) input.value = '';
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
        ${targetRefs(t).length ? `<button type="button" class="btn btn-secondary btn-sm" data-focus-threat="${escHtml(t.threat_id || '')}" style="margin-top:var(--space-3);">Focus affected DFD elements (${targetRefs(t).length})</button>` : '<div class="text-xs text-muted" style="margin-top:var(--space-3);">No canonical DFD target reference is available for this candidate.</div>'}
        ${t.confidence_reason ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--text-muted);"><strong>Confidence reason:</strong> ${escHtml(t.confidence_reason)}</div>` : ''}
        ${t.abuse_case ? `<div style="margin-top:var(--space-4);padding:var(--space-3) var(--space-4);background:var(--accent-light);border:1px solid var(--accent-border);border-radius:var(--r-md);"><div class="threat-meta-label" style="color:var(--accent);">Abuse Case</div><div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(t.abuse_case)}</div></div>` : ''}
        ${t.recommended_control ? `<div style="margin-top:var(--space-3);padding:var(--space-3) var(--space-4);background:var(--green-light);border:1px solid var(--green-border);border-radius:var(--r-md);"><div class="threat-meta-label" style="color:var(--green);">Recommended Control</div><div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(t.recommended_control)}</div></div>` : ''}
        ${t.assumption ? `<div style="margin-top:var(--space-3);font-size:0.78rem;color:var(--text-muted);"><strong>Assumption:</strong> ${escHtml(t.assumption)}</div>` : ''}
        ${t.missing_info ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--orange);"><strong>Missing Info:</strong> ${escHtml(t.missing_info)}</div>` : ''}
      </div>
    </div>`;
  }).join('');
  el.querySelectorAll('[data-focus-threat]').forEach(button => {
    button.addEventListener('click', event => {
      event.stopPropagation();
      focusThreatTargets(button.dataset.focusThreat);
    });
  });
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
