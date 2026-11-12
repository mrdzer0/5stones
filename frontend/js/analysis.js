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
let canonicalExpandForSelection = false;
let diagramViewMode = loadDiagramViewMode();
let diagramLevel = loadDiagramLevel();
let analysisIsRunning = false;
let resultsWorkspaceOpen = false;
let isModelWorkspace = false;
let pendingArtifactAnalysisTypes = [];
const VALID_ANALYSIS_TABS = ['diagram', 'trust-boundaries', 'stride', 'linddun', 'controls', 'tests', 'gaps'];
const ANALYSIS_WORKFLOW_PHASES = {
  model: {
    tabs: ['diagram', 'trust-boundaries'],
    defaultTab: 'diagram',
    label: 'Model',
    description: 'Confirm the DFD and trust-boundary decisions before reviewing findings.',
  },
  findings: {
    tabs: ['stride', 'linddun'],
    defaultTab: 'stride',
    label: 'Findings',
    description: 'Review grounded security and privacy scenarios against the canonical model.',
  },
  'action-plan': {
    tabs: ['controls', 'tests'],
    defaultTab: 'controls',
    label: 'Action plan',
    description: 'Map applicable controls and verification scenarios to reviewed findings.',
  },
  evidence: {
    tabs: ['gaps'],
    defaultTab: 'gaps',
    label: 'Evidence',
    description: 'Resolve missing information and validate assumptions before sign-off.',
  },
};
const TAB_TO_WORKFLOW_PHASE = Object.fromEntries(
  Object.entries(ANALYSIS_WORKFLOW_PHASES).flatMap(([phase, config]) => config.tabs.map(tab => [tab, phase]))
);
const lastAnalysisTabByPhase = Object.fromEntries(
  Object.entries(ANALYSIS_WORKFLOW_PHASES).map(([phase, config]) => [phase, config.defaultTab])
);
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

  if (document.body.dataset.page === 'model') {
    isModelWorkspace = true;
    await initializeModelWorkspace();
    return;
  }

  if (document.body.dataset.page === 'findings') {
    await initializeFindingsWorkspace();
    return;
  }

  if (document.body.dataset.page === 'action-plan') {
    await initializeActionPlanWorkspace();
    return;
  }

  if (document.body.dataset.page === 'evidence') {
    await initializeEvidenceWorkspace();
    return;
  }

  setupAnalysisProgressCollapse();
  setupContextCollapse();
  setupAnalysisTabs();
  setupOverviewActions();
  setupDiagramUtilities();
  renderEmptyAnalysisOverview();

  await loadProject();
  await tryLoadExistingReport();
  restoreAnalysisTab();
  // A fresh Analysis route should open at its workspace overview. Preserve
  // deep-link behavior when a tab/hash explicitly targets a subview.
  if (!location.hash && !window.UIState?.read?.().view) {
    window.requestAnimationFrame(() => window.scrollTo({ top: 0, left: 0, behavior: 'auto' }));
  }

  // Analysis actions
  document.getElementById('btn-run-analysis').addEventListener('click', runFullAnalysis);
  document.getElementById('btn-retry-persisted-analysis')?.addEventListener('click', retryAffectedAnalysis);
  document.getElementById('overview-open-results')?.addEventListener('click', () => {
    goToModelWorkspace(projectId);
  });
  document.getElementById('overview-back-button')?.addEventListener('click', closeAnalysisResults);
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
    if (currentReport?.dfd_model) scheduleCanonicalLayoutSave({ savePositions: false });
  });
  document.getElementById('btn-diagram-reflow')?.addEventListener('click', reflowCanonicalDiagram);
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
    }, 180);
  });

  // Report nav links
  const reportRoute = window.UIState?.route('report', projectId, window.UIState.read()) || `/report.html?id=${encodeURIComponent(projectId)}`;
  const reportLink = document.getElementById('nav-report');
  if (reportLink) reportLink.href = reportRoute;
  const reportBtn = document.getElementById('btn-view-report');
  if (reportBtn) reportBtn.href = reportRoute;
  document.getElementById('btn-proceed-results')?.addEventListener('click', () => {
    document.getElementById('analyzing-card').style.display = 'none';
    setAnalysisRunning(false);
    if (currentReport) {
      renderResults(currentReport);
      switchTab('diagram', { persist: false });
    }
  });
  // Expose a deterministic browser-test readiness signal only after project
  // data is loaded and all analysis actions, including the run handler, bind.
  document.body.dataset.analysisWorkspaceReady = 'true';
});

async function initializeModelWorkspace() {
  const projectName = document.getElementById('page-project-name');
  window.UIState?.bindProjectLinks(projectId, { phase: 'model', view: 'diagram' });
  try {
    currentProject = await API.projects.get(projectId);
    if (projectName) projectName.textContent = currentProject.name || 'Project';
    const report = await API.analysis.report(projectId);
    currentReport = report;
    if (report.analysis_run?.run_id) window.UIState?.update({ project: projectId, run: String(report.analysis_run.run_id) });
    const analysisHref = window.UIState?.route('analysis', projectId, { ...window.UIState.read(), phase: '', view: '' }) || `/analysis.html?id=${encodeURIComponent(projectId)}`;
    const routeState = window.UIState?.read() || {};
    const reportHref = window.UIState?.route('report', projectId, routeState) || `/report.html?id=${encodeURIComponent(projectId)}`;
    const modelHref = window.UIState?.route('model', projectId, { ...routeState, phase: 'model', view: 'diagram' }) || `/model.html?id=${encodeURIComponent(projectId)}`;
    const findingsHref = window.UIState?.route('findings', projectId, { ...routeState, phase: 'findings', view: '' }) || `/findings.html?id=${encodeURIComponent(projectId)}`;
    const actionPlanHref = window.UIState?.route('action-plan', projectId, { ...routeState, phase: 'action-plan', view: '' }) || `/action-plan.html?id=${encodeURIComponent(projectId)}`;
    const evidenceHref = window.UIState?.route('evidence', projectId, { ...routeState, phase: 'evidence', view: '' }) || `/evidence.html?id=${encodeURIComponent(projectId)}`;
    ['nav-analysis', 'back-analysis'].forEach(id => { const link = document.getElementById(id); if (link) link.href = analysisHref; });
    ['nav-report', 'btn-model-report'].forEach(id => { const link = document.getElementById(id); if (link) link.href = reportHref; });
    const modelFindingsLink = document.getElementById('btn-model-findings');
    if (modelFindingsLink) modelFindingsLink.href = findingsHref;
    const findingsLink = document.getElementById('nav-findings');
    if (findingsLink) findingsLink.href = findingsHref;
    const actionPlanLink = document.getElementById('nav-action-plan');
    if (actionPlanLink) actionPlanLink.href = actionPlanHref;
    const evidenceLink = document.getElementById('nav-evidence');
    if (evidenceLink) evidenceLink.href = evidenceHref;
    const modelLink = document.getElementById('nav-model');
    if (modelLink) modelLink.href = modelHref;

    setupDiagramUtilities();
    setupDiagramModeSwitch();
    setupDiagramLevelSwitch();
    setupModelWorkspaceControls();
    const hasCanonicalModel = Boolean(report?.dfd_model?.nodes?.length);
    const hasGroundedLegacyProjection = Boolean(
      report?.trust_model?.views?.context?.nodes?.length
      || report?.trust_boundaries?.length
      || report?.data_flows?.length
    );
    if (hasCanonicalModel || hasGroundedLegacyProjection) renderDiagram(report);
    else {
      const canvas = document.getElementById('threat-diagram-canvas');
      if (canvas) canvas.innerHTML = '<div class="diagram-grounded-empty"><strong>No canonical DFD is available yet</strong><span>Run analysis from the Analysis workspace, or add architecture evidence, then return here to review the model.</span></div>';
    }
    renderDiagramTextAlternative(report);
    renderGraphCoverageSummary(report);
    renderDfdInventory(report);
    renderModelBoundaryQueue(report);
    updateModelReadiness(report);
    syncDfdHistoryButtons();

    const routeSelection = window.UIState?.read().selection || '';
    if (routeSelection.startsWith('dfd-node:') || routeSelection.startsWith('dfd-flow:') || routeSelection.startsWith('boundary:')) {
      if (diagramLevel !== 'context') {
        diagramLevel = 'context';
        syncDiagramLevelUi();
        renderDiagram(report);
        renderDiagramTextAlternative(report);
      }
    }
    if (routeSelection.startsWith('dfd-node:')) focusModelElement('node', routeSelection.slice(9));
    else if (routeSelection.startsWith('dfd-flow:')) focusModelElement('flow', routeSelection.slice(9));
    else if (routeSelection.startsWith('boundary:')) focusModelElement('boundary', routeSelection.slice(9));
  } catch (error) {
    const revision = document.getElementById('model-revision-status');
    if (revision) revision.textContent = 'Model unavailable';
    const queue = document.getElementById('model-boundary-queue');
    if (queue) queue.innerHTML = `<div class="model-empty-state">${escHtml(error.message || 'Could not load the project model.')}</div>`;
    showToast('Could not load DFD model: ' + error.message, 'error');
  }
}

function setupModelWorkspaceControls() {
  document.getElementById('model-review-trigger')?.addEventListener('click', event => {
    if (event.target.closest('#model-review-trigger-count')) return;
    const rail = document.getElementById('model-inspector-rail');
    const panel = document.getElementById('boundary-review-panel');
    if (rail?.dataset.uxOpen === 'true' && panel && !panel.hidden) hideBoundaryReviewPanel();
    else if (panel?.hidden) showBoundaryReviewPanel({ focus: true });
    else openModelInspectorSheet({ focusQueue: true });
  });
  document.getElementById('model-review-trigger-count')?.addEventListener('click', event => {
    event.preventDefault();
    event.stopPropagation();
    toggleBoundaryReviewVisibility();
  });
  document.getElementById('model-sheet-backdrop')?.addEventListener('click', () => closeModelInspector());
  document.getElementById('btn-diagram-reflow')?.addEventListener('click', reflowCanonicalDiagram);
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
  document.getElementById('model-inspector-close')?.addEventListener('click', () => {
    closeModelInspector();
  });
  document.getElementById('model-boundary-close')?.addEventListener('click', () => hideBoundaryReviewPanel());
  syncModelRailLayout();
  document.getElementById('start-boundary-guided')?.addEventListener('click', startGuidedBoundaryReview);
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    const inspector = document.getElementById('node-inspector');
    const rail = document.getElementById('model-inspector-rail');
    if (rail?.dataset.uxOpen === 'true' || inspector?.dataset.uxOpen === 'true') {
      event.preventDefault();
      closeModelInspector();
    }
  });
  document.getElementById('model-boundary-queue')?.addEventListener('click', event => {
    const flow = event.target.closest('[data-model-flow]');
    if (flow) { focusModelElement('flow', flow.dataset.modelFlow); return; }
    const boundary = event.target.closest('[data-model-boundary]');
    if (boundary) focusModelElement('boundary', boundary.dataset.modelBoundary);
    const review = event.target.closest('[data-model-review]');
    if (review) updateModelBoundaryReview(review.dataset.modelReview, review.dataset.modelStatus);
  });
  window.addEventListener('resize', () => {
    window.clearTimeout(diagramResizeTimer);
    diagramResizeTimer = window.setTimeout(() => {
      const rail = document.getElementById('model-inspector-rail');
      if (rail && isModelMobileSheet() && rail.dataset.uxOpen === 'true' && !document.body.classList.contains('model-sheet-open')) openModelInspectorSheet({ returnFocus: false });
      if (rail && !isModelMobileSheet() && document.body.classList.contains('model-sheet-open')) closeModelInspector({ returnFocus: false });
      if (currentReport?.dfd_model && diagramNetwork && !restoreCanonicalViewport(currentReport.dfd_model)) fitModelDiagram({ animate: false });
    }, 180);
  });
}

function isModelMobileSheet() {
  return Boolean(window.matchMedia?.('(max-width: 820px)').matches);
}

function updateModelSheetTrigger(open = false) {
  const trigger = document.getElementById('model-review-trigger');
  if (trigger) trigger.setAttribute('aria-expanded', String(open));
}

function updateBoundaryReviewTrigger() {
  const trigger = document.getElementById('model-review-trigger');
  const rail = document.getElementById('model-inspector-rail');
  const panel = document.getElementById('boundary-review-panel');
  if (!trigger) return;
  const railOpen = rail?.dataset.uxOpen === 'true';
  const visible = Boolean(panel && !panel.hidden);
  const action = !railOpen ? 'Open' : visible ? 'Hide' : 'Show';
  trigger.title = `${action} boundary review`;
  trigger.setAttribute('aria-label', `${action} boundary review`);
}

function syncModelRailLayout() {
  const rail = document.getElementById('model-inspector-rail');
  const panel = document.getElementById('boundary-review-panel');
  const inspector = document.getElementById('node-inspector');
  if (!rail) return;
  rail.classList.toggle('boundary-review-hidden', Boolean(panel?.hidden));
  rail.classList.toggle('model-selection-visible', Boolean(inspector && inspector.style.display !== 'none'));
  updateBoundaryReviewTrigger();
}

function showBoundaryReviewPanel({ focus = false } = {}) {
  const panel = document.getElementById('boundary-review-panel');
  const reviewButton = document.getElementById('start-boundary-guided');
  if (!panel) return;
  panel.hidden = false;
  openModelInspectorSheet({ focusQueue: false, returnFocus: document.activeElement });
  syncModelRailLayout();
  if (focus) reviewButton?.focus({ preventScroll: true });
}

function hideBoundaryReviewPanel({ returnFocus = true } = {}) {
  const panel = document.getElementById('boundary-review-panel');
  const trigger = document.getElementById('model-review-trigger');
  const inspector = document.getElementById('node-inspector');
  if (!panel) return;
  panel.hidden = true;
  syncModelRailLayout();
  if (inspector?.style.display === 'none') {
    closeModelInspector({ returnFocus: false });
  }
  if (returnFocus) trigger?.focus({ preventScroll: true });
}

function toggleBoundaryReviewVisibility() {
  const panel = document.getElementById('boundary-review-panel');
  if (!panel) return;
  if (panel.hidden) showBoundaryReviewPanel({ focus: true });
  else hideBoundaryReviewPanel();
}

function openModelInspectorSheet({ focusQueue = false, returnFocus = document.activeElement } = {}) {
  const rail = document.getElementById('model-inspector-rail');
  const backdrop = document.getElementById('model-sheet-backdrop');
  const reviewButton = document.getElementById('start-boundary-guided');
  if (!rail) return;
  const alreadyOpen = rail.dataset.uxOpen === 'true';
  if (!isModelMobileSheet()) {
    rail.dataset.uxOpen = 'true';
    rail.dataset.mobileState = 'open';
    document.body.classList.add('model-rail-open');
    updateModelSheetTrigger(true);
    syncModelRailLayout();
    if (focusQueue) reviewButton?.focus({ preventScroll: true });
    return;
  }
  rail.dataset.mobileState = 'open';
  document.body.classList.add('model-sheet-open', 'model-sheet-scroll-lock');
  if (backdrop) {
    backdrop.hidden = false;
    backdrop.setAttribute('aria-hidden', 'false');
  }
  updateModelSheetTrigger(true);
  if (!alreadyOpen) window.UXFocus?.open(rail, returnFocus);
  // UXFocus makes the workspace inert for the modal. Keep the backdrop clickable.
  if (backdrop) {
    backdrop.inert = false;
    backdrop.removeAttribute('aria-hidden');
  }
  syncModelRailLayout();
  if (focusQueue) {
    reviewButton?.focus({ preventScroll: true });
    window.setTimeout(() => reviewButton?.focus({ preventScroll: true }), 0);
  }
}

function startGuidedBoundaryReview() {
  const candidates = (currentReport?.trust_boundaries || currentReport?.dfd_model?.boundaries || []).filter(item => ['Candidate', 'candidate', 'unresolved'].includes(item.status || 'Candidate'));
  const target = candidates[0] || (currentReport?.dfd_model?.boundaries || [])[0];
  if (!target) { showToast('No trust-boundary review item is available.', 'info'); return; }
  focusModelElement('boundary', target.boundary_id || target.id);
  window.UXTelemetry?.start('boundary_review');
}

function fitModelDiagram({ animate = true } = {}) {
  if (!diagramNetwork) return;
  const ids = diagramNetwork.body.data.nodes.getIds();
  if (currentReport?.dfd_model && ids.length && canonicalResolveNodeOverlaps(diagramNetwork, ids, 40)) diagramNetwork.redraw();
  diagramNetwork.fit({
    animation: animate ? { duration: 280, easingFunction: 'easeInOutQuad' } : false,
    nodes: ids,
    padding: 56,
  });
  window.requestAnimationFrame(() => keepSelectedModelElementVisible());
}

function selectedModelGraphNodeIds() {
  if (!diagramNetwork) return [];
  const selection = window.UIState?.read().selection || '';
  if (selection.startsWith('dfd-node:')) {
    const id = selection.slice(9);
    return diagramNetwork.body.data.nodes.get(id) ? [id] : [];
  }
  if (selection.startsWith('dfd-flow:')) {
    const id = selection.slice(9);
    const edge = diagramNetwork.body.data.edges.get(id)
      || diagramNetwork.body.data.edges.getIds().map(edgeId => diagramNetwork.body.data.edges.get(edgeId)).find(item => (item?._canonicalFlowIds || []).includes(id));
    return edge ? [edge.from, edge.to].filter(value => diagramNetwork.body.data.nodes.get(value)) : [];
  }
  if (selection.startsWith('boundary:')) {
    const boundary = (currentReport?.dfd_model?.boundaries || []).find(item => String(item.id) === selection.slice(9));
    const ids = new Set();
    (boundary?.crossing_flow_ids || []).forEach(flowId => {
      const flow = (currentReport?.dfd_model?.flows || []).find(item => String(item.id) === String(flowId));
      if (flow) { ids.add(String(flow.source_id)); ids.add(String(flow.target_id)); }
    });
    return [...ids].filter(value => diagramNetwork.body.data.nodes.get(value));
  }
  return [];
}

function keepSelectedModelElementVisible() {
  if (!diagramNetwork) return;
  const ids = selectedModelGraphNodeIds();
  if (!ids.length) return;
  const positions = diagramNetwork.getPositions(ids);
  const points = ids.map(id => positions[id]).filter(point => point && Number.isFinite(point.x) && Number.isFinite(point.y));
  if (!points.length) return;
  const position = {
    x: points.reduce((sum, point) => sum + point.x, 0) / points.length,
    y: points.reduce((sum, point) => sum + point.y, 0) / points.length,
  };
  const canvas = document.getElementById('threat-diagram-canvas');
  const canvasBox = canvas?.getBoundingClientRect();
  const rail = document.getElementById('model-inspector-rail');
  const railBox = rail?.getBoundingClientRect();
  const point = diagramNetwork.canvasToDOM(position);
  const currentDomY = (canvasBox?.top || 0) + point.y;
  const safeTop = (canvasBox?.top || 0) + 28;
  const safeBottom = isModelMobileSheet() && document.body.classList.contains('model-sheet-open') && railBox
    ? Math.min((canvasBox?.bottom || window.innerHeight) - 28, railBox.top - 20)
    : (canvasBox?.bottom || window.innerHeight) - 28;
  let targetDomY = currentDomY;
  if (safeBottom >= safeTop) targetDomY = Math.min(Math.max(currentDomY, safeTop), safeBottom);
  const scale = diagramNetwork.getScale();
  const view = diagramNetwork.getViewPosition();
  const graphDeltaY = scale > 0 ? (currentDomY - targetDomY) / scale : 0;
  diagramNetwork.moveTo({ position: { x: view.x, y: view.y + graphDeltaY }, scale, animation: false });
}

function updateModelReadiness(report) {
  const revision = document.getElementById('model-revision-status');
  if (revision) revision.textContent = `DFD revision ${report?.dfd_model?.revision ?? '—'}`;
  const summary = document.getElementById('model-readiness-summary');
  const readiness = report?.dfd_validation?.readiness || report?.dfd_validation?.analysis_readiness;
  const readinessLabel = readiness?.status
    ? String(readiness.status).replace(/[_-]+/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase())
    : 'Not evaluated';
  const runState = report?.analysis_state || {};
  if (summary) summary.textContent = runState.result_state === 'not_started'
    ? 'Not started · run analysis from Overview to build the canonical DFD'
    : readiness
      ? `${runState.status_label || 'Needs review'} · ${readinessLabel} · ${report.dfd_model?.nodes?.length || 0} elements · ${(report.dfd_model?.flows || []).length} flows`
      : `${runState.status_label || 'Needs review'} · ${report?.dfd_model?.nodes?.length || 0} elements · ${(report?.dfd_model?.flows || []).length} flows · Select an element for details`;
}

function renderModelBoundaryQueue(report = currentReport) {
  const container = document.getElementById('model-boundary-queue');
  if (!container) return;
  const model = report?.dfd_model || {};
  const canonical = model.boundaries || [];
  const reviewBoundaries = report?.trust_boundaries?.length ? report.trust_boundaries : canonical;
  const canonicalById = new Map(canonical.map(item => [String(item.id), item]));
  const nodes = new Map((model.nodes || []).map(item => [String(item.id), item]));
  const zones = new Map((model.zones || []).map(item => [String(item.id), item]));
  const flows = new Map((model.flows || []).map(item => [String(item.id), item]));
  const queueCount = document.getElementById('model-boundary-count');
  const triggerCount = document.getElementById('model-review-trigger-count');
  const summary = document.getElementById('model-boundary-summary');
  const pending = reviewBoundaries.filter(item => ['Candidate', 'candidate', 'unresolved'].includes(item.status || 'Candidate')).length;
  if (queueCount) queueCount.textContent = String(pending);
  if (triggerCount) triggerCount.textContent = String(pending);
  if (summary) summary.textContent = `${pending} pending · ${reviewBoundaries.length - pending} reviewed`;
  if (!reviewBoundaries.length) {
    container.innerHTML = '<div class="model-empty-state">No trust-boundary candidates. Cross-zone flows and their evidence remain visible in the diagram.</div>';
    return;
  }
  container.innerHTML = reviewBoundaries.map(item => {
    const id = String(item.boundary_id || item.id || '');
    const boundary = canonicalById.get(id) || canonical.find(value => value.crossing_flow_ids?.some(flowId => (item.crossing_flow_ids || []).includes(flowId)));
    const flowIds = [...new Set([...(item.crossing_flow_ids || []), ...(boundary?.crossing_flow_ids || [])].map(String))];
    const status = item.status || boundary?.status || 'Candidate';
    const evidence = [...new Set([...(item.evidence_refs || []), ...(boundary?.evidence_refs || [])])];
    const source = item.source || (boundary?.source_zone_ids || []).map(zoneId => zones.get(String(zoneId))?.name || zoneId).join(', ') || 'Source zone';
    const destination = item.destination || (boundary?.target_zone_ids || []).map(zoneId => zones.get(String(zoneId))?.name || zoneId).join(', ') || 'Target zone';
    const title = item.boundary_label || boundary?.name || item.name || 'Trust transition';
    const normalizedStatus = String(status).toLowerCase();
    const flowLinks = flowIds.map(flowId => {
      const flow = flows.get(flowId);
      const from = nodes.get(String(flow?.source_id))?.name || flow?.source_id || 'Source';
      const to = nodes.get(String(flow?.target_id))?.name || flow?.target_id || 'Destination';
      return `<button type="button" class="model-flow-link" data-model-flow="${escHtml(flowId)}">${escHtml(flow?.display_id || flowId)} · ${escHtml(from)} → ${escHtml(to)}</button>`;
    }).join('');
    const state = String(status).toLowerCase();
    return `<article class="model-boundary-card ${state === 'rejected' ? 'is-rejected' : ''}">
      <button type="button" class="model-boundary-title" data-model-boundary="${escHtml(id)}"><span>${escHtml(title)}</span><span class="model-boundary-status is-${escHtml(state)}">${escHtml(status)}</span></button>
      <p>${escHtml(source)} <span aria-hidden="true">→</span> ${escHtml(destination)}</p>
      <details class="model-boundary-details"><summary>Show evidence and flows</summary><div class="model-boundary-details-body">
        ${item.basis || boundary?.rationale ? `<small>${escHtml(item.basis || boundary.rationale)}</small>` : ''}
        ${evidence.length ? `<div class="model-evidence-list"><strong>Evidence</strong>${evidence.map(ref => `<code>${escHtml(ref)}</code>`).join('')}</div>` : '<div class="model-evidence-list is-missing">No boundary evidence reference recorded.</div>'}
        ${flowLinks ? `<div class="model-linked-flows"><strong>Crossing flows</strong>${flowLinks}</div>` : '<div class="model-linked-flows is-missing">No linked flow is recorded.</div>'}
      </div></details>
      <div class="model-boundary-actions">${normalizedStatus !== 'confirmed' ? `<button type="button" class="btn btn-secondary btn-sm" data-model-review="${escHtml(id)}" data-model-status="Confirmed">Confirm</button>` : ''}${normalizedStatus !== 'rejected' ? `<button type="button" class="btn btn-ghost btn-sm" data-model-review="${escHtml(id)}" data-model-status="Rejected">Reject</button>` : ''}${!['candidate', 'unresolved'].includes(normalizedStatus) ? `<button type="button" class="btn btn-ghost btn-sm" data-model-review="${escHtml(id)}" data-model-status="Candidate">Reset</button>` : ''}</div>
    </article>`;
  }).join('');
}

function focusModelElement(type, id, { preferredViewKind = null } = {}) {
  const model = currentReport?.dfd_model;
  if (!model || !id) return;
  if (['node', 'flow', 'boundary'].includes(type) && model.views?.length) {
    const views = model.views;
    const currentKind = diagramLevel === 'context' ? 'context' : diagramLevel === 'scenarios' ? 'feature' : 'system';
    const currentView = currentKind === 'feature'
      ? views.find(view => view.id === canonicalFeatureViewId)
      : views.find(view => view.kind === currentKind);
    const includesTarget = view => {
      if (!view) return false;
      const refs = Object.values(view.projection_mappings || {}).flat().map(String);
      return refs.includes(String(id)) || view.element_refs?.map(String).includes(String(id));
    };
    let targetView = preferredViewKind
      ? views.find(view => view.kind === preferredViewKind && includesTarget(view)) || null
      : includesTarget(currentView) ? currentView : null;
    if (!targetView && type === 'node') {
      const canonical = model.nodes?.find(node => String(node.id) === String(id));
      if (canonical?.parent_process_id) {
        targetView = views.find(view => view.kind === 'feature' && String(view.parent_process_id) === String(canonical.parent_process_id));
      }
      if (!targetView && canonical?.type === 'process') {
        targetView = views.find(view => view.kind === 'feature' && String(view.parent_process_id) === String(canonical.id));
      }
    }
    if (!targetView && type === 'flow') {
      targetView = views.find(view => view.kind === 'feature' && includesTarget(view));
    }
    if (!targetView) {
      targetView = views.find(view => view.kind === 'system' && includesTarget(view))
        || views.find(view => view.kind === 'context' && includesTarget(view))
        || views.find(view => view.kind === 'system');
    }
    if (targetView && (targetView !== currentView || (targetView.kind === 'feature' && targetView.id !== canonicalFeatureViewId))) {
      const level = targetView.kind === 'context' ? 'context' : targetView.kind === 'feature' ? 'scenarios' : 'services';
      navigateCanonicalLevel(level, targetView.kind === 'feature' ? targetView.id : null);
    }
  }
  const selection = { node: `dfd-node:${id}`, flow: `dfd-flow:${id}`, boundary: `boundary:${id}` }[type];
  if (selection) window.UIState?.update({ project: projectId, selection });
  if (type === 'node') {
    let node = diagramNetwork?.body?.data?.nodes?.get(id)
      || diagramNetwork?.body?.data?.nodes?.getIds().map(nodeId => diagramNetwork.body.data.nodes.get(nodeId))
        .find(item => (item?._canonicalNodeIds || []).map(String).includes(String(id)));
    if (!node && !canonicalShowUnconnected) {
      canonicalShowUnconnected = true;
      renderDiagram(currentReport);
      node = diagramNetwork?.body?.data?.nodes?.get(id)
        || diagramNetwork?.body?.data?.nodes?.getIds().map(nodeId => diagramNetwork.body.data.nodes.get(nodeId))
          .find(item => (item?._canonicalNodeIds || []).map(String).includes(String(id)));
    }
    if (node) {
      diagramNetwork.selectNodes([node.id]);
      const canonicalNode = model.nodes?.find(item => String(item.id) === String(id));
      showNodeInspector(canonicalNode ? {
        ...node,
        _elementId: canonicalNode.id,
        _origLabel: `${canonicalNode.display_id || canonicalNode.id} ${canonicalNode.name}`,
        _modelMeta: `${canonicalNode.type} · mapped from ${node.id} · ${canonicalNode.scope} · ${canonicalNode.ownership}`,
      } : node);
    }
    return;
  }
  if (type === 'flow') {
    let edge = diagramNetwork?.body?.data?.edges?.get(id)
      || diagramNetwork?.body?.data?.edges?.getIds().map(edgeId => diagramNetwork.body.data.edges.get(edgeId)).find(item => (item?._canonicalFlowIds || []).includes(String(id)));
    if (!edge) {
      canonicalShowUnconnected = true;
      canonicalExpandForSelection = true;
      renderDiagram(currentReport);
      canonicalExpandForSelection = false;
      edge = diagramNetwork?.body?.data?.edges?.get(id)
        || diagramNetwork?.body?.data?.edges?.getIds().map(edgeId => diagramNetwork.body.data.edges.get(edgeId)).find(item => (item?._canonicalFlowIds || []).includes(String(id)));
    }
    if (edge) {
      diagramNetwork.selectEdges([edge.id]);
      const canonicalFlow = model.flows?.find(item => String(item.id) === String(id));
      if (canonicalFlow) showCanonicalFlowInspector(canonicalFlow);
      else showFlowInspector(edge);
    }
    else showToast('This flow is not present in the current DFD projection.', 'warn');
    return;
  }
  const boundary = (model.boundaries || []).find(item => String(item.id) === String(id));
  const legacy = (currentReport.trust_boundaries || []).find(item => String(item.boundary_id) === String(id));
  if (boundary) showBoundaryInspector(boundary);
  else if (legacy) showModelBoundaryInspector(legacy);
  else if (type === 'zone') {
    const zone = (model.zones || []).find(item => String(item.id) === String(id));
    if (zone) showZoneInspector(zone);
  } else if (type === 'data_object') {
    const dataObject = (model.data_objects || []).find(item => String(item.id) === String(id));
    if (dataObject) showDataObjectInspector(dataObject);
  } else if (type === 'question') {
    const question = (model.questions || []).find(item => String(item.id) === String(id));
    if (question) showDfdQuestionInspector(question);
  }
}

function showModelBoundaryInspector(item) {
  const id = String(item.boundary_id || item.id || '');
  const boundary = (currentReport?.dfd_model?.boundaries || []).find(value => String(value.id) === id);
  if (boundary) { showBoundaryInspector(boundary); return; }
  const inspector = document.getElementById('node-inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  if (!inspector || !title || !body) return;
  title.textContent = item.boundary_label || `${item.source || 'Source'} → ${item.destination || 'Destination'}`;
  const flows = (item.crossing_flow_ids || []).map(id => `<button type="button" class="model-flow-link" data-inspect-flow="${escHtml(id)}">Inspect flow ${escHtml(id)}</button>`).join('') || '<span>No linked flow.</span>';
  const findings = uniqueThreats(analysisVisibility(currentReport).threats.filter(threat => targetMatches(threat, id, 'trust_boundary')));
  body.innerHTML = `<div class="node-model-meta">${escHtml(item.source_trust_level || 'unknown')} → ${escHtml(item.destination_trust_level || 'unknown')} · ${escHtml(item.confidence || 'unknown')} confidence</div><p>${escHtml(item.basis || item.risk_note || 'Boundary rationale not recorded.')}</p>${modelEvidenceLinksHtml(item.evidence_refs || [])}<h3>Crossing flows</h3><div class="model-linked-flows">${flows}</div>${modelFindingLinksHtml(findings)}`;
  body.querySelectorAll('[data-inspect-flow]').forEach(button => button.addEventListener('click', () => focusModelElement('flow', button.dataset.inspectFlow)));
  inspector.style.display = 'block';
  revealModelInspector();
}

async function updateModelBoundaryReview(boundaryId, status) {
  if (!boundaryId || !['Confirmed', 'Rejected', 'Candidate'].includes(status)) return;
  try {
    const legacy = (currentReport?.trust_boundaries || []).find(item => String(item.boundary_id) === String(boundaryId));
    if (legacy) {
      await API.analysis.updateTrustBoundary(projectId, boundaryId, { status });
    } else {
      const model = cloneCanonicalDfdModel(currentReport?.dfd_model);
      const boundary = (model?.boundaries || []).find(item => String(item.id) === String(boundaryId));
      if (!boundary) return;
      boundary.status = status === 'Candidate' ? 'unresolved' : status.toLowerCase();
      await persistCanonicalDfdModel(model, { message: `Trust boundary marked ${status.toLowerCase()}` });
    }
    currentReport = await API.analysis.report(projectId);
    renderDiagram(currentReport);
    renderDiagramTextAlternative(currentReport);
    renderModelBoundaryQueue(currentReport);
    updateModelReadiness(currentReport);
    showToast(`Trust boundary marked ${status.toLowerCase()}.`, status === 'Rejected' ? 'warn' : 'success');
  } catch (error) {
    showToast('Could not update trust boundary: ' + error.message, 'error');
  }
}

function modelFindingLinksHtml(threats) {
  if (!threats.length) return '<div class="inspector-empty-note">No directly linked findings.</div>';
  return `<div class="inspector-findings"><strong>${threats.length} linked finding${threats.length === 1 ? '' : 's'}</strong>${threats.map(threat => {
    const href = window.UIState?.route('findings', projectId, { run: currentReport?.analysis_run?.run_id, phase: 'findings', selection: `threat:${threat.threat_id}` }) || `/findings.html?id=${encodeURIComponent(projectId)}&selected=${encodeURIComponent(`threat:${threat.threat_id}`)}`;
    return `<a class="inspector-finding-row model-finding-link" href="${escHtml(href)}">${badgeHtml(threat.risk_level, 'risk')}${badgeHtml(threat.framework, 'framework')}<span>${escHtml(threat.threat_category || 'Finding')} · ${escHtml(threat.threat_id || '')}</span></a>`;
  }).join('')}</div>`;
}

function modelEvidenceLinksHtml(refs) {
  const values = [...new Set((refs || []).map(ref => typeof ref === 'string' ? ref : ref?.locator || ref?.title || '').filter(Boolean))];
  if (!values.length) return '<section class="model-evidence-trace"><h3>Evidence</h3><p class="inspector-empty-note">No direct evidence reference recorded.</p></section>';
  return `<section class="model-evidence-trace"><h3>Evidence</h3><div class="model-evidence-links">${values.map(ref => {
    const href = window.UIState?.route('evidence', projectId, {
      run: currentReport?.analysis_run?.run_id,
      phase: 'evidence',
      view: '',
      selection: '',
      evidence: { query: ref },
    }) || `/evidence.html?id=${encodeURIComponent(projectId)}&eq=${encodeURIComponent(ref)}`;
    return `<a class="evidence-link model-evidence-link" href="${escHtml(href)}"><code>${escHtml(ref)}</code><span aria-hidden="true">↗</span></a>`;
  }).join('')}</div></section>`;
}

function revealModelInspector() {
  const inspector = document.getElementById('node-inspector');
  if (!inspector) return;
  inspector.style.display = 'block';
  syncModelRailLayout();
  if (isModelWorkspace) {
    openModelInspectorSheet({ returnFocus: document.activeElement });
  } else if (!isModelWorkspace) {
    window.UXFocus?.open(inspector, document.activeElement);
  }
  if (!isModelWorkspace || isModelMobileSheet()) {
    inspector.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'nearest' });
  }
  if (isModelWorkspace) window.requestAnimationFrame(() => keepSelectedModelElementVisible());
}

function closeModelInspector({ returnFocus = true } = {}) {
  const inspector = document.getElementById('node-inspector');
  const rail = document.getElementById('model-inspector-rail');
  const backdrop = document.getElementById('model-sheet-backdrop');
  if (inspector) {
    if (!isModelWorkspace) window.UXFocus?.close(inspector, returnFocus ? undefined : null);
    inspector.style.display = 'none';
  }
  if (isModelWorkspace && isModelMobileSheet() && rail?.dataset.uxOpen === 'true') {
    window.UXFocus?.close(rail, returnFocus ? undefined : null);
  }
  if (isModelWorkspace) {
    document.body.classList.remove('model-sheet-open', 'model-sheet-scroll-lock', 'model-rail-open');
    if (rail) {
      rail.dataset.mobileState = 'closed';
      rail.dataset.uxOpen = 'false';
    }
    if (backdrop) {
      backdrop.hidden = true;
      backdrop.setAttribute('aria-hidden', 'true');
      backdrop.inert = false;
    }
    updateModelSheetTrigger(false);
    syncModelRailLayout();
  }
}

function fullAnalysisTypes() {
  return ['trust_boundary', 'stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions'];
}

function setupContextCollapse() {
  const toggle = document.getElementById('context-collapse-toggle');
  if (!toggle) return;

  let stored = null;
  try { stored = localStorage.getItem('5stones-analysis-context-collapsed'); } catch (_) {}
  const collapsed = stored === null
    ? true
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
  const select = document.getElementById('analysis-tab-select');

  buttons.forEach(button => {
    button.addEventListener('click', () => switchTab(button.dataset.tab));
    button.addEventListener('keydown', event => {
      const phaseButtons = buttons.filter(candidate => !candidate.hidden);
      const index = phaseButtons.indexOf(button);
      let nextIndex = null;
      if (event.key === 'ArrowRight') nextIndex = (index + 1) % phaseButtons.length;
      if (event.key === 'ArrowLeft') nextIndex = (index - 1 + phaseButtons.length) % phaseButtons.length;
      if (event.key === 'Home') nextIndex = 0;
      if (event.key === 'End') nextIndex = phaseButtons.length - 1;
      if (nextIndex === null || index < 0 || !phaseButtons.length) return;
      event.preventDefault();
      switchTab(phaseButtons[nextIndex].dataset.tab, { focus: true });
    });
  });

  select?.addEventListener('change', event => switchTab(event.target.value));
  window.addEventListener('hashchange', () => {
    const tab = location.hash.replace(/^#analysis-/, '');
    if (VALID_ANALYSIS_TABS.includes(tab)) switchTab(tab, { persist: false });
  });
}

function openContextWorkflow() {
  document.body.classList.add('analysis-context-workflow');
  syncWorkflowNavigation('context');
  setContextCollapsed(false);
  document.getElementById('project-context-card')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
}

function syncWorkflowNavigation(tabOrStage) {
  const phase = TAB_TO_WORKFLOW_PHASE[tabOrStage] || tabOrStage;
  const config = ANALYSIS_WORKFLOW_PHASES[phase];
  if (!config) return;

  const toolbar = document.getElementById('analysis-tabs-toolbar');
  const phaseButtons = [...document.querySelectorAll('.tab-btn[data-tab]')];
  phaseButtons.forEach(button => { button.hidden = button.dataset.workflowPhase !== phase; });
  toolbar?.setAttribute('data-workflow-phase', phase);
  toolbar?.classList.toggle('is-single-view', config.tabs.length === 1);
  const title = document.getElementById('analysis-phase-title');
  const description = document.getElementById('analysis-phase-description');
  if (title) title.textContent = config.label;
  if (description) description.textContent = config.description;

  const select = document.getElementById('analysis-tab-select');
  select?.querySelectorAll('option').forEach(option => {
    option.hidden = !config.tabs.includes(option.value);
  });
  select?.querySelectorAll('optgroup').forEach(group => {
    group.hidden = ![...group.querySelectorAll('option')].some(option => config.tabs.includes(option.value));
  });
}

function restoreAnalysisTab() {
  if (!currentReport) {
    closeAnalysisResults();
    renderEmptyAnalysisOverview();
    return;
  }
  const routeView = window.UIState?.read().view;
  const hashTab = location.hash.replace(/^#analysis-/, '');
  const tab = [routeView, hashTab].find(item => VALID_ANALYSIS_TABS.includes(item));
  if (!tab) {
    closeAnalysisResults();
    renderAnalysisOverview(currentReport);
    return;
  }
  switchTab(tab, { persist: false });
  if (!routeView && VALID_ANALYSIS_TABS.includes(hashTab)) {
    const phase = TAB_TO_WORKFLOW_PHASE[hashTab] || 'model';
    window.UIState?.update({ project: projectId, run: String(currentReport.analysis_run?.run_id || ''), phase, view: hashTab }, { hash: `analysis-${hashTab}` });
    syncAnalysisReportLinks();
  }
}

function setupOverviewActions() {
  document.getElementById('analysis-next-actions-list')?.addEventListener('click', event => {
    const button = event.target.closest('[data-overview-action]');
    if (button) openOverviewAction(button.dataset.overviewAction);
  });
  document.getElementById('overview-context-action')?.addEventListener('click', openContextWorkflow);
}

function openOverviewAction(action) {
  if (action === 'run') {
    runFullAnalysis();
    return;
  }
  if (action === 'report') {
    goToReport(projectId);
    return;
  }
  if (!currentReport) return;
  if (action === 'retry') {
    retryAffectedAnalysis();
    return;
  }
  if (action === 'boundaries') {
    goToModelWorkspace(projectId);
    return;
  }
  if (['controls', 'tests'].includes(action)) {
    goToActionPlanWorkspace(projectId, action === 'tests' ? 'test' : 'control');
    return;
  }
  if (action === 'gaps') {
    goToEvidenceWorkspace(projectId);
    return;
  }

  const threats = analysisVisibility(currentReport).threats;
  const target = action === 'review'
    ? threats.find(item => ['Open', 'Needs Info', 'Needs Review'].includes(item.status || 'Open'))
    : threats.find(item => String(item.risk_level).toLowerCase() === action);
  if (!target) {
    goToFindingsWorkspace(projectId);
    return;
  }
  goToFindingsWorkspace(projectId, target.threat_id);
}

function goToFindingsWorkspace(id = projectId, selection = '') {
  const state = window.UIState?.read() || {};
  const selected = selection ? `threat:${selection}` : (state.selection?.startsWith('threat:') ? state.selection : '');
  const routeState = { ...state, run: currentReport?.analysis_run?.run_id || state.run, phase: 'findings', view: '', selection: selected };
  const href = window.UIState?.route('findings', id, routeState) || `/findings.html?id=${encodeURIComponent(id)}${selected ? `&selected=${encodeURIComponent(selected)}` : ''}`;
  window.location.assign(href);
}

function goToActionPlanWorkspace(id = projectId, type = '') {
  const state = window.UIState?.read() || {};
  const actionTypes = type ? [type] : (state.action?.types || []);
  const routeState = { ...state, run: currentReport?.analysis_run?.run_id || state.run, phase: 'action-plan', view: '', action: { ...(state.action || {}), types: actionTypes } };
  const href = window.UIState?.route('action-plan', id, routeState) || `/action-plan.html?id=${encodeURIComponent(id)}`;
  window.location.assign(href);
}

function goToEvidenceWorkspace(id = projectId, selection = '') {
  const state = window.UIState?.read() || {};
  const selected = selection || (state.selection?.startsWith('gap:') || state.selection?.startsWith('assumption:') ? state.selection : '');
  const routeState = { ...state, run: currentReport?.analysis_run?.run_id || state.run, phase: 'evidence', view: '', selection: selected };
  const href = window.UIState?.route('evidence', id, routeState) || `/evidence.html?id=${encodeURIComponent(id)}${selected ? `&selected=${encodeURIComponent(selected)}` : ''}`;
  window.location.assign(href);
}

function goToModelWorkspace(id = projectId, selection = '') {
  const state = window.UIState?.read() || {};
  if (selection) window.UIState?.update({ project: id, selection });
  const routeState = { ...state, run: currentReport?.analysis_run?.run_id || state.run, phase: 'model', view: 'diagram', ...(selection ? { selection } : {}) };
  const href = window.UIState?.route('model', id, routeState) || `/model.html?id=${encodeURIComponent(id)}${selection ? `&selected=${encodeURIComponent(selection)}` : ''}`;
  window.location.assign(href);
}

function reducedMotionBehavior() {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
}

function setupDiagramUtilities() {
  const fullscreenButton = document.getElementById('btn-diagram-fullscreen');
  fullscreenButton?.addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.getElementById(isModelWorkspace ? 'model-canvas-workspace' : 'tab-diagram')?.requestFullscreen();
    } catch (_) {
      showToast('Fullscreen is not available in this browser', 'warn');
    }
  });
  document.addEventListener('fullscreenchange', () => {
    const active = document.fullscreenElement?.id === (isModelWorkspace ? 'model-canvas-workspace' : 'tab-diagram');
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
  const selectedFeature = (currentReport?.dfd_model?.views || []).find(view => view.id === canonicalFeatureViewId)
    || (currentReport?.dfd_model?.views || []).find(view => view.kind === 'feature');
  const featureLabel = selectedFeature?.decomposition_status === 'decomposed'
    ? 'Feature breakdown · L2'
    : selectedFeature?.decomposition_status === 'pending' ? 'Feature detail · L2 pending' : 'Connection detail · L2';
  const levelLabels = canonical
    ? { context: 'Overview · L0', services: 'Services · L1', scenarios: featureLabel }
    : { context: 'Overview · L0', services: 'Services · L1', scenarios: 'Feature flow · L2' };
  document.querySelectorAll('[data-diagram-level]').forEach(button => {
    if (levelLabels[button.dataset.diagramLevel]) button.textContent = levelLabels[button.dataset.diagramLevel];
  });
  const trustLegend = document.getElementById('diagram-trust-legend');
  if (trustLegend) trustLegend.style.display = diagramLevel === 'context' && diagramViewMode === 'classic' ? '' : 'none';
  const mobileMap = document.getElementById('diagram-mobile-map');
  if (mobileMap) mobileMap.classList.toggle('is-level-hidden', diagramLevel !== 'context' || Boolean(currentReport?.dfd_model?.nodes?.length));
  const title = document.querySelector('.diagram-toolbar-title');
  if (title) title.textContent = canonical
    ? (diagramLevel === 'context' ? 'Overview · L0' : diagramLevel === 'services' ? 'Services · L1' : 'Feature flow · L2')
    : (diagramLevel === 'context' ? 'Overview · L0' : diagramLevel === 'services' ? 'Services · L1' : 'Feature flow · L2');
  const featureSelect = document.getElementById('canonical-feature-select');
  if (featureSelect) featureSelect.style.display = canonical && diagramLevel === 'scenarios' ? '' : 'none';
  const unconnectedButton = document.getElementById('btn-diagram-unconnected');
  if (unconnectedButton) unconnectedButton.hidden = !canonical || !['context', 'services'].includes(diagramLevel);
  ['btn-diagram-fit', 'btn-diagram-export', 'btn-diagram-export-svg', 'btn-diagram-export-json', 'btn-diagram-import-json'].forEach(id => {
    const button = document.getElementById(id);
    if (button) button.hidden = diagramLevel === 'scenarios' && !canonical;
  });
  const reflowButton = document.getElementById('btn-diagram-reflow');
  if (reflowButton) reflowButton.hidden = !canonical;
  const subtitle = document.querySelector('.diagram-toolbar-sub');
  if (subtitle) {
    if (diagramLevel === 'services' || (diagramLevel === 'context' && canonical)) {
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
      closeModelInspector();
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
      closeModelInspector();
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
  const coverage = response.parsed?.coverage_manifest || {};
  const unread = Array.isArray(coverage.unread_sections) ? coverage.unread_sections : [];
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
      ${coverage.chunk_count ? `<div class="artifact-result-metric"><strong>${coverage.processed_chunk_count || 0}/${coverage.chunk_count}</strong><span>sections with grounded extraction</span></div>` : ''}
    </div>
    ${unread.length ? `<div class="artifact-coverage-warning"><strong>${unread.length} unresolved section${unread.length === 1 ? '' : 's'} or source range${unread.length === 1 ? '' : 's'}</strong><ul>${unread.map(item => `<li>${escHtml(item.locator || item.section || item.chunk_id || 'Unlocated section')}${item.reason ? ` — ${escHtml(item.reason)}` : ''}</li>`).join('')}</ul></div>` : coverage.status === 'complete' ? '<div class="artifact-coverage-ok">All source ranges have grounded extraction.</div>' : ''}
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
    contextSummary.textContent = `Input ${score}/100 · ${level} · ${artifactCount} artifact${artifactCount === 1 ? '' : 's'}`;
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
  const renderCoverage = (source) => {
    const coverage = source?.coverage_manifest || {};
    const unread = Array.isArray(coverage.unread_sections) ? coverage.unread_sections : [];
    if (!coverage.chunk_count) return '';
    const state = coverage.status === 'complete' ? 'complete' : unread.length ? 'deferred' : 'partial';
    return `<span class="artifact-source-coverage is-${state}">${escHtml(coverage.status || 'unknown')} · ${coverage.processed_chunk_count || 0}/${coverage.chunk_count} grounded sections${unread.length ? ` · ${unread.length} unresolved` : ''}${unread.length ? `<details><summary>Show unresolved ranges</summary><ul>${unread.map(item => `<li>${escHtml(item.locator || item.section || item.chunk_id || 'Unlocated section')}${item.reason ? ` — ${escHtml(item.reason)}` : ''}</li>`).join('')}</ul></details>` : ''}</span>`;
  };
  const inventoryHtml = (inventory.artifact_count || operationCount || businessScenarioCount) ? `
    <div class="artifact-inventory-summary">
      <strong>${operationCount} canonical operations · ${businessScenarioCount} business flows</strong><br>
      ${inventory.overlap_count || 0} matched across API sources · ${inventory.scenario_count || 0} request scenarios
      ${inventory.conflict_count ? ` · <strong>${inventory.conflict_count} conflict${inventory.conflict_count === 1 ? '' : 's'} to review</strong>` : ' · no source conflicts'}
      <div class="artifact-source-list">
        ${(p.artifact_sources || []).filter(source => source?.active !== false).map(source => `
          <div class="artifact-source-item">
            <span>${escHtml(source.filename || source.artifact_type || 'Artifact')}</span>
            <small>${escHtml(String(source.artifact_type || 'source').toUpperCase())} · ${source.stats?.operation_count || 0} operations${renderCoverage(source)}</small>
          </div>`).join('')}
      </div>
    </div>` : '';
  el.innerHTML = `
    ${inventoryHtml}
    <div style="padding:var(--space-3);border:1px solid var(--border);border-radius:var(--r-md);background:var(--surface-2);margin-bottom:var(--space-4);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span style="font-size:0.76rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;">Input context completeness</span>
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
    if (report.analysis_run?.run_id) window.UIState?.update({ run: String(report.analysis_run.run_id) });
    syncAnalysisReportLinks();
    canonicalUndoStack = [];
    canonicalRedoStack = [];
    document.body.classList.add('analysis-has-report');
    renderResults(report);
    document.getElementById('btn-view-report').style.display = '';
    if (report.analysis_run?.status === 'running') {
      const types = report.analysis_run.requested_types || fullAnalysisTypes();
      startAnalysisProgress(types);
      document.getElementById('analyzing-card').style.display = '';
      setAnalysisRunning(true);
      startAnalysisProgressPolling(types, null, async () => {
        stopAnalysisProgressPolling();
        setAnalysisRunning(false);
        await tryLoadExistingReport();
        document.getElementById('analyzing-card').style.display = 'none';
      });
    }
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
  const phases = document.getElementById('analysis-blocker-phases');
  if (!panel || !title || !message) return;
  const run = report?.analysis_run;
  const qualityGate = report?.quality_gate || run?.quality_gate || {};
  const signoffPending = qualityGate.signoff_ready === false;
  const recovery = report?.analysis_recovery || {};
  const staleStages = report?.analysis_stale?.stages || [];
  pendingArtifactAnalysisTypes = staleStages;
  const affected = affectedAnalysisTypes(report, false);
  const retryTypes = affected.length ? affected : affectedAnalysisTypes(report);
  const failed = run?.status === 'failed';
  const warning = run?.status === 'completed_with_warnings';
  const notStarted = !run || run.status === 'not_started' || report?.analysis_state?.result_state === 'not_started';
  const recoveryBlocked = ['previous_results_preserved', 'baseline_used', 'analysis_unavailable'].includes(recovery.state);
  if (!report || notStarted || (!staleStages.length && !recoveryBlocked && !failed && !warning && !signoffPending)) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'flex';
  panel.classList.toggle('is-error', failed || recovery.state === 'analysis_unavailable');
  if (staleStages.length) {
    title.textContent = 'Analysis out of date';
    message.textContent = `${report.analysis_stale?.reason || 'Model inputs changed.'} Current results remain available but need refresh.`;
  } else if (recovery.state === 'previous_results_preserved') {
    title.textContent = 'Previous validated results preserved';
    message.textContent = recovery.message || 'Failed phases did not replace the last validated results. Existing results remain available for review.';
  } else if (recovery.state === 'analysis_unavailable' || failed) {
    title.textContent = 'Analysis needs a retry';
    message.textContent = recovery.message || run?.error || 'No validated replacement was produced. Existing saved context remains available.';
  } else if (recovery.state === 'baseline_used') {
    title.textContent = 'Baseline results need review';
    message.textContent = recovery.message || 'One or more phases used a fallback result. Review the affected phases before relying on them.';
  } else {
    title.textContent = warning ? 'Analysis completed with phase warnings' : 'Sign-off blockers';
    const reasons = (qualityGate.blocking_reasons || []).slice(0, 3);
    message.textContent = warning
      ? `Review warning phases before relying on the model. ${reasons.join(' · ')}`.trim()
      : `${qualityGate.summary || 'Some decisions are required before sign-off.'}${reasons.length ? ` ${reasons.join(' · ')}` : ''}`;
  }
  if (phases) phases.textContent = affected.length ? `Affected phases: ${affected.map(stage => stage.replaceAll('_', ' ')).join(', ')}.` : '';
  if (retry) {
    const retryable = Boolean(staleStages.length || recovery.retryable || run?.retryable || failed);
    retry.style.display = retryTypes.length && retryable ? '' : 'none';
    retry.textContent = retryTypes.length > 1 ? `Retry ${retryTypes.length} affected phases` : 'Retry affected phase';
    retry.disabled = analysisIsRunning;
  }
}

function affectedAnalysisTypes(report = currentReport, includeRequestedFallback = true) {
  const allowed = new Set(['trust_boundary', 'stride', 'linddun', 'controls', 'tests', 'missing_info', 'assumptions']);
  const run = report?.analysis_run || {};
  const recovery = report?.analysis_recovery || {};
  const values = [
    ...(report?.analysis_stale?.stages || []),
    ...(recovery.failed_stages || []),
    ...(run.warning_stages || []),
  ].map(stage => stage === 'dfd_model' ? 'trust_boundary' : stage).filter(stage => allowed.has(stage));
  const unique = [...new Set(values)];
  if (unique.length) return unique;
  if (!includeRequestedFallback) return [];
  return (run.requested_types || []).filter(stage => allowed.has(stage)).length
    ? run.requested_types.filter(stage => allowed.has(stage))
    : fullAnalysisTypes();
}

async function retryPersistedAnalysis() {
  return retryAffectedAnalysis();
}

async function retryAffectedAnalysis() {
  if (analysisIsRunning) return;
  await runAnalysis(affectedAnalysisTypes(currentReport));
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
    seconds: 5,
    shortLabel: 'Boundary mapping',
    note: 'Reviewing actors, entry points, data flows, and changes in trust level.'
  },
  'as-stride': {
    seconds: 65,
    shortLabel: 'STRIDE evaluation',
    note: 'Evaluating six STRIDE categories against the mapped attack surface.'
  },
  'as-linddun': {
    seconds: 65,
    shortLabel: 'Privacy review',
    note: 'Reviewing personal-data flows against the LINDDUN privacy categories.'
  },
  'as-controls': {
    seconds: 3,
    shortLabel: 'Control mapping',
    note: 'Matching identified risks to relevant controls and implementation guidance.'
  },
  'as-tests': {
    seconds: 3,
    shortLabel: 'Verification planning',
    note: 'Preparing actionable test scenarios from the current threat catalog.'
  },
  'as-gaps': {
    seconds: 20,
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
    return JSON.parse(localStorage.getItem('5stones-stage-durations-ri4') || '{}');
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
    localStorage.setItem('5stones-stage-durations-ri4', JSON.stringify(history));
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

function stageOutcomeMessage(aiStatus = {}) {
  const manifest = aiStatus.response_metadata?.generation_manifest;
  const failedBatch = manifest?.batches?.find(batch => ['invalid', 'unavailable', 'deferred'].includes(batch.status));
  const responseCode = aiStatus.error_code || failedBatch?.error_code || aiStatus.response_metadata?.parse_status;
  const cause = {
    truncated_json: 'Provider output was truncated.',
    truncated_response: 'Provider reached its output limit.',
    non_json_response: 'Provider returned prose instead of JSON.',
    empty_response: 'Provider returned an empty response.',
    empty_choices: 'Provider returned no completion.',
    provider_contract_invalid: 'Provider response did not match the threat schema.',
    provider_unavailable: 'Provider could not complete the request.',
    stage_timeout: 'The time budget was reached; unresolved DFD interactions were deferred.'
  }[responseCode];
  if (aiStatus.previous_results_preserved) {
    return `${cause ? `${cause} ` : ''}Previous validated results preserved while this phase is retried.`;
  }
  if (aiStatus.assessment_status === 'blocked') {
    return 'Not run because a required upstream phase did not produce validated findings.';
  }
  if (aiStatus.assessment_status === 'invalid') {
    return `${cause ? `${cause} ` : ''}No validated result was produced by the selected analysis engine.`;
  }
  if (aiStatus.assessment_status === 'partial') {
    if (aiStatus.engine === 'catalog') return 'Some threats need a manual control applicability decision. Review unassigned mappings.';
    if (aiStatus.engine === 'templates') return 'Some verification scenarios are blocked until their threats are reviewed.';
    const deferred = manifest?.deferred_refs?.length || 0;
    return `${cause ? `${cause} ` : ''}Partial assessment; ${deferred} DFD interactions remain deferred. Retry this phase.`;
  }
  if (aiStatus.baseline_used || aiStatus.engine === 'fallback') {
    return `Baseline framework results used. ${escHtml(userFacingAnalysisError(aiStatus.error))}`;
  }
  return escHtml(userFacingAnalysisError(aiStatus.error || 'The phase requires review.'));
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
  const percent = Math.min(99, Math.floor((completedCount / selectedStageIds.length) * 100));

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
  if (percentEl) percentEl.textContent = `${percent}%`;
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
  updateOverviewRunStatus();
}

function updateOverviewRunStatus() {
  const status = document.getElementById('analysis-overview-status');
  const title = document.getElementById('analysis-overview-title');
  const reportRunning = currentReport?.analysis_run?.status === 'running';
  if (!status || !(analysisIsRunning || reportRunning)) return;
  const phase = activeStageId ? originalLabels[activeStageId] : document.getElementById('analysis-progress-label')?.textContent;
  const percent = document.getElementById('analysis-progress-percent')?.textContent;
  status.textContent = `Running${phase ? ` · ${phase.replace(/…$/, '')}` : ''}${percent ? ` · ${percent}` : ''}`;
  if (title) title.textContent = 'Analysis is in progress';
  const caption = document.getElementById('analysis-next-actions-caption');
  if (caption) caption.textContent = 'The phase tracker is live; validated results remain available while this run completes.';
  const queue = document.getElementById('analysis-next-actions-list');
  if (queue) queue.innerHTML = `<li class="analysis-next-action is-current"><span class="analysis-next-action-step">▶</span><div><strong>${escHtml(phase || 'Analysis is running')}</strong><small>${escHtml(status.textContent)} · keep this page open or return later.</small></div></li>`;
}

function startAnalysisProgress(types) {
  if (analysisTimer) clearInterval(analysisTimer);
  const phaseLabel = document.getElementById('phase-elapsed-label');
  if (phaseLabel) phaseLabel.textContent = 'Current phase';
  const description = document.getElementById('analysis-progress-description');
  if (description) description.textContent = 'Review each phase below for results, warnings, and any information still needed. Timing varies with project scope and the selected analysis engine.';
  selectedStageIds = stageIdsForTypes(types);
  completedStageIds = new Set();
  activeStageId = null;
  analysisStartedAt = performance.now();
  phaseStartedAt = 0;
  updateAnalysisProgress();
  analysisTimer = setInterval(updateAnalysisProgress, 1000);
}

let analysisProgressPoll = null;
let observedProgressRunId = null;
let analysisProgressPollGeneration = 0;

function stopAnalysisProgressPolling() {
  analysisProgressPollGeneration += 1;
  if (analysisProgressPoll) clearInterval(analysisProgressPoll);
  analysisProgressPoll = null;
}

function renderPersistedAnalysisProgress(progress) {
  if (!progress?.run_id || !progress?.stages) return;
  if (observedProgressRunId !== progress.run_id) {
    const started = Date.parse(progress.started_at || '');
    if (Number.isFinite(started)) analysisStartedAt = performance.now() - Math.max(0, Date.now() - started);
  }
  observedProgressRunId = progress.run_id;
  const stageToId = {
    trust_boundary: 'as-trust', stride: 'as-stride', linddun: 'as-linddun',
    controls: 'as-controls', tests: 'as-tests', missing_info: 'as-gaps', assumptions: 'as-gaps'
  };
  const grouped = {};
  (progress.requested_types || []).forEach(stage => {
    const id = stageToId[stage];
    if (id) (grouped[id] ||= []).push(progress.stages[stage] || { state: 'queued' });
  });
  Object.keys(originalLabels).filter(id => !grouped[id]).forEach(id => {
    const element = document.getElementById(id);
    if (!element) return;
    element.className = 'analyzing-step-item skipped';
    element.innerHTML = `<div class="step-dot"></div><span>${originalLabels[id]} · not requested</span>`;
  });
  completedStageIds = new Set();
  let activeId = null;
  Object.entries(grouped).forEach(([id, records]) => {
    const element = document.getElementById(id);
    if (!element) return;
    const states = records.map(record => record.state);
    const active = states.includes('active');
    const terminal = states.every(state => ['completed', 'warning', 'blocked', 'skipped'].includes(state));
    const warning = states.some(state => ['warning', 'blocked'].includes(state));
    const skipped = states.every(state => state === 'skipped');
    element.className = `analyzing-step-item ${active ? 'active' : skipped ? 'skipped' : terminal ? warning ? 'error' : 'done' : ''}`.trim();
    const detail = skipped ? 'skipped' : terminal && warning ? 'needs review' : terminal ? 'complete' : active ? 'running' : 'queued';
    element.innerHTML = `<div class="step-dot"></div><span>${originalLabels[id]} · ${detail}</span>`;
    if (terminal && !skipped) completedStageIds.add(id);
    if (active) activeId = id;
  });
  if (activeStageId !== activeId) {
    activeStageId = activeId;
    const activeRecord = Object.entries(stageToId).find(([stage, id]) => id === activeId && progress.stages[stage]?.state === 'active');
    const started = Date.parse(progress.stages[activeRecord?.[0]]?.started_at || '');
    phaseStartedAt = activeId ? Number.isFinite(started) ? performance.now() - Math.max(0, Date.now() - started) : performance.now() : 0;
  }
  const title = document.querySelector('#analyzing-card h3');
  if (title && activeId) title.textContent = `${originalLabels[activeId]}…`;
  if (!activeId && progress.status === 'running') {
    const label = document.getElementById('analysis-progress-label');
    if (label) label.textContent = 'Waiting for the next phase…';
  }
  updateAnalysisProgress();
}

function startAnalysisProgressPolling(types, previousRunId = null, onComplete = null) {
  stopAnalysisProgressPolling();
  const generation = analysisProgressPollGeneration;
  const poll = async () => {
    try {
      const progress = await API.analysis.progress(projectId);
      if (generation !== analysisProgressPollGeneration) return;
      if (!progress?.run_id || progress.run_id === previousRunId) return;
      renderPersistedAnalysisProgress(progress);
      if (progress.status !== 'running') {
        stopAnalysisProgressPolling();
        if (onComplete) await onComplete(progress);
      }
    } catch (_) {
      // A transient poll error must not cancel the in-flight analysis request.
    }
  };
  poll();
  analysisProgressPoll = setInterval(poll, 650);
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
  activeStageId = null;
  phaseStartedAt = 0;
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
  const phaseLabel = document.getElementById('phase-elapsed-label');
  if (phaseLabel) phaseLabel.textContent = 'Last phase';
  const description = document.getElementById('analysis-progress-description');
  if (description) description.textContent = 'This run has ended. Review the phase results and DFD readiness before using the findings for sign-off.';
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
  updateOverviewRunStatus();
}

async function runAnalysis(types) {
  if (analysisIsRunning) return;
  window.UXTelemetry?.start('analysis_run');
  let runTelemetrySent = false;
  const previousRunId = currentReport?.analysis_run?.run_id || null;
  observedProgressRunId = null;
  if (window.UIState) {
    window.UIState.update({ phase: '', view: '' }, { hash: '' });
    syncAnalysisReportLinks();
  }
  setAnalysisRunning(true);
  resultsWorkspaceOpen = false;
  document.getElementById('results-tabs').style.display = 'none';
  document.getElementById('analyzing-card').style.display = '';
  document.getElementById('analyzing-actions').style.display = 'none';
  renderAnalysisRunState(currentReport);
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

  const setStepDone = (id, aiStatus = { ok: true }) => {
    const el = document.getElementById(id);
    if (!el) return;
    const duration = aiStatus?.duration_seconds != null
      ? `${Number(aiStatus.duration_seconds).toFixed(2)}s`
      : completeStageProgress(id);

    if (aiStatus && aiStatus.ok === false) {
      const manualReview = aiStatus.assessment_status === 'partial' && ['catalog', 'templates'].includes(aiStatus.engine);
      el.className = `analyzing-step-item ${manualReview ? 'warning' : 'error'}`;
      el.innerHTML = `
        <div class="step-dot" style="background:#DC2626;box-shadow:none;"></div>
        <div style="flex:1;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);width:100%;">
            <span style="color:#DC2626;font-weight:500;">${originalLabels[id]}</span>
            ${duration ? `<span class="stage-duration">${duration}</span>` : ''}
            ${manualReview ? '' : `<button class="btn btn-sm btn-ghost" onclick="event.stopPropagation(); retryStage('${id}')" style="color:#2563EB;padding:2px 8px;font-size:0.72rem;border:1px solid var(--border);border-radius:var(--r-sm);background:var(--surface);">
              ↻ Retry stage
            </button>`}
          </div>
          <div class="step-subtext" style="font-size:0.72rem;color:var(--orange);margin-top:2px;line-height:1.2;">
            ${stageOutcomeMessage(aiStatus)}
          </div>
        </div>
      `;
    } else {
      el.className = 'analyzing-step-item done';
      const engineLabel = aiStatus.engine === 'catalog' ? ' · catalog mapped' : aiStatus.engine === 'templates' ? ' · template scenarios' : '';
      el.innerHTML = `
        <div class="step-dot" style="background:var(--green);box-shadow:none;"></div>
        <span style="color:var(--green);">${originalLabels[id]}${engineLabel}</span>
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
  const gapTypes = types.filter(type => type === 'missing_info' || type === 'assumptions');
  const stageUiMap = [
    ['trust_boundary', 'as-trust'],
    ['stride', 'as-stride'],
    ['linddun', 'as-linddun'],
    ['controls', 'as-controls'],
    ['tests', 'as-tests'],
  ];
  const activeUiStages = stageUiMap.filter(([stage]) => types.includes(stage));
  if (gapTypes.length) activeUiStages.push(['gaps', 'as-gaps']);
  const activeUiIds = new Set(activeUiStages.map(([, id]) => id));
  stepIds.filter(id => !activeUiIds.has(id)).forEach(setStepSkipped);

  // The POST owns one run; a separate endpoint publishes each stage transition.
  let report;
  try {
    const request = API.analysis.run(projectId, types);
    startAnalysisProgressPolling(types, previousRunId);
    report = await request;
    stopAnalysisProgressPolling();
    currentReport = report;
    if (report.analysis_run?.run_id) window.UIState?.update({ run: String(report.analysis_run.run_id) });
    syncAnalysisReportLinks();
    activeUiStages.forEach(([stage, id]) => {
      const stageStatuses = stage === 'gaps'
        ? gapTypes.map(type => report.ai_status?.[type]).filter(Boolean)
        : [report.ai_status?.[stage]];
      const aiStatus = stage === 'gaps'
        ? {
            ok: stageStatuses.length > 0 && stageStatuses.every(status => status.ok !== false),
            duration_seconds: stageStatuses.reduce((sum, status) => sum + Number(status.duration_seconds || 0), 0),
            error: stageStatuses.find(status => status.ok === false)?.error,
            assessment_status: stageStatuses.find(status => status.ok === false)?.assessment_status,
            previous_results_preserved: stageStatuses.some(status => status.previous_results_preserved),
            baseline_used: stageStatuses.some(status => status.baseline_used),
          }
        : (stageStatuses[0] || { ok: false, error: 'Stage completed without a persisted status. Please retry this phase.' });
      if (!aiStatus.ok) anyFailed = true;
      setStepDone(id, aiStatus);
      completedStageIds.add(id);
    });
  } catch (err) {
    stopAnalysisProgressPolling();
    anyFailed = true;
    const active = activeStageId || activeUiStages[0]?.[1];
    activeUiStages.forEach(([, id]) => {
      if (id === active) setStepDone(id, { ok: false, error: err.message });
      else if (!completedStageIds.has(id)) setStepSkipped(id);
    });
    report = null;
  }

  try {
    report = report || await API.analysis.report(projectId);
    currentReport = report;

    if (anyFailed) {
      window.UXTelemetry?.complete('analysis_run', 'analysis', 'partial');
      runTelemetrySent = true;
      const recovery = report.analysis_recovery || {};
      const preserved = recovery.state === 'previous_results_preserved';
      const unavailable = recovery.state === 'analysis_unavailable';
      finishAnalysisProgress(preserved ? 'Previous results preserved · retry available' : unavailable ? 'Retry required · no validated replacement' : 'Review ready · warnings require review');
      if (titleEl) titleEl.textContent = preserved ? 'Previous results preserved for review' : unavailable ? 'Analysis requires a retry' : 'Analysis prepared with review warnings';
      document.getElementById('analyzing-actions').style.display = 'block';
      document.body.classList.add('analysis-has-report');
      pendingArtifactAnalysisTypes = [];
      setAnalysisRunning(false);
      renderResults(report);
      showToast(
        preserved
          ? 'Previous validated findings remain available while the failed stages are retried.'
          : unavailable
            ? 'No validated replacement was produced. Retry the affected stages.'
            : 'Some stages require review; inspect the per-phase results.',
        'warn'
      );
    } else {
      window.UXTelemetry?.complete('analysis_run', 'analysis', 'success');
      runTelemetrySent = true;
      const signoffPending = report.analysis_run?.quality_gate?.signoff_ready === false;
      finishAnalysisProgress(signoffPending ? 'All phases complete · sign-off review required' : 'All phases complete');
      document.getElementById('analyzing-card').style.display = 'none';
      document.body.classList.add('analysis-has-report');
      pendingArtifactAnalysisTypes = [];
      setAnalysisRunning(false);
      renderResults(report);
      restoreAnalysisTab();
      document.getElementById('btn-view-report').style.display = '';
      showToast(
        signoffPending
          ? `Analysis generated — ${report.risk_summary?.total || 0} provisional threat scenarios; resolve the sign-off quality gates`
          : `Analysis complete — ${report.risk_summary?.total || 0} threat scenarios identified`,
        signoffPending ? 'warn' : 'success'
      );
    }
  } catch (err) {
    if (!runTelemetrySent) window.UXTelemetry?.complete('analysis_run', 'analysis', 'failed');
    if (analysisTimer) clearInterval(analysisTimer);
    document.getElementById('analyzing-card').style.display = 'none';
    if (currentReport) renderResults(currentReport);
    else renderEmptyAnalysisOverview();
    setAnalysisRunning(false);
    if (currentReport) renderAnalysisRunState(currentReport);
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
  await runAnalysis(types);
};

// ── Result rendering ───────────────────────────────────────────────────────────
function renderResults(report) {
  currentReport = report;
  document.body.classList.add('analysis-has-report');
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
  const needsContext = threats.filter(item => item.finding_state === 'needs_context').length;
  document.getElementById('stride-summary').textContent = `STRIDE scenarios — ${stride.length} visible · input context ${completeness.score || 0}/100 · ${visibleNeedsReview} need review${needsContext ? ` · ${needsContext} risk deferred` : ''}`;
  document.getElementById('tests-summary').textContent = `Security test backlog — ${visibility.tests.length} scenarios mapped to visible threats`;
  updateAnalysisTabOptions(report, stride.length, linddun.length, visibility);
  renderAnalysisOverview(report, visibility);
  renderAnalysisRunState(report);
  syncAnalysisStaleness(report);
  renderDfdProposal(report);

  const resultsTabs = document.getElementById('results-tabs');
  if (!resultsWorkspaceOpen) {
    if (resultsTabs) resultsTabs.style.display = 'none';
    return;
  }
  if (resultsTabs) resultsTabs.style.display = '';

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
  syncDfdHistoryButtons();

  // STRIDE filter
  const strideFilter = document.getElementById('stride-filter');
  if (strideFilter) {
    const routeFilters = window.UIState?.read().filters;
    strideFilter.value = routeFilters?.stride || '';
    if (strideFilter.value) renderThreats('stride-threats-list', 'st', stride.filter(t => t.threat_category === strideFilter.value));
    strideFilter.onchange = (e) => {
      window.UIState?.update({ filters: { stride: e.target.value } });
      const filtered = e.target.value ? stride.filter(t => t.threat_category === e.target.value) : stride;
      renderThreats('stride-threats-list', 'st', filtered);
    };
  }
  // LINDDUN filter
  const linddunFilter = document.getElementById('linddun-filter');
  if (linddunFilter) {
    const routeFilters = window.UIState?.read().filters;
    linddunFilter.value = routeFilters?.linddun || '';
    if (linddunFilter.value) renderThreats('linddun-threats-list', 'ln', linddun.filter(t => t.threat_category === linddunFilter.value));
    linddunFilter.onchange = (e) => {
      window.UIState?.update({ filters: { linddun: e.target.value } });
      const filtered = e.target.value ? linddun.filter(t => t.threat_category === e.target.value) : linddun;
      renderThreats('linddun-threats-list', 'ln', filtered);
    };
  }
  // Tests filter
  const testsFilter = document.getElementById('tests-filter');
  if (testsFilter) {
    const routeFilters = window.UIState?.read().filters;
    testsFilter.value = routeFilters?.priority || '';
    if (testsFilter.value) renderTests(visibility.tests.filter(t => t.priority === testsFilter.value));
    testsFilter.onchange = (e) => {
      window.UIState?.update({ filters: { priority: e.target.value } });
      const filtered = e.target.value ? visibility.tests.filter(t => t.priority === e.target.value) : visibility.tests;
      renderTests(filtered);
    };
  }
  restoreSelectedThreat();
}

function restoreSelectedThreat() {
  const selected = window.UIState?.read().selection || '';
  if (!selected.startsWith('threat:')) return;
  const threatId = selected.slice('threat:'.length);
  const item = document.querySelector(`[data-threat-id="${CSS.escape(threatId)}"]`);
  if (!item) return;
  const trigger = item.querySelector('.threat-item-header');
  if (trigger?.getAttribute('aria-expanded') !== 'true') trigger?.click();
  window.setTimeout(() => item.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'center' }), 50);
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
    diagram: 'System diagram',
    'trust-boundaries': 'Boundary review',
    stride: 'STRIDE findings',
    linddun: 'LINDDUN findings',
    controls: 'Controls',
    tests: 'Verification tests',
    gaps: 'Gaps & assumptions',
  };
  const select = document.getElementById('analysis-tab-select');
  Object.entries(labels).forEach(([value, label]) => {
    const option = select?.querySelector(`option[value="${value}"]`);
    if (option) option.textContent = counts[value] === '' ? label : `${label} (${counts[value]})`;
  });
}

function renderEmptyAnalysisOverview() {
  const overview = document.getElementById('analysis-overview');
  if (overview) overview.style.display = '';
  const title = document.getElementById('analysis-overview-title');
  const guidance = document.getElementById('analysis-overview-guidance');
  const status = document.getElementById('analysis-overview-status');
  if (title) title.textContent = 'Analysis has not started';
  if (guidance) guidance.textContent = 'Run one analysis to build the model, evaluate threats, map controls, and prepare verification scenarios.';
  if (status) status.textContent = 'Not started';
  ['overview-scored', 'overview-critical', 'overview-high', 'overview-review', 'overview-gaps', 'overview-signoff'].forEach(id => {
    const element = document.getElementById(id);
    if (element) element.textContent = '—';
  });
  const caption = document.getElementById('analysis-next-actions-caption');
  if (caption) caption.textContent = 'Next: start the full analysis from the single Run analysis action above.';
  const queue = document.getElementById('analysis-next-actions-list');
  if (queue) queue.innerHTML = '<li class="analysis-next-action is-current"><span class="analysis-next-action-step">1</span><div><strong>Run the threat model</strong><small>One run covers the DFD, STRIDE, LINDDUN, controls, tests, and evidence gaps.</small></div></li>';
  const details = document.getElementById('overview-open-results');
  if (details) details.hidden = true;
}

function renderAnalysisOverview(report, visibility = analysisVisibility(report)) {
  const overview = document.getElementById('analysis-overview');
  if (overview) overview.style.display = '';
  const detailsButton = document.getElementById('overview-open-results');
  if (detailsButton) detailsButton.hidden = false;
  const threats = visibility.threats;
  const critical = threats.filter(item => findingRiskIsScored(item) && item.risk_level === 'Critical').length;
  const high = threats.filter(item => findingRiskIsScored(item) && item.risk_level === 'High').length;
  const medium = threats.filter(item => findingRiskIsScored(item) && item.risk_level === 'Medium').length;
  const low = threats.filter(item => findingRiskIsScored(item) && item.risk_level === 'Low').length;
  const scored = critical + high + medium + low;
  const statusReviewCount = threats.filter(item => ['Open', 'Needs Info', 'Needs Review'].includes(item.status || 'Open')).length;
  const boundaryCandidates = (report.trust_boundaries || []).filter(item => item.status === 'Candidate').length;
  const threatNeedsReview = threats.some(item => item.status) ? statusReviewCount : (report.risk_summary?.needs_review ?? statusReviewCount);
  const needsReview = threatNeedsReview + boundaryCandidates;
  const gaps = visibility.missingInfo.length + visibility.assumptions.length;
  const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = String(value); };
  setText('overview-scored', scored);
  setText('overview-critical', critical);
  setText('overview-high', high);
  setText('overview-review', needsReview);
  setText('overview-gaps', gaps);

  const title = document.getElementById('analysis-overview-title');
  const guidance = document.getElementById('analysis-overview-guidance');
  const status = document.getElementById('analysis-overview-status');
  const recovery = report.analysis_recovery || {};
  const run = report.analysis_run || {};
  const analysisState = report.analysis_state || {};
  const staleStages = report.analysis_stale?.stages || [];
  const running = analysisIsRunning || run.status === 'running';
  const notStarted = run.status === 'not_started' || analysisState.result_state === 'not_started';
  const failedStages = recovery.failed_stages || run.warning_stages || [];
  const liveProgress = document.getElementById('analysis-progress-label')?.textContent || '';
  const livePercent = document.getElementById('analysis-progress-percent')?.textContent || '';
  const phaseStatus = activeStageId ? originalLabels[activeStageId] : liveProgress;
  let statusText = 'Analysis complete';
  let headline = 'Threat model ready for review';
  let guidanceText = 'Review the queued actions in order, then confirm readiness in Sign-off.';
  if (notStarted) {
    statusText = 'Not started';
    headline = 'Analysis has not started';
    guidanceText = 'Add the minimum project context, then run one analysis to build the DFD, findings, controls, tests, and evidence queue.';
  } else if (running) {
    statusText = `Running${phaseStatus ? ` · ${phaseStatus.replace(/…$/, '')}` : ''}${livePercent ? ` · ${livePercent}` : ''}`;
    headline = 'Analysis is in progress';
    guidanceText = 'The live phase tracker below shows completed, active, and pending work. Previously validated results remain available.';
  } else if (recovery.state === 'previous_results_preserved') {
    statusText = 'Partial · previous results preserved';
    headline = 'Previous validated results are preserved';
    guidanceText = 'Failed phases are explicitly marked. Retry only the affected stages before relying on a refreshed result.';
  } else if (recovery.state === 'analysis_unavailable' || run.status === 'failed') {
    statusText = 'Action required · retry available';
    headline = 'The latest analysis needs a retry';
    guidanceText = 'No validated replacement was produced. The next-action queue identifies the affected phases.';
  } else if (staleStages.length) {
    statusText = 'Out of date · refresh required';
    headline = 'The model changed after this analysis';
    guidanceText = 'Existing results are retained for review, but the listed downstream phases must be refreshed.';
  } else if (run.status === 'completed_with_warnings' || recovery.state === 'baseline_used') {
    statusText = 'Completed · review warnings';
    headline = 'Analysis completed with items to review';
    guidanceText = 'Review warning phases and evidence coverage before treating these results as complete.';
  } else if (report.quality_gate?.signoff_ready === false || run.quality_gate?.signoff_ready === false) {
    statusText = 'Needs sign-off';
    headline = 'Threat model is ready for reviewer decisions';
    guidanceText = 'The model and findings are available. Resolve the queued blockers before sign-off.';
  }
  if (title) title.textContent = headline;
  if (guidance) guidance.textContent = guidanceText;
  if (status) status.textContent = statusText;
  const signoffGate = report.quality_gate || run.quality_gate || {};
  setText('overview-signoff', running ? 'Running' : signoffGate.signoff_ready === true ? 'Ready' : 'Review');

  const queue = [];
  if (!running && !notStarted && (staleStages.length || failedStages.length || ['previous_results_preserved', 'analysis_unavailable'].includes(recovery.state))) {
    queue.push({
      action: 'retry', phase: staleStages.length ? 'evidence' : 'findings',
      title: staleStages.length ? 'Refresh affected analysis phases' : 'Retry failed analysis phases',
      detail: `${(staleStages.length ? staleStages : failedStages).join(', ') || 'Affected stages'} · validated results remain preserved.`,
    });
  }
  if (!running && !notStarted && visibility.allRejected) queue.push({ action: 'boundaries', phase: 'model', title: 'Review rejected trust boundaries', detail: 'Dependent findings remain stored but hidden until boundary decisions are updated.' });
  else if (!running && !notStarted && boundaryCandidates) queue.push({ action: 'boundaries', phase: 'model', title: `Review ${boundaryCandidates} trust-boundary candidate${boundaryCandidates === 1 ? '' : 's'}`, detail: 'Confirm or reject candidates before relying on downstream findings.' });
  if (!running && !notStarted && critical) queue.push({ action: 'critical', phase: 'findings', title: `Review ${critical} critical scenario${critical === 1 ? '' : 's'}`, detail: 'Prioritize grounded critical findings and record the review decision.' });
  if (!running && !notStarted && high) queue.push({ action: 'high', phase: 'findings', title: `Review ${high} high-risk scenario${high === 1 ? '' : 's'}`, detail: 'Confirm context and disposition for the highest remaining scored risks.' });
  if (!running && !notStarted && needsReview > (critical + high + boundaryCandidates)) queue.push({ action: 'review', phase: 'findings', title: `Resolve ${needsReview - critical - high - boundaryCandidates} other review item(s)`, detail: 'Review remaining findings that still need a decision.' });
  const gate = report.quality_gate || run.quality_gate || {};
  const components = gate.components || {};
  if (notStarted) queue.push({ action: 'run', phase: 'analysis', title: 'Run the threat model', detail: 'Build the DFD, STRIDE, LINDDUN, controls, tests, and evidence review queue.' });
  if (!running && !notStarted && components.control_disposition?.status !== 'ready') queue.push({ action: 'controls', phase: 'action-plan', title: `Review ${visibility.controls.length} control mapping${visibility.controls.length === 1 ? '' : 's'}`, detail: 'Resolve applicability decisions and confirm the recommended safeguards.' });
  if (!running && !notStarted && gaps) queue.push({ action: 'gaps', phase: 'evidence', title: `Resolve ${gaps} evidence gap${gaps === 1 ? '' : 's'}`, detail: 'Answer open questions or record an explicit defer decision.' });
  if (!running && !notStarted && !queue.length) queue.push({ action: 'report', phase: 'signoff', title: 'Review sign-off and report provenance', detail: 'Confirm readiness, methodology, and the DFD revision used by this run.' });
  const queueList = document.getElementById('analysis-next-actions-list');
  const queueCaption = document.getElementById('analysis-next-actions-caption');
  if (queueCaption) queueCaption.textContent = running ? 'The current phase is progressing. Results remain available while this run completes.' : queue.length ? `${queue.length} next action${queue.length === 1 ? '' : 's'} · ordered by impact.` : 'No pending actions.';
  if (queueList) queueList.innerHTML = running
    ? `<li class="analysis-next-action is-current"><span class="analysis-next-action-step">▶</span><div><strong>${escHtml(statusText)}</strong><small>${escHtml(phaseStatus || 'Waiting for the active stage update.')}</small></div></li>`
    : queue.slice(0, 3).map((item, index) => `<li class="analysis-next-action ${index === 0 ? 'is-current' : ''}"><span class="analysis-next-action-step">${index + 1}</span><div><strong>${escHtml(item.title)}</strong><small>${escHtml(item.detail)}</small></div><button type="button" class="btn btn-secondary btn-sm" data-overview-action="${escHtml(item.action)}" data-next-phase="${escHtml(item.phase)}">Open</button></li>`).join('');
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
  const stale = report?.analysis_stale;
  const stages = Array.isArray(stale?.stages) ? stale.stages : [];
  pendingArtifactAnalysisTypes = stages;
  renderAnalysisRunState(report);
}

function switchTab(tabId, { persist = true, focus = false } = {}) {
  if (!VALID_ANALYSIS_TABS.includes(tabId) || !currentReport) return;
  if (!isModelWorkspace && ['stride', 'linddun'].includes(tabId)) {
    goToFindingsWorkspace(projectId, window.UIState?.read().selection?.replace(/^threat:/, '') || '');
    return;
  }
  if (!isModelWorkspace && ['controls', 'tests'].includes(tabId)) {
    goToActionPlanWorkspace(projectId, tabId === 'tests' ? 'test' : 'control');
    return;
  }
  if (!isModelWorkspace && tabId === 'gaps') {
    goToEvidenceWorkspace(projectId, window.UIState?.read().selection || '');
    return;
  }
  if (!isModelWorkspace && ['diagram', 'trust-boundaries'].includes(tabId)) {
    goToModelWorkspace(projectId, window.UIState?.read().selection || '');
    return;
  }
  if (!resultsWorkspaceOpen) {
    resultsWorkspaceOpen = true;
    document.getElementById('results-tabs').style.display = '';
    renderResults(currentReport);
  }
  const workflowPhase = TAB_TO_WORKFLOW_PHASE[tabId];
  if (workflowPhase) lastAnalysisTabByPhase[workflowPhase] = tabId;
  document.body.classList.remove('analysis-context-workflow');
  syncWorkflowNavigation(tabId);
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
    const phase = TAB_TO_WORKFLOW_PHASE[tabId] || 'model';
    window.UIState?.update({
      project: projectId,
      run: String(currentReport?.analysis_run?.run_id || window.UIState?.read().run || ''),
      phase,
      view: tabId,
    }, { hash: `analysis-${tabId}` });
    syncAnalysisReportLinks();
    if (!window.UIState) history.replaceState(null, '', `${location.pathname}${location.search}#analysis-${tabId}`);
  }

  // Re-fit diagram when switching to diagram tab
  if (tabId === 'diagram' && diagramNetwork) {
    setTimeout(() => diagramNetwork.fit({ animation: { duration: 300, easingFunction: 'easeInOutQuad' } }), 100);
  }
}

function closeAnalysisResults() {
  resultsWorkspaceOpen = false;
  const resultsTabs = document.getElementById('results-tabs');
  if (resultsTabs) resultsTabs.style.display = 'none';
  document.getElementById('analysis-overview')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'start' });
  if (window.UIState && projectId) {
    window.UIState.update({ project: projectId, phase: '', view: '' }, { hash: '' });
    syncAnalysisReportLinks();
  }
}

function syncAnalysisReportLinks() {
  if (!window.UIState || !projectId) return;
  const state = window.UIState.read();
  const href = window.UIState.route('report', projectId, state);
  const modelHref = window.UIState.route('model', projectId, { ...state, phase: 'model', view: 'diagram' });
  const findingsHref = window.UIState.route('findings', projectId, { ...state, phase: 'findings', view: '' });
  const actionPlanHref = window.UIState.route('action-plan', projectId, { ...state, phase: 'action-plan', view: '' });
  const evidenceHref = window.UIState.route('evidence', projectId, { ...state, phase: 'evidence', view: '' });
  ['nav-report', 'btn-view-report'].forEach(id => {
    const link = document.getElementById(id);
    if (link) link.href = href;
  });
  const modelLink = document.getElementById('nav-model');
  if (modelLink) modelLink.href = modelHref;
  const findingsLink = document.getElementById('nav-findings');
  if (findingsLink) findingsLink.href = findingsHref;
  const actionPlanLink = document.getElementById('nav-action-plan');
  if (actionPlanLink) actionPlanLink.href = actionPlanHref;
  const evidenceLink = document.getElementById('nav-evidence');
  if (evidenceLink) evidenceLink.href = evidenceHref;
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
    window.UXTelemetry?.complete('boundary_review', 'analysis', 'success', { phase: 'model' });
    window.UIState?.update({ selection: `boundary:${boundaryId}` });
    syncAnalysisReportLinks();
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
    window.__5stonesDfdDebug = {
      getNodeBoxes: () => diagramNetwork?.body?.data?.nodes?.getIds?.().map(id => ({ id, box: diagramNetwork.getBoundingBox(id) })) || [],
    };
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
  if ((model.views || []).some(view => Array.isArray(view.projection_nodes) && Array.isArray(view.projection_flows))) {
    const asView = view => {
      const nodes = (view?.projection_nodes || []).map(node => ({
        ...node,
        element_id: node.id,
        label: `${node.display_id || ''} ${node.name || ''}`.trim(),
        element_type: node.type,
        model_level: view.kind,
      }));
      const flows = (view?.projection_flows || []).map(flow => ({
        ...flow,
        element_id: flow.id,
        flow_id: flow.id,
        source: nodes.find(node => node.id === flow.source_id)?.name || flow.source_id,
        destination: nodes.find(node => node.id === flow.target_id)?.name || flow.target_id,
        element_type: 'data_flow',
        model_level: view.kind,
      }));
      return { ...view, nodes, flows, boundaries: [] };
    };
    const views = model.views || [];
    const feature = views.find(view => view.id === canonicalFeatureViewId) || views.find(view => view.kind === 'feature');
    return {
      context: asView(views.find(view => view.kind === 'context')),
      system: asView(views.find(view => view.kind === 'system')),
      services: report?.trust_model?.views?.services || asView(views.find(view => view.kind === 'system')),
      scenarios: report?.trust_model?.views?.scenarios || asView(feature),
      assets: { items: (model.data_objects || []).map(item => ({ element_id: item.id, label: item.name, ...item })) },
    };
  }
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
    context: { label: 'Overview · L0', nodes, flows, boundaries },
    system: { label: 'Services · L1', nodes, flows, boundaries },
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
  const viewKind = diagramLevel === 'context' ? 'context' : diagramLevel === 'scenarios' ? 'feature' : 'system';
  const selectedProjection = resolveDfdProjection(report?.dfd_model, viewKind === 'feature' ? (canonicalFeatureViewId || 'feature') : viewKind);
  const canonicalIds = selectedProjection
    ? new Set(Object.values(selectedProjection.mappings).flat().map(String))
    : null;
  const levelMapped = threats.filter(item => canonicalIds
    ? targetRefs(item).some(ref => canonicalIds.has(String(ref.id)))
    : targetRefs(item).some(ref => ref.model_level === (diagramLevel === 'context' ? 'context' : diagramLevel.slice(0, -1))));
  el.innerHTML = `
    <span class="diagram-mapping-label">Coverage</span>
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
    const readiness = validation?.readiness || validation?.analysis_readiness;
    const semanticQuality = model?.semantic_quality || validation?.semantic_quality;
    const topologyIssues = readiness?.topology_coverage?.issues || validation?.semantic_issues || [];
    const knowledgeIssues = readiness?.knowledge_completeness?.issues || [];
    const reviewerIssues = readiness?.reviewer_acceptance?.issues || [];
    const qualityIssues = (semanticQuality?.issues || []).map(item => item.message ? `${item.code}: ${item.message}` : item);
    const issues = [...new Set([...qualityIssues, ...topologyIssues, ...knowledgeIssues, ...reviewerIssues])];
    const statusLabel = readiness?.status === 'ready' ? 'ready' : readiness?.status === 'not_ready' ? 'not ready' : (issues.length ? 'needs review' : 'not evaluated');
    topologyStatus.hidden = !model || (!issues.length && statusLabel === 'ready');
    topologyStatus.innerHTML = !topologyStatus.hidden ? `
      <strong>DFD readiness: ${escHtml(statusLabel)}</strong>
      ${readiness ? `<div class="dfd-readiness-summary">Structural: <strong>${escHtml(readiness.structural_validity?.status || 'unknown')}</strong> · Topology: <strong>${escHtml(readiness.topology_coverage?.status || 'unknown')}</strong> · Knowledge: <strong>${escHtml(readiness.knowledge_completeness?.status || 'unknown')}</strong> · Reviewer: <strong>${escHtml(readiness.reviewer_acceptance?.status || 'unknown')}</strong></div>` : ''}
      ${semanticQuality ? `<div class="dfd-quality-summary"><strong>Semantic quality</strong><span>${escHtml(semanticQuality.status || 'review')} · ${Number(semanticQuality.counts?.primary_interactions || 0)} primary interaction${Number(semanticQuality.counts?.primary_interactions || 0) === 1 ? '' : 's'} · ${Number(semanticQuality.counts?.deferred_interactions || 0)} deferred</span></div>` : ''}
      ${issues.length ? `<details class="dfd-quality-details" ${issues.length <= 3 ? 'open' : ''}><summary>${issues.length} quality issue${issues.length === 1 ? '' : 's'} · review before sign-off</summary><ul>${issues.slice(0, 12).map(issue => `<li>${escHtml(issue)}</li>`).join('')}</ul>${issues.length > 12 ? `<span class="text-xs text-muted">${issues.length - 12} more issue${issues.length - 12 === 1 ? '' : 's'} available in the inventory and evidence workspaces.</span>` : ''}</details>` : ''}` : '';
  }
  if (!panel || !container) return;
  if (!model) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = '';
  const nodeById = new Map((model.nodes || []).map(node => [String(node.id), node]));
  const semanticQuality = model.semantic_quality || report?.dfd_validation?.semantic_quality;
  const qualityIssues = semanticQuality?.issues || [];
  const rows = [
    ...(model.nodes || []).map(node => ({
      type: 'node', id: node.id, displayId: node.display_id, name: node.name,
      detail: `${node.type} · ${node.scope} · ${node.ownership} · ${node.exposure} · grouping ${node.grouping_status || 'unknown'}${node.tenant_id ? ` · tenant ${node.tenant_id}` : ''}${node.environment ? ` · ${node.environment}` : ''}`,
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
    ...((model.deferred_interactions || []).map(item => ({
      type: 'deferred_interaction', id: item.id, displayId: 'DF', name: `${item.source || '(unknown)'} → ${item.destination || '(unknown)'}`,
      detail: `deferred · ${item.owner || 'Product / Architecture'} · ${item.reason || 'evidence or endpoint review required'}`,
    }))),
  ];
  if (!rows.length) {
    container.innerHTML = '<p class="text-sm text-muted">The canonical model has no inventory elements yet.</p>';
    return;
  }
  container.innerHTML = `
    ${semanticQuality ? `<div class="dfd-inventory-quality" aria-label="DFD semantic quality summary"><div><strong>Semantic quality: ${escHtml(semanticQuality.status || 'review')}</strong><span>${Number(semanticQuality.counts?.nodes || 0)} nodes · ${Number(semanticQuality.counts?.flows || 0)} flows · ${Number(semanticQuality.counts?.primary_interactions || 0)} primary</span></div><div class="dfd-quality-actions"><span>${qualityIssues.length} review item${qualityIssues.length === 1 ? '' : 's'}</span><span>${Number(semanticQuality.counts?.deferred_interactions || 0)} deferred</span></div></div>` : ''}
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
  if (canonicalExpandForSelection) return new Set();
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
  if (type === 'deferred_interaction') {
    const deferred = (model.deferred_interactions || []).find(item => String(item.id) === String(id));
    const question = (model.questions || []).find(item => String(item.id).includes(String(id)));
    if (question) showDfdQuestionInspector(question);
    else if (deferred) showToast(`${deferred.reason || 'Deferred interaction requires review'} Next: ${deferred.next_action || 'add evidence'}`, 'info');
    return;
  }
  const selectionType = { node: 'dfd-node', flow: 'dfd-flow', boundary: 'boundary', zone: 'zone' }[type];
  if (!isModelWorkspace) {
    goToModelWorkspace(projectId, selectionType ? `${selectionType}:${id}` : '');
    return;
  }
  if (isModelWorkspace) {
    focusModelElement(type, id);
    return;
  }
  if (selectionType) {
    window.UIState?.update({ selection: `${selectionType}:${id}` });
    syncAnalysisReportLinks();
  }
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
  // The server owns semantic projection membership and flow balancing.
  // Client edits only maintain placeholder feature records until save returns
  // the rebuilt canonical projections.
  const processIds = new Set((model.nodes || []).filter(node => node.type === 'process').map(node => node.id));
  model.views = (model.views || []).filter(view =>
    view.kind !== 'feature' || processIds.has(view.parent_process_id)
  );
  processIds.forEach(processId => {
    if ((model.views || []).some(view => view.kind === 'feature' && view.parent_process_id === processId)) return;
    model.views.push({
      id: `view-feature-${processId}`,
      kind: 'feature',
      parent_process_id: processId,
      element_refs: [processId],
      projection_mappings: { [processId]: [processId] },
      input_flow_ids: [],
      output_flow_ids: [],
      port_mappings: { input: [], output: [] },
      projection_nodes: [],
      projection_flows: [],
      decomposition_status: 'detail_only',
      projection_issues: [],
      positions: {},
      collapsed_groups: [],
      viewport: {},
    });
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
  revealModelInspector();
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
  revealModelInspector();
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
  const crossingFlows = (boundary.crossing_flow_ids || []).map(id => {
    const flow = (currentReport?.dfd_model?.flows || []).find(item => String(item.id) === String(id));
    return flow ? `<button type="button" class="model-flow-link" data-boundary-flow="${escHtml(flow.id)}">${escHtml(`${flow.display_id || flow.id} · ${flow.name || 'unnamed flow'}`)}</button>` : '';
  }).join('');
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
    <section class="guided-boundary-review" aria-labelledby="guided-boundary-title"><span class="analysis-overview-kicker">Guided review</span><h3 id="guided-boundary-title">Does the access or ownership rule change here?</h3><p>Compare the source and destination zones, identity, privilege, and data exposure. Choose “Belum tahu” when evidence is not sufficient.</p><div class="guided-review-actions"><button type="button" class="btn btn-secondary btn-sm" data-guided-boundary="confirmed">Yes, access differs</button><button type="button" class="btn btn-ghost btn-sm" data-guided-boundary="rejected">No, same rule</button><button type="button" class="btn btn-ghost btn-sm" data-guided-boundary="candidate">Belum tahu</button></div><p class="finding-muted">Belum tahu keeps the boundary unresolved for later evidence review.</p></section>
    ${crossingFlows ? `<h3>Crossing flows</h3><div class="model-linked-flows">${crossingFlows}</div>` : ''}
    ${isModelWorkspace ? modelFindingLinksHtml(threats) : `<div class="inspector-findings"><strong>${threats.length} mapped finding${threats.length === 1 ? '' : 's'}</strong></div>`}`;
  body.querySelector('[data-save-dfd-boundary]')?.addEventListener('click', () => saveCanonicalBoundary(boundary.id, body));
  body.querySelectorAll('[data-guided-boundary]').forEach(button => button.addEventListener('click', async () => {
    const status = button.dataset.guidedBoundary === 'confirmed' ? 'Confirmed' : button.dataset.guidedBoundary === 'rejected' ? 'Rejected' : 'Candidate';
    await updateModelBoundaryReview(boundary.id, status);
    window.UXTelemetry?.complete('boundary_review', 'model', 'success', { phase: 'model' });
  }));
  body.querySelectorAll('[data-boundary-flow]').forEach(button => button.addEventListener('click', () => focusModelElement('flow', button.dataset.boundaryFlow)));
  body.insertAdjacentHTML('beforeend', modelEvidenceLinksHtml(boundary.evidence_refs || []));
  wireDfdDeleteButton(body);
  revealModelInspector();
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
  const zoneIds = new Set(canonicalZoneDescendants(String(zone.id), new Map((model?.zones || []).map(item => [String(item.id), item]))));
  const memberIds = new Set((model?.nodes || []).filter(node => (node.zone_ids || []).some(id => zoneIds.has(String(id)))).map(node => String(node.id)));
  const relatedFlows = (model?.flows || []).filter(flow => memberIds.has(String(flow.source_id)) || memberIds.has(String(flow.target_id)));
  const internalCount = relatedFlows.filter(flow => memberIds.has(String(flow.source_id)) && memberIds.has(String(flow.target_id))).length;
  const flowList = relatedFlows.map(flow => `<button type="button" class="btn btn-ghost btn-sm" data-zone-flow-id="${escHtml(flow.id)}">${escHtml(flow.display_id || flow.id)} · ${escHtml(flow.name || 'unknown data')} · ${escHtml(flow.protocol || 'protocol unknown')}</button>`).join('');
  const parentOptions = (model?.zones || []).filter(item => item.id !== zone.id).map(item =>
    `<option value="${escHtml(item.id)}" ${item.id === zone.parent_zone_id ? 'selected' : ''}>${escHtml(`${item.display_id} ${item.name}`)}</option>`
  ).join('');
  title.textContent = `${zone.display_id || zone.id} ${zone.name}`;
  body.innerHTML = `
    <details class="dfd-zone-interactions"><summary>${memberIds.size} member nodes · ${internalCount} internal flows · ${relatedFlows.length - internalCount} crossing flows</summary><div class="dfd-editor-actions">${flowList || '<span>No grounded flow in this zone.</span>'}</div></details>
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
  body.querySelectorAll('[data-zone-flow-id]').forEach(button => button.addEventListener('click', () => {
    const flow = model?.flows?.find(item => String(item.id) === button.dataset.zoneFlowId);
    if (flow) showCanonicalFlowInspector(flow);
  }));
  wireDfdDeleteButton(body);
  revealModelInspector();
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
  revealModelInspector();
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
  if (!isModelWorkspace) {
    const selected = refs.find(ref => String(ref.id) === String(threat.primary_interaction_ref))
      || refs.find(ref => ref.type === 'data_flow')
      || refs.find(ref => ['entity', 'process', 'data_store'].includes(ref.type));
    const selectionType = selected
      ? ({ data_flow: 'dfd-flow', entity: 'dfd-node', process: 'dfd-node', data_store: 'dfd-node', external_entity: 'dfd-node' }[selected.type])
      : (flowIds.size ? 'dfd-flow' : nodeIds.size ? 'dfd-node' : '');
    const selectedId = selected?.id || (flowIds.size ? [...flowIds][0] : [...nodeIds][0]);
    if (selectionType && selectedId) goToModelWorkspace(projectId, `${selectionType}:${selectedId}`);
    else goToModelWorkspace(projectId);
    return;
  }
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

function canonicalLayoutPositions(model, visibleNodes, visibleFlows, viewKind, selectedView = null, forceReflow = false) {
  const view = selectedView || (model.views || []).find(item => item.kind === viewKind) || (model.views || []).find(item => item.kind === 'context');
  const saved = view?.positions || {};
  const hasCompleteSavedLayout = visibleNodes.length > 0 && visibleNodes.every(node => {
    const position = saved[node.id];
    return Number.isFinite(Number(position?.x)) && Number.isFinite(Number(position?.y));
  });
  if (hasCompleteSavedLayout && !forceReflow) {
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

  const zoneLayout = canonicalCompactZoneLayout(model, visibleNodes, visibleFlows, positions, {
    dense: viewKind === 'context' && visibleNodes.length <= 6 && usableFlows.length > 0,
  });
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

function canonicalEstimatedNodeSize(node) {
  const label = `${node.display_id || node.id} ${node.name || ''}`;
  const lines = Math.max(1, Math.ceil(label.length / 26));
  return { width: 280, height: Math.max(94, 48 + lines * 20) };
}

function canonicalCompactZoneLayout(model, visibleNodes, visibleFlows, basePositions, { dense = false } = {}) {
  const zones = model.zones || [];
  const zonesById = new Map(zones.map(zone => [String(zone.id), zone]));
  const topGroups = new Map();
  const nodeById = new Map(visibleNodes.map(node => [String(node.id), node]));
  const topZoneFor = node => canonicalTopZoneId(String(node.zone_ids?.[0] || ''), zonesById);
  visibleNodes.forEach(node => {
    const directZone = String(node.zone_ids?.[0] || '__unknown__');
    const topZone = topZoneFor(node);
    if (!topGroups.has(topZone)) topGroups.set(topZone, []);
    topGroups.get(topZone).push({ node, directZone });
  });
  const groups = new Map();
  topGroups.forEach((records, topZoneId) => {
    const subGroups = new Map();
    records.forEach(record => {
      if (!subGroups.has(record.directZone)) subGroups.set(record.directZone, []);
      subGroups.get(record.directZone).push(record.node);
    });
    const localPositions = {};
    let groupTop = 10;
    let groupWidth = 0;
    [...subGroups.entries()].forEach(([, nodes]) => {
      nodes.sort((a, b) => {
        const left = basePositions[a.id] || { x: 0, y: 0 };
        const right = basePositions[b.id] || { x: 0, y: 0 };
        return left.y - right.y || left.x - right.x || canonicalSortKey(a).localeCompare(canonicalSortKey(b));
      });
      const columns = dense ? 1 : Math.min(3, Math.max(1, Math.ceil(Math.sqrt(nodes.length))));
      const rows = Math.max(1, Math.ceil(nodes.length / columns));
      const columnWidths = Array.from({ length: columns }, (_, column) =>
        Math.max(...nodes.filter((_, index) => index % columns === column).map(node => dense
          ? Math.min(240, Math.max(170, `${node.display_id || node.id} ${node.name || ''}`.length * 7 + 38))
          : canonicalEstimatedNodeSize(node).width), 0));
      const rowHeights = Array.from({ length: rows }, (_, row) =>
        Math.max(...nodes.slice(row * columns, (row + 1) * columns).map(node => canonicalEstimatedNodeSize(node).height), 0));
      const columnLefts = columnWidths.map((_, column) =>
        (dense ? 38 : 80) + columnWidths.slice(0, column).reduce((sum, width) => sum + width + (dense ? 48 : 72), 0));
      const rowTops = rowHeights.map((_, row) =>
        groupTop + 80 + rowHeights.slice(0, row).reduce((sum, height) => sum + height + 62, 0));
      nodes.forEach((node, index) => {
        const column = index % columns;
        const row = Math.floor(index / columns);
        localPositions[node.id] = {
          x: columnLefts[column] + columnWidths[column] / 2,
          y: rowTops[row] + rowHeights[row] / 2,
        };
      });
      groupWidth = Math.max(groupWidth, columnLefts[columns - 1] + columnWidths[columns - 1] + (dense ? 38 : 80));
      groupTop = rowTops[rows - 1] + rowHeights[rows - 1] + 55;
    });
    groups.set(topZoneId, { positions: localPositions, width: Math.max(dense ? 246 : 360, groupWidth), height: groupTop + 40, nodeCount: records.length });
  });

  const degree = new Map([...groups.keys()].map(id => [id, 0]));
  const crossFlows = visibleFlows.map(flow => {
    const source = nodeById.get(String(flow.source_id));
    const target = nodeById.get(String(flow.target_id));
    return source && target ? { source: topZoneFor(source), target: topZoneFor(target) } : null;
  }).filter(flow => flow && flow.source !== flow.target);
  crossFlows.forEach(flow => {
    degree.set(flow.source, (degree.get(flow.source) || 0) + 1);
    degree.set(flow.target, (degree.get(flow.target) || 0) + 1);
  });
  const ranked = [...groups.keys()].sort((a, b) =>
    (degree.get(b) || 0) - (degree.get(a) || 0)
    || groups.get(b).nodeCount - groups.get(a).nodeCount
    || a.localeCompare(b));
  const hub = ranked[0];
  if (!hub) return { positions: {}, bounds: { width: 900, height: 680 } };
  const left = [], right = [], isolated = [];
  ranked.slice(1).forEach(id => {
    const incoming = crossFlows.filter(flow => flow.source === id && flow.target === hub).length;
    const outgoing = crossFlows.filter(flow => flow.source === hub && flow.target === id).length;
    if (!(degree.get(id) || 0)) isolated.push(id);
    else if (incoming > outgoing) left.push(id);
    else right.push(id);
  });
  const leftWidth = Math.max(0, ...left.map(id => groups.get(id).width));
  const hubX = 100 + (left.length ? leftWidth + (dense ? 75 : 170) : 0);
  const hubY = 100;
  const rightX = hubX + groups.get(hub).width + (dense ? 75 : 170);
  const placements = new Map([[hub, { x: hubX, y: hubY }]]);
  const placeSide = (ids, x) => {
    const totalHeight = ids.reduce((sum, id) => sum + groups.get(id).height + 90, -90);
    let y = Math.max(100, hubY + (groups.get(hub).height - totalHeight) / 2);
    ids.forEach(id => {
      placements.set(id, { x, y });
      y += groups.get(id).height + 90;
    });
  };
  if (left.length) placeSide(left, 100);
  if (right.length) placeSide(right, rightX);
  let bottom = Math.max(...[...placements].map(([id, place]) => place.y + groups.get(id).height)) + 130;
  isolated.forEach(id => {
    placements.set(id, { x: hubX, y: bottom });
    bottom += groups.get(id).height + 90;
  });
  const positions = {};
  groups.forEach((group, id) => {
    const place = placements.get(id);
    Object.entries(group.positions).forEach(([nodeId, position]) => {
      positions[nodeId] = { x: position.x + place.x, y: position.y + place.y };
    });
  });
  const width = Math.max(...[...placements].map(([id, place]) => place.x + groups.get(id).width), 800) + 100;
  const height = Math.max(...[...placements].map(([id, place]) => place.y + groups.get(id).height), 580) + 100;
  return { positions, bounds: { width, height } };
}

function canonicalResolveNodeOverlaps(network, nodeIds, gap = 28) {
  const positions = network.getPositions();
  const ordered = nodeIds.map(id => ({ id, box: network.getBoundingBox(id) }))
    .filter(item => item.box && [item.box.left, item.box.right, item.box.top, item.box.bottom].every(Number.isFinite))
    .sort((a, b) => a.box.top - b.box.top || a.box.left - b.box.left || String(a.id).localeCompare(String(b.id)));
  const placed = [];
  let moved = false;
  ordered.forEach(item => {
    const position = positions[item.id];
    if (!position) return;
    let box = { ...item.box };
    for (const prior of placed) {
      const overlapsX = box.left < prior.right + gap && box.right > prior.left - gap;
      if (overlapsX && box.top < prior.bottom + gap && box.bottom > prior.top - gap) {
        const shift = prior.bottom + gap - box.top;
        box = { left: box.left, right: box.right, top: box.top + shift, bottom: box.bottom + shift };
      }
    }
    const deltaY = box.top - item.box.top;
    if (deltaY > 0.5) {
      network.moveNode(item.id, position.x, position.y + deltaY);
      moved = true;
    }
    placed.push(box);
  });
  return moved;
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

function resolveDfdProjection(model, viewIdOrKind) {
  if (!model?.views?.length) return null;
  const view = model.views.find(item => item.id === viewIdOrKind)
    || model.views.find(item => item.kind === viewIdOrKind)
    || (viewIdOrKind === 'feature' ? model.views.find(item => item.kind === 'feature') : null);
  if (!view) return null;
  return {
    view,
    nodes: view.projection_nodes || [],
    flows: view.projection_flows || [],
    mappings: view.projection_mappings || {},
    nodeById: new Map((view.projection_nodes || []).map(item => [String(item.id), item])),
  };
}

function navigateCanonicalLevel(level, featureViewId = null) {
  if (!['context', 'services', 'scenarios'].includes(level) || !currentReport?.dfd_model) return;
  diagramLevel = level;
  if (featureViewId) canonicalFeatureViewId = featureViewId;
  try { localStorage.setItem('5stones-dfd-level', diagramLevel); } catch (_) {}
  closeModelInspector();
  syncDiagramLevelUi();
  renderDiagram(currentReport);
  renderDiagramTextAlternative(currentReport);
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
}

function updateCanonicalZoneLayer(model, visualNodes) {
  if (!diagramNetwork) return;
  const layer = document.getElementById('diagram-zone-layer');
  if (!layer) return;
  const zonesById = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const depthMemo = new Map();
  const positions = diagramNetwork.getPositions();
  layer.querySelectorAll('[data-zone-id]').forEach(element => {
    const zoneId = element.dataset.zoneId;
    const zone = zonesById.get(String(zoneId));
    if (!zone) return;
    const descendantIds = canonicalZoneDescendants(String(zone.id), zonesById);
    const zoneIds = new Set(descendantIds);
    const boxes = visualNodes.filter(node => positions[node.id] && (node.zone_ids || []).some(id => zoneIds.has(String(id))))
      .map(node => diagramNetwork.getBoundingBox(node.id))
      .filter(box => box && [box.left, box.right, box.top, box.bottom].every(Number.isFinite));
    if (!boxes.length) {
      element.style.display = 'none';
      return;
    }
    const depth = Number(element.dataset.zoneDepth || 0);
    const nestedLevels = Math.max(0, ...descendantIds.map(id => canonicalZoneDepth(id, zonesById, depthMemo) - depth));
    const paddingX = 34 + nestedLevels * 24;
    const paddingTop = 58 + nestedLevels * 28;
    const paddingBottom = 30 + nestedLevels * 22;
    const left = diagramNetwork.canvasToDOM({ x: Math.min(...boxes.map(box => box.left)), y: 0 }).x - paddingX;
    const top = diagramNetwork.canvasToDOM({ x: 0, y: Math.min(...boxes.map(box => box.top)) }).y - paddingTop;
    const right = diagramNetwork.canvasToDOM({ x: Math.max(...boxes.map(box => box.right)), y: 0 }).x + paddingX;
    const bottom = diagramNetwork.canvasToDOM({ x: 0, y: Math.max(...boxes.map(box => box.bottom)) }).y + paddingBottom;
    element.style.display = '';
    element.style.left = `${left}px`;
    element.style.top = `${top}px`;
    element.style.width = `${Math.max(150, right - left)}px`;
    element.style.height = `${Math.max(110, bottom - top)}px`;
    element.title = `${zone.display_id || zone.id} ${zone.name} · ${boxes.length} visible node${boxes.length === 1 ? '' : 's'}`;
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
      _canonicalNodeIds: [...new Set(members.flatMap(node => node._canonicalNodeIds || [node.id]).map(String))],
      _threats: uniqueThreats(members.flatMap(node => node._threats || [])),
    });
    members.forEach(node => nodeTarget.set(String(node.id), groupId));
  });
  const projectedFlows = [];
  const aggregated = new Map();
  flows.forEach(flow => {
    const sourceId = nodeTarget.get(String(flow.source_id));
    const targetId = nodeTarget.get(String(flow.target_id));
    if (!sourceId || !targetId || sourceId === targetId) return;
    const canonicalFlowIds = flow._collapsedFlowIds?.length ? flow._collapsedFlowIds : flow.canonical_flow_ids?.length ? flow.canonical_flow_ids : [flow.id];
    const canonicalFlows = flow._collapsedFlows?.length ? flow._collapsedFlows : [flow];
    const projected = { ...flow, source_id: sourceId, target_id: targetId, _collapsedFlowIds: [...canonicalFlowIds], _collapsedFlows: [...canonicalFlows] };
    if (sourceId === String(flow.source_id) && targetId === String(flow.target_id)) {
      projectedFlows.push(projected);
      return;
    }
    const key = `${sourceId}::${targetId}`;
    const existing = aggregated.get(key);
    if (existing) {
      existing._collapsedFlowIds.push(...canonicalFlowIds);
      existing._collapsedFlows.push(...canonicalFlows);
      existing.data_object_ids = [...new Set([...(existing.data_object_ids || []), ...(flow.data_object_ids || [])])];
      existing.boundary_crossings = [...new Set([...(existing.boundary_crossings || []), ...(flow.boundary_crossings || [])])];
      existing.evidence_refs = [...new Set([...(existing.evidence_refs || []), ...(flow.evidence_refs || [])])];
      if (flow.crossing_status === 'unresolved') existing.crossing_status = 'unresolved';
      for (const field of ['protocol', 'authn', 'authz', 'interaction_kind']) {
        if (existing[field] !== flow[field]) existing[field] = 'mixed';
      }
      return;
    }
    aggregated.set(key, projected);
    projectedFlows.push(projected);
  });
  projectedFlows.forEach(flow => {
    if (flow._collapsedFlowIds.length > 1) {
      flow.id = `dfd-aggregate:${flow.source_id}:${flow.target_id}`;
      flow.display_id = `${flow._collapsedFlowIds.length} flows`;
      flow.name = `${flow._collapsedFlowIds.length} flows in collapsed zone`;
    }
  });
  return { nodes: visualNodes, flows: projectedFlows };
}

function canonicalFlowSmooth(ordinal, count) {
  if (count <= 1) return { enabled: true, type: 'cubicBezier', forceDirection: 'horizontal', roundness: .22 };
  return { enabled: true, type: ordinal % 2 === 0 ? 'curvedCW' : 'curvedCCW', roundness: .18 + Math.floor(ordinal / 2) * .12 };
}

function canonicalScopeReviewTargets(model) {
  const typeRank = { process: 0, data_store: 1, entity: 2 };
  return [...(model?.nodes || [])].sort((left, right) => {
    const scopeRank = Number(left.scope !== 'unknown') - Number(right.scope !== 'unknown');
    if (scopeRank) return scopeRank;
    const leftRank = typeRank[left.type] ?? 3;
    const rightRank = typeRank[right.type] ?? 3;
    return leftRank - rightRank || String(left.name || left.id).localeCompare(String(right.name || right.id));
  });
}

function bindCanonicalScopeReviewActions(container) {
  container.querySelectorAll('[data-context-scope-review-id]').forEach(button => {
    button.addEventListener('click', () => focusModelElement('node', button.dataset.contextScopeReviewId, { preferredViewKind: 'system' }));
  });
}

function renderCanonicalDiagram(report, viewKind = 'context', { forceReflow = false } = {}) {
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
      const detail = view.decomposition_status === 'decomposed' ? ' · decomposed' : view.decomposition_status === 'pending' ? ' · needs evidence' : ' · connections only';
      return `<option value="${escHtml(view.id)}" ${view.id === canonicalFeatureViewId ? 'selected' : ''}>${escHtml(`${parent?.name || view.parent_process_id}${detail}`)}</option>`;
    }).join('');
  }
  const selectedFeature = viewKind === 'feature'
    ? featureViews.find(view => view.id === canonicalFeatureViewId) || featureViews[0]
    : null;
  const resolvedProjection = resolveDfdProjection(model, selectedFeature?.id || viewKind);
  const selectedView = resolvedProjection?.view || selectedFeature || (model.views || []).find(view => view.kind === viewKind);
  const hasStructuredProjection = Boolean(resolvedProjection);
  const canonicalFlowById = new Map((model.flows || []).map(flow => [String(flow.id), flow]));
  const visibleRefs = selectedFeature ? new Set(selectedFeature.element_refs || []) : null;
  const allVisibleNodes = hasStructuredProjection
    ? resolvedProjection.nodes.map(node => ({ ...node }))
    : visibleRefs ? (model.nodes || []).filter(node => visibleRefs.has(node.id)) : (model.nodes || []);
  const allVisibleFlows = hasStructuredProjection
    ? resolvedProjection.flows.map(flow => ({
      ...flow,
      _collapsedFlowIds: [...(flow.canonical_flow_ids || [])],
      _collapsedFlows: (flow.canonical_flow_ids || []).map(id => canonicalFlowById.get(String(id))).filter(Boolean),
    }))
    : visibleRefs ? (model.flows || []).filter(flow => visibleRefs.has(flow.id)) : (model.flows || []);
  const connectedNodeIds = new Set(allVisibleFlows.flatMap(flow => [String(flow.source_id), String(flow.target_id)]));
  const canFocusConnected = (viewKind === 'context' || viewKind === 'system') && connectedNodeIds.size > 0;
  const hiddenUnconnectedCount = canFocusConnected && !canonicalShowUnconnected
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
    unconnectedButton.hidden = !canFocusConnected || !allVisibleNodes.some(node => !connectedNodeIds.has(String(node.id)));
    unconnectedButton.textContent = canonicalShowUnconnected ? 'Hide unconnected' : `Show unconnected (${hiddenUnconnectedCount})`;
    unconnectedButton.setAttribute('aria-pressed', String(canonicalShowUnconnected));
  }
  const layout = canonicalLayoutPositions(model, visibleNodes, visibleFlows, viewKind, selectedFeature, forceReflow);
  canonicalRenderedViewKind = viewKind;
  const shell = document.getElementById('diagram-canvas-shell');
  if (shell) shell.style.height = `${Math.max(680, Math.min(1100, Math.ceil(layout.bounds.height)))}px`;
  const nodeRows = visibleNodes.map(node => {
    const zoneId = String(node.zone_ids?.[0] || 'unknown');
    const mapped = uniqueThreats(threats.filter(threat => targetMatches(threat, node.canonical_node_ids || node.id)));
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
      _canonicalNodeIds: [...(node.canonical_node_ids || [node.id])],
      zone_ids: [...(node.zone_ids || [])],
      _collapsedZoneId: node._collapsedZoneId || null,
      _collapsedNodeIds: [...(node._collapsedNodeIds || [])],
      _modelMeta: `${node.type} · ${zone?.name || 'zone unknown'} · ${status}${node.knowledge_status ? ` · knowledge=${node.knowledge_status}` : ''}`,
    };
  });
  const nodeById = new Map(visibleNodes.map(node => [String(node.id), node]));
  const pairCounts = new Map();
  visibleFlows.forEach(flow => {
    const pair = `${flow.source_id}::${flow.target_id}`;
    pairCounts.set(pair, (pairCounts.get(pair) || 0) + 1);
  });
  const pairOrdinals = new Map();
  const edgeRows = visibleFlows.map(flow => {
    const source = nodeById.get(String(flow.source_id));
    const target = nodeById.get(String(flow.target_id));
    const constituents = flow._collapsedFlows || [flow];
    const mapped = uniqueThreats(threats.filter(threat =>
      constituents.some(item => targetMatches(threat, item.id, 'data_flow')
        || targetMatches(threat, item.boundary_crossings || [], 'trust_boundary'))
    ));
    const data = (flow.data_object_ids || []).map(id => dataObjects.get(String(id))?.name || id);
    const crossing = (flow.boundary_crossings || []).length > 0 || flow.crossing_status === 'unresolved';
    const crossingText = flow.crossing_status === 'unresolved'
      ? 'Boundary crossing unresolved — review zone membership.'
      : `Crossings: ${(flow.boundary_crossings || []).join(', ') || 'none'}`;
    const pair = `${flow.source_id}::${flow.target_id}`;
    const ordinal = pairOrdinals.get(pair) || 0;
    pairOrdinals.set(pair, ordinal + 1);
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
      smooth: canonicalFlowSmooth(ordinal, pairCounts.get(pair) || 1),
      _sourceLabel: source?.name || flow.source_id,
      _destinationLabel: target?.name || flow.target_id,
      _flowDetails: [
        `${constituents.length} canonical flow${constituents.length === 1 ? '' : 's'}`,
        ...constituents.flatMap(item => [
          `${item.display_id || item.id}: ${item.name || 'unknown data'}`,
          `Interaction: ${item.interaction_kind || 'unknown'} · Protocol: ${item.protocol || 'unknown'}`,
          `AuthN: ${item.authn || 'unknown'} · AuthZ: ${item.authz || 'unknown'}`,
          `Crossings: ${(item.boundary_crossings || []).join(', ') || 'none'} · Evidence: ${(item.evidence_refs || []).join(', ') || 'none'}`,
        ]),
      ],
      _canonicalFlowIds: constituents.map(item => String(item.id)),
      _crossing: crossing,
      _logical: flow.crossing_status === 'resolved' && !(flow.boundary_crossings || []).length,
      _threats: mapped,
    };
  });
  if (!nodeRows.length) {
    const contextIssue = (selectedView?.projection_issues || []).find(issue => issue.includes('context_scope_unknown'));
    if (contextIssue) {
      const scopeTargets = canonicalScopeReviewTargets(model);
      const targetButtons = scopeTargets.slice(0, 6).map(node => `
        <button type="button" class="diagram-scope-review-link" data-context-scope-review-id="${escHtml(node.id)}">
          <strong>${escHtml(`Edit scope: ${node.display_id || node.id} ${node.name}`)}</strong>
          <span>${escHtml(`${node.type} · current scope: ${node.scope || 'unknown'}`)}</span>
        </button>`).join('');
      const decisionText = scopeTargets.length
        ? 'Choose a row to open that component’s editor in L1. Set Scope to in_scope for an element inside this system or external_dependency for an element outside it, then click Save semantic metadata. L1 keeps showing the modeled components; this decision defines the system aggregate and crossing flows in L0. The model will not guess the boundary.'
        : 'There are no canonical elements to classify yet. Add or confirm model elements before defining the system boundary.';
      container.innerHTML = `<div class="diagram-grounded-empty diagram-scope-empty">
        <strong>Context view needs an explicit scope decision</strong>
        <span>${escHtml(contextIssue)}</span>
        <p>${escHtml(decisionText)}</p>
        ${targetButtons ? `<div class="diagram-scope-review-list" aria-label="Canonical elements to review for system scope">${targetButtons}</div>` : ''}
      </div>`;
      bindCanonicalScopeReviewActions(container);
    } else {
      container.innerHTML = '<div class="diagram-grounded-empty"><strong>Canonical DFD is empty</strong><span>Add or confirm model elements before running threat analysis.</span></div>';
    }
    document.getElementById('diagram-zone-layer')?.replaceChildren();
    return;
  }
  const data = { nodes: new vis.DataSet(nodeRows), edges: new vis.DataSet(edgeRows) };
  renderCanonicalZoneLayer(model, visibleNodes);
  const toolbarTitle = document.querySelector('.diagram-toolbar-title');
  const toolbarSubtitle = document.querySelector('.diagram-toolbar-sub');
  if (toolbarTitle) toolbarTitle.textContent = viewKind === 'feature'
    ? selectedFeature?.decomposition_status === 'decomposed' ? 'Feature breakdown · L2'
      : selectedFeature?.decomposition_status === 'pending' ? 'Feature detail · L2 pending'
        : 'Connection detail · L2 unavailable'
    : viewKind === 'system' ? 'Services · L1' : 'Overview · L0';
  const visualConnectedNodeIds = new Set(visibleFlows.flatMap(flow => [String(flow.source_id), String(flow.target_id)]));
  const isolatedCount = visibleNodes.filter(node => !visualConnectedNodeIds.has(String(node.id))).length;
  if (toolbarSubtitle) {
    const hierarchyStatus = viewKind === 'feature'
      ? ` · ${selectedFeature?.decomposition_status === 'decomposed' ? 'evidence-backed subprocess decomposition' : selectedFeature?.decomposition_status === 'pending' ? 'subprocess evidence is incomplete' : 'one-hop connections only; decomposition is not documented'}`
      : '';
    const inScopeCount = (model.nodes || []).filter(node => node.scope === 'in_scope').length;
    const unknownScopeCount = (model.nodes || []).filter(node => node.scope === 'unknown').length;
    const scopeReviewStatus = viewKind === 'system'
      ? inScopeCount === 0 ? ' · No system scope is saved yet; edit a component’s Scope and save to build L0'
        : unknownScopeCount ? ` · ${unknownScopeCount} component scope decision${unknownScopeCount === 1 ? '' : 's'} still unknown` : ''
      : '';
    toolbarSubtitle.textContent = `Revision ${model.revision} · ${visibleNodes.length} elements · ${visibleFlows.length} flows${hierarchyStatus}${scopeReviewStatus}${hiddenUnconnectedCount ? ` · ${hiddenUnconnectedCount} unconnected` : isolatedCount ? ` · ${isolatedCount} without grounded flow` : ''}`;
  }
  diagramNetwork = new vis.Network(container, data, {
    physics: false,
    interaction: { hover: true, tooltipDelay: 180, zoomView: true, dragView: true, keyboard: { enabled: true, bindToWindow: false } },
    nodes: { chosen: true },
    edges: { selectionWidth: 2.5, hoverWidth: 2.2 },
  });
  const network = diagramNetwork;
  let initialized = false;
  let zoneFrame = null;
  const refreshZones = () => {
    if (zoneFrame != null) return;
    zoneFrame = window.requestAnimationFrame(() => {
      zoneFrame = null;
      if (diagramNetwork === network) updateCanonicalZoneLayer(model, visibleNodes);
    });
  };
  network.on('afterDrawing', () => {
    if (!initialized) {
      initialized = true;
      const moved = canonicalResolveNodeOverlaps(network, visibleNodes.map(node => node.id), 40);
      if (moved) network.redraw();
      if (forceReflow || !restoreCanonicalViewport(model)) {
        network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' }, padding: 56 });
      }
      window.requestAnimationFrame(() => keepSelectedModelElementVisible());
      if (forceReflow) scheduleCanonicalLayoutSave();
    }
    refreshZones();
  });
  network.on('animationFinished', refreshZones);
  network.on('zoom', refreshZones);
  network.on('dragging', refreshZones);
  network.on('click', params => {
    if (params.nodes.length) {
      const selected = data.nodes.get(params.nodes[0]);
      if (selected?.type === 'system' && viewKind === 'context') {
        navigateCanonicalLevel('services');
        return;
      }
      if (viewKind === 'system' && selected?._canonicalNodeIds?.length) {
        const childView = (model.views || []).find(view => view.kind === 'feature'
          && selected._canonicalNodeIds.includes(String(view.parent_process_id)));
        if (childView) {
          navigateCanonicalLevel('scenarios', childView.id);
          return;
        }
      }
      const selectedId = selected?._collapsedZoneId || selected?.id;
      if (selectedId) {
        window.UIState?.update({ selection: `${selected?._collapsedZoneId ? 'zone' : 'dfd-node'}:${selectedId}` });
        syncAnalysisReportLinks();
      }
      if (selected?._collapsedZoneId) {
        const zone = (model.zones || []).find(item => String(item.id) === String(selected._collapsedZoneId));
        if (zone) showZoneInspector(zone);
      } else showNodeInspector(selected);
    }
    else if (params.edges.length) {
      const selected = data.edges.get(params.edges[0]);
      const canonicalId = selected?._canonicalFlowIds?.[0] || selected?.id || params.edges[0];
      window.UIState?.update({ selection: `dfd-flow:${canonicalId}` });
      syncAnalysisReportLinks();
      const canonicalFlow = (model.flows || []).find(item => String(item.id) === String(canonicalId));
      if (selected?._canonicalFlowIds?.length > 1) showFlowInspector(selected);
      else if (canonicalFlow) showCanonicalFlowInspector(canonicalFlow);
      else showFlowInspector(selected);
    } else {
      window.UIState?.update({ selection: '' });
      syncAnalysisReportLinks();
      closeModelInspector();
    }
  });
  network.on('dragEnd', () => {
    refreshZones();
    scheduleCanonicalLayoutSave();
  });
}

function reflowCanonicalDiagram() {
  if (!currentReport?.dfd_model) return;
  renderCanonicalDiagram(currentReport, canonicalRenderedViewKind, { forceReflow: true });
  showToast('DFD positions recalculated; selected element preserved', 'success');
}

function scheduleCanonicalLayoutSave({ savePositions = true } = {}) {
  if (!currentReport?.dfd_model || !diagramNetwork) return;
  window.clearTimeout(canonicalLayoutSaveTimer);
  canonicalLayoutSaveTimer = window.setTimeout(async () => {
    const model = JSON.parse(JSON.stringify(currentReport.dfd_model));
    const view = canonicalViewFor(model, canonicalRenderedViewKind);
    if (!view) return;
    const positions = diagramNetwork.getPositions();
    if (savePositions) {
      const canonicalNodeIds = new Set([
        ...(model.nodes || []).map(node => String(node.id)),
        ...(view.projection_nodes || []).map(node => String(node.id)),
      ]);
      view.positions = {
        ...(view.positions || {}),
        ...Object.fromEntries(Object.entries(positions).filter(([id]) => canonicalNodeIds.has(String(id))).map(([id, position]) => [id, {
          x: Number(position.x.toFixed(2)),
          y: Number(position.y.toFixed(2)),
        }])),
      };
    }
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
    if (response.semantic_changed) window.UXTelemetry?.complete('dfd_edit', 'analysis', 'success', { phase: 'model' });
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
    if (render && isModelWorkspace) {
      renderDiagram(currentReport);
      renderDiagramTextAlternative(currentReport);
      renderModelBoundaryQueue(currentReport);
      updateModelReadiness(currentReport);
    } else if (render) renderResults(currentReport);
    syncDfdHistoryButtons();
    showToast(message, 'success');
    return response;
  } catch (err) {
    showToast('Could not save canonical DFD: ' + err.message, 'error');
    if (/409|conflict/i.test(err.message || '')) {
      if (isModelWorkspace) {
        currentReport = await API.analysis.report(projectId);
        renderDiagram(currentReport);
        renderModelBoundaryQueue(currentReport);
        updateModelReadiness(currentReport);
      } else await tryLoadExistingReport();
    }
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
  if (report?.dfd_model?.nodes?.length) {
    const featureViews = (report.dfd_model.views || []).filter(view => view.kind === 'feature' && view.parent_process_id);
    const viewKind = diagramLevel === 'context' ? 'context' : diagramLevel === 'scenarios' ? 'feature' : 'system';
    const resolved = resolveDfdProjection(report.dfd_model, viewKind === 'feature' ? (canonicalFeatureViewId || 'feature') : viewKind);
    const selected = resolved?.view;
    const nodes = resolved?.nodes || [];
    const flows = resolved?.flows || [];
    const projectionNodesById = new Map(nodes.map(node => [String(node.id), node]));
    const canonicalFlowById = new Map((report.dfd_model.flows || []).map(flow => [String(flow.id), flow]));
    const projectionLabel = diagramLevel === 'context' ? 'Overview · L0' : diagramLevel === 'scenarios' ? 'Feature detail · L2' : 'Services · L1';
    const statusLabel = selected?.decomposition_status === 'decomposed'
      ? 'evidence-backed decomposition'
      : selected?.decomposition_status === 'pending' ? 'decomposition needs evidence'
        : selected?.decomposition_status === 'detail_only' ? 'connection detail only; no decomposition evidence' : '';
    const nodeItems = nodes.map(node => {
      const mapped = node.canonical_node_ids || [node.id];
      const details = `${node.type} · ${node.scope} · ${node.ownership} · ${mapped.length} mapped canonical element${mapped.length === 1 ? '' : 's'}`;
      return `<li><button type="button" class="diagram-outline-link" data-outline-type="projection-node" data-outline-id="${escHtml(node.id)}"><strong>${escHtml(`${node.display_id || node.id} ${node.name}`)}</strong></button> — ${escHtml(details)}</li>`;
    }).join('');
    const flowItems = flows.map(flow => {
      const originals = (flow.canonical_flow_ids || []).map(id => canonicalFlowById.get(String(id))).filter(Boolean);
      const description = originals.map(item => `${item.display_id || item.id}: ${item.name}`).join(' / ') || flow.name;
      return `<li><button type="button" class="diagram-outline-link" data-outline-type="projection-flow" data-outline-id="${escHtml(flow.id)}"><strong>${escHtml(flow.display_id || flow.id)}</strong></button> ${escHtml(`${projectionNodesById.get(String(flow.source_id))?.name || flow.source_id} → ${projectionNodesById.get(String(flow.target_id))?.name || flow.target_id}: ${description}`)} <small>${escHtml(flow.grounding_status)} · ${escHtml((flow.boundary_crossings || []).join(', ') || 'no recorded trust-boundary crossing')}</small></li>`;
    }).join('');
    const outlineContext = viewKind === 'feature'
      ? `${projectionLabel} · ${escHtml(selected?.parent_process_id || 'selected process')} · ${escHtml(statusLabel)}`
      : projectionLabel;
    const issueItems = (selected?.projection_issues || []).map(issue => `<li>${escHtml(issue)}</li>`).join('');
    const needsScopeDecision = viewKind === 'context' && (selected?.projection_issues || []).some(issue => issue.includes('context_scope_unknown'));
    const scopeTargets = needsScopeDecision ? canonicalScopeReviewTargets(report.dfd_model) : [];
    const scopeItems = scopeTargets.map(node => `<li><button type="button" class="diagram-outline-link" data-context-scope-review-id="${escHtml(node.id)}"><strong>${escHtml(`Edit scope: ${node.display_id || node.id} ${node.name}`)}</strong></button> — ${escHtml(`${node.type} · current scope: ${node.scope || 'unknown'}`)}</li>`).join('');
    const scopeSection = needsScopeDecision
      ? `<section class="diagram-outline-group"><h3>Set system scope</h3><p class="text-sm text-muted">Choose an element to open its L1 editor. Set Scope to in_scope or external_dependency and click Save semantic metadata. L1 continues to show modeled components; the saved decision builds the L0 system aggregate.</p><ul>${scopeItems || '<li>No canonical nodes are available to classify.</li>'}</ul></section>`
      : '';
    content.innerHTML = `<div class="diagram-outline-intro"><strong>${outlineContext}</strong><span>${nodes.length} elements · ${flows.length} flows</span></div>${issueItems ? `<section class="diagram-outline-group"><h3>Review needed</h3><ul>${issueItems}</ul></section>` : ''}${scopeSection}<section class="diagram-outline-group"><h3>Elements <span class="diagram-outline-count">${nodes.length}</span></h3><ul>${nodeItems || '<li>No elements are available for this projection.</li>'}</ul></section><section class="diagram-outline-group"><h3>Data flows <span class="diagram-outline-count">${flows.length}</span></h3><ul>${flowItems || '<li>No data flows are available for this projection.</li>'}</ul></section>`;
    bindCanonicalScopeReviewActions(content);
    content.querySelectorAll('[data-outline-type="projection-node"]').forEach(button => button.addEventListener('click', () => {
      const node = nodes.find(item => String(item.id) === String(button.dataset.outlineId));
      if (!node) return;
      if (node.type === 'system' && viewKind === 'context') {
        navigateCanonicalLevel('services');
        return;
      }
      if (viewKind === 'system') {
        const childView = featureViews.find(view => (node.canonical_node_ids || [node.id]).includes(String(view.parent_process_id)));
        if (childView) {
          navigateCanonicalLevel('scenarios', childView.id);
          return;
        }
      }
      const canonicalId = (node.canonical_node_ids || [node.id])[0];
      if (canonicalId) focusModelElement('node', canonicalId);
    }));
    content.querySelectorAll('[data-outline-type="projection-flow"]').forEach(button => button.addEventListener('click', () => {
      const flow = flows.find(item => String(item.id) === String(button.dataset.outlineId));
      const canonicalId = flow?.canonical_flow_ids?.[0];
      if (canonicalId) focusModelElement('flow', canonicalId);
    }));
    if (canvas) canvas.setAttribute('aria-label', `${projectionLabel} with ${nodes.length} nodes and ${flows.length} flows`);
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
    else closeModelInspector();
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
    closeModelInspector();
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
  // Small, read-only inspection hook used by the Chromium release gate to
  // verify the canvas contract without relying on screenshot pixel guesses.
  window.__5stonesDfdDebug = {
    getNodeBoxes: () => data.nodes.getIds().map(id => ({ id, box: diagramNetwork?.getBoundingBox(id) || null })),
  };
  diagramNetwork.once('afterDrawing', () => {
    diagramNetwork.fit({ animation: { duration: 450, easingFunction: 'easeInOutQuad' } });
  });
  diagramNetwork.on('click', params => {
    if (params.nodes.length) {
      showNodeInspector(data.nodes.get(params.nodes[0]));
    } else if (params.edges.length) {
      showFlowInspector(data.edges.get(params.edges[0]));
    } else {
      closeModelInspector();
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
      <p class="dfd-flow-impact-preview">Impact preview: the canonical flow ID stays stable; its data-object labels, L1/L2 mappings, trust-boundary crossings, and linked finding badges are recalculated on save. Check parent input/output ports in the L2 outline after saving.</p>
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
  const nextDataObjectIds = [...(read('data_object_ids')?.selectedOptions || [])].map(option => option.value);
  if (JSON.stringify([...new Set(flow.data_object_ids || [])].sort()) !== JSON.stringify([...new Set(nextDataObjectIds)].sort())) {
    const linkedFindings = analysisVisibility(currentReport).threats.filter(threat => targetMatches(threat, flow.id, 'data_flow')).length;
    if (!window.confirm(`Update data mapping for ${flow.display_id || flow.id}?\n\nThis recalculates projected labels and coverage across L0/L1/L2. ${linkedFindings} linked finding(s) keep this canonical flow target. Review parent ports and rerun analysis after saving.`)) return;
  }
  flow.data_object_ids = nextDataObjectIds;
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
  const canonicalFlow = currentReport?.dfd_model?.flows?.find(item => String(item.id) === String(edge.id));
  const canonicalThreats = canonicalFlow
    ? analysisVisibility(currentReport).threats.filter(threat => targetMatches(threat, canonicalFlow.id, 'data_flow') || targetMatches(threat, canonicalFlow.boundary_crossings || [], 'trust_boundary'))
    : [];
  title.textContent = `${edge._sourceLabel || 'Source'} ↔ ${edge._destinationLabel || 'Destination'}`;
  const crossing = edge._crossing
    ? '<div class="flow-boundary-note">This flow crosses a trust boundary and should be reviewed for authentication, authorization, validation, and transport protection.</div>'
    : `<div class="flow-internal-note">${edge._logical ? 'Logical routing relationship; this does not assert a deployment or trust boundary.' : 'This flow stays within one trust zone.'}</div>`;
  const details = (edge._flowDetails || []).filter(Boolean).length
    ? edge._flowDetails.filter(Boolean).map(item => `<li>${escHtml(item)}</li>`).join('')
    : `<li>${escHtml(edge.label || 'Service interaction')}</li>`;
  const threats = uniqueThreats((edge._threats || []).length ? edge._threats : canonicalThreats);
  const findings = isModelWorkspace
    ? modelFindingLinksHtml(threats)
    : threats.length
    ? `<div class="inspector-findings"><strong>${threats.length} mapped findings</strong>${threats.map(t => `
        <div class="inspector-finding-row">${badgeHtml(t.risk_level, 'risk')}${badgeHtml(t.framework, 'framework')}<span>${escHtml(t.threat_category || 'Finding')}</span></div>`).join('')}</div>`
    : '<div class="inspector-empty-note">No finding is directly targeted to this flow.</div>';
  if (canonicalFlow) {
    body.innerHTML = `${crossing}${canonicalFlowEditorHtml(canonicalFlow)}<ul class="flow-detail-list">${details}</ul>${modelEvidenceLinksHtml(canonicalFlow.evidence_refs || [])}${findings}`;
    body.querySelector('[data-save-dfd-flow]')?.addEventListener('click', () => saveCanonicalFlow(canonicalFlow.id, body));
    wireDfdDeleteButton(body);
  } else {
    const flowButtons = (edge._canonicalFlowIds || []).map(id => {
      const item = currentReport?.dfd_model?.flows?.find(flow => String(flow.id) === id);
      return item ? `<button type="button" class="btn btn-secondary btn-sm" data-inspect-canonical-flow="${escHtml(id)}">Inspect ${escHtml(item.display_id || id)}</button>` : '';
    }).join('');
    body.innerHTML = `${crossing}${flowButtons ? `<div class="dfd-editor-actions">${flowButtons}</div>` : ''}<ul class="flow-detail-list">${details}</ul>${findings}`;
    body.querySelectorAll('[data-inspect-canonical-flow]').forEach(button => button.addEventListener('click', () => {
      const item = currentReport?.dfd_model?.flows?.find(flow => String(flow.id) === button.dataset.inspectCanonicalFlow);
      if (item) showCanonicalFlowInspector(item);
    }));
  }
  revealModelInspector();
}

function showCanonicalFlowInspector(flow) {
  const model = currentReport?.dfd_model || {};
  const nodes = new Map((model.nodes || []).map(node => [String(node.id), node]));
  const mapped = uniqueThreats(analysisVisibility(currentReport).threats.filter(threat =>
    targetMatches(threat, flow.id, 'data_flow') || targetMatches(threat, flow.boundary_crossings || [], 'trust_boundary')));
  showFlowInspector({
    id: flow.id,
    label: flow.name,
    _sourceLabel: nodes.get(String(flow.source_id))?.name || flow.source_id,
    _destinationLabel: nodes.get(String(flow.target_id))?.name || flow.target_id,
    _flowDetails: [
      `${flow.display_id || flow.id}: ${flow.name || 'unknown data'}`,
      `Interaction: ${flow.interaction_kind || 'unknown'} · Protocol: ${flow.protocol || 'unknown'}`,
      `AuthN: ${flow.authn || 'unknown'} · AuthZ: ${flow.authz || 'unknown'}`,
      `Crossings: ${(flow.boundary_crossings || []).join(', ') || 'none'}`,
      `Evidence: ${(flow.evidence_refs || []).join(', ') || 'none'}`,
    ],
    _crossing: Boolean((flow.boundary_crossings || []).length) || flow.crossing_status === 'unresolved',
    _logical: flow.crossing_status === 'resolved' && !(flow.boundary_crossings || []).length,
    _threats: mapped,
  });
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
    closeModelInspector();
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
      closeModelInspector();
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
  const parentOptions = (model.nodes || []).filter(item => item.type === 'process' && item.id !== node.id).map(parent =>
    `<option value="${escHtml(parent.id)}" ${node.parent_process_id === parent.id ? 'selected' : ''}>${escHtml(`${parent.display_id} ${parent.name}`)}</option>`
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
      <div class="node-model-meta">Canonical identity: ${escHtml(node.identity_key || 'unknown')} · grouping ${escHtml(node.grouping_status || 'unknown')} · ${escHtml(node.grouping_basis || 'identity context not documented')}</div>
      <label class="form-label" for="dfd-node-name">Name</label>
      <input class="form-input" id="dfd-node-name" data-dfd-field="name" value="${escHtml(node.name)}" maxlength="240" required />
      <div class="dfd-editor-grid">
        <label class="form-label">Scope<select class="form-select" data-dfd-field="scope">${options('scope', ['in_scope', 'external_dependency', 'unknown'], node.scope)}</select></label>
        <label class="form-label">Ownership<select class="form-select" data-dfd-field="ownership">${options('ownership', ['organization', 'customer', 'vendor', 'shared', 'unknown'], node.ownership)}</select></label>
        <label class="form-label">Exposure<select class="form-select" data-dfd-field="exposure">${options('exposure', ['internet_facing', 'private', 'local', 'unknown'], node.exposure)}</select></label>
        <label class="form-label">Operator / control party<input class="form-input" data-dfd-field="operator_control_party" value="${escHtml(node.operator_control_party || '')}" maxlength="240" /></label>
      </div>
      <label class="form-label">Description<textarea class="form-input" data-dfd-field="description" rows="2" maxlength="1000">${escHtml(node.description || '')}</textarea></label>
      ${['process', 'data_store'].includes(node.type) ? `<label class="form-label">Parent process for L2 decomposition<select class="form-select" data-dfd-field="parent_process_id"><option value="">Top-level / no parent</option>${parentOptions}</select><small>Changing membership rebuilds L1/L2 projections and their ports. The canonical node and finding references remain unchanged; analysis becomes stale.</small></label>` : ''}
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
  const oldScope = node.scope || 'unknown';
  const proposedScope = read('scope')?.value || 'unknown';
  if (oldScope !== proposedScope) {
    const affectedFlows = model.flows.filter(flow => flow.source_id === node.id || flow.target_id === node.id);
    const affectedThreats = analysisVisibility(currentReport).threats.filter(threat =>
      targetMatches(threat, [node.id, ...affectedFlows.map(flow => flow.id)])
    );
    const summary = `Change ${node.display_id || node.id} scope from ${oldScope} to ${proposedScope}?\n\nThis changes the explicit system boundary and may regroup ${affectedFlows.length} connected flow(s) in L0. ${affectedThreats.length} linked finding(s) retain canonical targets. Dependent analysis will become stale and must be rerun.`;
    if (!window.confirm(summary)) {
      const selector = read('scope');
      if (selector) selector.value = oldScope;
      return;
    }
  }
  const oldParentId = node.parent_process_id || null;
  const proposedParentId = read('parent_process_id')?.value || null;
  if (oldParentId !== proposedParentId) {
    const affectedFlows = model.flows.filter(flow => flow.source_id === node.id || flow.target_id === node.id);
    const affectedThreats = analysisVisibility(currentReport).threats.filter(threat =>
      targetMatches(threat, [node.id, ...affectedFlows.map(flow => flow.id)])
    );
    const nextParent = model.nodes.find(item => item.id === proposedParentId);
    const summary = `Change ${node.display_id || node.id} to ${nextParent?.display_id || 'top level'}?\n\nThis rebuilds L1/L2 membership and ports for ${affectedFlows.length} related flows. ${affectedThreats.length} linked finding(s) retain canonical targets. Semantic analysis will become stale and must be rerun.`;
    if (!window.confirm(summary)) {
      const selector = read('parent_process_id');
      if (selector) selector.value = oldParentId || '';
      return;
    }
  }
  node.name = name;
  node.scope = proposedScope;
  node.ownership = read('ownership')?.value || 'unknown';
  node.exposure = read('exposure')?.value || 'unknown';
  node.operator_control_party = read('operator_control_party')?.value.trim() || null;
  node.description = read('description')?.value.trim() || null;
  node.parent_process_id = proposedParentId;
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
  const response = await persistCanonicalDfdModel(model, { message: 'DFD node metadata saved' });
  if (!response && button?.isConnected) button.disabled = false;
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
    body.insertAdjacentHTML('beforeend', modelEvidenceLinksHtml(canonicalNode.evidence_refs || []));
    if (threats.length) {
      body.insertAdjacentHTML('beforeend', isModelWorkspace ? modelFindingLinksHtml(threats) : `<div class="inspector-findings"><strong>${threats.length} mapped finding${threats.length === 1 ? '' : 's'}</strong>${threats.map(t => `
        <div class="inspector-finding-row">${badgeHtml(t.risk_level, 'risk')}${badgeHtml(t.framework, 'framework')}<span>${escHtml(t.threat_category || 'Finding')}</span></div>`).join('')}</div>`);
    } else {
      body.insertAdjacentHTML('beforeend', '<div class="inspector-empty-note">No finding is directly targeted to this node.</div>');
    }
    revealModelInspector();
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
          ${t.analysis_state === 'historical' ? '<span class="badge badge-medium">Previous snapshot · revalidate</span>' : ''}
          <span style="font-size:0.78rem;font-weight:500;">${escHtml(t.threat_category)}</span>
        </div>
        <div style="font-size:0.8rem;color:var(--text-2);">${escHtml((t.threat_description || '').substring(0, 120))}…</div>
        ${t.recommended_control ? `<div style="font-size:0.75rem;color:var(--green);margin-top:2px;">→ ${escHtml(t.recommended_control)}</div>` : ''}
      </div>
    `).join('');
  }

  if (isModelWorkspace && threats.length) body.insertAdjacentHTML('beforeend', modelFindingLinksHtml(threats));
  revealModelInspector();
}

function diagramExportScene() {
  const canvas = diagramNetwork?.canvas?.frame?.canvas;
  if (!canvas) throw new Error('Diagram canvas is unavailable');
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) throw new Error('Diagram has no visible size');
  const sx = canvas.width / rect.width;
  const sy = canvas.height / rect.height;
  const palette = [
    { stroke: '#457B9D', fill: '#F3F8FC' },
    { stroke: '#6D28D9', fill: '#F9F6FF' },
    { stroke: '#D97706', fill: '#FFF9F1' },
    { stroke: '#DC2626', fill: '#FFF5F6' },
  ];
  const zones = currentReport?.dfd_model ? [...document.querySelectorAll('#diagram-zone-layer .diagram-zone')]
    .filter(element => getComputedStyle(element).display !== 'none')
    .map(element => {
      const box = element.getBoundingClientRect();
      return {
        id: element.dataset.zoneId,
        label: element.querySelector('span')?.textContent || element.dataset.zoneId,
        x: (box.left - rect.left) * sx,
        y: (box.top - rect.top) * sy,
        width: box.width * sx,
        height: box.height * sy,
        ...palette[Math.min(Number(element.dataset.zoneDepth || 0), palette.length - 1)],
      };
    }) : [];
  const edges = diagramNetwork.body.data.edges.get();
  const projection = resolveDfdProjection(currentReport?.dfd_model,
    canonicalRenderedViewKind === 'feature' ? (canonicalFeatureViewId || 'feature') : canonicalRenderedViewKind);
  const validation = currentReport?.dfd_validation || {};
  const canonicalNodeIds = new Set((currentReport?.dfd_model?.nodes || []).map(node => String(node.id)));
  const individuallyVisible = new Set((projection?.nodes || []).filter(node =>
    canonicalNodeIds.has(String(node.id)) && (node.canonical_node_ids || []).length === 1 && String(node.canonical_node_ids[0]) === String(node.id)
  ).map(node => String(node.id)));
  const hiddenInternalNodeCount = (currentReport?.dfd_model?.nodes || []).filter(node =>
    node.scope === 'in_scope' && !individuallyVisible.has(String(node.id))
  ).length;
  return {
    canvas, zones, width: canvas.width, height: canvas.height,
    revision: currentReport?.dfd_model?.revision || null,
    semanticHash: currentReport?.dfd_model?.semantic_hash || null,
    viewKind: canonicalRenderedViewKind,
    viewId: projection?.view.id || canonicalRenderedViewKind,
    parentProcessId: projection?.view.parent_process_id || null,
    decompositionStatus: projection?.view.decomposition_status || 'unknown',
    validationStatus: validation.valid === false ? 'blocked' : validation.semantic_ready === true ? 'ready' : 'review',
    projectionIssues: projection?.view.projection_issues || [],
    hiddenInternalNodeCount,
    projectedNodeCount: projection?.nodes.length || diagramNetwork.body.data.nodes.getIds().length,
    projectedFlowCount: projection?.flows.length || edges.length,
    flowRefs: edges.flatMap(edge => edge._canonicalFlowIds || [edge.id]).map(String),
    nodeRefs: diagramNetwork.body.data.nodes.getIds().map(String),
    nodeMappings: diagramNetwork.body.data.nodes.get().map(node => ({projection_id: String(node.id), canonical_ids: (node._canonicalNodeIds || [node._elementId || node.id]).map(String)})),
    flowMappings: edges.map(edge => ({projection_id: String(edge.id), canonical_ids: (edge._canonicalFlowIds || [edge.id]).map(String)})),
  };
}

function drawDiagramZones(context, scene) {
  scene.zones.forEach(zone => {
    context.fillStyle = zone.fill;
    context.strokeStyle = zone.stroke;
    context.lineWidth = 2;
    context.setLineDash([8, 6]);
    context.beginPath();
    if (context.roundRect) context.roundRect(zone.x, zone.y, zone.width, zone.height, 18);
    else context.rect(zone.x, zone.y, zone.width, zone.height);
    context.fill();
    context.stroke();
    context.setLineDash([]);
    context.fillStyle = zone.stroke;
    context.font = '600 12px monospace';
    context.fillText(zone.label, zone.x + 14, zone.y + 25, Math.max(80, zone.width - 28));
  });
}

function drawExportMetadata(context, scene) {
  const label = `${String(scene.viewKind).toUpperCase()} ${scene.viewId} · r${scene.revision || '?'} · ${scene.validationStatus} · ${scene.projectedNodeCount} nodes / ${scene.projectedFlowCount} flows · ${scene.hiddenInternalNodeCount} internal details aggregated`;
  context.save();
  context.fillStyle = 'rgba(255,255,255,.94)';
  context.fillRect(12, Math.max(0, scene.height - 30), Math.min(scene.width - 24, 760), 20);
  context.fillStyle = '#526777';
  context.font = '12px sans-serif';
  context.fillText(label, 18, scene.height - 16, Math.max(40, scene.width - 36));
  context.restore();
}

function exportDiagramPng() {
  if (!diagramNetwork) return;
  try {
    const scene = diagramExportScene();
    const output = document.createElement('canvas');
    output.width = scene.width;
    output.height = scene.height;
    const context = output.getContext('2d');
    context.fillStyle = '#FFFFFF';
    context.fillRect(0, 0, scene.width, scene.height);
    drawDiagramZones(context, scene);
    context.drawImage(scene.canvas, 0, 0);
    drawExportMetadata(context, scene);
    const link = document.createElement('a');
    link.download = `dfd-${projectId}${scene.revision ? `-r${scene.revision}` : ''}-${scene.viewId}.png`;
    link.href = output.toDataURL('image/png');
    link.click();
    showToast('Current diagram view exported as PNG', 'success');
  } catch {
    showToast('Could not export diagram', 'error');
  }
}

function diagramSvgMarkup(scene, exportProjectId) {
  const xml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[char]));
  const metadata = { revision: scene.revision, semantic_hash: scene.semanticHash, view: scene.viewKind,
    view_id: scene.viewId, parent_process_id: scene.parentProcessId, decomposition_status: scene.decompositionStatus,
    validation_status: scene.validationStatus, projection_issues: scene.projectionIssues,
    hidden_internal_node_details: scene.hiddenInternalNodeCount,
    projected_node_count: scene.projectedNodeCount, projected_flow_count: scene.projectedFlowCount,
    zone_ids: scene.zones.map(zone => zone.id), node_refs: scene.nodeRefs, flow_refs: scene.flowRefs,
    node_mappings: scene.nodeMappings, flow_mappings: scene.flowMappings };
  const zones = scene.zones.map(zone => `
      <rect data-zone-id="${xml(zone.id)}" x="${zone.x}" y="${zone.y}" width="${zone.width}" height="${zone.height}" rx="18" fill="${zone.fill}" stroke="${zone.stroke}" stroke-width="2" stroke-dasharray="8 6"/>
      <text x="${zone.x + 14}" y="${zone.y + 25}" font-size="12" font-family="monospace" font-weight="600" fill="${zone.stroke}">${xml(zone.label)}</text>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${scene.width}" height="${scene.height}" viewBox="0 0 ${scene.width} ${scene.height}" role="img" data-view-id="${xml(scene.viewId)}" data-revision="${xml(scene.revision)}" data-validation-status="${xml(scene.validationStatus)}"><title>DFD ${xml(exportProjectId)} revision ${xml(scene.revision)} · ${xml(scene.viewKind)} · ${xml(scene.validationStatus)}</title><desc>Current ${xml(scene.viewKind)} projection with ${scene.projectedNodeCount} nodes and ${scene.projectedFlowCount} flows. Decomposition status: ${xml(scene.decompositionStatus)}. ${scene.hiddenInternalNodeCount} internal node details are aggregated. ${xml(scene.projectionIssues.join('; '))}</desc><metadata>${xml(JSON.stringify(metadata))}</metadata><rect width="100%" height="100%" fill="#FFFFFF"/>${zones}<image href="${scene.canvas.toDataURL('image/png')}" x="0" y="0" width="${scene.width}" height="${scene.height}"/></svg>`;
}

async function exportDiagramSvg() {
  if (!projectId) return;
  try {
    const scene = diagramExportScene();
    const svg = diagramSvgMarkup(scene, projectId);
    const blob = new Blob([svg], { type: 'image/svg+xml' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `dfd-${projectId}${scene.revision ? `-r${scene.revision}` : ''}-${scene.viewId}.svg`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    showToast('Current diagram view exported as SVG', 'success');
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
    el.innerHTML = `<div class="empty-state" style="padding:var(--space-8);"><div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><h3>${hidden ? 'Threat scenarios hidden by boundary review' : 'No threat scenarios identified'}</h3><p>${hidden ? 'The scenarios remain stored. Restore the rejected boundary to Candidate or Confirmed to show them again.' : 'Run the structured review to evaluate potential threat scenarios.'}</p></div>`;
    return;
  }

  el.innerHTML = threats.map((t, i) => {
    const uid = `${prefix}-${i}`;   // unique: 'st-0', 'ln-0', etc.
    const primaryTarget = targetRefs(t).find(ref => String(ref.id) === String(t.primary_interaction_ref));
    const primaryInteraction = primaryTarget?.label || t.primary_interaction_ref;
    return `
    <div class="threat-item" id="threat-${uid}" data-threat-id="${escHtml(t.threat_id || '')}" data-risk="${escHtml(t.risk_level || '')}" data-status="${escHtml(t.status || 'Open')}">
      <button type="button" class="threat-item-header threat-review-header" id="threat-trigger-${uid}"
        aria-expanded="false" aria-controls="threat-body-${uid}" onclick="toggleThreat('${uid}')">
        <span class="threat-header-badges">
          ${findingRiskBadgeHtml(t)}
          ${findingStateBadgeHtml(t)}
          ${badgeHtml(t.framework, 'framework')}
          ${t.analysis_state === 'historical' ? '<span class="badge badge-medium">Previous snapshot · revalidate</span>' : ''}
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
          <div class="threat-meta-item"><div class="threat-meta-label">Primary DFD interaction</div><div class="threat-meta-value">${primaryInteractionSelectHtml(t, primaryInteraction)}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Trust Boundary</div><div class="threat-meta-value">${escHtml(t.trust_boundary || '—')}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Classification</div><div class="threat-meta-value">${escHtml(t.data_classification || '—')}</div></div>
        </div>
        <div class="threat-review-grid">
          <div class="threat-meta-item"><div class="threat-meta-label">Evidence strength</div><div class="threat-meta-value">${evidenceBadgeHtml(t)}</div></div>
          <div class="threat-meta-item"><div class="threat-meta-label">Review Status</div><div class="threat-meta-value">${statusSelectHtml(t)}</div></div>
        </div>
        ${evidenceCardHtml(t)}
        ${t.interaction_mapping_status !== 'mapped' ? `<div class="alert alert-warning" style="margin-top:var(--space-3);"><div><strong>Primary DFD interaction required.</strong><br><span class="text-sm">${escHtml(t.interaction_mapping_reason || 'Select exactly one canonical flow before this scenario can be grounded or scored.')}</span></div></div>` : ''}
        ${t.absence_of_evidence_guarded ? `<div class="alert alert-warning" style="margin-top:var(--space-3);"><div><strong>Control gap is not evidenced.</strong><br><span class="text-sm">Document omission was converted to an information gap. This scenario is not a confirmed vulnerability and its risk is deferred.</span>${t.unverified_claim ? `<details style="margin-top:6px;"><summary>Show original unverified claim</summary><div>${escHtml(t.unverified_claim)}</div></details>` : ''}</div></div>` : ''}
        ${targetRefs(t).length ? `<button type="button" class="btn btn-secondary btn-sm" data-focus-threat="${escHtml(t.threat_id || '')}" style="margin-top:var(--space-3);">Focus affected DFD elements (${targetRefs(t).length})</button>` : '<div class="text-xs text-muted" style="margin-top:var(--space-3);">No canonical DFD target reference is available for this candidate.</div>'}
        ${t.grounding_reason ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--text-muted);"><strong>Finding state:</strong> ${escHtml(t.grounding_reason)}</div>` : ''}
        ${t.confidence_reason ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--text-muted);"><strong>Confidence reason:</strong> ${escHtml(t.confidence_reason)}</div>` : ''}
        ${riskAuditHtml(t)}
        ${riskOverrideEditorHtml(t, uid)}
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

function riskOverrideEditorHtml(threat, uid) {
  const eligible = ['grounded', 'reviewed', 'verified'].includes(threat.finding_state);
  const selected = threat.risk_override_level || threat.risk_level || 'Medium';
  return `<div class="threat-meta-item" style="margin-top:var(--space-3);">
    <div class="threat-meta-label">Reviewer risk override</div>
    <div style="display:grid;grid-template-columns:minmax(110px,.35fr) minmax(180px,1fr) auto;gap:8px;align-items:center;">
      <select id="risk-level-${uid}" class="form-select" style="height:32px;font-size:.74rem;" ${eligible ? '' : 'disabled'}>
        ${['Critical', 'High', 'Medium', 'Low'].map(level => `<option value="${level}" ${level === selected ? 'selected' : ''}>${level}</option>`).join('')}
      </select>
      <input id="risk-reason-${uid}" class="form-input" style="height:32px;font-size:.74rem;" value="${escHtml(threat.risk_override_reason || '')}" placeholder="Required rationale (minimum 10 characters)" ${eligible ? '' : 'disabled'}>
      <div style="display:flex;gap:6px;">
        <button type="button" class="btn btn-secondary btn-sm" onclick="updateThreatRiskOverride('${escHtml(threat.threat_id)}','${uid}',false)" ${eligible ? '' : 'disabled'}>Apply</button>
        ${threat.risk_override_level ? `<button type="button" class="btn btn-ghost btn-sm" onclick="updateThreatRiskOverride('${escHtml(threat.threat_id)}','${uid}',true)">Clear</button>` : ''}
      </div>
    </div>
    <div class="text-xs text-muted" style="margin-top:5px;">${eligible ? 'The deterministic calculation remains visible; every override is recorded in audit history.' : 'Ground or review this scenario before overriding final risk.'}</div>
  </div>`;
}

window.updateThreatRiskOverride = async function(threatId, uid, clearOverride = false) {
  const level = document.getElementById(`risk-level-${uid}`)?.value;
  const reason = document.getElementById(`risk-reason-${uid}`)?.value?.trim() || '';
  if (!clearOverride && reason.length < 10) {
    showToast('Risk override requires a rationale of at least 10 characters', 'warning');
    return;
  }
  try {
    const response = await API.analysis.updateThreat(projectId, threatId, clearOverride
      ? { risk_override_level: null, risk_override_reason: null }
      : { risk_override_level: level, risk_override_reason: reason });
    const threat = currentReport?.threats?.find(item => String(item.threat_id) === String(threatId));
    if (threat) Object.assign(threat, response?.threat || {});
    if (currentReport && response?.quality_gate) currentReport.quality_gate = response.quality_gate;
    if (currentReport && response?.risk_summary) currentReport.risk_summary = response.risk_summary;
    if (currentReport) renderResults(currentReport);
    showToast(clearOverride ? 'Risk override cleared' : 'Risk override recorded', 'success');
  } catch (err) {
    showToast('Could not update risk override: ' + err.message, 'error');
  }
};

function statusSelectHtml(t) {
  const statuses = ['Open', 'Needs Info', 'Reviewed', 'Accepted', 'Mitigation Planned', 'Mitigated', 'Verified'];
  const canVerify = (t.verification_evidence_refs || []).length
    && ['runtime_test', 'code_review', 'configuration_review'].includes(t.verification_method)
    && t.verification_result === 'confirmed';
  return `<select class="form-select" style="height:30px;font-size:0.76rem;" onchange="updateThreatStatus('${escHtml(t.threat_id)}', this.value)">
    ${statuses.map(s => `<option value="${s}" ${t.status === s ? 'selected' : ''} ${s === 'Verified' && !canVerify && t.status !== 'Verified' ? 'disabled' : ''}>${s}${s === 'Verified' && !canVerify ? ' (verification evidence required)' : ''}</option>`).join('')}
  </select>`;
}

function primaryInteractionSelectHtml(threat, currentLabel) {
  const model = currentReport?.dfd_model || {};
  const nodes = new Map((model.nodes || []).map(node => [String(node.id), node.name || node.id]));
  const flows = model.flows || [];
  if (!flows.length) return `<span>${escHtml(currentLabel || 'No canonical flow available')}</span>`;
  const options = flows.map(flow => {
    const label = `${flow.display_id || flow.id}: ${nodes.get(String(flow.source_id)) || flow.source_id} → ${nodes.get(String(flow.target_id)) || flow.target_id}`;
    return `<option value="${escHtml(flow.id)}" ${String(flow.id) === String(threat.primary_interaction_ref) ? 'selected' : ''}>${escHtml(label)}</option>`;
  }).join('');
  return `<select class="form-select" style="height:32px;font-size:0.74rem;" aria-label="Primary DFD interaction" onchange="updateThreatPrimaryInteraction('${escHtml(threat.threat_id)}', this.value)"><option value="" ${threat.primary_interaction_ref ? '' : 'selected'} disabled>Select one canonical flow</option>${options}</select>`;
}

window.updateThreatPrimaryInteraction = async function(threatId, primaryInteractionRef) {
  try {
    const response = await API.analysis.updateThreat(projectId, threatId, { primary_interaction_ref: primaryInteractionRef });
    const threat = currentReport?.threats?.find(item => String(item.threat_id) === String(threatId));
    if (threat) Object.assign(threat, response?.threat || {});
    if (currentReport && response?.quality_gate) currentReport.quality_gate = response.quality_gate;
    if (currentReport && response?.risk_summary) currentReport.risk_summary = response.risk_summary;
    if (currentReport) renderResults(currentReport);
    showToast('Primary DFD interaction updated', 'success');
  } catch (err) {
    if (currentReport) renderResults(currentReport);
    showToast('Could not update primary interaction: ' + err.message, 'error');
  }
};

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
    const response = await API.analysis.updateThreat(projectId, threatId, { status });
    window.UXTelemetry?.complete('finding_review', 'analysis', 'success', { phase: 'findings' });
    window.UIState?.update({ selection: `threat:${threatId}` });
    syncAnalysisReportLinks();
    const threat = currentReport?.threats?.find(item => String(item.threat_id) === String(threatId));
    if (threat) Object.assign(threat, response?.threat || { status });
    if (currentReport && response?.quality_gate) {
      currentReport.quality_gate = response.quality_gate;
      if (currentReport.analysis_run) currentReport.analysis_run.quality_gate = response.quality_gate;
    }
    if (currentReport && response?.risk_summary) currentReport.risk_summary = response.risk_summary;
    document.querySelector(`[data-threat-id="${CSS.escape(String(threatId))}"]`)?.setAttribute('data-status', status);
    if (currentReport) renderResults(currentReport);
    showToast('Threat status updated', 'success');
  } catch (err) {
    if (currentReport) renderResults(currentReport);
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
          <div style="display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap;justify-content:flex-end;">
            <span class="badge badge-neutral">${escHtml(c.control_origin === 'existing' ? 'Existing control' : 'Recommendation')}</span>
            <span class="badge ${statusColor[c.implementation_status] || 'badge-neutral'}">Implementation: ${escHtml(c.implementation_status || 'Unknown')}</span>
            <span class="badge badge-neutral">Evidence state: ${escHtml(c.implementation_state || 'unknown')}</span>
            <span class="badge badge-neutral">Review: ${escHtml(c.review_status || 'Open')}</span>
          </div>
        </div>
        ${c.implementation_guidance ? `<div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:var(--space-2);">${escHtml(c.implementation_guidance)}</div>` : ''}
        ${c.checklist_items?.length ? `<ul style="margin:var(--space-3) 0;padding-left:18px;font-size:0.8rem;color:var(--text-2);">${c.checklist_items.map(item => `<li style="margin-bottom:4px;">${escHtml(item)}</li>`).join('')}</ul>` : ''}
        ${c.verification_method ? `<div style="font-size:0.78rem;color:var(--green);margin-bottom:var(--space-2);"><strong>Verify:</strong> ${escHtml(c.verification_method)}</div>` : ''}
        ${c.implementation_status_reason ? `<div style="font-size:0.75rem;color:var(--orange);margin-bottom:var(--space-2);">${escHtml(c.implementation_status_reason)}</div>` : ''}
        <div style="display:flex;gap:var(--space-4);font-size:0.75rem;color:var(--text-faint);flex-wrap:wrap;">
          <span>Owner: <strong>${escHtml(c.owner || '—')}</strong></span>
          <span>Priority: <strong>${escHtml(c.priority || 'Medium')}</strong></span>
          <span>Threat links: <strong>${escHtml(String((c.threat_ids || []).length))}</strong></span>
          <span>DFD targets: <strong>${escHtml(String((c.target_refs || []).length))}</strong></span>
          <span>Verification: <strong>${escHtml(c.verification_status || 'unverified')}</strong></span>
          <span>Evidence collected: <strong>${escHtml(String((c.evidence_collected_refs || []).length))}</strong></span>
        </div>
        ${c.evidence ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:var(--space-2);">Evidence request: ${escHtml(c.evidence)}</div>` : ''}
        ${c.implementation_evidence_requested?.length ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:var(--space-2);">Implementation evidence requested: ${escHtml(c.implementation_evidence_requested.join('; '))}</div>` : ''}
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
        <div style="display:flex;gap:var(--space-4);flex-wrap:wrap;margin-top:var(--space-3);font-size:0.78rem;color:var(--text-muted);">
          <span>Execution: <strong>${escHtml(t.execution_status || 'Not Run')}</strong></span>
          <span>Applicability: <strong>${escHtml(t.applicability_status || 'applicable')}</strong></span>
          <span>Threat: <strong class="mono">${escHtml(t.threat_id || '—')}</strong></span>
          ${t.related_control ? `<span style="color:var(--green);"><strong>Control:</strong> ${escHtml(t.related_control)}${t.related_control_id ? ` <span class="mono">(${escHtml(t.related_control_id)})</span>` : ''}</span>` : '<span>Control: <strong>Unassigned</strong></span>'}
          <span>DFD targets: <strong>${escHtml(String((t.target_refs || []).length))}</strong></span>
        </div>
        ${t.applicability_status && t.applicability_status !== 'applicable' ? `<div style="margin-top:var(--space-3);font-size:0.78rem;color:var(--orange);"><strong>Applicability reason:</strong> ${escHtml(t.applicability_reason || 'Review required before execution.')}</div>` : ''}
        ${t.evidence_needed?.length ? `<div style="margin-top:var(--space-3);font-size:0.78rem;color:var(--text-muted);"><strong>Evidence needed:</strong> ${escHtml(t.evidence_needed.join(', '))}</div>` : ''}
        ${t.actual_result ? `<div style="margin-top:var(--space-2);font-size:0.78rem;color:var(--text-muted);"><strong>Actual result:</strong> ${escHtml(t.actual_result)}</div>` : ''}
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
      currentReport.analysis_stale = {
        stages: pendingArtifactAnalysisTypes,
        reason: `${file.name} updated the project context. Refresh affected phases before relying on current findings.`,
        changed_at: new Date().toISOString(),
      };
      renderAnalysisRunState(currentReport);
      renderAnalysisOverview(currentReport);
      document.body.classList.add('analysis-has-report');
      document.getElementById('analysis-run-state')?.scrollIntoView({ behavior: reducedMotionBehavior(), block: 'nearest' });
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
