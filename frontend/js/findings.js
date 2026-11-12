/* Unified STRIDE/LINDDUN triage workspace (U3). */
let findingsProjectId = null;
let findingsProject = null;
let findingsReport = null;
let findingsVisible = [];
let findingsSelectedId = '';
let findingsGuided = false;

async function initializeFindingsWorkspace() {
  findingsProjectId = getProjectId();
  if (!findingsProjectId) { showToast('No project ID specified', 'error'); return; }
  window.UIState?.bindProjectLinks(findingsProjectId, { phase: 'findings' });
  try {
    const [project, report] = await Promise.all([
      API.projects.get(findingsProjectId), API.analysis.report(findingsProjectId),
    ]);
    findingsProject = project;
    findingsReport = report;
    if (report.analysis_run?.run_id) window.UIState?.update({ run: String(report.analysis_run.run_id) });
    document.getElementById('page-project-name').textContent = project.name || 'Project';
    syncFindingsRoutes();
    restoreFindingsControls();
    bindFindingsControls();
    renderFindings();
  } catch (error) {
    document.getElementById('findings-list').innerHTML = `<div class="findings-empty"><strong>Findings could not be loaded</strong><span>${escHtml(error.message)}</span><button type="button" class="btn btn-secondary btn-sm" id="findings-retry-load">Retry load</button><a class="btn btn-ghost btn-sm" href="${escHtml(`/analysis.html?id=${encodeURIComponent(findingsProjectId)}`)}">Back to analysis</a></div>`;
    document.getElementById('findings-retry-load')?.addEventListener('click', initializeFindingsWorkspace);
    showToast('Could not load findings: ' + error.message, 'error');
  }
}

function syncFindingsRoutes() {
  if (!window.UIState || !findingsProjectId) return;
  const state = window.UIState.read();
  const href = (page, patch = {}) => window.UIState.route(page, findingsProjectId, { ...state, ...patch });
  document.getElementById('nav-analysis').href = href('analysis', { phase: '', view: '', selection: '' });
  document.getElementById('back-analysis').href = href('analysis', { phase: '', view: '', selection: '' });
  document.getElementById('nav-model').href = href('model', { phase: 'model', view: 'diagram', selection: '' });
  document.getElementById('btn-findings-model').href = href('model', { phase: 'model', view: 'diagram', selection: '' });
  document.getElementById('nav-findings').href = href('findings', { phase: 'findings', view: '', selection: state.selection });
  document.getElementById('nav-action-plan').href = href('action-plan', { phase: 'action-plan', view: '', selection: '' });
  document.getElementById('nav-evidence').href = href('evidence', { phase: 'evidence', view: '', selection: '' });
  document.getElementById('nav-report').href = href('report', { phase: 'signoff', view: '' });
}

function restoreFindingsControls() {
  const state = window.UIState?.read() || {};
  document.getElementById('findings-search').value = state.query || '';
  setMultiSelect('findings-framework', state.filters?.findingFramework || []);
  setMultiSelect('findings-severity', state.filters?.findingSeverity || []);
  setMultiSelect('findings-status', state.filters?.findingStatus || []);
  setMultiSelect('findings-state', state.filters?.findingState || []);
  const interaction = state.filters?.findingInteraction || [];
  document.getElementById('findings-interaction').value = interaction[0] || '';
  document.getElementById('findings-sort').value = state.sort || 'risk';
  findingsSelectedId = state.selection?.startsWith('threat:') ? state.selection.slice(7) : '';
  const preset = document.getElementById('findings-preset');
  if (preset) preset.value = findingsPresetValue(state.filters || {});
  const advanced = document.getElementById('findings-advanced-filters');
  if (advanced) advanced.open = preset?.value === 'custom';
}

function setMultiSelect(id, values) {
  if (window.WorkspaceFilters?.setValues(id, values)) return;
  const selected = new Set(values);
  [...document.getElementById(id).options].forEach(option => { option.selected = selected.has(option.value); });
}

function selectedValues(id) {
  if (window.WorkspaceFilters) return window.WorkspaceFilters.values(id);
  return [...document.getElementById(id).selectedOptions].map(option => option.value);
}

function findingsFilterCount(filters = (window.UIState?.read() || {}).filters || {}) {
  return ['findingFramework', 'findingSeverity', 'findingStatus', 'findingState', 'findingInteraction']
    .reduce((count, key) => count + (filters[key]?.length || 0), 0);
}

function findingsPresetValue(filters = (window.UIState?.read() || {}).filters || {}) {
  const count = findingsFilterCount(filters);
  if (!count) return '';
  const only = (key, values) => Object.entries(filters).every(([name, value]) =>
    name === key ? JSON.stringify(value || []) === JSON.stringify(values) : !(value || []).length);
  if (only('findingStatus', ['Open', 'Needs Info'])) return 'needs-review';
  if (only('findingState', ['needs_context'])) return 'deferred';
  return 'custom';
}

function renderFindingsFilterSummary() {
  const filters = (window.UIState?.read() || {}).filters || {};
  const labels = { findingFramework: 'Framework', findingSeverity: 'Severity', findingStatus: 'Status', findingState: 'State', findingInteraction: 'DFD mapping' };
  const values = Object.entries(labels).flatMap(([key, label]) => (filters[key] || []).map(value => ({ key, label, value })));
  const countNode = document.getElementById('findings-filter-count');
  if (countNode) countNode.textContent = values.length ? String(values.length) : '';
  const chips = document.getElementById('findings-filter-chips');
  if (chips) chips.innerHTML = values.map(item => `<button type="button" class="filter-chip" data-clear-finding-filter="${escHtml(item.key)}" data-filter-value="${escHtml(item.value)}">${escHtml(item.label)}: ${escHtml(item.value)} <span aria-hidden="true">×</span></button>`).join('');
}

function applyFindingsPreset(value) {
  ['findings-framework', 'findings-severity', 'findings-status', 'findings-state'].forEach(id => setMultiSelect(id, []));
  document.getElementById('findings-interaction').value = '';
  if (value === 'needs-review') setMultiSelect('findings-status', ['Open', 'Needs Info']);
  if (value === 'deferred') setMultiSelect('findings-state', ['needs_context']);
  const advanced = document.getElementById('findings-advanced-filters');
  if (advanced) advanced.open = value === 'custom';
}

function bindFindingsControls() {
  const search = document.getElementById('findings-search');
  const clear = document.getElementById('findings-clear-search');
  const updateFromControls = (replace = true) => {
    const state = {
      project: findingsProjectId,
      query: search.value.trim().slice(0, 160),
      sort: document.getElementById('findings-sort').value,
      filters: {
        findingFramework: selectedValues('findings-framework'),
        findingSeverity: selectedValues('findings-severity'),
        findingStatus: selectedValues('findings-status'),
        findingState: selectedValues('findings-state'),
        findingInteraction: [document.getElementById('findings-interaction').value].filter(Boolean),
      },
    };
    const previousSelection = findingsSelectedId;
    window.UIState?.update({ ...state, selection: '' }, { replace });
    syncFindingsRoutes();
    clear.hidden = !search.value;
    renderFindings();
    if (previousSelection && findingsVisible.some(item => String(item.threat_id) === previousSelection)) {
      findingsSelectedId = previousSelection;
      renderFindingInspector(findingsVisible.find(item => String(item.threat_id) === previousSelection));
    }
  };
  search.addEventListener('input', updateFromControls);
  window.WorkspaceFilters?.bindApply('findings', () => updateFromControls(false));
  document.getElementById('findings-preset')?.addEventListener('change', event => { applyFindingsPreset(event.target.value); updateFromControls(); });
  document.getElementById('findings-filter-chips')?.addEventListener('click', event => {
    const chip = event.target.closest('[data-clear-finding-filter]');
    if (!chip) return;
    const id = ({ findingFramework: 'findings-framework', findingSeverity: 'findings-severity', findingStatus: 'findings-status', findingState: 'findings-state' })[chip.dataset.clearFindingFilter];
    if (id) setMultiSelect(id, selectedValues(id).filter(value => value !== chip.dataset.filterValue));
    if (chip.dataset.clearFindingFilter === 'findingInteraction') document.getElementById('findings-interaction').value = '';
    updateFromControls();
  });
  document.getElementById('start-findings-guided')?.addEventListener('click', startGuidedFindingReview);
  clear.addEventListener('click', () => { search.value = ''; search.focus(); updateFromControls(); });
  document.getElementById('findings-reset').addEventListener('click', () => {
    search.value = '';
    ['findings-framework', 'findings-severity', 'findings-status', 'findings-state'].forEach(id => setMultiSelect(id, []));
    document.getElementById('findings-interaction').value = '';
    document.getElementById('findings-sort').value = 'risk';
    updateFromControls();
    search.focus();
  });
  document.getElementById('findings-list').addEventListener('click', event => {
    const button = event.target.closest('[data-finding-id]');
    if (button) openFinding(button.dataset.findingId);
  });
  document.getElementById('findings-list').addEventListener('keydown', event => {
    const buttons = [...document.querySelectorAll('#findings-list [data-finding-id]')];
    const index = buttons.indexOf(document.activeElement);
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const next = Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
      buttons.forEach((button, buttonIndex) => { button.tabIndex = buttonIndex === next ? 0 : -1; });
      buttons[next]?.focus();
    } else if (event.key === 'Enter' && index >= 0) {
      event.preventDefault(); openFinding(buttons[index].dataset.findingId);
    }
  });
  document.addEventListener('keydown', event => {
    const tag = document.activeElement?.tagName?.toLowerCase();
    const typing = ['input', 'textarea', 'select'].includes(tag) || document.activeElement?.isContentEditable;
    if (event.key === '/' && !typing) { event.preventDefault(); search.focus(); }
    if (event.key === 'Escape' && findingsSelectedId) {
      event.preventDefault(); closeFinding();
    }
  });
  window.addEventListener('popstate', () => {
    restoreFindingsControls(); renderFindings();
    const selected = findingsVisible.find(item => String(item.threat_id) === findingsSelectedId);
    if (selected) renderFindingInspector(selected);
  });
}

function findingInteraction(threat) {
  const flows = findingsReport?.dfd_model?.flows || [];
  const ref = String(threat.primary_interaction_ref || '');
  const flow = flows.find(item => String(item.id) === ref);
  if (flow) return { state: 'mapped', flow };
  return { state: 'deferred', flow: null };
}

function findingSeverity(threat) {
  return threat.scenario_risk_level || threat.scenario_severity || (!threat.risk_methodology_version ? threat.risk_level : '') || 'Unknown';
}

function filterAndSortFindings() {
  const state = window.UIState?.read() || {};
  const filters = state.filters || {};
  const query = (state.query || '').toLowerCase();
  const searchFields = item => [item.threat_id, item.framework, item.threat_category, item.threat_description, item.asset, item.component, item.trust_boundary, item.evidence, item.evidence_refs, item.missing_info, item.recommended_control, item.abuse_case].flat().filter(Boolean).join(' ').toLowerCase();
  let items = analysisVisibility(findingsReport || {}).threats.filter(item => {
    const interaction = findingInteraction(item);
    const severity = findingSeverity(item);
    return (!query || searchFields(item).includes(query))
      && (!filters.findingFramework?.length || filters.findingFramework.includes(item.framework))
      && (!filters.findingSeverity?.length || filters.findingSeverity.includes(severity))
      && (!filters.findingStatus?.length || filters.findingStatus.includes(item.status || 'Open'))
      && (!filters.findingState?.length || filters.findingState.includes(item.finding_state || 'hypothesis'))
      && (!filters.findingInteraction?.length || filters.findingInteraction.includes(interaction.state));
  });
  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1, Unknown: 0 };
  const sort = state.sort || 'risk';
  items.sort((a, b) => {
    if (sort === 'risk') return Number(findingRiskIsScored(b)) - Number(findingRiskIsScored(a)) || (rank[b.risk_level] || 0) - (rank[a.risk_level] || 0) || String(a.threat_id).localeCompare(String(b.threat_id));
    if (sort === 'severity') return (rank[findingSeverity(b)] || 0) - (rank[findingSeverity(a)] || 0) || String(a.threat_id).localeCompare(String(b.threat_id));
    if (sort === 'framework') return String(a.framework).localeCompare(String(b.framework)) || String(a.threat_category).localeCompare(String(b.threat_category));
    if (sort === 'status') return String(a.status || 'Open').localeCompare(String(b.status || 'Open'));
    if (sort === 'asset') return String(a.asset || '').localeCompare(String(b.asset || ''));
    return String(a.threat_category || '').localeCompare(String(b.threat_category || ''));
  });
  return items;
}

function renderFindings() {
  findingsVisible = filterAndSortFindings();
  const all = analysisVisibility(findingsReport || {}).threats;
  const scored = findingsVisible.filter(findingRiskIsScored).length;
  document.getElementById('findings-count').textContent = `${findingsVisible.length} of ${all.length} findings · ${scored} assessed`;
  const runState = findingsReport?.analysis_state || {};
  const orientationStatus = document.getElementById('findings-orientation-status');
  if (orientationStatus) orientationStatus.textContent = `${runState.status_label || 'Needs review'} · ${findingsVisible.length}/${all.length} visible · ${scored} assessed`;
  document.getElementById('findings-result-summary').textContent = `${findingsVisible.length} result${findingsVisible.length === 1 ? '' : 's'}`;
  renderFindingsFilterSummary();
  const guidedProgress = document.getElementById('findings-guided-progress');
  if (guidedProgress) {
    const pending = all.filter(item => ['Open', 'Needs Info'].includes(item.status || 'Open'));
    guidedProgress.textContent = findingsGuided ? `${pending.length} review item${pending.length === 1 ? '' : 's'} remain` : '';
    const next = document.getElementById('findings-orientation-next');
    if (next) next.textContent = runState.result_state === 'not_started'
      ? 'Run analysis from Overview first'
      : runState.next_actions?.[0]?.title || (pending.length ? `Review ${pending.length} open item${pending.length === 1 ? '' : 's'}` : 'Filter by risk or DFD interaction');
  }
  const list = document.getElementById('findings-list');
  const scrollTop = list.scrollTop;
  if (!findingsVisible.length) {
    list.setAttribute('role', 'status');
    list.removeAttribute('aria-activedescendant');
    list.innerHTML = '<div class="findings-empty">No findings match these search and filter settings.</div>';
    list.scrollTop = scrollTop;
    document.getElementById('findings-inspector').innerHTML = '<div class="findings-inspector-empty"><strong>No matching finding</strong><span>Adjust or reset filters to broaden the results.</span></div>';
    return;
  }
  list.setAttribute('role', 'listbox');
  list.innerHTML = findingsVisible.map((item, index) => {
    const id = String(item.threat_id || '');
    const interaction = findingInteraction(item);
    const severity = findingSeverity(item);
    const tabIndex = id === findingsSelectedId || (!findingsSelectedId && index === 0) ? 0 : -1;
    return `<button type="button" role="option" tabindex="${tabIndex}" aria-selected="${id === findingsSelectedId}" class="finding-list-item${id === findingsSelectedId ? ' is-selected' : ''}" data-finding-id="${escHtml(id)}">
      <span class="finding-list-top"><span>${badgeHtml(item.framework || 'Unknown', 'framework')}${badgeHtml(item.status || 'Open', 'status')}</span><span class="finding-id">${escHtml(id)}</span></span>
      <strong>${escHtml(item.threat_category || 'Finding')} · ${escHtml(item.asset || item.component || 'Unspecified asset')}</strong>
      <span class="finding-list-description">${escHtml(item.threat_description || item.description || 'No scenario description provided.')}</span>
      <span class="finding-list-bottom"><span class="finding-risk-pair"><span>Scenario <b>${escHtml(severity)}</b></span><span>Final <b>${findingRiskIsScored(item) ? escHtml(item.risk_override_level || item.risk_level) : 'Deferred'}</b></span></span><span class="finding-interaction-state ${interaction.state}">${interaction.state === 'mapped' ? `DFD · ${escHtml(interaction.flow.display_id || interaction.flow.id)}` : 'DFD interaction deferred'}</span></span>
    </button>`;
  }).join('');
  list.scrollTop = scrollTop;
  if (findingsSelectedId) {
    const selected = findingsVisible.find(item => String(item.threat_id) === findingsSelectedId);
    if (selected) {
      renderFindingInspector(selected);
      window.UXFocus?.open(document.getElementById('findings-inspector'), document.querySelector(`[data-finding-id="${CSS.escape(findingsSelectedId)}"]`));
    }
    else closeFinding(false);
  }
}

function openFinding(id) {
  const finding = findingsVisible.find(item => String(item.threat_id) === String(id));
  if (!finding) return;
  findingsSelectedId = String(id);
  const trigger = document.querySelector(`[data-finding-id="${CSS.escape(findingsSelectedId)}"]`);
  window.UXTelemetry?.start('finding_review');
  window.UIState?.update({ project: findingsProjectId, phase: 'findings', selection: `threat:${findingsSelectedId}` }, { replace: false });
  document.querySelectorAll('#findings-list [data-finding-id]').forEach(button => button.setAttribute('aria-selected', String(button.dataset.findingId === findingsSelectedId)));
  renderFindingInspector(finding);
  window.UXFocus?.open(document.getElementById('findings-inspector'), trigger);
}

function startGuidedFindingReview() {
  findingsGuided = true;
  const pending = analysisVisibility(findingsReport || {}).threats.filter(item => ['Open', 'Needs Info'].includes(item.status || 'Open'));
  const target = pending[0] || findingsVisible[0];
  if (!target) { showToast('No finding is ready for guided review', 'info'); return; }
  findingsSelectedId = String(target.threat_id);
  renderFindings();
  openFinding(findingsSelectedId);
}

function guidedNextFinding(threat) {
  const pending = analysisVisibility(findingsReport || {}).threats.filter(item => ['Open', 'Needs Info'].includes(item.status || 'Open'));
  const index = pending.findIndex(item => String(item.threat_id) === String(threat.threat_id));
  const next = pending[index + 1] || pending[0];
  if (next && String(next.threat_id) !== String(threat.threat_id)) {
    findingsSelectedId = String(next.threat_id);
    renderFindings();
    openFinding(findingsSelectedId);
  } else showToast('Guided review queue is complete', 'success');
}

function closeFinding(updateHistory = true) {
  const previousId = findingsSelectedId;
  findingsSelectedId = '';
  if (updateHistory) window.UIState?.update({ selection: '' }, { replace: true });
  document.querySelectorAll('#findings-list [data-finding-id]').forEach(button => button.setAttribute('aria-selected', 'false'));
  document.getElementById('findings-inspector').innerHTML = '<div class="findings-inspector-empty"><strong>Select a finding</strong><span>Its evidence, canonical DFD interaction, risk state, and triage controls will appear here.</span></div>';
  const returnTo = document.querySelector(`[data-finding-id="${CSS.escape(previousId)}"]`);
  window.UXFocus?.close(document.getElementById('findings-inspector'), returnTo);
  if (!window.UXFocus) returnTo?.focus({ preventScroll: true });
}

function canonicalFlowLabel(flow) {
  const nodes = new Map((findingsReport?.dfd_model?.nodes || []).map(node => [String(node.id), node.name || node.id]));
  return `${flow.display_id || flow.id}: ${nodes.get(String(flow.source_id)) || flow.source_id} → ${nodes.get(String(flow.target_id)) || flow.target_id}`;
}

function findingActionTraceHtml(threat) {
  const state = window.UIState?.read() || {};
  const visibility = analysisVisibility(findingsReport || {});
  const controls = visibility.controls.filter(control => (control.threat_ids || []).some(id => String(id) === String(threat.threat_id)));
  const tests = visibility.tests.filter(test => String(test.threat_id || '') === String(threat.threat_id));
  const controlLinks = controls.map(control => {
    const href = window.UIState?.route('action-plan', findingsProjectId, { run: state.run, phase: 'action-plan', selection: `control:${control.control_id}` }) || `/action-plan.html?id=${encodeURIComponent(findingsProjectId)}&selected=${encodeURIComponent(`control:${control.control_id}`)}`;
    return `<a class="finding-dfd-link" href="${escHtml(href)}">${escHtml(control.name || control.control_id)} · ${escHtml(control.control_id || '')} <span aria-hidden="true">↗</span></a>`;
  }).join('') || '<span class="finding-muted">No linked control is recorded.</span>';
  const testLinks = tests.map(test => {
    const href = window.UIState?.route('action-plan', findingsProjectId, { run: state.run, phase: 'action-plan', selection: `test:${test.test_id}` }) || `/action-plan.html?id=${encodeURIComponent(findingsProjectId)}&selected=${encodeURIComponent(`test:${test.test_id}`)}`;
    return `<a class="finding-dfd-link" href="${escHtml(href)}">${escHtml(test.scenario_name || test.test_id)} · ${escHtml(test.test_id || '')} <span aria-hidden="true">↗</span></a>`;
  }).join('') || '<span class="finding-muted">No linked verification test is recorded.</span>';
  return `<section class="finding-detail-section finding-action-trace"><h3>Action trace</h3><div class="finding-trace-group"><strong>Controls</strong>${controlLinks}</div><div class="finding-trace-group"><strong>Verification tests</strong>${testLinks}</div></section>`;
}

function renderFindingInspector(threat) {
  const interaction = findingInteraction(threat);
  const flowOptions = (findingsReport?.dfd_model?.flows || []).map(flow => `<option value="${escHtml(flow.id)}" ${interaction.flow && String(interaction.flow.id) === String(flow.id) ? 'selected' : ''}>${escHtml(canonicalFlowLabel(flow))}</option>`).join('');
  const scenarioSeverity = findingSeverity(threat);
  const finalRisk = findingRiskIsScored(threat) ? (threat.risk_override_level || threat.risk_level) : '';
  const statuses = ['Open', 'Needs Info', 'Reviewed', 'Accepted', 'Mitigation Planned', 'Mitigated', 'Verified'];
  const dfdContext = interaction.flow
    ? `<a class="finding-dfd-link" href="${escHtml(window.UIState?.route('model', findingsProjectId, { ...window.UIState.read(), phase: 'model', view: 'diagram', selection: `dfd-flow:${interaction.flow.id}` }) || `/model.html?id=${encodeURIComponent(findingsProjectId)}&selected=${encodeURIComponent(`dfd-flow:${interaction.flow.id}`)}`)}">${escHtml(canonicalFlowLabel(interaction.flow))} <span aria-hidden="true">↗</span></a>`
    : `<div class="finding-deferred-note"><strong>${interaction.state === 'deferred' ? 'DFD interaction deferred' : 'DFD interaction not mapped'}</strong><span>${escHtml(threat.interaction_mapping_reason || (interaction.state === 'deferred' ? 'No canonical primary flow is assigned; treat this as an explicit evidence/context gap, not a confirmed vulnerability.' : 'A reviewer must select one canonical DFD flow before the scenario can be grounded and scored.'))}</span></div>`;
  document.getElementById('findings-inspector').innerHTML = `
    <header class="findings-inspector-header"><div><span class="analysis-overview-kicker">Finding detail</span><h2>${escHtml(threat.threat_category || 'Finding')}</h2><span class="finding-id">${escHtml(threat.threat_id || '')}</span></div><button type="button" class="btn btn-ghost btn-sm findings-inspector-close" aria-label="Close finding details">×</button></header>
    <div class="findings-inspector-content">
      <div class="finding-badges">${badgeHtml(threat.framework || 'Unknown', 'framework')}${findingStateBadgeHtml(threat)}</div>
      <p class="finding-full-description">${escHtml(threat.threat_description || threat.description || 'No scenario description provided.')}</p>
      <section class="finding-risk-section" aria-label="Risk assessment"><h3>Risk assessment</h3><div class="finding-risk-cards"><div><span>Scenario severity</span><strong>${escHtml(scenarioSeverity)}</strong><small>Scenario-level signal; not a validated vulnerability.</small></div><div><span>Final assessed risk</span><strong>${finalRisk ? escHtml(finalRisk) : 'Deferred / not assessed'}</strong><small>${finalRisk ? escHtml(threat.risk_rationale || 'Deterministic risk assessment') : 'Requires grounded or reviewed evidence and applicable methodology.'}</small></div></div></section>
      <section class="finding-detail-section"><h3>Canonical primary DFD interaction</h3>${dfdContext}${flowOptions ? `<label class="finding-flow-picker">Assign or change primary flow<select class="form-select" id="finding-primary-flow"><option value="">${interaction.state === 'deferred' ? 'Keep deferred / unassigned' : 'Select canonical flow…'}</option>${flowOptions}</select></label>` : '<p class="finding-muted">No canonical DFD flows are available in this project.</p>'}</section>
      <section class="finding-detail-section finding-context-grid"><div><span>Asset</span><strong>${escHtml(threat.asset || 'Not specified')}</strong></div><div><span>Component</span><strong>${escHtml(threat.component || 'Not specified')}</strong></div><div><span>Trust boundary</span><strong>${escHtml(threat.trust_boundary || 'Not specified')}</strong></div><div><span>Finding state</span><strong>${escHtml(findingStatePresentation(threat).label)}</strong></div></section>
      ${threat.evidence ? `<section class="finding-detail-section"><h3>Evidence</h3><p>${escHtml(threat.evidence)}</p></section>` : ''}
      ${Array.isArray(threat.evidence_refs) && threat.evidence_refs.length ? `<section class="finding-detail-section"><h3>Evidence references</h3><ul>${threat.evidence_refs.map(ref => `<li>${escHtml(typeof ref === 'string' ? ref : ref.locator || ref.title || JSON.stringify(ref))}</li>`).join('')}</ul></section>` : ''}
      ${threat.missing_info ? `<section class="finding-detail-section"><h3>Information needed</h3><p>${escHtml(threat.missing_info)}</p></section>` : ''}
      ${threat.recommended_control ? `<section class="finding-detail-section"><h3>Recommended control</h3><p>${escHtml(threat.recommended_control)}</p></section>` : ''}
      ${findingActionTraceHtml(threat)}
      ${findingsGuided ? `<section class="finding-guided-review" id="finding-guided-review" aria-labelledby="finding-guided-title"><div class="guided-review-heading"><div><span class="analysis-overview-kicker">Guided review</span><h3 id="finding-guided-title">Make this scenario actionable</h3></div><span class="guided-review-step">${escHtml(threat.threat_id || '')}</span></div><p><strong>What might happen?</strong> Confirm the scenario description, then record what evidence is available and what should be checked next.</p><label>Evidence available<select class="form-select" id="finding-guided-evidence"><option value="unknown">Belum tahu</option><option value="available">Yes, evidence supports review</option><option value="missing">No, evidence is still missing</option></select></label><label>What should be checked next?<textarea class="form-control" id="finding-guided-next" rows="3" placeholder="Add a concrete check, owner, or source locator"></textarea></label><div class="guided-review-actions"><button type="button" class="btn btn-ghost btn-sm" id="finding-guided-back">Back</button><button type="button" class="btn btn-ghost btn-sm" id="finding-guided-defer">Save as deferred</button><button type="button" class="btn btn-primary btn-sm" id="finding-guided-save">Save &amp; next</button></div><p class="finding-muted">Belum tahu keeps this item in review/deferred state; it does not create a confirmed vulnerability.</p></section>` : ''}
      <section class="finding-triage"><h3>Triage</h3><label>Review status<select class="form-select" id="finding-status">${statuses.map(status => `<option ${status === (threat.status || 'Open') ? 'selected' : ''}>${status}</option>`).join('')}</select></label><p class="finding-muted">Status records reviewer workflow only; it does not promote a scenario to a confirmed vulnerability.</p></section>
    </div>`;
  document.querySelector('.findings-inspector-close').addEventListener('click', () => closeFinding());
  document.getElementById('finding-status').addEventListener('change', event => updateFinding(threat, { status: event.target.value }));
  document.getElementById('finding-primary-flow')?.addEventListener('change', event => {
    const value = event.target.value;
    if (value) updateFinding(threat, { primary_interaction_ref: value });
  });
  document.getElementById('finding-guided-back')?.addEventListener('click', () => closeFinding());
  document.getElementById('finding-guided-defer')?.addEventListener('click', async () => {
    if (await updateFinding(threat, { status: 'Needs Info' })) guidedNextFinding(threat);
  });
  document.getElementById('finding-guided-save')?.addEventListener('click', async () => {
    const evidenceState = document.getElementById('finding-guided-evidence')?.value;
    if (await updateFinding(threat, { status: evidenceState === 'available' ? 'Reviewed' : 'Needs Info' })) guidedNextFinding(threat);
  });
}

async function updateFinding(threat, patch) {
  try {
    const result = await API.analysis.updateThreat(findingsProjectId, threat.threat_id, patch);
    Object.assign(threat, result?.threat || patch);
    findingsReport = await API.analysis.report(findingsProjectId);
    renderFindings();
    if (findingsSelectedId) renderFindingInspector(findingsVisible.find(item => String(item.threat_id) === findingsSelectedId) || threat);
    window.UXTelemetry?.complete('finding_review', 'findings', 'success', { phase: 'findings' });
    showToast('Finding updated', 'success');
    return true;
  } catch (error) {
    window.UXTelemetry?.complete('finding_review', 'findings', 'failed', { phase: 'findings' });
    showToast('Could not update finding: ' + error.message, 'error');
    renderFindingInspector(threat);
    return false;
  }
}
