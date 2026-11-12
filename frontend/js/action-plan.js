/* Controls and verification test workspace (U4). */
let actionProjectId = null;
let actionProject = null;
let actionReport = null;
let actionVisible = [];
let actionSelectedKey = '';

async function initializeActionPlanWorkspace() {
  actionProjectId = getProjectId();
  if (!actionProjectId) { showToast('No project ID specified', 'error'); return; }
  window.UIState?.bindProjectLinks(actionProjectId, { phase: 'action-plan' });
  try {
    const [project, report] = await Promise.all([
      API.projects.get(actionProjectId), API.analysis.report(actionProjectId),
    ]);
    actionProject = project;
    actionReport = report;
    if (report.analysis_run?.run_id) window.UIState?.update({ run: String(report.analysis_run.run_id) });
    document.getElementById('page-project-name').textContent = project.name || 'Project';
    syncActionRoutes();
    restoreActionControls();
    bindActionControls();
    renderActionWorkspace();
  } catch (error) {
    document.getElementById('action-list').innerHTML = `<div class="action-empty"><strong>Action plan could not be loaded</strong><span>${escHtml(error.message)}</span><button type="button" class="btn btn-secondary btn-sm" id="action-retry-load">Retry load</button><a class="btn btn-ghost btn-sm" href="${escHtml(`/analysis.html?id=${encodeURIComponent(actionProjectId)}`)}">Back to analysis</a></div>`;
    document.getElementById('action-retry-load')?.addEventListener('click', initializeActionPlanWorkspace);
    showToast('Could not load action plan: ' + error.message, 'error');
  }
}

function syncActionRoutes() {
  if (!window.UIState || !actionProjectId) return;
  const state = window.UIState.read();
  const href = (page, patch = {}) => window.UIState.route(page, actionProjectId, { ...state, ...patch });
  document.getElementById('nav-analysis').href = href('analysis', { phase: '', view: '', selection: '' });
  document.getElementById('back-analysis').href = href('analysis', { phase: '', view: '', selection: '' });
  document.getElementById('nav-model').href = href('model', { phase: 'model', view: 'diagram', selection: '' });
  document.getElementById('nav-findings').href = href('findings', { phase: 'findings', view: '', selection: '' });
  document.getElementById('btn-action-findings').href = href('findings', { phase: 'findings', view: '', selection: '' });
  document.getElementById('nav-action-plan').href = href('action-plan', { phase: 'action-plan', view: '', selection: state.selection });
  document.getElementById('nav-evidence').href = href('evidence', { phase: 'evidence', view: '', selection: '' });
  document.getElementById('nav-report').href = href('report', { phase: 'signoff', view: '' });
}

function restoreActionControls() {
  const state = window.UIState?.read() || {};
  const action = state.action || {};
  document.getElementById('action-search').value = action.query || '';
  setActionMulti('action-type', action.types || []);
  setActionMulti('action-priority', action.priorities || []);
  setActionMulti('action-status', action.statuses || []);
  setActionMulti('action-executable', action.executability || []);
  document.getElementById('action-owner').value = action.owner || '';
  document.getElementById('action-sort').value = action.sort || 'priority';
  actionSelectedKey = state.selection?.startsWith('control:') || state.selection?.startsWith('test:') ? state.selection : '';
  const preset = document.getElementById('action-preset');
  if (preset) preset.value = actionPresetValue(action);
  const advanced = document.getElementById('action-advanced-filters');
  if (advanced) advanced.open = preset?.value === 'custom';
}

function setActionMulti(id, values) {
  if (window.WorkspaceFilters?.setValues(id, values)) return;
  const selected = new Set(values);
  [...document.getElementById(id).options].forEach(option => { option.selected = selected.has(option.value); });
}

function selectedActionValues(id) {
  if (window.WorkspaceFilters) return window.WorkspaceFilters.values(id);
  return [...document.getElementById(id).selectedOptions].map(option => option.value);
}

function actionFilterCount(action = (window.UIState?.read() || {}).action || {}) {
  return (action.types?.length || 0) + (action.priorities?.length || 0) + (action.statuses?.length || 0) + (action.executability?.length || 0) + (action.owner ? 1 : 0);
}

function actionPresetValue(action = (window.UIState?.read() || {}).action || {}) {
  const count = actionFilterCount(action);
  if (!count) return '';
  const only = (key, values) => Object.entries(action).filter(([name]) => name !== 'sort').every(([name, value]) => name === key ? JSON.stringify(value || []) === JSON.stringify(values) : !(value || []).length);
  if (only('executability', ['unassigned', 'needs_review'])) return 'needs-decision';
  if (only('types', ['control'])) return 'controls';
  if (only('types', ['test'])) return 'tests';
  return 'custom';
}

function renderActionFilterSummary() {
  const action = (window.UIState?.read() || {}).action || {};
  const labels = { types: 'Type', priorities: 'Priority', statuses: 'Status', executability: 'Readiness' };
  const values = Object.entries(labels).flatMap(([key, label]) => (action[key] || []).map(value => ({ key, label, value })));
  if (action.owner) values.push({ key: 'owner', label: 'Owner', value: action.owner });
  const countNode = document.getElementById('action-filter-count');
  if (countNode) countNode.textContent = values.length ? String(values.length) : '';
  const chips = document.getElementById('action-filter-chips');
  if (chips) chips.innerHTML = values.map(item => `<button type="button" class="filter-chip" data-clear-action-filter="${escHtml(item.key)}" data-filter-value="${escHtml(item.value)}">${escHtml(item.label)}: ${escHtml(item.value)} <span aria-hidden="true">×</span></button>`).join('');
}

function applyActionPreset(value) {
  ['action-type', 'action-priority', 'action-status'].forEach(id => setActionMulti(id, []));
  setActionMulti('action-executable', []);
  document.getElementById('action-owner').value = '';
  if (value === 'needs-decision') setActionMulti('action-executable', ['unassigned', 'needs_review']);
  if (value === 'controls') setActionMulti('action-type', ['control']);
  if (value === 'tests') setActionMulti('action-type', ['test']);
  const advanced = document.getElementById('action-advanced-filters');
  if (advanced) advanced.open = value === 'custom';
}

function bindActionControls() {
  const search = document.getElementById('action-search');
  const clear = document.getElementById('action-clear-search');
  const updateFromControls = (replace = true) => {
    const state = {
      project: actionProjectId,
      action: {
        query: search.value.trim().slice(0, 160),
        types: selectedActionValues('action-type'),
        priorities: selectedActionValues('action-priority'),
        statuses: selectedActionValues('action-status'),
        executability: selectedActionValues('action-executable'),
        owner: document.getElementById('action-owner').value.trim().slice(0, 80),
        sort: document.getElementById('action-sort').value,
      },
    };
    window.UIState?.update({ ...state, selection: '' }, { replace });
    actionSelectedKey = '';
    syncActionRoutes();
    clear.hidden = !search.value;
    renderActionWorkspace();
  };
  search.addEventListener('input', updateFromControls);
  window.WorkspaceFilters?.bindApply('action-plan', () => updateFromControls(false));
  document.getElementById('action-preset')?.addEventListener('change', event => { applyActionPreset(event.target.value); updateFromControls(); });
  document.getElementById('action-primary-review')?.addEventListener('click', () => {
    if (actionReport?.analysis_state?.result_state === 'not_started') {
      window.location.assign(window.UIState?.route('analysis', actionProjectId) || `/analysis.html?id=${encodeURIComponent(actionProjectId)}`);
      return;
    }
    const preset = document.getElementById('action-preset');
    if (!preset) return;
    preset.value = 'needs-decision';
    applyActionPreset('needs-decision');
    updateFromControls();
    document.getElementById('action-list')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  document.getElementById('action-filter-chips')?.addEventListener('click', event => {
    const chip = event.target.closest('[data-clear-action-filter]');
    if (!chip) return;
    const id = ({ types: 'action-type', priorities: 'action-priority', statuses: 'action-status' })[chip.dataset.clearActionFilter];
    if (id) setActionMulti(id, selectedActionValues(id).filter(value => value !== chip.dataset.filterValue));
    if (chip.dataset.clearActionFilter === 'executability') setActionMulti('action-executable', []);
    if (chip.dataset.clearActionFilter === 'owner') document.getElementById('action-owner').value = '';
    updateFromControls();
  });
  clear.addEventListener('click', () => { search.value = ''; search.focus(); updateFromControls(); });
  document.getElementById('action-reset').addEventListener('click', () => {
    search.value = '';
    ['action-type', 'action-priority', 'action-status'].forEach(id => setActionMulti(id, []));
    setActionMulti('action-executable', []);
    document.getElementById('action-owner').value = '';
    document.getElementById('action-sort').value = 'priority';
    updateFromControls();
    search.focus();
  });
  document.getElementById('action-list').addEventListener('click', event => {
    const button = event.target.closest('[data-action-key]');
    if (button) openActionItem(button.dataset.actionKey);
  });
  document.getElementById('action-list').addEventListener('keydown', event => {
    const buttons = [...document.querySelectorAll('#action-list [data-action-key]')];
    const index = buttons.indexOf(document.activeElement);
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const next = Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
      buttons.forEach((button, buttonIndex) => { button.tabIndex = buttonIndex === next ? 0 : -1; });
      buttons[next]?.focus();
    } else if (event.key === 'Enter' && index >= 0) {
      event.preventDefault(); openActionItem(buttons[index].dataset.actionKey);
    }
  });
  document.addEventListener('keydown', event => {
    const tag = document.activeElement?.tagName?.toLowerCase();
    const typing = ['input', 'textarea', 'select'].includes(tag) || document.activeElement?.isContentEditable;
    if (event.key === '/' && !typing) { event.preventDefault(); search.focus(); }
    if (event.key === 'Escape' && actionSelectedKey) { event.preventDefault(); closeActionItem(); }
  });
  window.addEventListener('popstate', () => {
    restoreActionControls();
    renderActionWorkspace();
    const selected = actionVisible.find(item => item.key === actionSelectedKey);
    if (selected) renderActionInspector(selected);
  });
}

function actionItems() {
  const visibility = analysisVisibility(actionReport || {});
  const controls = visibility.controls.map(control => ({
    key: `control:${control.control_id}`,
    type: 'control',
    id: String(control.control_id || ''),
    name: control.name || 'Unnamed control',
    priority: control.priority || control.provider_priority || 'Unprioritized',
    status: control.review_status || control.implementation_status || control.status || 'Unknown',
    owner: control.owner || '',
    executable: control.mapping_status === 'unassigned' || !(control.threat_ids || []).length
      ? 'unassigned'
      : (control.implementation_state === 'unknown' || control.review_status === 'Open' ? 'needs_review' : 'executable'),
    raw: control,
  }));
  const tests = visibility.tests.map(test => ({
    key: `test:${test.test_id}`,
    type: 'test',
    id: String(test.test_id || ''),
    name: test.scenario_name || 'Unnamed verification test',
    priority: test.priority || test.provider_priority || 'Unprioritized',
    status: test.execution_status || 'Not Run',
    owner: test.owner || '',
    executable: test.applicability_status === 'blocked'
      ? 'blocked'
      : test.applicability_status === 'not_applicable' || test.quality_status === 'blocked' || (!test.related_control_id && !test.related_control)
        ? 'needs_review'
        : 'executable',
    raw: test,
  }));
  return [...controls, ...tests];
}

function actionIsInSearch(item, query) {
  if (!query) return true;
  const raw = item.raw || {};
  const threatIds = item.type === 'control' ? raw.threat_ids : [raw.threat_id, raw.related_control_id, raw.related_control];
  const threatText = threatIds.flatMap(id => {
    const threat = (actionReport?.threats || []).find(candidate => String(candidate.threat_id) === String(id));
    return threat ? [threat.threat_id, threat.threat_category, threat.threat_description, threat.asset] : [];
  });
  return [item.id, item.name, item.owner, item.status, raw.description, raw.implementation_guidance, raw.evidence, raw.applicability_reason, raw.steps, raw.expected_result, threatText]
    .flat(Infinity).filter(Boolean).join(' ').toLowerCase().includes(query);
}

function filteredActionItems() {
  const state = window.UIState?.read() || {};
  const action = state.action || {};
  const query = (action.query || '').toLowerCase();
  const priorities = { Critical: 5, High: 4, Medium: 3, Low: 2, Unprioritized: 1 };
  const items = actionItems().filter(item =>
    actionIsInSearch(item, query)
    && (!action.types?.length || action.types.includes(item.type))
    && (!action.priorities?.length || action.priorities.includes(item.priority))
    && (!action.statuses?.length || action.statuses.includes(item.status))
    && (!action.executability?.length || action.executability.includes(item.executable))
    && (!action.owner || item.owner.toLowerCase().includes(action.owner.toLowerCase()))
  );
  items.sort((a, b) => {
    if (action.sort === 'type') return a.type.localeCompare(b.type) || a.name.localeCompare(b.name);
    if (action.sort === 'status') return a.status.localeCompare(b.status) || a.name.localeCompare(b.name);
    if (action.sort === 'owner') return a.owner.localeCompare(b.owner) || a.name.localeCompare(b.name);
    if (action.sort === 'name') return a.name.localeCompare(b.name);
    return (priorities[b.priority] || 0) - (priorities[a.priority] || 0) || a.type.localeCompare(b.type) || a.name.localeCompare(b.name);
  });
  return items;
}

function actionQueueHtml() {
  const all = actionItems();
  const unassignedControls = all.filter(item => item.type === 'control' && item.executable === 'unassigned').length;
  const applicability = all.filter(item => item.type === 'test' && item.executable === 'needs_review').length;
  const executableTests = all.filter(item => item.type === 'test' && item.executable === 'executable').length;
  const cards = [];
  if (unassignedControls) cards.push(`<button type="button" class="action-queue-card is-warning" data-action-queue="controls-unassigned"><strong>${unassignedControls}</strong><span>Controls needing applicability mapping</span><small>Review unassigned control → threat links</small></button>`);
  if (applicability) cards.push(`<button type="button" class="action-queue-card is-warning" data-action-queue="tests-review"><strong>${applicability}</strong><span>Tests needing a decision</span><small>Blocked, non-applicable, or missing control linkage</small></button>`);
  if (executableTests) cards.push(`<button type="button" class="action-queue-card" data-action-queue="tests-ready"><strong>${executableTests}</strong><span>Executable tests</span><small>Ready for QA or security verification</small></button>`);
  return cards.length ? cards.join('') : '<div class="action-queue-empty" role="status">No decision queue is open. Use Task view to inspect all controls or tests.</div>';
}

function renderActionWorkspace() {
  actionVisible = filteredActionItems();
  const all = actionItems();
  const controls = all.filter(item => item.type === 'control').length;
  const tests = all.filter(item => item.type === 'test').length;
  const needsDecision = all.filter(item => item.executable !== 'executable').length;
  document.getElementById('action-queue').innerHTML = actionQueueHtml();
  document.getElementById('action-plan-count').textContent = `${actionVisible.length} of ${all.length} actions · ${controls} controls · ${tests} tests`;
  const runState = actionReport?.analysis_state || {};
  const orientationStatus = document.getElementById('action-orientation-status');
  if (orientationStatus) orientationStatus.textContent = `${runState.status_label || 'Needs review'} · ${actionVisible.length}/${all.length} visible · ${needsDecision} need decision`;
  const primaryReview = document.getElementById('action-primary-review');
  if (primaryReview && runState.result_state === 'not_started') primaryReview.textContent = 'Run analysis from Overview';
  document.getElementById('action-result-summary').textContent = `${actionVisible.length} result${actionVisible.length === 1 ? '' : 's'}`;
  renderActionFilterSummary();
  document.querySelectorAll('[data-action-queue]').forEach(button => button.addEventListener('click', () => {
    const value = button.dataset.actionQueue;
    const action = window.UIState.read().action || {};
    const patch = value === 'controls-unassigned'
      ? { types: ['control'], executability: ['unassigned'] }
      : value === 'tests-review'
        ? { types: ['test'], executability: ['needs_review'] }
        : value === 'tests-ready'
          ? { types: ['test'], executability: ['executable'] }
        : {};
    window.UIState?.update({ action: { ...action, ...patch }, selection: '' }, { replace: true });
    actionSelectedKey = '';
    restoreActionControls();
    renderActionWorkspace();
  }));
  const list = document.getElementById('action-list');
  const scrollTop = list.scrollTop;
  if (!actionVisible.length) {
    list.setAttribute('role', 'status');
    list.removeAttribute('aria-activedescendant');
    list.innerHTML = '<div class="action-empty">No controls or tests match these filters.</div>';
    list.scrollTop = scrollTop;
    document.getElementById('action-inspector').innerHTML = '<div class="action-inspector-empty"><strong>No matching action</strong><span>Adjust or reset filters to broaden the work queue.</span></div>';
    return;
  }
  list.setAttribute('role', 'listbox');
  list.innerHTML = actionVisible.map((item, index) => {
    const raw = item.raw;
    const relation = item.type === 'control' ? `${(raw.threat_ids || []).length} finding${(raw.threat_ids || []).length === 1 ? '' : 's'}` : (raw.related_control_id || raw.related_control ? 'Control linked' : 'Control unassigned');
    const tabIndex = item.key === actionSelectedKey || (!actionSelectedKey && index === 0) ? 0 : -1;
    return `<button type="button" role="option" tabindex="${tabIndex}" aria-selected="${item.key === actionSelectedKey}" class="action-list-item${item.key === actionSelectedKey ? ' is-selected' : ''}" data-action-key="${escHtml(item.key)}">
      <span class="action-list-top"><span>${badgeHtml(item.type === 'control' ? 'Control' : 'Test', item.type === 'control' ? 'framework' : 'status')}${badgeHtml(item.priority, 'risk')}</span><span class="action-id">${escHtml(item.id)}</span></span>
      <strong>${escHtml(item.name)}</strong><span class="action-list-meta">${escHtml(item.owner || 'Unassigned')} · ${escHtml(item.status)} · ${escHtml(relation)}</span>
      <span class="action-list-bottom"><span class="action-executable ${item.executable}">${item.executable === 'executable' ? 'Executable' : item.executable === 'blocked' ? 'Blocked' : item.executable === 'unassigned' ? 'Unassigned' : 'Needs review'}</span><span>${item.type === 'test' ? `${(raw.steps || []).length} step${(raw.steps || []).length === 1 ? '' : 's'}` : `${(raw.checklist_items || []).length} checklist item${(raw.checklist_items || []).length === 1 ? '' : 's'}`}</span></span>
    </button>`;
  }).join('');
  list.scrollTop = scrollTop;
  if (actionSelectedKey) {
    const selected = actionVisible.find(item => item.key === actionSelectedKey);
    if (selected) {
      renderActionInspector(selected);
      window.UXFocus?.open(document.getElementById('action-inspector'), document.querySelector(`[data-action-key="${CSS.escape(actionSelectedKey)}"]`));
    }
    else closeActionItem(false);
  }
}

function openActionItem(key) {
  const item = actionVisible.find(candidate => candidate.key === key);
  if (!item) return;
  actionSelectedKey = key;
  const trigger = document.querySelector(`[data-action-key="${CSS.escape(key)}"]`);
  window.UIState?.update({ project: actionProjectId, phase: 'action-plan', selection: key }, { replace: false });
  document.querySelectorAll('#action-list [data-action-key]').forEach(button => {
    const selected = button.dataset.actionKey === key;
    button.setAttribute('aria-selected', String(selected));
    button.classList.toggle('is-selected', selected);
  });
  renderActionInspector(item);
  window.UXFocus?.open(document.getElementById('action-inspector'), trigger);
}

function closeActionItem(updateHistory = true) {
  const previous = actionSelectedKey;
  actionSelectedKey = '';
  if (updateHistory) window.UIState?.update({ selection: '' }, { replace: true });
  document.querySelectorAll('#action-list [data-action-key]').forEach(button => { button.setAttribute('aria-selected', 'false'); button.classList.remove('is-selected'); });
  document.getElementById('action-inspector').innerHTML = '<div class="action-inspector-empty"><strong>Select a control or test</strong><span>Guidance, checklist, evidence, ownership, and links to the finding and DFD will appear here.</span></div>';
  const returnTo = previous ? document.querySelector(`[data-action-key="${CSS.escape(previous)}"]`) : null;
  window.UXFocus?.close(document.getElementById('action-inspector'), returnTo);
  if (!window.UXFocus) returnTo?.focus({ preventScroll: true });
}

function actionNodeLabel(id) {
  const model = actionReport?.dfd_model || {};
  for (const collection of ['nodes', 'data_objects', 'flows', 'boundaries']) {
    const item = (model[collection] || []).find(candidate => String(candidate.id) === String(id));
    if (item) return item.display_id ? `${item.display_id}: ${item.name || item.id}` : (item.name || item.id);
  }
  return id;
}

function actionTargetHref(ref) {
  const type = String(ref.type || '').toLowerCase();
  const selectionType = type === 'data_flow' || type === 'flow' ? 'dfd-flow' : type === 'boundary' || type === 'trust_boundary' ? 'boundary' : 'dfd-node';
  const selection = `${selectionType}:${ref.id}`;
  const href = window.UIState?.route('model', actionProjectId, { run: window.UIState.read().run, phase: 'model', view: 'diagram', selection }) || `/model.html?id=${encodeURIComponent(actionProjectId)}&selected=${encodeURIComponent(selection)}`;
  return `<a class="action-link action-dfd-link" href="${escHtml(href)}">${escHtml(actionNodeLabel(ref.id))} <span aria-hidden="true">↗</span></a>`;
}

function actionFindingLinks(threatIds) {
  const state = window.UIState?.read() || {};
  return (threatIds || []).map(id => {
    const threat = (actionReport?.threats || []).find(item => String(item.threat_id) === String(id));
    const label = threat ? `${threat.threat_id}: ${threat.threat_category || 'Finding'}` : id;
    const href = window.UIState?.route('findings', actionProjectId, { run: state.run, phase: 'findings', selection: `threat:${id}` }) || `/findings.html?id=${encodeURIComponent(actionProjectId)}&selected=${encodeURIComponent(`threat:${id}`)}`;
    return `<a class="action-link" href="${escHtml(href)}">${escHtml(label)} <span aria-hidden="true">↗</span></a>`;
  }).join('') || '<span class="action-muted">No linked finding</span>';
}

function actionTestLinks(controlId) {
  const tests = actionItems().filter(item => item.type === 'test' && (String(item.raw.related_control_id || '') === String(controlId) || String(item.raw.related_control || '') === String((actionReport?.controls || []).find(control => String(control.control_id) === String(controlId))?.name || '')));
  return tests.map(test => `<button type="button" class="action-link action-link-button" data-open-action="${escHtml(test.key)}">${escHtml(test.name)}</button>`).join('') || '<span class="action-muted">No linked test</span>';
}

function actionRelatedControl(test) {
  const control = (actionReport?.controls || []).find(item => String(item.control_id) === String(test.related_control_id || '') || String(item.name) === String(test.related_control || ''));
  return control ? `<button type="button" class="action-link action-link-button" data-open-action="control:${escHtml(control.control_id)}">${escHtml(control.name)} <span aria-hidden="true">↗</span></button>` : '<span class="action-muted">Control unassigned</span>';
}

function renderActionInspector(item) {
  const raw = item.raw;
  const close = '<button type="button" class="btn btn-ghost btn-sm action-inspector-close" aria-label="Close action details">×</button>';
  const targetRefs = Array.isArray(raw.target_refs) ? raw.target_refs : [];
  const targets = targetRefs.length ? targetRefs.map(actionTargetHref).join('') : '<span class="action-muted">No canonical DFD target linked</span>';
  if (item.type === 'control') {
    const statuses = ['Open', 'In Progress', 'Implemented', 'Verified', 'Accepted Risk'];
    document.getElementById('action-inspector').innerHTML = `<header class="action-inspector-header"><div><span class="analysis-overview-kicker">Control detail</span><h2>${escHtml(raw.name || 'Unnamed control')}</h2><span class="action-id">${escHtml(raw.control_id || '')}</span></div>${close}</header><div class="action-inspector-content">
      <div class="action-badges">${badgeHtml('Control', 'framework')}${badgeHtml(raw.priority || 'Unprioritized', 'risk')}<span class="action-executable ${item.executable}">${escHtml(item.executable)}</span></div>
      ${raw.mapping_status === 'unassigned' ? `<div class="action-alert"><strong>Applicability decision required</strong><span>This control is not yet mapped to a finding. Review the threat links before accepting or implementing it.</span></div>` : ''}
      <section class="action-detail-section"><h3>Applicability and lifecycle</h3><p><strong>Recommendation:</strong> ${escHtml(raw.recommendation_status || 'recommended')}</p><p><strong>Mechanism addressed:</strong> ${escHtml(raw.mitigated_mechanism || 'Threat-specific mechanism not recorded.')}</p><p><strong>Rationale:</strong> ${escHtml(raw.applicability_rationale || raw.mapping_rationale || 'No applicability rationale recorded.')}</p></section>
      <section class="action-detail-section"><h3>Guidance</h3><p>${escHtml(raw.implementation_guidance || raw.description || 'No implementation guidance recorded.')}</p></section>
      <section class="action-detail-section"><h3>Checklist</h3>${raw.checklist_items?.length ? `<ol class="action-checklist">${raw.checklist_items.map(item => `<li>${escHtml(item)}</li>`).join('')}</ol>` : '<p class="action-muted">No checklist items recorded.</p>'}</section>
      <section class="action-detail-section"><h3>Evidence</h3><p>${escHtml(raw.evidence || 'No evidence request recorded.')}</p><p class="action-muted">Collected: ${escHtml((raw.evidence_collected_refs || []).join(', ') || 'None')}</p></section>
      <section class="action-detail-section"><h3>Traceability</h3><div class="action-trace-group"><strong>Linked findings</strong>${actionFindingLinks(raw.threat_ids)}</div><div class="action-trace-group"><strong>Canonical DFD targets</strong>${targets}</div><div class="action-trace-group"><strong>Verification tests</strong>${actionTestLinks(raw.control_id)}</div></section>
      <section class="action-edit-section"><h3>Review</h3><label>Status<select id="action-control-status" class="form-select">${statuses.map(status => `<option ${status === (raw.review_status || 'Open') ? 'selected' : ''}>${status}</option>`).join('')}</select></label><label>Applicability<select id="action-control-mapping" class="form-select"><option value="unassigned" ${raw.mapping_status === 'unassigned' ? 'selected' : ''}>Needs applicability decision</option><option value="mapped" ${raw.mapping_status !== 'unassigned' ? 'selected' : ''}>Applicable / mapped</option></select></label><label>Recommendation state<select id="action-control-recommendation" class="form-select">${['recommended', 'needs_review', 'planned', 'implemented', 'verified_effective', 'accepted_risk', 'not_applicable', 'unassigned'].map(state => `<option value="${state}" ${state === (raw.recommendation_status || 'recommended') ? 'selected' : ''}>${state.replaceAll('_', ' ')}</option>`).join('')}</select></label><label>Owner<input id="action-control-owner" class="form-input" value="${escHtml(raw.owner || '')}" placeholder="Assign an owner" /></label><button type="button" class="btn btn-primary btn-sm" id="action-control-save">Save review</button></section>
    </div>`;
    document.getElementById('action-control-save').addEventListener('click', () => updateActionControl(raw, { review_status: document.getElementById('action-control-status').value, mapping_status: document.getElementById('action-control-mapping').value, recommendation_status: document.getElementById('action-control-recommendation').value, owner: document.getElementById('action-control-owner').value.trim() }));
  } else {
    const applicability = raw.applicability_status || 'applicable';
    document.getElementById('action-inspector').innerHTML = `<header class="action-inspector-header"><div><span class="analysis-overview-kicker">Test detail</span><h2>${escHtml(raw.scenario_name || 'Unnamed verification test')}</h2><span class="action-id">${escHtml(raw.test_id || '')}</span></div>${close}</header><div class="action-inspector-content">
      <div class="action-badges">${badgeHtml('Test', 'status')}${badgeHtml(raw.priority || 'Unprioritized', 'risk')}<span class="action-executable ${item.executable}">${escHtml(item.executable)}</span></div>
      ${item.executable !== 'executable' ? `<div class="action-alert"><strong>${raw.applicability_status === 'blocked' || raw.applicability_status === 'not_applicable' ? 'Test needs an applicability decision' : 'Test needs control assignment'}</strong><span>${escHtml(raw.applicability_reason || 'Review the related control and applicability before execution.')}</span></div>` : ''}
      <section class="action-detail-section"><h3>Scenario</h3><p><strong>Preconditions:</strong> ${escHtml(raw.preconditions || '—')}</p><ol class="action-checklist">${(raw.steps || []).map(step => `<li>${escHtml(step)}</li>`).join('') || '<li>Steps not recorded.</li>'}</ol><p><strong>Expected result:</strong> ${escHtml(raw.expected_result || '—')}</p></section>
      <section class="action-detail-section"><h3>Evidence</h3><p>${escHtml((raw.evidence_needed || []).join('; ') || 'No evidence requirement recorded.')}</p><p class="action-muted">Execution evidence: ${escHtml((raw.execution_evidence_refs || []).join(', ') || 'None')}</p></section>
      <section class="action-detail-section"><h3>Traceability</h3><div class="action-trace-group"><strong>Finding</strong>${actionFindingLinks(raw.threat_id ? [raw.threat_id] : [])}</div><div class="action-trace-group"><strong>Related control</strong>${actionRelatedControl(raw)}</div><div class="action-trace-group"><strong>Canonical DFD targets</strong>${targets}</div></section>
      <section class="action-detail-section action-test-state"><h3>Execution state</h3><div><span>Execution</span><strong>${escHtml(raw.execution_status || 'Not Run')}</strong></div><div><span>Applicability</span><strong>${escHtml(applicability)}</strong></div><div><span>Owner</span><strong>${escHtml(raw.owner || 'Unassigned')}</strong></div></section>
    </div>`;
  }
  document.querySelector('.action-inspector-close').addEventListener('click', () => closeActionItem());
  document.querySelectorAll('[data-open-action]').forEach(button => button.addEventListener('click', () => openActionItem(button.dataset.openAction)));
}

async function updateActionControl(control, patch) {
  try {
    await API.analysis.updateControl(actionProjectId, control.control_id, patch);
    actionReport = await API.analysis.report(actionProjectId);
    renderActionWorkspace();
    const selected = actionVisible.find(item => item.key === actionSelectedKey);
    if (selected) renderActionInspector(selected);
    showToast('Control review updated', 'success');
  } catch (error) {
    showToast('Could not update control: ' + error.message, 'error');
    renderActionInspector({ type: 'control', raw: control, key: `control:${control.control_id}`, id: control.control_id, name: control.name, priority: control.priority || 'Unprioritized', status: control.review_status || 'Open', owner: control.owner || '', executable: control.mapping_status === 'unassigned' ? 'unassigned' : 'needs_review' });
  }
}
