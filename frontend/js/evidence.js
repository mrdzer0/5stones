/* Evidence workspace (U5): context, artifact coverage, gaps, and assumptions. */
let evidenceProjectId = null;
let evidenceProject = null;
let evidenceReport = null;
let evidenceVisible = [];
let evidenceSelectedKey = '';

const EVIDENCE_MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const EVIDENCE_ARTIFACT_ACCEPT = {
  prd: '.pdf,.docx,.md,.markdown,.txt', openapi: '.json,.yaml,.yml', postman: '.json',
  markdown: '.md,.markdown,.txt', database_schema: '.sql,.txt', csv: '.csv,.txt',
  har: '.har,.json', text: '.txt,.md,.markdown',
};

async function initializeEvidenceWorkspace() {
  evidenceProjectId = getProjectId();
  if (!evidenceProjectId) { showToast('No project ID specified', 'error'); return; }
  window.UIState?.bindProjectLinks(evidenceProjectId, { phase: 'evidence' });
  try {
    [evidenceProject, evidenceReport] = await Promise.all([
      API.projects.get(evidenceProjectId), API.analysis.report(evidenceProjectId),
    ]);
    if (evidenceReport.analysis_run?.run_id) window.UIState?.update({ run: String(evidenceReport.analysis_run.run_id) });
    document.getElementById('page-project-name').textContent = evidenceProject.name || 'Project';
    syncEvidenceRoutes();
    restoreEvidenceControls();
    bindEvidenceControls();
    bindEvidenceContextEditor();
    bindEvidenceUpload();
    renderEvidenceWorkspace();
  } catch (error) {
    document.getElementById('evidence-list').innerHTML = `<div class="evidence-empty"><strong>Evidence could not be loaded</strong><span>${escHtml(error.message)}</span><button type="button" class="btn btn-secondary btn-sm" id="evidence-retry-load">Retry load</button><a class="btn btn-ghost btn-sm" href="${escHtml(`/analysis.html?id=${encodeURIComponent(evidenceProjectId)}`)}">Back to analysis</a></div>`;
    document.getElementById('evidence-retry-load')?.addEventListener('click', initializeEvidenceWorkspace);
    showToast('Could not load evidence: ' + error.message, 'error');
  }
}

function syncEvidenceRoutes() {
  if (!window.UIState || !evidenceProjectId) return;
  const state = window.UIState.read();
  const href = (page, patch = {}) => window.UIState.route(page, evidenceProjectId, { ...state, ...patch });
  document.getElementById('nav-analysis').href = href('analysis', { phase: '', view: '', selection: '' });
  document.getElementById('back-analysis').href = href('analysis', { phase: '', view: '', selection: '' });
  document.getElementById('nav-model').href = href('model', { phase: 'model', view: 'diagram', selection: '' });
  document.getElementById('nav-findings').href = href('findings', { phase: 'findings', view: '', selection: '' });
  document.getElementById('nav-action-plan').href = href('action-plan', { phase: 'action-plan', view: '', selection: '' });
  document.getElementById('nav-evidence').href = href('evidence', { phase: 'evidence', view: '', selection: state.selection });
  document.getElementById('nav-report').href = href('report', { phase: 'signoff', view: '', selection: '' });
}

function restoreEvidenceControls() {
  const state = window.UIState?.read() || {};
  const filters = state.evidence || {};
  document.getElementById('evidence-search').value = filters.query || '';
  setEvidenceMultiSelect('evidence-type', filters.types || []);
  setEvidenceMultiSelect('evidence-status', filters.statuses || []);
  document.getElementById('evidence-owner').value = filters.owner || '';
  document.getElementById('evidence-sort').value = filters.sort || 'priority';
  evidenceSelectedKey = state.selection?.startsWith('gap:') || state.selection?.startsWith('assumption:') ? state.selection : '';
  const preset = document.getElementById('evidence-preset');
  if (preset) preset.value = evidencePresetValue(filters);
  const advanced = document.getElementById('evidence-advanced-filters');
  if (advanced) advanced.open = preset?.value === 'custom';
}

function setEvidenceMultiSelect(id, values) {
  if (window.WorkspaceFilters?.setValues(id, values)) return;
  const selected = new Set(values);
  [...document.getElementById(id).options].forEach(option => { option.selected = selected.has(option.value); });
}

function selectedEvidenceValues(id) {
  if (window.WorkspaceFilters) return window.WorkspaceFilters.values(id);
  return [...document.getElementById(id).selectedOptions].map(option => option.value);
}

function evidenceFilterCount(filters = (window.UIState?.read() || {}).evidence || {}) {
  return (filters.types?.length || 0) + (filters.statuses?.length || 0) + (filters.owner ? 1 : 0);
}

function evidencePresetValue(filters = (window.UIState?.read() || {}).evidence || {}) {
  const count = evidenceFilterCount(filters);
  if (!count) return '';
  const only = (key, values) => Object.entries(filters).filter(([name]) => name !== 'sort').every(([name, value]) => name === key ? JSON.stringify(value || []) === JSON.stringify(values) : !(value || []).length);
  if (only('statuses', ['Open'])) return 'needs-attention';
  if (only('statuses', ['Deferred'])) return 'deferred';
  return 'custom';
}

function renderEvidenceFilterSummary() {
  const filters = (window.UIState?.read() || {}).evidence || {};
  const labels = { types: 'Type', statuses: 'State' };
  const values = Object.entries(labels).flatMap(([key, label]) => (filters[key] || []).map(value => ({ key, label, value })));
  if (filters.owner) values.push({ key: 'owner', label: 'Owner', value: filters.owner });
  const countNode = document.getElementById('evidence-filter-count');
  if (countNode) countNode.textContent = values.length ? String(values.length) : '';
  const chips = document.getElementById('evidence-filter-chips');
  if (chips) chips.innerHTML = values.map(item => `<button type="button" class="filter-chip" data-clear-evidence-filter="${escHtml(item.key)}" data-filter-value="${escHtml(item.value)}">${escHtml(item.label)}: ${escHtml(item.value)} <span aria-hidden="true">×</span></button>`).join('');
}

function applyEvidencePreset(value) {
  ['evidence-type', 'evidence-status'].forEach(id => setEvidenceMultiSelect(id, []));
  document.getElementById('evidence-owner').value = '';
  if (value === 'needs-attention') setEvidenceMultiSelect('evidence-status', ['Open']);
  if (value === 'deferred') setEvidenceMultiSelect('evidence-status', ['Deferred']);
  const advanced = document.getElementById('evidence-advanced-filters');
  if (advanced) advanced.open = value === 'custom';
}

function bindEvidenceControls() {
  const search = document.getElementById('evidence-search');
  const clear = document.getElementById('evidence-clear-search');
  const updateFromControls = (replace = true) => {
    const state = window.UIState?.read() || {};
    const next = {
      project: evidenceProjectId,
      evidence: {
        query: search.value.trim().slice(0, 160),
        types: selectedEvidenceValues('evidence-type'),
        statuses: selectedEvidenceValues('evidence-status'),
        owner: document.getElementById('evidence-owner').value.trim().slice(0, 80),
        sort: document.getElementById('evidence-sort').value,
      },
    };
    window.UIState?.update({ ...state, ...next, selection: '' }, { replace });
    clear.hidden = !search.value;
    renderEvidenceWorkspace();
  };
  search.addEventListener('input', updateFromControls);
  window.WorkspaceFilters?.bindApply('evidence', () => updateFromControls(false));
  document.getElementById('evidence-preset')?.addEventListener('change', event => { applyEvidencePreset(event.target.value); updateFromControls(); });
  document.getElementById('evidence-filter-chips')?.addEventListener('click', event => {
    const chip = event.target.closest('[data-clear-evidence-filter]');
    if (!chip) return;
    const id = ({ types: 'evidence-type', statuses: 'evidence-status' })[chip.dataset.clearEvidenceFilter];
    if (id) setEvidenceMultiSelect(id, selectedEvidenceValues(id).filter(value => value !== chip.dataset.filterValue));
    if (chip.dataset.clearEvidenceFilter === 'owner') document.getElementById('evidence-owner').value = '';
    updateFromControls();
  });
  clear.addEventListener('click', () => { search.value = ''; search.focus(); updateFromControls(); });
  document.getElementById('evidence-reset').addEventListener('click', () => {
    search.value = '';
    setEvidenceMultiSelect('evidence-type', []);
    setEvidenceMultiSelect('evidence-status', []);
    document.getElementById('evidence-owner').value = '';
    document.getElementById('evidence-sort').value = 'priority';
    updateFromControls();
    search.focus();
  });
  document.getElementById('evidence-list').addEventListener('click', event => {
    const button = event.target.closest('[data-evidence-key]');
    if (button) openEvidenceItem(button.dataset.evidenceKey);
  });
  document.getElementById('evidence-list').addEventListener('keydown', event => {
    const buttons = [...document.querySelectorAll('#evidence-list [data-evidence-key]')];
    const index = buttons.indexOf(document.activeElement);
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const next = Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
      buttons.forEach((button, buttonIndex) => { button.tabIndex = buttonIndex === next ? 0 : -1; });
      buttons[next]?.focus();
    } else if (event.key === 'Enter' && index >= 0) {
      event.preventDefault(); openEvidenceItem(buttons[index].dataset.evidenceKey);
    }
  });
  document.addEventListener('keydown', event => {
    const tag = document.activeElement?.tagName?.toLowerCase();
    const typing = ['input', 'textarea', 'select'].includes(tag) || document.activeElement?.isContentEditable;
    if (event.key === '/' && !typing) { event.preventDefault(); search.focus(); }
    if (event.key === 'Escape' && evidenceSelectedKey && !document.getElementById('context-editor').open) {
      event.preventDefault(); closeEvidenceItem();
    }
  });
  window.addEventListener('popstate', () => { restoreEvidenceControls(); renderEvidenceWorkspace(); });
}

function evidenceItems() {
  const visibility = analysisVisibility(evidenceReport || {});
  const threats = visibility.threats || [];
  const threatFor = raw => {
    const id = raw.related_threat_id || raw.threat_id;
    if (id) return threats.find(threat => String(threat.threat_id) === String(id));
    const area = String(raw.area || '').toLowerCase();
    return area ? threats.find(threat => `${threat.threat_category || ''} ${threat.asset || ''} ${threat.component || ''}`.toLowerCase().includes(area)) : null;
  };
  const targetRefs = raw => {
    const refs = Array.isArray(raw.target_refs) ? raw.target_refs : (Array.isArray(raw.linked_refs) ? raw.linked_refs : []);
    return refs.filter(ref => ref && ref.id && !['threat', 'control', 'test', 'linked_object'].includes(String(ref.type || '').toLowerCase())).slice(0, 8);
  };
  const decisions = visibility.decisions || [];
  if (decisions.length) {
    return decisions.map(raw => {
      const sourceType = String(raw.decision_type || '').toLowerCase();
      const type = sourceType === 'assumption' ? 'assumption' : 'gap';
      const threatId = raw.dependency_refs?.threat_ids?.[0];
      const threat = threatId ? threats.find(candidate => String(candidate.threat_id) === String(threatId)) : null;
      return {
        type, key: `decision:${raw.decision_id}`, id: raw.decision_id || 'decision', raw, decision: true,
        title: raw.area || (type === 'assumption' ? 'Assumption' : 'Decision required'),
        description: raw.question_to_ask || raw.question || 'Resolve this analysis decision.',
        detail: raw.effect_on_analysis || raw.effect_on_signoff || '', priority: raw.priority || 'Medium',
        status: raw.status || 'Open', owner: raw.owner || 'Security review',
        nextAction: raw.next_action || 'Answer, accept, defer, or obsolete this decision.',
        threat, targetRefs: targetRefs(raw), source: `${sourceType || 'analysis'} · ${raw.source_present === false ? 'preserved from previous run' : 'current run'}`,
        sourceRefs: Array.isArray(raw.evidence_refs) ? raw.evidence_refs : [],
      };
    });
  }
  const missing = (visibility.missingInfo || []).map(raw => {
    const threat = threatFor(raw);
    return {
      type: 'gap', key: `gap:${raw.missing_id}`, id: raw.missing_id || 'missing-info', raw,
      title: raw.area || 'Missing information', description: raw.question_to_ask || raw.question || 'Clarify this project detail.',
      detail: raw.why_it_matters || '', priority: raw.priority || 'Medium', status: raw.status || 'Open',
      owner: raw.owner || raw.target_team || 'Security review', nextAction: raw.next_action || raw.question_to_ask || raw.question || 'Add evidence or answer the open question.',
      threat, targetRefs: targetRefs(raw), source: raw.source || 'Analysis context', sourceRefs: Array.isArray(raw.evidence_refs) ? raw.evidence_refs : [],
    };
  });
  const assumptions = (visibility.assumptions || []).map(raw => {
    const threat = threatFor(raw);
    return {
      type: 'assumption', key: `assumption:${raw.assumption_id}`, id: raw.assumption_id || 'assumption', raw,
      title: raw.area || 'Assumption', description: raw.assumption || 'Validate this assumption.',
      detail: raw.impact_if_wrong || raw.evidence || '', priority: raw.priority || (raw.confidence === 'low' ? 'High' : 'Medium'),
      status: raw.status || 'Open', owner: raw.owner || 'Security review', nextAction: raw.next_action || raw.recommended_validation || raw.verification_question || 'Validate the assumption with project evidence.',
      threat, targetRefs: targetRefs(raw), source: raw.source || 'Analysis context', sourceRefs: Array.isArray(raw.evidence_refs) ? raw.evidence_refs : [],
    };
  });
  return [...missing, ...assumptions];
}

function filteredEvidenceItems() {
  const state = window.UIState?.read() || {};
  const filters = state.evidence || {};
  const query = String(filters.query || '').toLowerCase();
  let items = evidenceItems().filter(item => {
    const haystack = [item.id, item.type, item.title, item.description, item.detail, item.owner, item.status, item.nextAction, item.source, item.sourceRefs, item.threat?.threat_id, item.threat?.threat_category].filter(Boolean).join(' ').toLowerCase();
    return (!query || haystack.includes(query))
      && (!filters.types?.length || filters.types.includes(item.type))
      && (!filters.statuses?.length || filters.statuses.includes(item.status))
      && (!filters.owner || item.owner.toLowerCase().includes(String(filters.owner).toLowerCase()));
  });
  const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  const sort = filters.sort || 'priority';
  items.sort((a, b) => sort === 'status' ? a.status.localeCompare(b.status) : sort === 'owner' ? a.owner.localeCompare(b.owner) : sort === 'type' ? a.type.localeCompare(b.type) : sort === 'area' ? a.title.localeCompare(b.title) : (rank[b.priority] || 0) - (rank[a.priority] || 0));
  return items;
}

function renderEvidenceWorkspace() {
  const all = evidenceItems();
  evidenceVisible = filteredEvidenceItems();
  const openCount = all.filter(item => !['Answered', 'Resolved', 'Accepted assumption', 'Obsolete'].includes(item.status)).length;
  const context = evidenceProject || {};
  const score = context.completeness_score ?? context.completeness?.score ?? context.context_completeness_score;
  document.getElementById('evidence-context-score').textContent = score === undefined || score === null ? 'Review' : `${Math.round(Number(score))}%`;
  document.getElementById('evidence-context-summary').textContent = `${(context.actors || []).length} actors · ${(context.entry_points || []).length} entry points · ${(context.data_involved || []).length} data sets`;
  const artifacts = (context.artifact_sources || []).filter(source => source.active !== false);
  document.getElementById('evidence-artifact-count').textContent = String(artifacts.length);
  document.getElementById('evidence-artifact-summary').textContent = artifacts.length ? `${artifacts.filter(source => source.coverage_manifest?.status === 'complete').length}/${artifacts.length} complete coverage` : 'No artifact evidence uploaded';
  document.getElementById('evidence-open-count').textContent = String(openCount);
  document.getElementById('evidence-open-summary').textContent = openCount ? 'Resolve or defer each item before sign-off.' : 'No unresolved gaps or assumptions.';
  document.getElementById('evidence-count').textContent = `${evidenceVisible.length} of ${all.length} review items`;
  const runState = evidenceReport?.analysis_state || {};
  const orientationStatus = document.getElementById('evidence-orientation-status');
  if (orientationStatus) orientationStatus.textContent = `${runState.status_label || 'Needs review'} · ${openCount} open · ${artifacts.length} source${artifacts.length === 1 ? '' : 's'}`;
  const orientationNext = document.getElementById('evidence-orientation-next');
  if (orientationNext) orientationNext.textContent = runState.result_state === 'not_started'
    ? 'Add evidence or run analysis from Overview'
    : runState.next_actions?.[0]?.title || (openCount ? `Resolve ${openCount} open item${openCount === 1 ? '' : 's'}` : 'Update context or add evidence');
  renderEvidenceFilterSummary();
  renderEvidenceCoverage(artifacts);
  const list = document.getElementById('evidence-list');
  const scrollTop = list.scrollTop;
  list.innerHTML = evidenceVisible.length ? evidenceVisible.map(renderEvidenceRow).join('') : '<div class="evidence-empty"><strong>No matching evidence items</strong><span>Change the filters or add a source artifact.</span></div>';
  list.scrollTop = scrollTop;
  document.getElementById('evidence-result-summary').textContent = `${evidenceVisible.length} visible · ${openCount} unresolved`;
  const selected = evidenceVisible.find(item => item.key === evidenceSelectedKey) || evidenceItems().find(item => item.key === evidenceSelectedKey);
  if (selected) {
    document.querySelectorAll('#evidence-list [data-evidence-key]').forEach(button => { button.classList.toggle('is-selected', button.dataset.evidenceKey === selected.key); button.setAttribute('aria-selected', String(button.dataset.evidenceKey === selected.key)); });
    renderEvidenceInspector(selected);
    window.UXFocus?.open(document.getElementById('evidence-inspector'), document.querySelector(`[data-evidence-key="${CSS.escape(selected.key)}"]`));
  } else if (evidenceSelectedKey) {
    closeEvidenceItem(false);
  }
}

function renderEvidenceRow(item) {
  const linked = item.threat ? `Finding ${item.threat.threat_id}` : item.targetRefs.length ? `${item.targetRefs.length} linked DFD target${item.targetRefs.length > 1 ? 's' : ''}` : 'Project context';
  const index = evidenceVisible.findIndex(candidate => candidate.key === item.key);
  const tabIndex = item.key === evidenceSelectedKey || (!evidenceSelectedKey && index === 0) ? 0 : -1;
  const question = String(item.description || '').trim();
  const nextAction = String(item.nextAction || '').trim();
  const repeatsQuestion = question.toLowerCase() === nextAction.toLowerCase();
  const actionHtml = nextAction && !repeatsQuestion ? `<div class="evidence-next-action"><b>Next action</b> ${escHtml(nextAction)}</div>` : '';
  return `<button type="button" tabindex="${tabIndex}" class="evidence-list-item ${item.key === evidenceSelectedKey ? 'is-selected' : ''}" data-evidence-key="${escHtml(item.key)}" role="option" aria-selected="${item.key === evidenceSelectedKey}"><div class="evidence-list-top"><span class="evidence-type-badge ${item.type}">${item.type === 'gap' ? 'Gap' : 'Assumption'}</span>${badgeHtml(item.priority, 'risk')}<span class="evidence-id">${escHtml(item.id)}</span></div><strong>${escHtml(item.title)}</strong><p><b>Question to answer</b> ${escHtml(question)}</p><div class="evidence-list-meta"><span><b>Owner</b> ${escHtml(item.owner)}</span><span><b>State</b> ${escHtml(item.status)}</span><span><b>Linked</b> ${escHtml(linked)}</span></div>${actionHtml}</button>`;
}

function renderEvidenceCoverage(artifacts) {
  const list = document.getElementById('evidence-artifact-list');
  if (!artifacts.length) {
    list.innerHTML = '<div class="evidence-empty"><strong>No active artifacts</strong><span>Add a PRD, API contract, schema, or other source to build ingestion coverage.</span></div>';
    document.getElementById('evidence-coverage-summary').textContent = 'No sources';
    return;
  }
  let unread = 0;
  const html = artifacts.map(source => {
    const manifest = source.coverage_manifest || {};
    const stats = source.stats || {};
    const sectionCandidates = [
      ...(Array.isArray(manifest.unread_sections) ? manifest.unread_sections : []),
      ...(Array.isArray(manifest.deferred_sections) ? manifest.deferred_sections : []),
      ...(Array.isArray(manifest.extraction_omissions) ? manifest.extraction_omissions : []),
    ];
    const seenSections = new Set();
    const sections = sectionCandidates.filter(section => {
      const key = `${section.chunk_id || ''}|${section.locator || ''}|${section.reason || ''}`;
      if (seenSections.has(key)) return false;
      seenSections.add(key);
      return true;
    });
    unread += sections.length;
    const status = manifest.status || (manifest.deferred_sections?.length ? 'partial' : 'unknown');
    const processed = manifest.processed_chunk_count ?? stats.processed_chunk_count ?? stats.processed_chunks ?? 0;
    const chunks = manifest.chunk_count ?? stats.chunk_count ?? stats.chunks ?? 0;
    return `<article class="evidence-artifact-card"><div class="evidence-artifact-header"><div><strong>${escHtml(source.filename || source.name || 'Artifact')}</strong><span>${escHtml(source.artifact_type || 'source')} · ${escHtml(status)}</span></div><span class="evidence-coverage-stat">${escHtml(String(processed))}/${escHtml(String(chunks || '?'))} chunks</span></div><div class="evidence-artifact-meta"><span>${escHtml(String(sections.length))} unread/deferred section${sections.length === 1 ? '' : 's'}</span><span>${source.revision ? `revision ${escHtml(String(source.revision))}` : source.content_hash ? `hash ${escHtml(String(source.content_hash).slice(0, 12))}` : 'coverage manifest available'}</span></div>${sections.length ? `<details class="evidence-unread" open><summary>Unread or deferred sections (${sections.length})</summary><ul>${sections.map(section => `<li><strong>${escHtml(section.section || section.locator || section.chunk_id || 'Unlocated section')}</strong><span>${escHtml(section.locator || section.chunk_id || '')}${section.reason ? ` · ${escHtml(section.reason)}` : ''}</span></li>`).join('')}</ul></details>` : '<p class="evidence-complete-note">All indexed sections are available to the analysis pipeline.</p>'}</article>`;
  }).join('');
  list.innerHTML = html;
  document.getElementById('evidence-coverage-summary').textContent = `${artifacts.length} source${artifacts.length === 1 ? '' : 's'} · ${unread} unread/deferred`;
}

function evidenceNodeLabel(id) {
  const model = evidenceReport?.dfd_model || {};
  for (const collection of ['nodes', 'data_objects', 'flows', 'boundaries']) {
    const item = (model[collection] || []).find(candidate => String(candidate.id) === String(id));
    if (item) return item.display_id ? `${item.display_id}: ${item.name || item.id}` : (item.name || item.id);
  }
  return id;
}

function evidenceTargetLinks(item) {
  const state = window.UIState?.read() || {};
  const targets = item.targetRefs.map(ref => {
    const type = String(ref.type || '').toLowerCase();
    const selectionType = type === 'data_flow' || type === 'flow' ? 'dfd-flow' : type === 'boundary' || type === 'trust_boundary' ? 'boundary' : 'dfd-node';
    const selection = `${selectionType}:${ref.id}`;
    const href = window.UIState?.route('model', evidenceProjectId, { run: state.run, phase: 'model', view: 'diagram', selection }) || `/model.html?id=${encodeURIComponent(evidenceProjectId)}&selected=${encodeURIComponent(selection)}`;
    return `<a class="evidence-link" href="${escHtml(href)}">${escHtml(ref.label || evidenceNodeLabel(ref.id))} ↗</a>`;
  }).join('');
  const threatLink = item.threat ? (() => {
    const href = window.UIState?.route('findings', evidenceProjectId, { run: state.run, phase: 'findings', selection: `threat:${item.threat.threat_id}` }) || `/findings.html?id=${encodeURIComponent(evidenceProjectId)}&selected=${encodeURIComponent(`threat:${item.threat.threat_id}`)}`;
    return `<a class="evidence-link" href="${escHtml(href)}">${escHtml(item.threat.threat_id)} · ${escHtml(item.threat.threat_category || 'Finding')} ↗</a>`;
  })() : '';
  return threatLink + targets || '<span class="evidence-muted">Project context · no canonical target selected</span>';
}

function renderEvidenceInspector(item) {
  const raw = item.raw || {};
  const statuses = ['Open', 'Assigned', 'Answered', 'Accepted assumption', 'Deferred', 'Obsolete'];
  const inspectorLabel = item.decision ? 'Decision review' : (item.type === 'gap' ? 'Gap review' : 'Assumption review');
  const resolutionValue = raw.answer || raw.resolution || '';
  document.getElementById('evidence-inspector').innerHTML = `<header class="evidence-inspector-header"><div><span class="analysis-overview-kicker">${inspectorLabel}</span><h2>${escHtml(item.title)}</h2><span class="evidence-id">${escHtml(item.id)}</span></div><button type="button" class="btn btn-ghost btn-sm evidence-inspector-close" aria-label="Close evidence details">×</button></header><div class="evidence-inspector-content"><div class="evidence-badges">${badgeHtml(item.decision ? 'Decision' : (item.type === 'gap' ? 'Gap' : 'Assumption'), 'framework')}${badgeHtml(item.priority, 'risk')}<span class="evidence-state ${String(item.status).toLowerCase()}">${escHtml(item.status)}</span></div><section class="evidence-detail-section"><h3>${item.decision ? 'Decision to resolve' : (item.type === 'gap' ? 'Question' : 'Assumption')}</h3><p>${escHtml(item.description)}</p>${item.detail ? `<p class="evidence-muted">${escHtml(item.detail)}</p>` : ''}</section><section class="evidence-detail-section"><h3>Linked object</h3><div class="evidence-trace-group">${evidenceTargetLinks(item)}</div></section><section class="evidence-edit-section"><h3>Resolution</h3><label>Owner<input id="evidence-item-owner" class="form-input" value="${escHtml(item.owner)}" placeholder="Assign an owner" /></label><label>State<select id="evidence-item-status" class="form-select">${statuses.map(status => `<option ${status === item.status ? 'selected' : ''}>${status}</option>`).join('')}</select></label><label>Answer or accepted rationale<textarea id="evidence-item-answer" class="form-input" rows="3" placeholder="Record the answer, evidence-based conclusion, or accepted assumption">${escHtml(resolutionValue)}</textarea></label><label>Next action<textarea id="evidence-item-next-action" class="form-input" rows="3">${escHtml(item.nextAction)}</textarea></label><label>Review notes<textarea id="evidence-item-notes" class="form-input" rows="3">${escHtml(raw.notes || '')}</textarea></label><label>Source locator or evidence reference<textarea id="evidence-item-source" class="form-input" rows="3" placeholder="Document section, ticket, test run, or URL">${escHtml((item.sourceRefs || []).join('\n'))}</textarea></label><button type="button" class="btn btn-primary btn-sm" id="save-evidence-item">Save evidence decision</button></section><section class="evidence-detail-section"><h3>Source and provenance</h3><p class="evidence-muted">${escHtml(item.source)}${raw.evidence ? ` · ${escHtml(raw.evidence)}` : ''}</p>${raw.verification_question ? `<p><strong>Verification:</strong> ${escHtml(raw.verification_question)}</p>` : ''}${raw.impact_if_wrong ? `<p><strong>Impact if wrong:</strong> ${escHtml(raw.impact_if_wrong)}</p>` : ''}</section></div>`;
  document.querySelector('.evidence-inspector-close').addEventListener('click', () => closeEvidenceItem());
  document.getElementById('save-evidence-item').addEventListener('click', () => updateEvidenceItem(item, {
    owner: document.getElementById('evidence-item-owner').value.trim(), status: document.getElementById('evidence-item-status').value,
    answer: document.getElementById('evidence-item-answer').value.trim(),
    next_action: document.getElementById('evidence-item-next-action').value.trim(), notes: document.getElementById('evidence-item-notes').value.trim(), evidence_refs: document.getElementById('evidence-item-source').value.split('\n').map(value => value.trim()).filter(Boolean),
  }));
}

function openEvidenceItem(key) {
  const item = evidenceItems().find(candidate => candidate.key === key);
  if (!item) return;
  evidenceSelectedKey = key;
  const trigger = document.querySelector(`[data-evidence-key="${CSS.escape(key)}"]`);
  window.UIState?.update({ selection: key }, { replace: true });
  document.querySelectorAll('#evidence-list [data-evidence-key]').forEach(button => { button.classList.toggle('is-selected', button.dataset.evidenceKey === key); button.setAttribute('aria-selected', String(button.dataset.evidenceKey === key)); });
  renderEvidenceInspector(item);
  window.UXFocus?.open(document.getElementById('evidence-inspector'), trigger);
}

function closeEvidenceItem(updateHistory = true) {
  const previous = evidenceSelectedKey;
  evidenceSelectedKey = '';
  if (updateHistory) window.UIState?.update({ selection: '' }, { replace: true });
  document.querySelectorAll('#evidence-list [data-evidence-key]').forEach(button => { button.classList.remove('is-selected'); button.setAttribute('aria-selected', 'false'); });
  document.getElementById('evidence-inspector').innerHTML = '<div class="evidence-inspector-empty"><strong>Select an unresolved item</strong><span>Owner, state, linked object, next action, and evidence details will appear here.</span></div>';
  const returnTo = previous ? document.querySelector(`[data-evidence-key="${CSS.escape(previous)}"]`) : null;
  window.UXFocus?.close(document.getElementById('evidence-inspector'), returnTo);
  if (!window.UXFocus) returnTo?.focus({ preventScroll: true });
}

async function updateEvidenceItem(item, patch) {
  try {
    const response = item.decision
      ? await API.analysis.updateDecision(evidenceProjectId, item.id, patch)
      : await API.analysis.updateEvidenceItem(evidenceProjectId, item.type, item.id, patch);
    const updated = response.item || {};
    const source = evidenceItems().find(candidate => candidate.key === item.key);
    if (source) Object.assign(source.raw, updated);
    evidenceReport = await API.analysis.report(evidenceProjectId);
    renderEvidenceWorkspace();
    evidenceSelectedKey = item.key;
    const selected = evidenceItems().find(candidate => candidate.key === item.key);
    if (selected) renderEvidenceInspector(selected);
    showToast('Evidence decision saved', 'success');
  } catch (error) {
    showToast('Could not save evidence decision: ' + error.message, 'error');
  }
}

function bindEvidenceContextEditor() {
  const dialog = document.getElementById('context-editor');
  let contextTrigger = null;
  const close = () => {
    if (dialog.open) dialog.close();
    contextTrigger?.focus({ preventScroll: true });
  };
  const open = () => { contextTrigger = document.activeElement; populateContextEditor(); dialog.showModal(); dialog.querySelector('input, textarea, select, button')?.focus({ preventScroll: true }); };
  document.getElementById('open-context-editor').addEventListener('click', open);
  document.getElementById('open-context-editor-inline').addEventListener('click', open);
  document.getElementById('close-context-editor').addEventListener('click', close);
  document.getElementById('cancel-context-editor').addEventListener('click', close);
  dialog.addEventListener('cancel', event => { event.preventDefault(); close(); });
  document.getElementById('context-editor-form').addEventListener('submit', async event => {
    event.preventDefault();
    const payload = {
      description: document.getElementById('context-description').value.trim(), environment: document.getElementById('context-environment').value.trim(), auth_method: document.getElementById('context-auth_method').value.trim(),
      actors: contextLines('context-actors'), entry_points: contextLines('context-entry_points'), data_involved: contextLines('context-data_involved'), external_systems: contextLines('context-external_systems'), critical_actions: contextLines('context-critical_actions'), existing_controls: contextLines('context-existing_controls'), has_pii: document.getElementById('context-has_pii').checked,
    };
    const button = document.getElementById('save-context-editor');
    button.disabled = true;
    try {
      evidenceProject = await API.projects.update(evidenceProjectId, payload);
      close(); renderEvidenceWorkspace(); showToast('Project context updated', 'success');
    } catch (error) { showToast('Could not update context: ' + error.message, 'error'); }
    finally { button.disabled = false; }
  });
}

function contextLines(id) { return document.getElementById(id).value.split('\n').map(value => value.trim()).filter(Boolean).filter((value, index, all) => all.indexOf(value) === index); }

function populateContextEditor() {
  const context = evidenceProject || {};
  const set = (id, value) => { document.getElementById(id).value = Array.isArray(value) ? value.join('\n') : (value || ''); };
  set('context-description', context.description); set('context-environment', context.environment); set('context-auth_method', context.auth_method); set('context-actors', context.actors); set('context-entry_points', context.entry_points); set('context-data_involved', context.data_involved); set('context-external_systems', context.external_systems); set('context-critical_actions', context.critical_actions); set('context-existing_controls', context.existing_controls); document.getElementById('context-has_pii').checked = Boolean(context.has_pii);
}

function bindEvidenceUpload() {
  const type = document.getElementById('evidence-artifact-type');
  const file = document.getElementById('evidence-artifact-file');
  const button = document.getElementById('upload-evidence-artifact');
  const status = document.getElementById('evidence-upload-status');
  const updateAccept = () => { file.setAttribute('accept', EVIDENCE_ARTIFACT_ACCEPT[type.value] || '.txt'); };
  type.addEventListener('change', updateAccept); updateAccept();
  button.addEventListener('click', async () => {
    const selected = file.files?.[0];
    if (!selected) { status.textContent = 'Select an artifact first.'; return; }
    if (selected.size > EVIDENCE_MAX_ARTIFACT_BYTES) { status.textContent = 'Artifact is larger than 5 MB.'; return; }
    button.disabled = true; status.textContent = `Uploading ${selected.name}…`;
    try {
      await API.artifacts.uploadFile(evidenceProjectId, type.value, selected);
      [evidenceProject, evidenceReport] = await Promise.all([API.projects.get(evidenceProjectId), API.analysis.report(evidenceProjectId)]);
      file.value = ''; renderEvidenceWorkspace(); status.textContent = 'Evidence added. Unread or deferred sections are listed below.'; showToast('Artifact evidence added', 'success');
    } catch (error) { status.textContent = `Upload failed: ${error.message}`; showToast('Could not add evidence: ' + error.message, 'error'); }
    finally { button.disabled = false; }
  });
  document.getElementById('focus-artifact-intake').addEventListener('click', () => { const intake = document.getElementById('evidence-intake'); if (intake) intake.open = true; intake?.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
}
