/**
 * Report page — full report view with filters and export
 */
let projectId = null;
let currentProject = null;
let currentReport = null;
let liveReport = null;
let liveReleaseDecision = null;
let reportRevisionCatalog = [];
let viewingRevisionId = '';
let reportSearchQuery = '';
let lastScrolledSelection = '';
const REPORT_PAGE_SIZE = { boundaries: 20, threats: 20, controls: 20, tests: 20, gaps: 12, assumptions: 12 };
const reportPages = { boundaries: 1, threats: 1, controls: 1, tests: 1, gaps: 1, assumptions: 1 };

document.addEventListener('DOMContentLoaded', async () => {
  projectId = getProjectId();
  if (!projectId) { showToast('No project ID', 'error'); return; }
  window.UIState?.bindProjectLinks(projectId, { phase: 'signoff' });
  setupReportAppendixToggles();
  const routeFilters = window.UIState?.read().filters || {};
  document.getElementById('threat-filter-framework').value = routeFilters.framework || '';
  document.getElementById('threat-filter-risk').value = routeFilters.risk || '';

  // Inject project ID into navigation links
  const navAnalysis = document.getElementById('nav-analysis');
  if (navAnalysis) navAnalysis.href = window.UIState?.route('analysis', projectId, window.UIState.read()) || `/analysis.html?id=${encodeURIComponent(projectId)}`;
  const navReport = document.getElementById('nav-report');
  if (navReport) navReport.href = window.UIState?.route('report', projectId, window.UIState.read()) || `/report.html?id=${encodeURIComponent(projectId)}`;
  const btnBack = document.getElementById('btn-back-to-analysis');
  if (btnBack) btnBack.href = window.UIState?.route('analysis', projectId, window.UIState.read()) || `/analysis.html?id=${encodeURIComponent(projectId)}`;
  syncReportRouteLinks();

  await loadReport();

  document.getElementById('save-draft-report').addEventListener('click', saveDraftReport);
  document.getElementById('sign-report').addEventListener('click', signReport);
  document.getElementById('export-md').addEventListener('click', () => exportReport('markdown'));
  document.getElementById('export-csv').addEventListener('click', () => exportReport('csv'));
  document.getElementById('export-json').addEventListener('click', () => exportReport('json'));
  document.getElementById('report-revision-select')?.addEventListener('change', event => loadReportRevision(event.target.value));
  document.getElementById('report-revision-current')?.addEventListener('click', () => loadReportRevision(''));

  document.getElementById('threat-filter-framework').addEventListener('change', () => {
    window.UIState?.update({ filters: { framework: document.getElementById('threat-filter-framework').value } });
    syncReportRouteLinks();
    renderFilteredReport();
  });
  document.getElementById('threat-filter-risk').addEventListener('change', () => {
    window.UIState?.update({ filters: { risk: document.getElementById('threat-filter-risk').value } });
    syncReportRouteLinks();
    renderFilteredReport();
  });
  const searchInput = document.getElementById('report-search');
  const clearSearch = document.getElementById('report-search-clear');
  searchInput.addEventListener('input', () => {
    reportSearchQuery = searchInput.value.trim().toLowerCase();
    clearSearch.hidden = !reportSearchQuery;
    renderFilteredReport();
  });
  clearSearch.addEventListener('click', () => {
    searchInput.value = '';
    reportSearchQuery = '';
    clearSearch.hidden = true;
    renderFilteredReport();
    searchInput.focus();
  });
  document.addEventListener('keydown', event => {
    const isTyping = /input|textarea|select/i.test(document.activeElement?.tagName || '');
    if (event.key === '/' && !isTyping) {
      event.preventDefault();
      searchInput.focus();
    }
    if (event.key === 'Escape' && document.activeElement === searchInput && searchInput.value) {
      clearSearch.click();
    }
  });
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-report-page]');
    if (!button) return;
    const key = button.dataset.reportPage;
    reportPages[key] = Number(button.dataset.page || 1);
    renderFilteredReport();
    document.getElementById(`report-${key}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-report-detail-toggle]');
    if (!button) return;
    const expanding = button.getAttribute('aria-expanded') !== 'true';
    if (expanding) {
      button.closest('table')?.querySelectorAll('[data-report-detail-toggle][aria-expanded="true"]')
        .forEach(openButton => setReportRowExpanded(openButton, false));
    }
    setReportRowExpanded(button, expanding);
  });
  setupReportNavigation();
  if (window.location.hash) {
    window.setTimeout(() => {
      const target = document.querySelector(window.location.hash);
      if (target?.id && target.id !== 'report-overview') openReportSection(target.id, true);
      target?.scrollIntoView();
      if (target) {
        document.querySelectorAll('.report-toc a').forEach(link => {
          link.classList.toggle('active', link.dataset.reportSection === target.id);
        });
      }
    }, 350);
  }
});

function syncReportRouteLinks() {
  if (!window.UIState || !projectId) return;
  const state = window.UIState.read();
  const analysisHref = window.UIState.route('analysis', projectId, { ...state, phase: '', view: '' });
  const reportHref = window.UIState.route('report', projectId, state);
  const modelHref = window.UIState.route('model', projectId, { ...state, phase: 'model', view: 'diagram' });
  const findingsHref = window.UIState.route('findings', projectId, { ...state, phase: 'findings', view: '' });
  const actionPlanHref = window.UIState.route('action-plan', projectId, { ...state, phase: 'action-plan', view: '' });
  const evidenceHref = window.UIState.route('evidence', projectId, { ...state, phase: 'evidence', view: '' });
  const navAnalysis = document.getElementById('nav-analysis');
  const navReport = document.getElementById('nav-report');
  const navModel = document.getElementById('nav-model');
  const navFindings = document.getElementById('nav-findings');
  const navActionPlan = document.getElementById('nav-action-plan');
  const navEvidence = document.getElementById('nav-evidence');
  const btnBack = document.getElementById('btn-back-to-analysis');
  if (navAnalysis) navAnalysis.href = analysisHref;
  if (navReport) navReport.href = reportHref;
  if (navModel) navModel.href = modelHref;
  if (navFindings) navFindings.href = findingsHref;
  if (navActionPlan) navActionPlan.href = actionPlanHref;
  if (navEvidence) navEvidence.href = evidenceHref;
  if (btnBack) btnBack.href = analysisHref;
}

async function loadReport() {
  try {
    const [project, report] = await Promise.all([
      API.projects.get(projectId),
      API.analysis.report(projectId),
    ]);
    currentProject = project;
    liveReport = report;
    liveReleaseDecision = report.release_decision || null;
    currentReport = report;
    viewingRevisionId = '';
    if (report.analysis_run?.run_id) window.UIState?.update({ run: String(report.analysis_run.run_id) });
    syncReportRouteLinks();
    document.getElementById('report-page-title').textContent = project.name + ' — Report';
    renderReport(project, report);
    await loadReportRevisions();
  } catch (err) {
    showToast('Could not load report: ' + err.message, 'error');
    document.getElementById('report-header').innerHTML = `
      <div class="report-header-title">Report not available</div>
      <div class="report-header-meta">Complete the analysis stages before preparing a report.</div>`;
  }
}

function renderReport(project, report) {
  updateReportRiskPills(report);
  document.getElementById('report-title').textContent = project.name + ' — Threat Model Report';
  document.getElementById('report-generated').textContent = 'Generated: ' + (report.generated_at ? new Date(report.generated_at + 'Z').toLocaleString() : '—');
  document.getElementById('report-env').textContent = project.environment || 'No environment set';

  renderCompleteness(report.completeness?.score !== undefined ? report.completeness : (project.completeness || {
    score: project.completeness_score || 0,
    level: project.completeness_level || 'Not scored',
  }), report.quality_gate || report.analysis_run?.quality_gate || project.quality_gate || {});
  renderFormalReportMetadata(report.formal_report || {}, report.quality_gate || report.analysis_run?.quality_gate || {});
  renderReportDfdSnapshot(report);

  renderFilteredReport();
}

async function loadReportRevisions() {
  try {
    const data = await API.analysis.reportRevisions(projectId);
    reportRevisionCatalog = data.revisions || [];
    const select = document.getElementById('report-revision-select');
    if (select) {
      select.innerHTML = `<option value="">Current draft projection</option>${reportRevisionCatalog.map(item => `<option value="${escHtml(item.revision_id || '')}">${escHtml(`${item.revision_id || 'revision'} · ${item.status || 'draft'} · DFD r${item.dfd_revision ?? '—'}`)}</option>`).join('')}`;
      select.value = viewingRevisionId;
    }
    renderFormalReportMetadata(currentReport?.formal_report || data.current || {}, currentReport?.quality_gate || {});
    const revisions = reportRevisionCatalog;
    const el = document.getElementById('report-revision-history');
    el.innerHTML = revisions.length
      ? `<ul>${revisions.map(item => `<li><strong>${escHtml(item.revision_id || `r${item.revision}`)}</strong> · ${escHtml(item.status || 'draft')} · DFD ${escHtml(String(item.dfd_revision ?? '—'))} · ${escHtml(item.signed_by || 'not signed')} · ${escHtml(item.signed_at || item.created_at || '—')}</li>`).join('')}</ul>`
      : '<p class="report-muted">No materialized snapshot yet. The current report is a draft projection.</p>';
  } catch (error) {
    document.getElementById('report-revision-history').innerHTML = `<p class="report-muted">Revision history unavailable: ${escHtml(error.message)}</p>`;
  }
}

async function loadReportRevision(revisionId) {
  if (!revisionId) {
    viewingRevisionId = '';
    currentReport = liveReport;
    if (currentProject && currentReport) renderReport(currentProject, currentReport);
    renderRevisionReaderState();
    return;
  }
  try {
    const snapshot = await API.analysis.reportRevision(projectId, revisionId);
    const snapshotReport = snapshot.report || snapshot;
    viewingRevisionId = revisionId;
    currentReport = {
      ...snapshotReport,
      formal_report: snapshot.formal_report || snapshotReport.formal_report || {},
      // This verdict describes the current project evidence while an older
      // immutable report revision is selected in the reader.
      release_decision: liveReleaseDecision,
    };
    renderReport(currentProject, currentReport);
    renderRevisionReaderState();
    showToast(`Reading immutable ${revisionId}`, 'success');
  } catch (error) {
    const select = document.getElementById('report-revision-select');
    if (select) select.value = viewingRevisionId;
    showToast('Could not load report revision: ' + error.message, 'error');
  }
}

function renderRevisionReaderState() {
  const selected = Boolean(viewingRevisionId);
  const select = document.getElementById('report-revision-select');
  const current = document.getElementById('report-revision-current');
  const status = document.getElementById('report-revision-reader-status');
  if (select) select.value = viewingRevisionId;
  if (current) current.hidden = !selected;
  if (status) status.textContent = selected
    ? `${viewingRevisionId} · immutable read-only snapshot`
    : 'Current report is read-only; edits belong in the review workspaces.';
  const save = document.getElementById('save-draft-report');
  const sign = document.getElementById('sign-report');
  if (save) { save.disabled = selected; save.title = selected ? 'Select the current report before creating a draft snapshot' : 'Materialize a read-only draft snapshot'; }
  if (sign) { sign.disabled = selected || sign.dataset.gateDisabled === 'true'; if (selected) sign.title = 'Immutable snapshots cannot be signed from the reader'; }
}

function renderFormalReportMetadata(metadata, qualityGate) {
  const status = metadata.status || 'draft';
  const analysisState = currentReport?.analysis_state || {};
  const statusEl = document.getElementById('report-formal-status');
  if (statusEl) { statusEl.textContent = status; statusEl.className = `report-formal-state ${status}`; }
  const set = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value || '—'; };
  set('report-revision', metadata.revision ? `r${metadata.revision}` : 'Draft');
  set('report-dfd-revision', metadata.dfd_revision ? `r${metadata.dfd_revision}` : 'Unknown');
  set('report-run-provenance', metadata.analysis_run_id || 'Unknown');
  set('report-methodology', (metadata.methodology?.risk_methodology_versions || []).join(', ') || 'Deferred / not recorded');
  set('report-source-manifest', `${(metadata.source_manifest || []).length} source(s)`);
  renderEnterpriseReleaseDecision(currentReport?.release_decision || liveReleaseDecision, metadata);
  const manifestEl = document.getElementById('report-source-manifest-list');
  if (manifestEl) manifestEl.innerHTML = metadata.source_manifest?.length
    ? `<ul>${metadata.source_manifest.map(source => `<li><strong>${escHtml(source.filename || 'Unknown source')}</strong> · ${escHtml(source.artifact_type || 'unknown')} · revision ${escHtml(String(source.revision ?? '—'))} · ${escHtml(source.coverage_status || 'coverage unknown')} · ${escHtml(String(source.content_hash || 'no hash').slice(0, 16))}</li>`).join('')}</ul>`
    : '<p class="report-muted">No source manifest recorded.</p>';
  const riskSummary = currentReport?.risk_summary || {};
  const disposition = metadata.risk_disposition || riskSummary;
  const scored = Number(disposition.scored ?? disposition.scored_total ?? 0);
  const deferred = Number(disposition.deferred ?? disposition.needs_context_total ?? disposition.risk_deferred_total ?? 0);
  const total = Number(disposition.total ?? riskSummary.total ?? scored + deferred);
  const dispositionEl = document.getElementById('report-risk-disposition');
  if (dispositionEl) dispositionEl.innerHTML = analysisState.result_state === 'not_started'
    ? '<strong>Assessment not started:</strong> run the threat model before interpreting risk counts.'
    : ['partial', 'fallback', 'failed'].includes(analysisState.result_state) && !scored && !deferred
      ? '<strong>Assessment incomplete:</strong> no validated risk denominator is available. Review the affected stages before treating this as a clean result.'
      : total && !scored && deferred
        ? `<strong>Assessment deferred:</strong> 0 scored · ${deferred} deferred · ${total} total. This is not evidence that no risk exists; context or verification is still required.`
        : `<strong>Risk disposition:</strong> ${scored} scored · ${deferred} deferred · ${total} total.`;
  const blockers = qualityGate.blocking_reasons || currentReport?.quality_gate?.blocking_reasons || [];
  const blockerEl = document.getElementById('report-blockers');
  if (blockerEl) {
    blockerEl.dataset.state = blockers.length ? 'blocked' : 'clear';
    blockerEl.setAttribute('aria-label', 'Sign-off blockers');
    blockerEl.innerHTML = blockers.length
      ? `<strong>Unresolved sign-off blockers (${blockers.length})</strong><ul tabindex="0" aria-label="Blocker details">${blockers.slice(0, 6).map(reason => `<li>${escHtml(reason)}</li>`).join('')}</ul>`
      : '<strong>Sign-off blockers:</strong> none recorded.';
  }
  const signButton = document.getElementById('sign-report');
  if (signButton) {
    const gateDisabled = status === 'signed' || qualityGate.signoff_ready !== true;
    signButton.dataset.gateDisabled = String(gateDisabled);
    signButton.disabled = viewingRevisionId !== '' || gateDisabled;
    signButton.title = status === 'signed' ? 'This revision is immutable' : qualityGate.signoff_ready === true ? 'Sign this ready report' : 'Resolve sign-off blockers first';
  }
  renderRevisionReaderState();
}

function renderEnterpriseReleaseDecision(decision, metadata = {}) {
  const panel = document.getElementById('report-release-decision');
  const title = document.getElementById('report-release-title');
  const statusEl = document.getElementById('report-release-status');
  const summary = document.getElementById('report-release-summary');
  const blockersEl = document.getElementById('report-release-blockers');
  if (!panel || !statusEl || !summary || !blockersEl) return;

  const allowedStatuses = new Set(['ready', 'not_ready', 'superseded']);
  const projectedStatus = decision?.status || metadata.release_decision_status || 'not_ready';
  const status = allowedStatuses.has(projectedStatus) ? projectedStatus : 'not_ready';
  const blockers = Array.isArray(decision?.blockers) ? decision.blockers : [];
  const visibleBlockers = blockers.length ? blockers : (status === 'ready' ? [] : [{
    code: 'release_decision_evidence_missing',
    message: 'Verified enterprise release blockers are unavailable. Treat this report as not ready.',
  }]);

  panel.dataset.status = status;
  statusEl.textContent = status.toUpperCase();
  statusEl.className = `badge ${status === 'ready' ? 'badge-mitigated' : 'badge-medium'}`;
  if (title) title.textContent = viewingRevisionId
    ? 'Current project release decision'
    : 'Enterprise release decision';
  summary.textContent = status === 'ready'
    ? 'The current report revision passes the enterprise release decision checks.'
    : status === 'superseded'
      ? 'The signed revision no longer matches current project, source, or DFD evidence.'
      : 'Release is blocked. A signed history or completed analysis alone does not authorize release.';
  const additionalCount = Math.max(0, visibleBlockers.length - 8);
  blockersEl.innerHTML = visibleBlockers.length
    ? `${visibleBlockers.slice(0, 8).map(item => `<li><code>${escHtml(item.code || 'release_blocker')}</code>: ${escHtml(item.message || 'A release requirement is not satisfied.')}</li>`).join('')}${additionalCount ? `<li>${additionalCount} additional blocker${additionalCount === 1 ? '' : 's'}; export JSON for the complete list.</li>` : ''}`
    : '';
  blockersEl.tabIndex = 0;
  blockersEl.setAttribute('aria-label', 'Release blockers');
  blockersEl.hidden = !visibleBlockers.length;
}

function renderReportDfdSnapshot(report) {
  const caption = document.getElementById('report-dfd-snapshot-caption');
  const visual = document.getElementById('report-dfd-snapshot-visual');
  const open = document.getElementById('report-dfd-open');
  if (!caption || !visual) return;
  const model = report?.dfd_model;
  const revision = model?.revision ?? report?.formal_report?.dfd_revision;
  if (!model?.nodes?.length) {
    caption.textContent = 'No canonical DFD snapshot is available for this report revision.';
    visual.innerHTML = '<div class="report-dfd-snapshot-empty">DFD provenance is unavailable; review the Model workspace before sign-off.</div>';
    if (open) open.hidden = true;
    return;
  }
  const zones = new Map((model.zones || []).map(zone => [String(zone.id), zone]));
  const nodeZone = node => zones.get(String(node.zone_ids?.[0] || ''))?.name || 'Unclassified zone';
  const groups = new Map();
  (model.nodes || []).forEach(node => {
    const key = nodeZone(node);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(node);
  });
  caption.textContent = `Canonical DFD r${revision ?? '—'} · ${model.nodes.length} nodes · ${(model.flows || []).length} flows · findings reference this revision.`;
  visual.innerHTML = `<div class="report-dfd-zone-grid">${[...groups.entries()].map(([zone, nodes]) => `<section class="report-dfd-zone" aria-label="${escHtml(zone)} zone"><h3>${escHtml(zone)}</h3><ul>${nodes.slice(0, 6).map(node => `<li><strong>${escHtml(node.display_id || node.id)}</strong><span>${escHtml(node.name || node.id)}</span></li>`).join('')}${nodes.length > 6 ? `<li class="report-dfd-more">+${nodes.length - 6} more nodes</li>` : ''}</ul></section>`).join('')}</div><div class="report-dfd-flow-strip"><strong>Canonical flows</strong>${(model.flows || []).slice(0, 6).map(flow => `<span><b>${escHtml(flow.display_id || flow.id)}</b> ${escHtml(flow.name || 'unnamed flow')}</span>`).join('') || '<span>No canonical flow recorded.</span>'}</div>`;
  if (open) {
    open.hidden = false;
    open.href = window.UIState?.route('model', projectId, { run: report?.analysis_run?.run_id, phase: 'model', view: 'diagram' }) || `/model.html?id=${encodeURIComponent(projectId)}`;
  }
}

function openReportSection(sectionId, open = true) {
  const section = document.getElementById(sectionId);
  const card = section?.querySelector(':scope > .card');
  const toggle = section?.querySelector(':scope > .report-section-toggle');
  if (!section || !card || !toggle) return;
  card.hidden = !open;
  toggle.setAttribute('aria-expanded', String(open));
  toggle.classList.toggle('is-open', open);
  const icon = toggle.querySelector('.report-section-toggle-icon');
  if (icon) icon.textContent = open ? '−' : '+';
}

function setupReportAppendixToggles() {
  const labels = {
    'report-boundaries': 'Trust-boundary decisions',
    'report-threats': 'Threat scenarios',
    'report-controls': 'Control checklist',
    'report-tests': 'Security test backlog',
    'report-gaps': 'Missing information',
    'report-assumptions': 'Assumption register',
  };
  Object.entries(labels).forEach(([sectionId, label]) => {
    const section = document.getElementById(sectionId);
    const card = section?.querySelector(':scope > .card');
    if (!section || !card || section.querySelector(':scope > .report-section-toggle')) return;
    const isCoreFindings = sectionId === 'report-threats';
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'report-section-toggle';
    toggle.setAttribute('aria-expanded', String(isCoreFindings));
    card.id = `${sectionId}-content`;
    toggle.setAttribute('aria-controls', card.id);
    toggle.innerHTML = `<span><strong>${label}</strong></span><span class="report-section-toggle-icon" aria-hidden="true">${isCoreFindings ? '−' : '+'}</span>`;
    toggle.addEventListener('click', () => openReportSection(sectionId, card.hidden));
    section.insertBefore(toggle, card);
    card.hidden = !isCoreFindings;
    toggle.classList.toggle('is-open', isCoreFindings);
  });
}

function updateReportRiskPills(report) {
  const visibleThreats = analysisVisibility(report).threats;
  const disposition = report.risk_summary || {};
  const scoredTotal = Number(disposition.scored_total ?? disposition.scored ?? 0);
  const deferredTotal = Number(disposition.needs_context_total ?? disposition.deferred ?? disposition.risk_deferred_total ?? 0);
  const assessmentState = report?.analysis_state?.result_state;
  const display = value => (scoredTotal === 0 && (deferredTotal > 0 || ['not_started', 'partial', 'fallback', 'failed'].includes(assessmentState))) ? '—' : value;
  const rs = {
    critical: visibleThreats.filter(item => findingRiskIsScored(item) && item.risk_level === 'Critical').length,
    high: visibleThreats.filter(item => findingRiskIsScored(item) && item.risk_level === 'High').length,
    medium: visibleThreats.filter(item => findingRiskIsScored(item) && item.risk_level === 'Medium').length,
    low: visibleThreats.filter(item => findingRiskIsScored(item) && item.risk_level === 'Low').length,
  };

  document.getElementById('rp-critical').textContent = display(rs.critical || 0);
  document.getElementById('rp-high').textContent = display(rs.high || 0);
  document.getElementById('rp-medium').textContent = display(rs.medium || 0);
  document.getElementById('rp-low').textContent = display(rs.low || 0);
  document.getElementById('report-risk-pills')?.classList.toggle('is-deferred-only', scoredTotal === 0 && deferredTotal > 0);
}

function renderCompleteness(completeness, qualityGate = {}) {
  const header = document.getElementById('report-header');
  if (!header || document.getElementById('report-readiness')) return;
  const score = completeness.score || 0;
  const color = score >= 85 ? 'var(--green)' : score >= 65 ? 'var(--orange)' : 'var(--accent)';
  const signoffReady = qualityGate.signoff_ready === true;
  const allBlockers = qualityGate.blocking_reasons || [];
  const blockers = allBlockers.slice(0, 4);
  const componentLabels = {
    input_context: 'Input', dfd: 'DFD', analysis: 'Analysis', framework_coverage: 'Coverage',
    threat_review: 'Threat review', control_disposition: 'Controls', verification_plan: 'Tests',
  };
  const gateComponents = Object.entries(qualityGate.components || {});
  const el = document.createElement('div');
  el.id = 'report-readiness';
  el.className = 'report-readiness-compact';
  el.innerHTML = `
    <div class="report-readiness-topline">
      <span>Input context completeness</span>
      <strong>${score}/100 · ${escHtml(completeness.level || 'Not scored')}</strong>
    </div>
    <div class="report-readiness-progress" role="progressbar" aria-label="Input context completeness" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.max(0, Math.min(100, score))}">
      <div style="width:${Math.max(0, Math.min(100, score))}%;background:${color};"></div>
    </div>
    <div class="report-readiness-meta">
      ${completeness.artifact_count || 0} artifacts${(completeness.artifact_types || []).length ? ` · ${(completeness.artifact_types || []).map(escHtml).join(', ')}` : ''}
    </div>
    <div id="report-signoff-readiness" data-status="${signoffReady ? 'ready' : 'not_ready'}" class="report-signoff-readiness">
      <div class="report-readiness-topline">
        <strong>Sign-off Readiness</strong>
        <span class="badge ${signoffReady ? 'badge-mitigated' : 'badge-medium'}">${signoffReady ? 'Ready' : 'Not ready'}</span>
      </div>
      <div class="report-readiness-summary">${escHtml(qualityGate.summary || 'Quality gate has not been evaluated.')}</div>
      ${blockers.length ? `<div class="report-readiness-next"><strong>Next action:</strong> ${escHtml(blockers[0])}${allBlockers.length > 1 ? ` <span>· ${allBlockers.length - 1} more blocker${allBlockers.length === 2 ? '' : 's'}</span>` : ''}</div>` : ''}
      ${gateComponents.length || allBlockers.length > 1 ? `<details class="report-readiness-details"><summary>View gate details</summary>${gateComponents.length ? `<div aria-label="Sign-off gate components" class="report-readiness-badges">${gateComponents.map(([key, value]) => {
        const ready = value?.status === 'ready';
        return `<span class="badge ${ready ? 'badge-mitigated' : 'badge-medium'}" title="${escHtml((value?.reasons || []).join(' · '))}">${escHtml(componentLabels[key] || key)}: ${ready ? 'Ready' : 'Not ready'}</span>`;
      }).join('')}</div>` : ''}${allBlockers.length > 1 ? `<ul>${allBlockers.slice(1).map(reason => `<li>${escHtml(reason)}</li>`).join('')}</ul>` : ''}</details>` : ''}
    </div>`;
  header.appendChild(el);
}

function reportItemMatches(item) {
  if (!reportSearchQuery) return true;
  try {
    return JSON.stringify(item).toLowerCase().includes(reportSearchQuery);
  } catch (_) {
    return false;
  }
}

function renderFilteredReport() {
  if (!currentReport) return;
  const visibility = analysisVisibility(currentReport);
  const framework = document.getElementById('threat-filter-framework').value;
  const risk = document.getElementById('threat-filter-risk').value;
  const boundaries = (currentReport.trust_boundaries || []).filter(reportItemMatches);
  const threats = visibility.threats.filter(t =>
    (!framework || t.framework === framework) &&
    (!risk || t.risk_level === risk) &&
    reportItemMatches(t)
  );
  const controls = visibility.controls.filter(reportItemMatches);
  const tests = visibility.tests.filter(reportItemMatches);
  const gaps = visibility.missingInfo.filter(reportItemMatches);
  const assumptions = visibility.assumptions.filter(reportItemMatches);

  // Resolve a canonical deep-link before slicing the paginated table. This
  // keeps a shared URL useful even when the selected finding lives on page 2+.
  const selected = window.UIState?.read().selection || '';
  if (selected.startsWith('threat:')) {
    const selectedId = selected.slice('threat:'.length);
    const selectedIndex = threats.findIndex(item => String(item.threat_id) === String(selectedId));
    if (selectedIndex >= 0) reportPages.threats = Math.floor(selectedIndex / REPORT_PAGE_SIZE.threats) + 1;
  }

  renderTrustBoundariesReport(pageItems('boundaries', boundaries), visibility);
  renderThreatsTable(pageItems('threats', threats));
  restoreSelectedReportThreat();
  renderControlsTable(pageItems('controls', controls));
  renderTestsTable(pageItems('tests', tests));
  renderMissingInfo(pageItems('gaps', gaps));
  renderAssumptions(pageItems('assumptions', assumptions));
  Object.entries({ boundaries, threats, controls, tests, gaps, assumptions }).forEach(([key, items]) => renderReportPagination(key, items.length));
  updateReportNavigationCounts({ boundaries, threats, controls, tests, gaps, assumptions });
}

function pageItems(key, items) {
  const size = REPORT_PAGE_SIZE[key] || 20;
  const pages = Math.max(1, Math.ceil(items.length / size));
  reportPages[key] = Math.max(1, Math.min(reportPages[key] || 1, pages));
  const start = (reportPages[key] - 1) * size;
  return items.slice(start, start + size);
}

function renderReportPagination(key, total) {
  const el = document.getElementById(`report-pagination-${key}`);
  if (!el) return;
  const size = REPORT_PAGE_SIZE[key] || 20;
  const pages = Math.max(1, Math.ceil(total / size));
  const current = reportPages[key] || 1;
  if (pages <= 1) { el.innerHTML = total ? `<span>Showing all ${total} item${total === 1 ? '' : 's'}</span>` : ''; return; }
  el.innerHTML = `<span>Page ${current} of ${pages} · ${total} total</span><div>${Array.from({ length: pages }, (_, index) => index + 1).map(page => `<button type="button" class="btn btn-ghost btn-sm ${page === current ? 'is-active' : ''}" data-report-page="${key}" data-page="${page}" aria-label="Page ${page}">${page}</button>`).join('')}</div>`;
}

function restoreSelectedReportThreat() {
  const selected = window.UIState?.read().selection || '';
  if (!selected.startsWith('threat:')) return;
  const id = selected.slice('threat:'.length);
  const row = document.querySelector(`#threats-tbody tr[data-threat-id="${CSS.escape(id)}"]`);
  if (!row) { lastScrolledSelection = ''; return; }
  openReportSection('report-threats', true);
  row.classList.add('route-selected');
  const detailButton = row.querySelector('[data-report-detail-toggle]');
  if (detailButton) setReportRowExpanded(detailButton, true);
  if (lastScrolledSelection !== selected) {
    lastScrolledSelection = selected;
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

function setReportRowExpanded(button, expanded) {
  const detailRow = document.getElementById(button.getAttribute('aria-controls'));
  if (!detailRow) return;
  detailRow.hidden = !expanded;
  button.setAttribute('aria-expanded', String(expanded));
  button.setAttribute('aria-label', `${expanded ? 'Hide' : 'View'} details for ${button.dataset.detailName || 'item'}`);
  button.textContent = expanded ? 'Hide details' : 'View details';
  button.closest('tr')?.classList.toggle('is-expanded', expanded);
}

function updateReportNavigationCounts(filtered) {
  const visibility = analysisVisibility(currentReport);
  const totals = {
    boundaries: (currentReport.trust_boundaries || []).length,
    threats: visibility.threats.length,
    controls: visibility.controls.length,
    tests: visibility.tests.length,
    gaps: visibility.missingInfo.length,
    assumptions: visibility.assumptions.length,
  };
  const keys = Object.keys(totals);
  keys.forEach(key => {
    const count = filtered[key].length;
    const countEl = document.getElementById(`toc-count-${key}`);
    if (countEl) countEl.textContent = reportSearchQuery ? `${count}/${totals[key]}` : String(totals[key]);
    document.querySelector(`[data-report-section="report-${key}"]`)?.classList.toggle('is-empty', count === 0);
  });
  const visible = keys.reduce((sum, key) => sum + filtered[key].length, 0);
  const total = keys.reduce((sum, key) => sum + totals[key], 0);
  const sectionCount = keys.filter(key => filtered[key].length > 0).length;
  const summary = document.getElementById('report-search-summary');
  summary.textContent = reportSearchQuery
    ? `${visible} matching items across ${sectionCount} sections · ${total} indexed`
    : `${totals.boundaries} boundaries · ${totals.threats} visible scenarios · ${totals.controls} controls · ${totals.tests} tests · ${totals.gaps + totals.assumptions} review notes${visibility.hidden.threats ? ` · ${visibility.hidden.threats} scenarios hidden by boundary review` : ''}`;
}

function renderTrustBoundariesReport(boundaries, visibility = analysisVisibility(currentReport)) {
  const el = document.getElementById('report-boundaries-list');
  if (!el) return;
  if (!boundaries.length) {
    el.innerHTML = '<div class="report-empty">No trust boundaries match the current search.</div>';
    return;
  }
  const badgeClass = status => status === 'Confirmed' ? 'badge-low' : status === 'Rejected' ? 'badge-high' : 'badge-medium';
  const hiddenTotal = Object.values(visibility.hidden).reduce((sum, value) => sum + value, 0);
  el.innerHTML = `${hiddenTotal ? `<div class="trust-visibility-note"><strong>${hiddenTotal} dependent items hidden</strong><span>They remain stored and will reappear when a rejected boundary is restored to Candidate or Confirmed.</span></div>` : ''}${boundaries.map((boundary, index) => `
    <article class="report-list-item trust-report-item ${boundary.status === 'Rejected' ? 'is-rejected' : ''}" id="${reportRowId('boundary', boundary.boundary_id, index)}">
      <div class="trust-report-head">
        <div>
          <div class="report-finding-title">${escHtml(boundary.source || 'Unknown source')} → ${escHtml(boundary.destination || 'Unknown destination')}</div>
          <div class="text-xs text-muted">${escHtml(boundary.boundary_label || 'Zone transition')} · ${escHtml(boundary.confidence || 'Low')} confidence</div>
        </div>
        <span class="badge ${badgeClass(boundary.status)}">${escHtml(boundary.status || 'Candidate')}</span>
      </div>
      ${reportLongFieldHtml(boundary.basis || 'No evidence basis recorded.', 'evidence basis', 'report-finding-description', 130)}
      ${boundary.review_note ? `<div class="trust-report-note"><strong>Review note:</strong> ${reportLongFieldHtml(boundary.review_note, 'review note', 'report-note-copy', 120)}</div>` : ''}
      <details class="report-row-details"><summary>${(boundary.evidence_refs || []).length} supporting references</summary><div tabindex="0"><ul class="report-checklist">${(boundary.evidence_refs || []).map(ref => `<li>${escHtml(ref)}</li>`).join('') || '<li>No supporting reference recorded.</li>'}</ul></div></details>
    </article>
  `).join('')}`;
}

function setupReportNavigation() {
  const links = [...document.querySelectorAll('.report-toc a[data-report-section]')];
  const sections = links.map(link => document.getElementById(link.dataset.reportSection)).filter(Boolean);
  links.forEach(link => link.addEventListener('click', () => {
    links.forEach(item => item.classList.toggle('active', item === link));
    openReportSection(link.dataset.reportSection, true);
  }));
  if (!('IntersectionObserver' in window)) return;
  const observer = new IntersectionObserver(entries => {
    const visible = entries
      .filter(entry => entry.isIntersecting)
      .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
    if (!visible) return;
    links.forEach(link => link.classList.toggle('active', link.dataset.reportSection === visible.target.id));
  }, { rootMargin: '-190px 0px -60% 0px', threshold: [0, .1] });
  sections.forEach(section => observer.observe(section));
}

function reportLongFieldHtml(value, label, className = 'report-cell-value', limit = 130) {
  const text = String(value || '—');
  const escaped = escHtml(text);
  const lineBreaks = (text.match(/\n/g) || []).length;
  if (text.length <= limit && lineBreaks < 3) return `<div class="${className}">${escaped}</div>`;
  return `<div class="${className} report-cell-preview">${escaped}</div>
    <details class="report-row-details"><summary>Show full ${escHtml(label)}</summary><div tabindex="0"><p>${escaped}</p></div></details>`;
}

function reportDetailLineHtml(label, value) {
  const display = value == null || value === '' ? '—' : String(value);
  return `<div class="report-detail-line"><span class="report-detail-label">${escHtml(label)}</span><div>${escHtml(display)}</div></div>`;
}

function reportPrimaryTextHtml(label, value) {
  const full = String(value || '—');
  const shortened = full.length > 170;
  const preview = shortened ? `${full.slice(0, 167).trimEnd()}…` : full;
  return `<div class="report-detail-primary">
    <div class="report-detail-primary-label">${escHtml(label)}</div>
    <p>${escHtml(preview)}</p>
    ${shortened ? `<details class="report-detail-full"><summary>Read full ${escHtml(label.toLowerCase())}</summary><div>${escHtml(full)}</div></details>` : ''}
  </div>`;
}

function reportDetailGroupHtml(label, content) {
  return `<details class="report-detail-group"><summary>${escHtml(label)}</summary><div class="report-detail-group-body">${content}</div></details>`;
}

function renderThreatsTable(threats) {
  const tbody = document.getElementById('threats-tbody');
  if (!threats.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.threats > 0;
    tbody.innerHTML = `<tr><td colspan="3"><div class="report-empty">${hidden ? 'Threat scenarios are hidden by the rejected boundary. Restore it to Candidate or Confirmed to show them again.' : 'No threat scenarios match the current search and filters.'}</div></td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map((t, index) => `
    <tr id="${reportRowId('threat', t.threat_id, index)}" class="report-summary-row" data-threat-id="${escHtml(t.threat_id || '')}">
      <td data-label="Scenario">
        <div class="report-row-title">${escHtml(t.threat_category || 'Uncategorized threat')}</div>
        <div class="report-row-meta">${escHtml(t.framework || 'Framework unrecorded')} · ${escHtml(findingStatePresentation(t).label)} · <span class="mono" title="${escHtml(t.threat_id || '')}">${escHtml(shortReportCaseId(t.threat_id, 'T', index))}</span></div>
        <div class="report-table-preview">${escHtml(t.threat_description || 'No description provided.')}</div>
      </td>
      <td data-label="Assessment">
        <div class="report-assessment-cell">
          ${findingRiskBadgeHtml(t)}
          <div>${evidenceBadgeHtml(t)} <span class="report-secondary-line">· ${escHtml(t.confidence || 'Unknown')} confidence</span></div>
        </div>
      </td>
      <td data-label="Review">
        <div class="report-row-actions">
          ${threatStatusReadOnlyHtml(t)}
          <button type="button" class="report-detail-toggle" id="${reportRowId('threat-toggle', t.threat_id, index)}" data-report-detail-toggle data-detail-name="${escHtml(shortReportCaseId(t.threat_id, 'T', index))}" aria-label="View details for ${escHtml(shortReportCaseId(t.threat_id, 'T', index))}" aria-controls="${reportRowId('threat-detail', t.threat_id, index)}" aria-expanded="false">View details</button>
        </div>
      </td>
    </tr>
    <tr id="${reportRowId('threat-detail', t.threat_id, index)}" class="report-detail-row" hidden>
      <td colspan="3"><div class="report-expanded-body" role="region" aria-labelledby="${reportRowId('threat-toggle', t.threat_id, index)}" tabindex="0">
        <div class="report-detail-content">
          ${reportPrimaryTextHtml('Scenario', t.threat_description || 'No description provided.')}
          <div class="report-detail-groups">
            ${reportDetailGroupHtml('Control and abuse path', `
              ${reportDetailLineHtml('Recommended control', t.recommended_control || 'Not mapped')}
              ${t.abuse_case ? reportDetailLineHtml('Abuse case', t.abuse_case) : ''}
            `)}
            ${reportDetailGroupHtml('DFD context', `
              ${reportDetailLineHtml('Asset', t.asset)}
              ${reportDetailLineHtml('Trust boundary', t.trust_boundary)}
              ${reportDetailLineHtml('Primary interaction', t.primary_interaction_ref || 'Not mapped')}
              <div class="report-detail-line"><span class="report-detail-label">DFD revision</span><div>${reportDfdRevisionHtml(t)}</div></div>
              ${t.interaction_mapping_status !== 'mapped' ? reportDetailLineHtml('Mapping review', t.interaction_mapping_reason || 'Select exactly one canonical DFD flow.') : ''}
              ${t.framework === 'LINDDUN' && t.privacy_context_status ? reportDetailLineHtml('Privacy context', `${t.privacy_context_status}${t.privacy_context_missing?.length ? ` · missing ${t.privacy_context_missing.join(', ')}` : ''}`) : ''}
              <div class="report-detail-line"><span class="report-detail-label">Model targets</span><div>${reportTargetRefsHtml(t)}</div></div>
            `)}
            ${reportDetailGroupHtml('Evidence and confidence', `
              ${evidenceCardHtml(t)}
              ${t.confidence_reason ? reportDetailLineHtml('Confidence basis', t.confidence_reason) : ''}
              ${t.absence_of_evidence_guarded ? reportDetailLineHtml('Evidence guard', 'The asserted control gap is not evidenced. Risk is deferred pending verification.') : ''}
              ${t.unverified_claim ? reportDetailLineHtml('Unverified claim', t.unverified_claim) : ''}
            `)}
            ${reportDetailGroupHtml('Risk calculation', `
              ${t.grounding_reason ? reportDetailLineHtml('Finding basis', t.grounding_reason) : ''}
              ${riskAuditHtml(t, { inline: true })}
            `)}
          </div>
        </div>
      </div></td>
    </tr>
  `).join('');
}

function reportDfdRevisionHtml(item) {
  const current = currentReport?.formal_report?.dfd_revision ?? currentReport?.dfd_model?.revision;
  const referenced = item?.dfd_revision ?? item?.analysis_revision;
  if (current == null && referenced == null) return '<span class="report-target-empty">Unknown — requires review</span>';
  if (referenced != null && current != null && String(referenced) !== String(current)) {
    return `<span class="report-revision-warning">Stale: r${escHtml(String(referenced))} · current r${escHtml(String(current))}</span>`;
  }
  return `<span class="report-revision-ok">r${escHtml(String(referenced ?? current))} · aligned</span>`;
}

function reportTargetRefsHtml(item) {
  const refs = (item?.target_refs || []).filter(ref => ref?.id);
  if (!refs.length) return '<div class="report-target-empty">Unmapped — requires triage</div>';
  const priority = { scenario: 0, service: 1, context: 2, asset: 3 };
  const sorted = [...refs].sort((a, b) => {
    const primaryDelta = Number(String(b.id) === String(item.primary_interaction_ref)) - Number(String(a.id) === String(item.primary_interaction_ref));
    return primaryDelta || (priority[a.model_level] ?? 9) - (priority[b.model_level] ?? 9);
  });
  const visible = sorted.slice(0, 4);
  const typeLabel = { external_entity: 'Entity', external_system: 'External', process: 'Process', data_store: 'Store', data_flow: 'Flow', trust_boundary: 'Boundary', scenario: 'Scenario', data_asset: 'Data' };
  const modelSelection = { external_entity: 'dfd-node', external_system: 'dfd-node', process: 'dfd-node', entity: 'dfd-node', data_store: 'dfd-node', data_flow: 'dfd-flow', trust_boundary: 'boundary' };
  const renderRef = ref => modelSelection[ref.type]
    ? `<a class="report-target-chip report-target-link" href="${escHtml(window.UIState?.route('model', projectId, { run: currentReport?.analysis_run?.run_id, phase: 'model', view: 'diagram', selection: `${modelSelection[ref.type]}:${ref.id}` }) || `/model.html?id=${encodeURIComponent(projectId)}&selected=${encodeURIComponent(`${modelSelection[ref.type]}:${ref.id}`)}`)}" title="Open ${escHtml(`${ref.model_level || 'model'} · ${ref.id}`)} in DFD workspace"><b>${escHtml(String(ref.id) === String(item.primary_interaction_ref) ? 'Primary flow' : (typeLabel[ref.type] || ref.type))}</b>${escHtml(ref.label || ref.id)} ↗</a>`
    : `<span class="report-target-chip" title="${escHtml(`${ref.model_level || 'model'} · ${ref.id}`)}"><b>${escHtml(typeLabel[ref.type] || ref.type)}</b>${escHtml(ref.label || ref.id)}</span>`;
  return `<div class="report-target-list" tabindex="0" role="region" aria-label="DFD model targets">${visible.map(renderRef).join('')}</div>
    ${sorted.length > visible.length ? `<details class="report-row-details"><summary>View ${sorted.length - visible.length} more target${sorted.length - visible.length === 1 ? '' : 's'}</summary><div tabindex="0"><div class="report-target-list report-target-overflow">${sorted.slice(visible.length).map(renderRef).join('')}</div></div></details>` : ''}`;
}

function reportRowId(prefix, value, index) {
  const safe = String(value || index + 1).replace(/[^a-zA-Z0-9_-]+/g, '-');
  // Areas/names are semantic labels, not guaranteed identifiers. Keep the
  // index in the DOM id so repeated assumptions or gaps remain valid HTML.
  return `${prefix}-${safe}-${index + 1}`;
}

function shortReportCaseId(value, prefix, index) {
  const id = String(value || '').trim();
  if (!id) return `${prefix}-${index + 1}`;
  if (/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(id)) return `${prefix}-${id.slice(0, 8).toUpperCase()}`;
  return id.length > 18 ? `${id.slice(0, 15)}…` : id;
}

function threatStatusReadOnlyHtml(t) {
  const status = t.status || 'Open';
  const href = window.UIState?.route('findings', projectId, {
    run: currentReport?.analysis_run?.run_id,
    phase: 'findings', view: '', selection: `threat:${t.threat_id}`,
  }) || `/findings.html?id=${encodeURIComponent(projectId)}&selected=${encodeURIComponent(`threat:${t.threat_id}`)}`;
  return `<span class="report-readonly-status"><span class="badge ${status === 'Verified' || status === 'Mitigated' ? 'badge-mitigated' : status === 'Accepted' ? 'badge-low' : 'badge-medium'}">${escHtml(status)}</span><a class="report-review-link" href="${escHtml(href)}">Open in Findings ↗</a></span>`;
}

function renderControlsTable(controls) {
  const tbody = document.getElementById('controls-tbody');
  if (!controls.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.controls > 0;
    tbody.innerHTML = `<tr><td colspan="3"><div class="report-empty">${hidden ? 'Control mappings are hidden by the rejected boundary.' : 'No controls match the current search.'}</div></td></tr>`;
    return;
  }

  const statusColor = { Implemented: 'badge-mitigated', Partial: 'badge-medium', Missing: 'badge-critical', Unknown: 'badge-neutral' };

  tbody.innerHTML = controls.map((c, index) => `
    <tr id="${reportRowId('control', c.control_id || c.name, index)}" class="report-summary-row">
      <td data-label="Control">
        <div class="report-row-title">${escHtml(c.name || 'Unnamed control')}</div>
        <div class="report-row-meta"><span class="badge ${statusColor[c.implementation_status || c.status] || 'badge-neutral'}">${escHtml(c.review_status || c.implementation_status || c.status || 'Unknown')}</span></div>
      </td>
      <td data-label="Implementation"><div class="report-table-preview">${escHtml(c.implementation_guidance || c.description || 'No implementation guidance recorded.')}</div></td>
      <td data-label="Owner"><div class="report-row-actions"><span class="report-owner">${escHtml(c.owner || 'Unassigned')}</span><button type="button" class="report-detail-toggle" id="${reportRowId('control-toggle', c.control_id || c.name, index)}" data-report-detail-toggle data-detail-name="${escHtml(c.name || 'control')}" aria-label="View details for ${escHtml(c.name || 'control')}" aria-controls="${reportRowId('control-detail', c.control_id || c.name, index)}" aria-expanded="false">View details</button></div></td>
    </tr>
    <tr id="${reportRowId('control-detail', c.control_id || c.name, index)}" class="report-detail-row" hidden>
      <td colspan="3"><div class="report-expanded-body" role="region" aria-labelledby="${reportRowId('control-toggle', c.control_id || c.name, index)}" tabindex="0">
        <div class="report-detail-content">
          ${reportPrimaryTextHtml('Implementation guidance', c.implementation_guidance || c.description || 'Not recorded')}
          <div class="report-detail-groups">
            ${reportDetailGroupHtml('Verification checklist', `
              <ol class="report-detail-steps">${(c.checklist_items || []).map(item => `<li>${escHtml(item)}</li>`).join('') || '<li>Confirm implementation evidence.</li>'}</ol>
              ${reportDetailLineHtml('Verify with', c.verification_method || 'Manual implementation review')}
            `)}
            ${reportDetailGroupHtml('Evidence', `
              ${reportDetailLineHtml('Evidence', c.evidence || 'Not provided')}
              ${reportDetailLineHtml('Verification refs', (c.verification_evidence_refs || []).join(', ') || 'None recorded')}
              ${reportDetailLineHtml('Evidence requested', (c.implementation_evidence_requested || []).join('; ') || 'Not specified')}
              ${reportDetailLineHtml('Implementation refs', (c.implementation_evidence_refs || []).join(', ') || 'None recorded')}
              ${reportDetailLineHtml('Runtime refs', (c.runtime_verification_refs || []).join(', ') || 'None recorded')}
            `)}
            ${reportDetailGroupHtml('Model mapping', `
              ${reportDetailLineHtml('Control', c.name || 'Unnamed control')}
              ${c.control_id ? reportDetailLineHtml('Control ID', c.control_id) : ''}
              ${reportDetailLineHtml('Origin', c.control_origin || 'Recommended')}
              ${reportDetailLineHtml('State', c.implementation_state || 'Unknown')}
              ${reportDetailLineHtml('Location', c.location_ref?.id || 'Unknown')}
              ${reportDetailLineHtml('DFD targets', (c.target_refs || []).map(ref => ref.id).join(', ') || 'Unknown')}
            `)}
          </div>
        </div>
      </div></td>
    </tr>
  `).join('');
}

function renderTestsTable(tests) {
  const tbody = document.getElementById('tests-tbody');
  if (!tests.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.tests > 0;
    tbody.innerHTML = `<tr><td colspan="3"><div class="report-empty">${hidden ? 'Test cases are hidden by the rejected boundary.' : 'No test cases match the current search.'}</div></td></tr>`;
    return;
  }

  tbody.innerHTML = tests.map((t, index) => `
    <tr id="${reportRowId('test', t.test_id, index)}" class="report-summary-row">
      <td data-label="Test case">
        <div class="report-row-title">${escHtml(t.scenario_name || 'Unnamed test scenario')}</div>
        <div class="report-row-meta mono" title="${escHtml(t.test_id || '')}">${escHtml(shortReportCaseId(t.test_id, 'TM', index))}</div>
      </td>
      <td data-label="Expected result"><div class="report-table-preview">${escHtml(t.expected_result || 'Expected result not recorded.')}</div></td>
      <td data-label="Execution"><div class="report-row-actions">${badgeHtml(t.priority || 'Unprioritized', 'risk')}<span class="report-owner">${escHtml(t.owner || 'Unassigned')}</span><button type="button" class="report-detail-toggle" id="${reportRowId('test-toggle', t.test_id, index)}" data-report-detail-toggle data-detail-name="${escHtml(shortReportCaseId(t.test_id, 'TM', index))}" aria-label="View details for ${escHtml(shortReportCaseId(t.test_id, 'TM', index))}" aria-controls="${reportRowId('test-detail', t.test_id, index)}" aria-expanded="false">View details</button></div></td>
    </tr>
    <tr id="${reportRowId('test-detail', t.test_id, index)}" class="report-detail-row" hidden>
      <td colspan="3"><div class="report-expanded-body" role="region" aria-labelledby="${reportRowId('test-toggle', t.test_id, index)}" tabindex="0">
        <div class="report-detail-content">
          ${reportPrimaryTextHtml('Expected result', t.expected_result || 'Not recorded')}
          <div class="report-detail-groups">
            ${reportDetailGroupHtml('Test steps', `
              ${reportDetailLineHtml('Test case', t.scenario_name || 'Unnamed test scenario')}
              ${t.test_id ? reportDetailLineHtml('Test ID', t.test_id) : ''}
              <ol class="report-detail-steps">${(t.steps || []).map(step => `<li>${escHtml(step)}</li>`).join('') || '<li>Define executable validation steps.</li>'}</ol>
            `)}
            ${reportDetailGroupHtml('Applicability', `
              ${reportDetailLineHtml('Status', t.applicability_status || 'Applicable')}
              ${t.applicability_status && t.applicability_status !== 'applicable' ? reportDetailLineHtml('Reason', t.applicability_reason || 'Review required before execution.') : ''}
              ${t.threat_id ? reportDetailLineHtml('Related threat', t.threat_id) : ''}
              ${reportDetailLineHtml('Priority', t.priority || 'Unprioritized')}
              ${reportDetailLineHtml('Owner', t.owner || 'Unassigned')}
            `)}
          </div>
        </div>
      </div></td>
    </tr>
  `).join('');
}

function renderMissingInfo(items) {
  const el = document.getElementById('missing-info-list');
  if (!items.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.missingInfo > 0;
    el.innerHTML = `<div class="report-empty">${hidden ? 'Information gaps are hidden by the rejected boundary.' : 'No information gaps match the current search.'}</div>`;
    return;
  }
  el.innerHTML = items.map((m, index) => `
      <div class="report-list-item" id="${reportRowId('gap', m.area, index)}">
      <div style="display:flex;gap:var(--space-2);align-items:center;">
        ${badgeHtml(m.priority || 'Medium', 'risk')}
        <div style="font-weight:600;font-size:0.8rem;color:var(--orange);">${escHtml(m.area)}</div>
        <span style="font-size:0.72rem;color:var(--text-faint);">${escHtml(m.target_team || 'Dev/Tech Lead')}</span>
      </div>
      ${reportLongFieldHtml(m.question_to_ask || m.question, 'question', 'report-note-copy', 100)}
      ${m.why_it_matters ? reportLongFieldHtml(m.why_it_matters, 'rationale', 'report-note-copy report-note-muted', 100) : ''}
    </div>
  `).join('');
}

function renderAssumptions(items) {
  const el = document.getElementById('assumptions-list');
  if (!items.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.assumptions > 0;
    el.innerHTML = `<div class="report-empty">${hidden ? 'Assumptions are hidden by the rejected boundary.' : 'No assumptions match the current search.'}</div>`;
    return;
  }
  el.innerHTML = items.map((a, index) => `
    <div class="report-list-item" id="${reportRowId('assumption', a.area, index)}">
      <div style="display:flex;gap:var(--space-3);align-items:flex-start;">
        <div style="flex:1;">
          <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:4px;">
            <div style="font-weight:600;font-size:0.8rem;color:var(--text);">${escHtml(a.area)}</div>
            <span class="text-xs text-muted">${escHtml(a.owner || 'Dev/Tech Lead')}</span>
          </div>
          ${reportLongFieldHtml(a.assumption, 'assumption', 'report-note-copy', 100)}
        </div>
        <div style="display:flex;align-items:center;gap:var(--space-2);">
          ${confidenceDots(a.confidence)}
          <span style="font-size:0.72rem;color:var(--text-faint);">${escHtml(a.confidence)}</span>
        </div>
      </div>
      ${a.evidence || a.impact_if_wrong || a.verification_question || a.recommended_validation || a.related_threat ? `<details class="report-row-details"><summary>Evidence &amp; validation</summary><div tabindex="0">
        ${a.evidence ? `<p><strong>Evidence:</strong> ${escHtml(a.evidence)}</p>` : ''}
        ${a.impact_if_wrong ? `<p><strong>Impact if wrong:</strong> ${escHtml(a.impact_if_wrong)}</p>` : ''}
        ${a.verification_question ? `<p><strong>Ask development:</strong> ${escHtml(a.verification_question)}</p>` : ''}
        ${a.recommended_validation ? `<p><strong>Recommended validation:</strong> ${escHtml(a.recommended_validation)}</p>` : ''}
        ${a.related_threat ? `<p><strong>Related threat:</strong> ${escHtml(a.related_threat)}</p>` : ''}
      </div></details>` : ''}
    </div>
  `).join('');
}

async function exportReport(format) {
  try {
    // Web rendering is intentionally paginated; exports remain the complete
    // appendix and therefore use the all-items projection.
    const res = await API.export.get(projectId, format, 'all', viewingRevisionId);
    if (format === 'json') {
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      downloadBlob(blob, `threat-model-${projectId}${viewingRevisionId ? `-${viewingRevisionId}` : ''}.json`);
    } else {
      const text = await res.text();
      const type = format === 'csv' ? 'text/csv' : 'text/markdown';
      const ext = format === 'csv' ? 'csv' : 'md';
      const blob = new Blob([text], { type });
      downloadBlob(blob, `threat-model-${projectId}${viewingRevisionId ? `-${viewingRevisionId}` : ''}.${ext}`);
    }
    window.UXTelemetry?.complete('report_export', 'report', 'success', { format });
    showToast(`Exported as ${format.toUpperCase()}`, 'success');
  } catch (err) {
    window.UXTelemetry?.complete('report_export', 'report', 'failed', { format });
    showToast('Export failed: ' + err.message, 'error');
  }
}

async function saveDraftReport() {
  const button = document.getElementById('save-draft-report');
  button.disabled = true;
  try {
    await API.analysis.createReportDraft(projectId, { note: 'Draft snapshot created from the read-only report.' });
    await loadReportRevisions();
    showToast('Read-only draft snapshot saved', 'success');
  } catch (error) {
    showToast('Could not save draft snapshot: ' + error.message, 'error');
  } finally { button.disabled = false; }
}

async function signReport() {
  const button = document.getElementById('sign-report');
  if (button.disabled) return;
  button.disabled = true;
  try {
    // The API records the authenticated server-side principal as signer.
    // Never collect or submit a reviewer identity from the browser.
    const response = await API.analysis.signReport(projectId, {});
    currentReport.formal_report = response.formal_report;
    await loadReport();
    showToast('Report signed and locked as an immutable revision', 'success');
  } catch (error) {
    showToast('Could not sign report: ' + error.message, 'error');
    renderFormalReportMetadata(currentReport?.formal_report || {}, currentReport?.quality_gate || {});
  } finally { button.disabled = false; }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
