/**
 * ThreatModelz API Client
 * All backend calls go through this module.
 */

const API_BASE = '';  // Same origin (served by FastAPI)

function workspaceRequestHeaders() {
  const workspaceId = typeof sessionStorage === 'undefined' ? null : sessionStorage.getItem('workspace_id');
  const token = typeof sessionStorage === 'undefined' ? null : sessionStorage.getItem('workspace_access_token');
  const csrf = typeof document === 'undefined'
    ? null
    : document.cookie.split(';').map(value => value.trim()).find(value => value.startsWith('5stones_csrf='))?.slice('5stones_csrf='.length);
  return {
    ...(workspaceId ? { 'X-Workspace-ID': workspaceId } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {}),
  };
}

function redirectToAuthentication() {
  if (typeof window === 'undefined' || window.location.pathname === '/auth.html') return;
  const next = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  window.location.assign(`/auth.html?next=${encodeURIComponent(next)}`);
}

async function authenticatedFetch(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...workspaceRequestHeaders(), ...options.headers },
  });
  if (response.status === 401 && !path.startsWith('/api/auth/')) redirectToAuthentication();
  return response;
}

function formatApiErrorPayload(payload, status) {
  const detail = payload?.detail ?? payload?.message;
  const parts = [];
  if (typeof detail === 'string' && detail.trim()) parts.push(detail.trim());
  else if (Array.isArray(detail)) {
    for (const item of detail.slice(0, 5)) {
      if (typeof item === 'string') parts.push(item);
      else if (item && typeof item === 'object') {
        const location = Array.isArray(item.loc) ? item.loc.filter(value => value !== 'body').join('.') : '';
        parts.push([location, item.msg || item.message].filter(Boolean).join(': ') || JSON.stringify(item));
      }
    }
  } else if (detail && typeof detail === 'object') {
    const message = detail.message || detail.error;
    if (typeof message === 'string' && message.trim()) parts.push(message.trim());
    if (detail.current_revision != null) parts.push(`current revision ${detail.current_revision}`);
    const issueFields = ['errors', 'topology_issues', 'semantic_issues', 'blocking_reasons'];
    const issues = issueFields.flatMap(field => {
      const value = field === 'blocking_reasons' ? detail.readiness?.[field] : detail[field];
      return Array.isArray(value) ? value.filter(item => typeof item === 'string') : [];
    });
    for (const issue of [...new Set(issues)].slice(0, 5)) parts.push(issue);
    if (!parts.length) parts.push(JSON.stringify(detail));
  }
  if (!parts.length) parts.push(`API error ${status}`);
  return parts.join(' · ');
}

async function apiFetch(path, options = {}) {
  const res = await authenticatedFetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...workspaceRequestHeaders(), ...options.headers },
  });
  if (!res.ok) {
    let payload = null;
    try { payload = await res.json(); } catch {}
    const error = new Error(formatApiErrorPayload(payload, res.status));
    error.name = 'ApiError';
    error.status = res.status;
    error.detail = payload?.detail;
    throw error;
  }
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) return res.json();
  if (ct.includes('text/')) return res.text();
  return res;
}

// ── Projects ─────────────────────────────────────────────────────────────────
const API = {
  auth: {
    config: () => apiFetch('/api/auth/config'),
    login: (data) => apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify(data) }),
    register: (data) => apiFetch('/api/auth/register', { method: 'POST', body: JSON.stringify(data) }),
    me: () => apiFetch('/api/auth/me'),
    logout: () => apiFetch('/api/auth/logout', { method: 'POST' }),
  },
  projects: {
    list:   ()           => apiFetch('/api/projects'),
    get:    (id)         => apiFetch(`/api/projects/${id}`),
    create: (data)       => apiFetch('/api/projects', { method: 'POST', body: JSON.stringify(data) }),
    update: (id, data)   => apiFetch(`/api/projects/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id)         => apiFetch(`/api/projects/${id}`, { method: 'DELETE' }),
    exportArchive: (id) => authenticatedFetch(`/api/projects/${encodeURIComponent(id)}/archive`),
    importArchive: async (file) => {
      const form = new FormData();
      form.append('file', file, file.name);
      const response = await authenticatedFetch('/api/projects/import-archive', { method: 'POST', body: form });
      if (!response.ok) {
        let payload = null;
        try { payload = await response.json(); } catch {}
        const error = new Error(formatApiErrorPayload(payload, response.status));
        error.name = 'ApiError';
        error.status = response.status;
        error.detail = payload?.detail;
        throw error;
      }
      return response.json();
    },
    legacyImportStatus: () => apiFetch('/api/projects/legacy-import/status'),
    importLegacy: () => apiFetch('/api/projects/legacy-import', { method: 'POST' }),
  },
  artifacts: {
    upload: (id, data)   => apiFetch(`/api/projects/${id}/artifact`, { method: 'POST', body: JSON.stringify(data) }),
    uploadFile: (id, artifactType, file) => {
      const form = new FormData();
      form.append('artifact_type', artifactType);
      form.append('file', file);
      return authenticatedFetch(`/api/projects/${id}/artifact/file`, { method: 'POST', headers: workspaceRequestHeaders(), body: form })
        .then(async res => {
          if (!res.ok) {
            let payload = null;
            try { payload = await res.json(); } catch {}
            const error = new Error(formatApiErrorPayload(payload, res.status));
            error.name = 'ApiError';
            error.status = res.status;
            error.detail = payload?.detail;
            throw error;
          }
          return res.json();
        });
    },
    policy: () => apiFetch('/api/projects/artifact/policy'),
  },
  analysis: {
    run:     (id, types) => apiFetch(`/api/projects/${id}/analyze`, { method: 'POST', body: JSON.stringify({ analysis_types: types }) }),
    retry:   (id)        => apiFetch(`/api/projects/${id}/analyze/retry`, { method: 'POST' }),
    progress:(id)        => apiFetch(`/api/projects/${id}/analyze/progress`),
    stride:  (id)        => apiFetch(`/api/projects/${id}/analyze/stride`, { method: 'POST' }),
    linddun: (id)        => apiFetch(`/api/projects/${id}/analyze/linddun`, { method: 'POST' }),
    report:  (id)        => apiFetch(`/api/projects/${id}/report`),
    reportRevisions: (id) => apiFetch(`/api/projects/${id}/report/revisions`),
    createReportDraft: (id, data = {}) => apiFetch(`/api/projects/${id}/report/revisions`, { method: 'POST', body: JSON.stringify(data) }),
    signReport: (id, data = {}) => apiFetch(`/api/projects/${id}/report/signoff`, { method: 'POST', body: JSON.stringify(data) }),
    reportRevision: (id, revisionId) => apiFetch(`/api/projects/${id}/report/revisions/${encodeURIComponent(revisionId)}`),
    updateTrustBoundary: (projectId, boundaryId, data) => apiFetch(`/api/projects/${projectId}/trust-boundaries/${boundaryId}`, { method: 'PATCH', body: JSON.stringify(data) }),
    updateThreat: (projectId, threatId, data) => apiFetch(`/api/projects/${projectId}/threats/${threatId}`, { method: 'PATCH', body: JSON.stringify(data) }),
    updateControl: (projectId, controlId, data) => apiFetch(`/api/projects/${projectId}/controls/${controlId}`, { method: 'PATCH', body: JSON.stringify(data) }),
    updateEvidenceItem: (projectId, itemType, itemId, data) => apiFetch(`/api/projects/${projectId}/evidence-items/${encodeURIComponent(itemType)}/${encodeURIComponent(itemId)}`, { method: 'PATCH', body: JSON.stringify(data) }),
    updateDecision: (projectId, decisionId, data) => apiFetch(`/api/projects/${projectId}/decisions/${encodeURIComponent(decisionId)}`, { method: 'PATCH', body: JSON.stringify(data) }),
  },
  dfd: {
    get:  (id) => apiFetch(`/api/projects/${id}/dfd`),
    exportSvg: (id) => authenticatedFetch(`/api/projects/${id}/dfd/export?format=svg`, { headers: workspaceRequestHeaders() }),
    exportJson: (id) => authenticatedFetch(`/api/projects/${id}/dfd/export?format=json`, { headers: workspaceRequestHeaders() }),
    save: (id, model, expectedRevision) => apiFetch(`/api/projects/${id}/dfd`, {
      method: 'PUT',
      body: JSON.stringify({ model, expected_revision: expectedRevision }),
    }),
    applyProposal: (id, data) => apiFetch(`/api/projects/${id}/dfd/proposal/apply`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    dismissProposal: (id, data) => apiFetch(`/api/projects/${id}/dfd/proposal/resolve`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    importJson: (id, data) => apiFetch(`/api/projects/${id}/dfd/import`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
    impactPreview: (id, elementType, elementId) => apiFetch(`/api/projects/${id}/dfd/impact-preview`, {
      method: 'POST',
      body: JSON.stringify({ element_type: elementType, element_id: elementId }),
    }),
  },
  export: {
    get: (id, format, scope = 'visible', revisionId = '') => authenticatedFetch(`/api/projects/${id}/export?format=${format}&scope=${encodeURIComponent(scope)}${revisionId ? `&revision_id=${encodeURIComponent(revisionId)}` : ''}`, { headers: workspaceRequestHeaders() }),
  },
  settings: {
    get:              ()       => apiFetch('/api/settings'),
    update:           (data)   => apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify(data) }),
    addProvider:      (data)   => apiFetch('/api/settings/providers', { method: 'POST', body: JSON.stringify(data) }),
    activateProvider: (id)     => apiFetch(`/api/settings/providers/${id}/activate`, { method: 'PUT' }),
    updateProvider:   (id, data) => apiFetch(`/api/settings/providers/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    deleteProvider:   (id)     => apiFetch(`/api/settings/providers/${id}`, { method: 'DELETE' }),
    checkConnection:  (data)   => apiFetch('/api/settings/check-connection', { method: 'POST', body: JSON.stringify(data) }),
    listModels:       (base_url, api_key = 'ollama', provider_id = '') => apiFetch('/api/settings/list-models', {
      method: 'POST',
      body: JSON.stringify({ base_url, api_key, provider_id }),
    }),
    setActiveSource:  (data)   => apiFetch('/api/settings/active-source', { method: 'PUT', body: JSON.stringify(data) }),
  },
  audit: {
    list: (limit = 100)  => apiFetch(`/api/settings/audit?limit=${limit}`),
  },
};
window.API = API;

// ── URL helpers ───────────────────────────────────────────────────────────────
function getProjectId() {
  if (window.UIState) return window.UIState.read().project || null;
  const params = new URLSearchParams(window.location.search);
  return params.get('id');
}

function setProjectId(id) {
  if (window.UIState) {
    window.UIState.update({ project: String(id || '') });
    return;
  }
  const url = new URL(window.location.href);
  url.searchParams.set('id', id);
  window.history.pushState({}, '', url);
}

function goToAnalysis(projectId) {
  window.location.href = window.UIState ? window.UIState.route('analysis', projectId) : `/analysis.html?id=${encodeURIComponent(projectId)}`;
}

function goToReport(projectId) {
  window.location.href = window.UIState ? window.UIState.route('report', projectId) : `/report.html?id=${encodeURIComponent(projectId)}`;
}

// ── Reversible boundary-driven visibility ───────────────────────────────────
function analysisVisibility(report = {}) {
  const boundaries = (report.trust_boundaries || []).filter(item => item?.boundary_id);
  const activeBoundaryIds = new Set(
    boundaries.filter(item => item.status !== 'Rejected').map(item => String(item.boundary_id))
  );
  const allRejected = boundaries.length > 0 && activeBoundaryIds.size === 0;

  const threats = (report.threats || []).filter(threat => {
    if (!boundaries.length) return true;
    const linked = (threat?.trust_boundary_ids || []).map(String).filter(Boolean);
    // Threats with no boundary dependency are always visible regardless of boundary decisions.
    // Only threats that explicitly depend on a rejected boundary are hidden.
    if (!linked.length) return true;
    if (!linked.some(id => boundaries.some(boundary => String(boundary.boundary_id) === id))) return true;
    return linked.some(id => activeBoundaryIds.has(id));
  });
  const visibleThreatIds = new Set(threats.map(item => String(item.threat_id || '')).filter(Boolean));
  const linkedItemVisible = ids => {
    const links = (ids || []).filter(Boolean).map(String);
    // Unlinked items do not depend on a rejected boundary.
    if (!links.length) return true;
    // Otherwise check against the actual set of visible threats (which already
    // respects same-zone threats surviving boundary rejection).
    return links.some(id => visibleThreatIds.has(id));
  };
  const controls = (report.controls || []).filter(item => linkedItemVisible(item.threat_ids));
  const tests = (report.test_scenarios || []).filter(item => linkedItemVisible([item.threat_id]));
  const assumptions = (report.assumptions || []).filter(item => linkedItemVisible([item.related_threat_id]));
  const missingInfo = (report.missing_info || []).filter(item => linkedItemVisible([item.related_threat_id]));
  const decisions = (report.deferred_decisions || []).filter(item => linkedItemVisible(
    item?.dependency_refs?.threat_ids || item?.linked_refs?.filter(ref => ref?.type === 'threat').map(ref => ref.id)
  ));

  return {
    boundaries,
    activeBoundaryIds,
    allRejected,
    threats,
    controls,
    tests,
    assumptions,
    missingInfo,
    decisions,
    hidden: {
      threats: (report.threats || []).length - threats.length,
      controls: (report.controls || []).length - controls.length,
      tests: (report.test_scenarios || []).length - tests.length,
      assumptions: (report.assumptions || []).length - assumptions.length,
      missingInfo: (report.missing_info || []).length - missingInfo.length,
      decisions: (report.deferred_decisions || []).length - decisions.length,
    },
  };
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function badgeHtml(value, type) {
  const classes = {
    Critical: 'badge-critical',
    High: 'badge-high',
    Medium: 'badge-medium',
    Low: 'badge-low',
    STRIDE: 'badge-stride',
    LINDDUN: 'badge-linddun',
    Open: 'badge-open',
    Mitigated: 'badge-mitigated',
    Reviewed: 'badge-neutral',
    Accepted: 'badge-neutral',
  };
  const cls = classes[value] || 'badge-neutral';
  return `<span class="badge ${cls}">${escHtml(value)}</span>`;
}

function findingStatePresentation(threat = {}) {
  const state = threat.finding_state || threat.finding_status || 'hypothesis';
  const states = {
    grounded: { label: 'Grounded scenario', className: 'badge-mitigated' },
    hypothesis: { label: 'Hypothesis', className: 'badge-neutral' },
    needs_context: { label: 'Needs context', className: 'badge-medium' },
    reviewed: { label: 'Reviewed scenario', className: 'badge-stride' },
    verified: { label: 'Verified with evidence', className: 'badge-mitigated' },
    candidate: { label: 'Hypothesis', className: 'badge-neutral' },
  };
  return { state, ...(states[state] || states.hypothesis) };
}

function findingStateBadgeHtml(threat) {
  const presentation = findingStatePresentation(threat);
  const reason = threat?.grounding_reason || 'Finding grounding has not been evaluated.';
  return `<span class="badge ${presentation.className}" title="${escHtml(reason)}">${escHtml(presentation.label)}</span>`;
}

function findingRiskIsScored(threat = {}) {
  if (threat.risk_methodology_version) {
    return threat.risk_status === 'assessed'
      && ['Critical', 'High', 'Medium', 'Low'].includes(threat.risk_level);
  }
  return threat.finding_state !== 'needs_context'
    && threat.risk_status !== 'deferred'
    && ['Critical', 'High', 'Medium', 'Low'].includes(threat.risk_level);
}

function findingRiskBadgeHtml(threat = {}) {
  if (findingRiskIsScored(threat)) {
    const title = threat.risk_rationale || `${threat.risk_methodology_version || 'Legacy methodology'} risk assessment`;
    return `<span title="${escHtml(title)}">${badgeHtml(threat.risk_level, 'risk')}</span>`;
  }
  const scenarioRisk = threat.scenario_risk_level;
  const label = scenarioRisk
    ? `Final risk deferred · scenario ${scenarioRisk}`
    : 'Risk not assessed';
  return `<span class="badge badge-neutral" title="${escHtml(threat.risk_rationale || 'Risk is not scored until the scenario is grounded or reviewed.')} ">${escHtml(label)}</span>`;
}

function riskAuditHtml(threat = {}, options = {}) {
  const calculation = threat.risk_calculation || {};
  const impact = calculation.impact || {};
  const likelihood = calculation.likelihood || {};
  const factors = [...(impact.factors || []), ...(likelihood.factors || [])];
  const factorRows = factors.map(factor =>
    `<li><strong>${escHtml(factor.name || 'factor')}:</strong> ${escHtml(Array.isArray(factor.value) ? factor.value.join(', ') : factor.value)} · ${escHtml(factor.score)}/5 <span class="text-muted">(${escHtml(factor.source || 'unknown source')})</span></li>`
  ).join('');
  const uncertainties = (calculation.uncertainties || []).map(value => `<li>${escHtml(value)}</li>`).join('');
  const provider = threat.provider_risk_level
    ? `<div><strong>Provider estimate:</strong> ${escHtml(threat.provider_risk_level)} · advisory, not used as final severity</div>`
    : '';
  const override = threat.risk_source === 'reviewer_override'
    ? `<div><strong>Reviewer override:</strong> ${escHtml(threat.risk_override_level)} — ${escHtml(threat.risk_override_reason || 'No reason recorded')}</div>`
    : '';
  const content = `
    <div><strong>Method:</strong> ${escHtml(threat.risk_methodology_version || 'legacy/unversioned')} · ${escHtml(calculation.matrix || 'not calculated')}</div>
    <div><strong>Result:</strong> impact ${escHtml(impact.score ?? '—')}/5 × likelihood ${escHtml(likelihood.score ?? '—')}/5 = ${escHtml(threat.risk_score ?? '—')}/25</div>
    <div><strong>Rationale:</strong> ${escHtml(threat.risk_rationale || calculation.reason || 'Not available')}</div>
    ${provider}${override}
    ${factorRows ? `<ul class="report-checklist">${factorRows}</ul>` : ''}
    ${uncertainties ? `<div><strong>Uncertainty:</strong><ul class="report-checklist">${uncertainties}</ul></div>` : ''}
    <div class="text-xs text-muted">Input fingerprint: ${escHtml(threat.risk_assessment_fingerprint || 'not available')}</div>`;
  if (options.inline) return `<div class="report-audit-inline">${content}</div>`;
  return `<details class="report-row-details risk-audit"><summary>Risk calculation${threat.risk_score ? ` · ${escHtml(threat.risk_score)}/25` : ''}</summary><div tabindex="0">${content}</div></details>`;
}

function confidenceDots(level) {
  const map = { High: 3, Medium: 2, Low: 1 };
  const n = map[level] || 1;
  const cls = level ? level.toLowerCase() : 'low';
  return `<div class="confidence-dots">${[1,2,3].map(i =>
    `<div class="confidence-dot ${i <= n ? cls : ''}"></div>`
  ).join('')}</div>`;
}

function evidencePresentation(threat) {
  const sourceType = ['direct', 'context', 'inference'].includes(threat?.evidence_type)
    ? threat.evidence_type
    : 'inference';
  const evidenceRole = ['scenario', 'context', 'inference'].includes(threat?.evidence_role)
    ? threat.evidence_role
    : ((threat?.scenario_evidence_refs || []).length ? 'scenario' : ((threat?.context_evidence_refs || []).length ? 'context' : sourceType));
  const type = evidenceRole === 'context' ? 'context' : sourceType;
  const meta = {
    direct: {
      label: 'Direct evidence',
      note: 'Verified excerpt from an uploaded artifact',
      className: 'evidence-direct',
    },
    context: {
      label: 'Context signal',
      note: 'Relevant project context; implementation is not yet verified',
      className: 'evidence-context',
    },
    inference: {
      label: 'Framework inference',
      note: 'Analysis hypothesis that requires validation',
      className: 'evidence-inference',
    },
  }[type];
  return {
    ...meta,
    type,
    sourceType,
    evidenceRole,
    source: threat?.evidence_source || (type === 'inference' ? 'Framework analysis' : 'Project context'),
    locator: threat?.evidence_locator || '',
    snippet: threat?.evidence_snippet || 'No supporting signal was captured for this finding.',
    supporting: Array.isArray(threat?.evidence) ? threat.evidence.filter(Boolean).slice(0, 3) : [],
    scenarioRefs: Array.isArray(threat?.scenario_evidence_refs) ? threat.scenario_evidence_refs : [],
    contextRefs: Array.isArray(threat?.context_evidence_refs) ? threat.context_evidence_refs : [],
  };
}

function evidenceBadgeHtml(threat) {
  const evidence = evidencePresentation(threat);
  return `<span class="evidence-kind ${evidence.className}" title="${escHtml(evidence.note)}">${escHtml(evidence.label)}</span>`;
}

function evidenceCardHtml(threat) {
  const evidence = evidencePresentation(threat);
  const supporting = evidence.supporting.filter(item => !String(item).includes(evidence.snippet));
  return `
    <div class="evidence-panel ${evidence.className}">
      <div class="evidence-panel-head">
        ${evidenceBadgeHtml(threat)}
        <span class="evidence-panel-source">${escHtml(evidence.source)}${evidence.locator ? ` · ${escHtml(evidence.locator)}` : ''}</span>
      </div>
      <div class="evidence-panel-snippet">${escHtml(evidence.snippet)}</div>
      <div class="evidence-panel-note">${escHtml(evidence.note)}</div>
      <div class="evidence-panel-note"><strong>Scenario evidence:</strong> ${escHtml(evidence.scenarioRefs.join(', ') || 'None cited')} · <strong>Review context:</strong> ${escHtml(evidence.contextRefs.join(', ') || 'None')}</div>
      ${supporting.length ? `
        <details class="evidence-supporting">
          <summary>${supporting.length} additional signal${supporting.length > 1 ? 's' : ''}</summary>
          <ul>${supporting.map(item => `<li>${escHtml(item)}</li>`).join('')}</ul>
        </details>` : ''}
    </div>`;
}

function evidenceCompactHtml(threat) {
  const evidence = evidencePresentation(threat);
  const needsDetails = evidence.snippet.length > 105 || evidence.locator.length > 72
    || evidence.supporting.length || evidence.scenarioRefs.length || evidence.contextRefs.length;
  return `
    <div class="evidence-compact">
      <div class="evidence-compact-head">${evidenceBadgeHtml(threat)}<span>${escHtml(evidence.source)}</span></div>
      <div class="evidence-compact-text">${escHtml(evidence.snippet)}</div>
      ${evidence.locator ? `<div class="evidence-compact-locator">${escHtml(evidence.locator)}</div>` : ''}
    </div>
    ${needsDetails ? `<details class="report-row-details"><summary>Evidence details</summary><div tabindex="0">
      <p><strong>Full excerpt:</strong> ${escHtml(evidence.snippet)}</p>
      ${evidence.locator ? `<p><strong>Source location:</strong> ${escHtml(evidence.locator)}</p>` : ''}
      ${evidence.scenarioRefs.length ? `<p><strong>Scenario references:</strong> ${escHtml(evidence.scenarioRefs.join(', '))}</p>` : ''}
      ${evidence.contextRefs.length ? `<p><strong>Context references:</strong> ${escHtml(evidence.contextRefs.join(', '))}</p>` : ''}
      ${evidence.supporting.length ? `<p><strong>Additional signals:</strong></p><ul class="report-checklist">${evidence.supporting.map(item => `<li>${escHtml(item)}</li>`).join('')}</ul>` : ''}
    </div></details>` : ''}`;
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function relativeTime(isoStr) {
  if (!isoStr) return '—';
  const date = new Date(isoStr + (isoStr.endsWith('Z') ? '' : 'Z'));
  const diff = (Date.now() - date.getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return date.toLocaleDateString();
}

function showToast(msg, type = 'success') {
  let toast = document.getElementById('tm-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'tm-toast';
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');
    toast.style.cssText = `
      position:fixed;bottom:24px;right:24px;z-index:9999;
      padding:12px 18px;border-radius:8px;font-size:0.845rem;font-weight:500;
      font-family:var(--font);box-shadow:var(--shadow-lg);
      transition:opacity 300ms;max-width:320px;line-height:1.4;
    `;
    document.body.appendChild(toast);
  }
  const colors = {
    success: 'background:#15803D;color:#fff;',
    error:   'background:#DC2626;color:#fff;',
    info:    'background:#1D4ED8;color:#fff;',
    warn:    'background:#D97706;color:#fff;',
  };
  toast.style.cssText += colors[type] || colors.info;
  toast.textContent = msg;
  toast.style.opacity = '1';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, 3200);
}

// ── Tag input helper ──────────────────────────────────────────────────────────
function initTagInput(wrapId, inputId) {
  const wrap = document.getElementById(wrapId);
  const input = document.getElementById(inputId);
  if (!wrap || !input) return;

  const tags = [];

  function addTag(val) {
    const v = val.trim();
    if (!v || tags.includes(v)) return;
    tags.push(v);
    const tag = document.createElement('span');
    tag.className = 'tag-item';
    tag.innerHTML = `${escHtml(v)}<button type="button" aria-label="Remove">×</button>`;
    tag.querySelector('button').onclick = () => {
      const i = tags.indexOf(v);
      if (i > -1) tags.splice(i, 1);
      tag.remove();
    };
    wrap.insertBefore(tag, input);
    input.value = '';
  }

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addTag(input.value);
    }
    if (e.key === 'Backspace' && !input.value && tags.length) {
      const last = wrap.querySelectorAll('.tag-item');
      if (last.length) {
        const lastTag = last[last.length - 1];
        tags.pop();
        lastTag.remove();
      }
    }
  });

  wrap.addEventListener('click', () => input.focus());

  return { getTags: () => [...tags], setTags: (arr) => arr.forEach(addTag) };
}
