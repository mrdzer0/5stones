/**
 * Report page — full report view with filters and export
 */
let projectId = null;
let currentReport = null;
let reportSearchQuery = '';

document.addEventListener('DOMContentLoaded', async () => {
  projectId = getProjectId();
  if (!projectId) { showToast('No project ID', 'error'); return; }

  // Inject project ID into navigation links
  const navAnalysis = document.getElementById('nav-analysis');
  if (navAnalysis) navAnalysis.href = `/analysis.html?id=${projectId}`;
  const navReport = document.getElementById('nav-report');
  if (navReport) navReport.href = `/report.html?id=${projectId}`;
  const btnBack = document.getElementById('btn-back-to-analysis');
  if (btnBack) btnBack.href = `/analysis.html?id=${projectId}`;

  await loadReport();

  document.getElementById('export-md').addEventListener('click', () => exportReport('markdown'));
  document.getElementById('export-csv').addEventListener('click', () => exportReport('csv'));
  document.getElementById('export-json').addEventListener('click', () => exportReport('json'));

  document.getElementById('threat-filter-framework').addEventListener('change', renderFilteredReport);
  document.getElementById('threat-filter-risk').addEventListener('change', renderFilteredReport);
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
  setupReportNavigation();
  if (window.location.hash) {
    window.setTimeout(() => {
      const target = document.querySelector(window.location.hash);
      target?.scrollIntoView();
      if (target) {
        document.querySelectorAll('.report-toc a').forEach(link => {
          link.classList.toggle('active', link.dataset.reportSection === target.id);
        });
      }
    }, 350);
  }
});

async function loadReport() {
  try {
    const [project, report] = await Promise.all([
      API.projects.get(projectId),
      API.analysis.report(projectId),
    ]);
    currentReport = report;
    document.getElementById('report-page-title').textContent = project.name + ' — Report';
    renderReport(project, report);
  } catch (err) {
    showToast('Could not load report: ' + err.message, 'error');
    document.getElementById('report-header').innerHTML = `
      <div class="report-header-title">Report not available</div>
      <div class="report-header-meta">Complete the analysis stages before preparing a report.</div>`;
  }
}

function renderReport(project, report) {
  const visibleThreats = analysisVisibility(report).threats;
  const rs = {
    critical: visibleThreats.filter(item => item.risk_level === 'Critical').length,
    high: visibleThreats.filter(item => item.risk_level === 'High').length,
    medium: visibleThreats.filter(item => item.risk_level === 'Medium').length,
    low: visibleThreats.filter(item => item.risk_level === 'Low').length,
  };

  document.getElementById('report-title').textContent = project.name + ' — Threat Model Report';
  document.getElementById('report-generated').textContent = 'Generated: ' + (report.generated_at ? new Date(report.generated_at + 'Z').toLocaleString() : '—');
  document.getElementById('report-env').textContent = project.environment || 'No environment set';

  document.getElementById('rp-critical').textContent = rs.critical || 0;
  document.getElementById('rp-high').textContent = rs.high || 0;
  document.getElementById('rp-medium').textContent = rs.medium || 0;
  document.getElementById('rp-low').textContent = rs.low || 0;
  renderCompleteness(report.completeness?.score !== undefined ? report.completeness : (project.completeness || {
    score: project.completeness_score || 0,
    level: project.completeness_level || 'Not scored',
  }));

  renderFilteredReport();
}

function renderCompleteness(completeness) {
  const header = document.getElementById('report-header');
  if (!header || document.getElementById('report-readiness')) return;
  const score = completeness.score || 0;
  const color = score >= 85 ? 'var(--green)' : score >= 65 ? 'var(--orange)' : 'var(--accent)';
  const el = document.createElement('div');
  el.id = 'report-readiness';
  el.style.cssText = 'margin-top:var(--space-4);max-width:520px;';
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
      <span style="font-size:0.78rem;color:var(--text-muted);font-weight:600;">Threat Model Readiness</span>
      <span style="font-size:0.78rem;color:var(--text-muted);">${score}/100 — ${escHtml(completeness.level || 'Not scored')}</span>
    </div>
    <div style="height:8px;background:rgba(255,255,255,0.22);border-radius:999px;overflow:hidden;">
      <div style="height:100%;width:${Math.max(0, Math.min(100, score))}%;background:${color};"></div>
    </div>
    <div style="margin-top:6px;font-size:0.74rem;color:var(--text-muted);">
      ${completeness.artifact_count || 0} artifacts${(completeness.artifact_types || []).length ? ` · ${(completeness.artifact_types || []).map(escHtml).join(', ')}` : ''}
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

  renderTrustBoundariesReport(boundaries, visibility);
  renderThreatsTable(threats);
  renderControlsTable(controls);
  renderTestsTable(tests);
  renderMissingInfo(gaps);
  renderAssumptions(assumptions);
  updateReportNavigationCounts({ boundaries, threats, controls, tests, gaps, assumptions });
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
    : `${totals.boundaries} boundaries · ${totals.threats} visible threats · ${totals.controls} controls · ${totals.tests} tests · ${totals.gaps + totals.assumptions} review notes${visibility.hidden.threats ? ` · ${visibility.hidden.threats} threats hidden by boundary review` : ''}`;
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
      <div class="report-finding-description">${escHtml(boundary.basis || 'No evidence basis recorded.')}</div>
      ${boundary.review_note ? `<div class="trust-report-note"><strong>Review note:</strong> ${escHtml(boundary.review_note)}</div>` : ''}
      <details class="report-row-details"><summary>${(boundary.evidence_refs || []).length} supporting references</summary><div><ul class="report-checklist">${(boundary.evidence_refs || []).map(ref => `<li>${escHtml(ref)}</li>`).join('') || '<li>No supporting reference recorded.</li>'}</ul></div></details>
    </article>
  `).join('')}`;
}

function setupReportNavigation() {
  const links = [...document.querySelectorAll('.report-toc a[data-report-section]')];
  const sections = links.map(link => document.getElementById(link.dataset.reportSection)).filter(Boolean);
  links.forEach(link => link.addEventListener('click', () => {
    links.forEach(item => item.classList.toggle('active', item === link));
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

function renderThreatsTable(threats) {
  const tbody = document.getElementById('threats-tbody');
  if (!threats.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.threats > 0;
    tbody.innerHTML = `<tr><td colspan="5"><div class="report-empty">${hidden ? 'Threat findings are hidden by the rejected boundary. Restore it to Candidate or Confirmed to show them again.' : 'No threats match the current search and filters.'}</div></td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map((t, index) => `
    <tr id="${reportRowId('threat', t.threat_id, index)}">
      <td data-label="Finding">
        <div class="report-finding-head">
          <div class="report-finding-badges">${badgeHtml(t.framework, 'framework')}<span class="mono text-xs report-case-id" title="${escHtml(t.threat_id || '')}">${escHtml(shortReportCaseId(t.threat_id, 'T', index))}</span></div>
          <div class="report-finding-title">${escHtml(t.threat_category || 'Uncategorized threat')}</div>
          <div class="report-finding-description">${escHtml(t.threat_description || 'No description provided.')}</div>
        </div>
      </td>
      <td data-label="Context">
        <div class="report-cell-stack">
          <div><div class="report-cell-label">Asset</div><div class="report-cell-value">${escHtml(t.asset || '—')}</div></div>
          <div><div class="report-cell-label">Boundary</div><div class="report-cell-value">${escHtml(t.trust_boundary || '—')}</div></div>
          <div><div class="report-cell-label">Model targets</div>${reportTargetRefsHtml(t)}</div>
        </div>
      </td>
      <td data-label="Evidence">${evidenceCompactHtml(t)}</td>
      <td data-label="Risk">
        <div class="report-cell-stack">${badgeHtml(t.risk_level, 'risk')}<div>${confidenceDots(t.confidence)} <span class="text-xs text-muted">${escHtml(t.confidence || 'Unknown')}</span></div></div>
      </td>
      <td data-label="Review">
        <div class="report-review-cell">
          ${threatStatusSelectHtml(t)}
          <details class="report-row-details"><summary>Control &amp; scenario details</summary><div>
            <p><strong>Recommended control:</strong> ${escHtml(t.recommended_control || 'Not mapped')}</p>
            ${t.abuse_case ? `<p><strong>Abuse case:</strong> ${escHtml(t.abuse_case)}</p>` : ''}
            ${t.framework === 'LINDDUN' && t.privacy_context_status ? `<p><strong>Privacy context:</strong> ${escHtml(t.privacy_context_status)}${t.privacy_context_missing?.length ? ` · missing ${escHtml(t.privacy_context_missing.join(', '))}` : ''}</p>` : ''}
            ${t.confidence_reason ? `<p><strong>Confidence:</strong> ${escHtml(t.confidence_reason)}</p>` : ''}
          </div></details>
        </div>
      </td>
    </tr>
  `).join('');
}

function reportTargetRefsHtml(item) {
  const refs = (item?.target_refs || []).filter(ref => ref?.id);
  if (!refs.length) return '<div class="report-target-empty">Unmapped — requires triage</div>';
  const priority = { scenario: 0, service: 1, context: 2, asset: 3 };
  const sorted = [...refs].sort((a, b) => (priority[a.model_level] ?? 9) - (priority[b.model_level] ?? 9));
  const visible = sorted.slice(0, 4);
  const typeLabel = { external_entity: 'Entity', external_system: 'External', process: 'Process', data_store: 'Store', data_flow: 'Flow', trust_boundary: 'Boundary', scenario: 'Scenario', data_asset: 'Data' };
  return `<div class="report-target-list">${visible.map(ref => `
    <span class="report-target-chip" title="${escHtml(`${ref.model_level || 'model'} · ${ref.id}`)}"><b>${escHtml(typeLabel[ref.type] || ref.type)}</b>${escHtml(ref.label || ref.id)}</span>`).join('')}
    ${refs.length > visible.length ? `<span class="report-target-more">+${refs.length - visible.length} targets</span>` : ''}
  </div>`;
}

function reportRowId(prefix, value, index) {
  const safe = String(value || index + 1).replace(/[^a-zA-Z0-9_-]+/g, '-');
  return `${prefix}-${safe}`;
}

function shortReportCaseId(value, prefix, index) {
  const id = String(value || '').trim();
  if (!id) return `${prefix}-${index + 1}`;
  if (/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(id)) return `${prefix}-${id.slice(0, 8).toUpperCase()}`;
  return id.length > 18 ? `${id.slice(0, 15)}…` : id;
}

function threatStatusSelectHtml(t) {
  const statuses = ['Open', 'Needs Info', 'Reviewed', 'Accepted', 'Mitigation Planned', 'Mitigated', 'Verified'];
  return `<select class="form-select report-status-select" aria-label="Review status for ${escHtml(t.threat_category || 'threat')}" onchange="updateThreatStatus('${escHtml(t.threat_id)}', this.value)">
    ${statuses.map(s => `<option value="${s}" ${t.status === s ? 'selected' : ''}>${s}</option>`).join('')}
  </select>`;
}

window.updateThreatStatus = async function(threatId, status) {
  try {
    await API.analysis.updateThreat(projectId, threatId, { status });
    const threat = (currentReport?.threats || []).find(t => t.threat_id === threatId);
    if (threat) threat.status = status;
    showToast('Threat status updated', 'success');
  } catch (err) {
    showToast('Could not update status: ' + err.message, 'error');
  }
};

function renderControlsTable(controls) {
  const tbody = document.getElementById('controls-tbody');
  if (!controls.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.controls > 0;
    tbody.innerHTML = `<tr><td colspan="4"><div class="report-empty">${hidden ? 'Control mappings are hidden by the rejected boundary.' : 'No controls match the current search.'}</div></td></tr>`;
    return;
  }

  const statusColor = { Implemented: 'badge-mitigated', Partial: 'badge-medium', Missing: 'badge-critical', Unknown: 'badge-neutral' };

  tbody.innerHTML = controls.map((c, index) => `
    <tr id="${reportRowId('control', c.control_id || c.name, index)}">
      <td data-label="Control">
        <div class="report-cell-stack"><div class="report-finding-title">${escHtml(c.name || 'Unnamed control')}</div><span class="badge ${statusColor[c.implementation_status || c.status] || 'badge-neutral'}">${escHtml(c.review_status || c.implementation_status || c.status || 'Unknown')}</span><div class="text-xs text-muted">${escHtml(c.control_origin || 'recommended')} · state ${escHtml(c.implementation_state || 'unknown')} · ${c.location_ref?.id ? `location ${escHtml(c.location_ref.id)}` : 'location unknown'}</div></div>
      </td>
      <td data-label="Implementation"><div class="report-cell-value">${escHtml(c.implementation_guidance || c.description || '—')}</div></td>
      <td data-label="Verification">
        <ul class="report-checklist">${(c.checklist_items || []).slice(0, 3).map(item => `<li>${escHtml(item)}</li>`).join('') || '<li>Confirm implementation evidence.</li>'}</ul>
        <details class="report-row-details"><summary>Evidence &amp; verification method</summary><div>
          <p><strong>Evidence:</strong> ${escHtml(c.evidence || 'Not provided')}</p>
          <p><strong>Verify with:</strong> ${escHtml(c.verification_method || 'Manual implementation review')}</p>
          <p><strong>DFD targets:</strong> ${escHtml((c.target_refs || []).map(ref => ref.id).join(', ') || 'Unknown')}</p>
          <p><strong>Verification evidence refs:</strong> ${escHtml((c.verification_evidence_refs || []).join(', ') || 'None recorded')}</p>
          <p><strong>Implementation evidence requested:</strong> ${escHtml((c.implementation_evidence_requested || []).join('; ') || 'Not specified')}</p>
          <p><strong>Implementation evidence refs:</strong> ${escHtml((c.implementation_evidence_refs || []).join(', ') || 'None recorded')}</p>
          <p><strong>Runtime verification refs:</strong> ${escHtml((c.runtime_verification_refs || []).join(', ') || 'None recorded')}</p>
        </div></details>
      </td>
      <td data-label="Owner"><div class="report-cell-value">${escHtml(c.owner || 'Unassigned')}</div></td>
    </tr>
  `).join('');
}

function renderTestsTable(tests) {
  const tbody = document.getElementById('tests-tbody');
  if (!tests.length) {
    const hidden = !reportSearchQuery && analysisVisibility(currentReport).hidden.tests > 0;
    tbody.innerHTML = `<tr><td colspan="4"><div class="report-empty">${hidden ? 'Test cases are hidden by the rejected boundary.' : 'No test cases match the current search.'}</div></td></tr>`;
    return;
  }

  tbody.innerHTML = tests.map((t, index) => `
    <tr id="${reportRowId('test', t.test_id, index)}">
      <td data-label="Test case">
        <div class="report-cell-stack"><span class="mono text-xs report-case-id" title="${escHtml(t.test_id || '')}">${escHtml(shortReportCaseId(t.test_id, 'TM', index))}</span><div class="report-finding-title">${escHtml(t.scenario_name || 'Unnamed test scenario')}</div></div>
      </td>
      <td data-label="Steps">
        <ol class="report-checklist">${(t.steps || []).slice(0, 2).map(step => `<li>${escHtml(step)}</li>`).join('') || '<li>Define executable validation steps.</li>'}</ol>
        ${(t.steps || []).length > 2 ? `<details class="report-row-details"><summary>Show ${t.steps.length - 2} more steps</summary><div><ol class="report-checklist">${t.steps.slice(2).map(step => `<li>${escHtml(step)}</li>`).join('')}</ol></div></details>` : ''}
      </td>
      <td data-label="Expected result"><div class="report-cell-value">${escHtml(t.expected_result || '—')}</div></td>
      <td data-label="Priority & owner"><div class="report-cell-stack">${badgeHtml(t.priority || 'Unprioritized', 'risk')}<div class="report-cell-value">${escHtml(t.owner || 'Unassigned')}</div></div></td>
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
      <div style="font-size:0.82rem;color:var(--text-2);margin-top:2px;">${escHtml(m.question_to_ask || m.question)}</div>
      <div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;font-style:italic;">${escHtml(m.why_it_matters)}</div>
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
          <div style="font-size:0.82rem;color:var(--text-2);">${escHtml(a.assumption)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:var(--space-2);">
          ${confidenceDots(a.confidence)}
          <span style="font-size:0.72rem;color:var(--text-faint);">${escHtml(a.confidence)}</span>
        </div>
      </div>
      ${a.evidence ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:8px;"><strong>Evidence:</strong> ${escHtml(a.evidence)}</div>` : ''}
      ${a.impact_if_wrong ? `<div style="font-size:0.75rem;color:var(--orange);margin-top:6px;"><strong>Impact if wrong:</strong> ${escHtml(a.impact_if_wrong)}</div>` : ''}
      ${a.verification_question ? `<div style="font-size:0.75rem;color:var(--text-2);margin-top:6px;"><strong>Ask dev:</strong> ${escHtml(a.verification_question)}</div>` : ''}
      ${a.recommended_validation ? `<div style="font-size:0.75rem;color:var(--green);margin-top:6px;"><strong>Validate:</strong> ${escHtml(a.recommended_validation)}</div>` : ''}
      ${a.related_threat ? `<div style="font-size:0.72rem;color:var(--text-faint);margin-top:6px;"><strong>Related threat:</strong> ${escHtml(a.related_threat)}</div>` : ''}
    </div>
  `).join('');
}

async function exportReport(format) {
  try {
    const res = await API.export.get(projectId, format);
    if (format === 'json') {
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      downloadBlob(blob, `threat-model-${projectId}.json`);
    } else {
      const text = await res.text();
      const type = format === 'csv' ? 'text/csv' : 'text/markdown';
      const ext = format === 'csv' ? 'csv' : 'md';
      const blob = new Blob([text], { type });
      downloadBlob(blob, `threat-model-${projectId}.${ext}`);
    }
    showToast(`Exported as ${format.toUpperCase()}`, 'success');
  } catch (err) {
    showToast('Export failed: ' + err.message, 'error');
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
