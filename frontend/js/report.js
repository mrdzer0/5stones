/**
 * Report page — full report view with filters and export
 */
let projectId = null;
let currentReport = null;

document.addEventListener('DOMContentLoaded', async () => {
  projectId = getProjectId();
  if (!projectId) { showToast('No project ID', 'error'); return; }

  // Inject project ID into navigation links
  const navAnalysis = document.getElementById('nav-analysis');
  if (navAnalysis) navAnalysis.href = `/analysis.html?id=${projectId}`;
  const btnBack = document.getElementById('btn-back-to-analysis');
  if (btnBack) btnBack.href = `/analysis.html?id=${projectId}`;

  await loadReport();

  document.getElementById('export-md').addEventListener('click', () => exportReport('markdown'));
  document.getElementById('export-csv').addEventListener('click', () => exportReport('csv'));
  document.getElementById('export-json').addEventListener('click', () => exportReport('json'));

  document.getElementById('threat-filter-framework').addEventListener('change', applyFilters);
  document.getElementById('threat-filter-risk').addEventListener('change', applyFilters);
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
      <div class="report-header-meta">Run analysis first to generate a report.</div>`;
  }
}

function renderReport(project, report) {
  const rs = report.risk_summary || {};

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

  renderThreatsTable(report.threats || []);
  renderControlsTable(report.controls || []);
  renderTestsTable(report.test_scenarios || []);
  renderMissingInfo(report.missing_info || []);
  renderAssumptions(report.assumptions || []);
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

function applyFilters() {
  const framework = document.getElementById('threat-filter-framework').value;
  const risk = document.getElementById('threat-filter-risk').value;
  const threats = (currentReport?.threats || []).filter(t =>
    (!framework || t.framework === framework) &&
    (!risk || t.risk_level === risk)
  );
  renderThreatsTable(threats);
}

function renderThreatsTable(threats) {
  const tbody = document.getElementById('threats-tbody');
  if (!threats.length) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align:center;padding:var(--space-8);color:var(--text-muted);">No threats match filters</td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map(t => `
    <tr>
      <td>${badgeHtml(t.framework, 'framework')}</td>
      <td><span style="font-size:0.8rem;font-weight:500;">${escHtml(t.threat_category)}</span></td>
      <td style="max-width:280px;">
        <div style="font-size:0.82rem;color:var(--text);">${escHtml(t.threat_description || '')}</div>
        ${t.abuse_case ? `<div style="font-size:0.75rem;color:var(--text-muted);margin-top:2px;"><em>${escHtml(t.abuse_case)}</em></div>` : ''}
      </td>
      <td><span style="font-size:0.8rem;">${escHtml(t.asset || '—')}</span></td>
      <td><span style="font-size:0.78rem;color:var(--text-muted);">${escHtml(t.trust_boundary || '—')}</span></td>
      <td><span style="font-size:0.78rem;">${escHtml(t.recommended_control || '—')}</span></td>
      <td style="max-width:220px;">
        <div style="font-size:0.76rem;color:var(--text);">${escHtml(t.evidence_source || '—')}</div>
        <div style="font-size:0.72rem;color:var(--text-muted);margin-top:2px;">${escHtml(t.confidence_reason || t.evidence_snippet || '—')}</div>
      </td>
      <td>${confidenceDots(t.confidence)}</td>
      <td>${badgeHtml(t.risk_level, 'risk')}</td>
      <td>${threatStatusSelectHtml(t)}</td>
    </tr>
  `).join('');
}

function threatStatusSelectHtml(t) {
  const statuses = ['Open', 'Needs Info', 'Reviewed', 'Accepted', 'Mitigation Planned', 'Mitigated', 'Verified'];
  return `<select class="form-select" style="height:30px;font-size:0.76rem;min-width:130px;" onchange="updateThreatStatus('${escHtml(t.threat_id)}', this.value)">
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
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:var(--space-6);color:var(--text-muted);">No controls mapped</td></tr>`;
    return;
  }

  const statusColor = { Implemented: 'badge-mitigated', Partial: 'badge-medium', Missing: 'badge-critical', Unknown: 'badge-neutral' };

  tbody.innerHTML = controls.map(c => `
    <tr>
      <td><div style="font-weight:500;font-size:0.845rem;">${escHtml(c.name)}</div></td>
      <td style="max-width:300px;"><span style="font-size:0.8rem;color:var(--text-muted);">${escHtml(c.implementation_guidance || c.description || '—')}</span></td>
      <td style="max-width:280px;">
        <ul style="margin:0;padding-left:16px;font-size:0.76rem;color:var(--text-muted);">
          ${(c.checklist_items || []).slice(0, 3).map(item => `<li>${escHtml(item)}</li>`).join('') || '<li>Confirm implementation evidence.</li>'}
        </ul>
        ${c.verification_method ? `<div style="font-size:0.72rem;color:var(--green);margin-top:4px;">${escHtml(c.verification_method)}</div>` : ''}
      </td>
      <td><span class="badge ${statusColor[c.status] || 'badge-neutral'}">${escHtml(c.review_status || c.status)}</span></td>
      <td><span style="font-size:0.78rem;color:var(--text-muted);">${escHtml(c.evidence || '—')}</span></td>
      <td><span style="font-size:0.82rem;">${escHtml(c.owner || '—')}</span></td>
    </tr>
  `).join('');
}

function renderTestsTable(tests) {
  const tbody = document.getElementById('tests-tbody');
  if (!tests.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:var(--space-6);color:var(--text-muted);">No test scenarios</td></tr>`;
    return;
  }

  tbody.innerHTML = tests.map(t => `
    <tr>
      <td><span class="mono text-xs" style="color:var(--text-faint);">${escHtml(t.test_id || '')}</span></td>
      <td><div style="font-weight:500;font-size:0.845rem;">${escHtml(t.scenario_name || '')}</div></td>
      <td style="max-width:220px;">
        <ol style="padding-left:16px;margin:0;font-size:0.78rem;color:var(--text-muted);">
          ${(t.steps || []).slice(0, 3).map(s => `<li>${escHtml(s)}</li>`).join('')}
          ${(t.steps || []).length > 3 ? `<li><em>+${t.steps.length - 3} more…</em></li>` : ''}
        </ol>
      </td>
      <td><span style="font-size:0.8rem;">${escHtml(t.expected_result || '—')}</span></td>
      <td>${badgeHtml(t.priority, 'risk')}</td>
      <td><span style="font-size:0.82rem;">${escHtml(t.owner || '—')}</span></td>
    </tr>
  `).join('');
}

function renderMissingInfo(items) {
  const el = document.getElementById('missing-info-list');
  if (!items.length) {
    el.innerHTML = `<div style="padding:var(--space-4);text-align:center;color:var(--text-muted);font-size:0.82rem;">No missing information identified</div>`;
    return;
  }
  el.innerHTML = items.map(m => `
      <div style="border-bottom:1px solid var(--border);padding:var(--space-3) 0;">
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
    el.innerHTML = `<div style="padding:var(--space-4);text-align:center;color:var(--text-muted);font-size:0.82rem;">No assumptions recorded</div>`;
    return;
  }
  el.innerHTML = items.map(a => `
    <div style="border-bottom:1px solid var(--border);padding:var(--space-4) 0;">
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
