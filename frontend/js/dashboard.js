/**
 * Dashboard — project list, stats, search
 */
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('project-archive-import').addEventListener('click', () => {
    document.getElementById('project-archive-input').click();
  });
  document.getElementById('project-archive-input').addEventListener('change', importProjectArchive);
  await loadDashboard();
  await loadLegacyImportStatus();

  document.getElementById('search-input').addEventListener('input', (e) => {
    filterProjects(e.target.value.toLowerCase());
  });
});

let allProjects = [];

async function loadDashboard() {
  try {
    allProjects = await API.projects.list();
    renderStats(allProjects);
    renderProjects(allProjects);
  } catch (err) {
    document.getElementById('projects-container').innerHTML =
      `<div class="alert alert-danger"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg><div>Could not load projects. Make sure the backend is running on port 8000.<br><small>${escHtml(err.message)}</small></div></div>`;
  }
}

function renderStats(projects) {
  let critical = 0, high = 0, open = 0;
  for (const p of projects) {
    const rs = p.risk_summary || {};
    critical += rs.critical || 0;
    high += rs.high || 0;
    open += (rs.total || 0);
  }
  document.getElementById('stat-total').textContent = projects.length;
  document.getElementById('stat-critical').textContent = critical;
  document.getElementById('stat-high').textContent = high;
  document.getElementById('stat-open').textContent = open;
}

function renderProjects(projects) {
  const container = document.getElementById('projects-container');

  if (!projects.length) {
    container.innerHTML = `
      <div class="empty-state" style="padding:var(--space-12);">
        <div class="empty-state-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <h3>No projects yet</h3>
        <p>Create your first threat model to get started with security analysis.</p>
        <a href="/project-new.html" class="btn btn-primary">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Create First Project
        </a>
      </div>`;
    return;
  }

  container.innerHTML = `<div class="project-grid" id="projects-grid">${projects.map(projectCardHtml).join('')}</div>`;
}

function projectCardHtml(p) {
  const rs = p.risk_summary || {};
  const hasReport = p.has_report || rs.total > 0;

  const riskPills = hasReport ? `
    <div class="project-risk-pills">
      ${rs.critical ? `<span class="risk-pill badge-critical">${rs.critical} Critical</span>` : ''}
      ${rs.high ? `<span class="risk-pill badge-high">${rs.high} High</span>` : ''}
      ${rs.medium ? `<span class="risk-pill badge-medium">${rs.medium} Medium</span>` : ''}
      ${rs.low ? `<span class="risk-pill badge-low">${rs.low} Low</span>` : ''}
      ${rs.needs_context_total ? `<span class="risk-pill badge-neutral">${rs.needs_context_total} risk deferred</span>` : ''}
    </div>` : `<div class="text-sm text-muted">No analysis yet</div>`;

  const status = p.signoff_ready === true
    ? `<span class="badge badge-mitigated">Sign-off ready</span>`
    : hasReport
      ? `<span class="badge badge-medium">Review required</span>`
      : `<span class="badge badge-neutral">Pending</span>`;

  const href = window.UIState
    ? window.UIState.route(hasReport ? 'report' : 'analysis', p.project_id)
    : `${hasReport ? '/report.html' : '/analysis.html'}?id=${encodeURIComponent(p.project_id)}`;
  const readiness = Number.isFinite(p.completeness_score) ? p.completeness_score : (p.completeness_score || 0);

  return `
  <div class="project-card" data-name="${escHtml(p.name?.toLowerCase())}" style="display:flex;flex-direction:column;cursor:default;">
    <a href="${href}" style="display:contents;text-decoration:none;color:inherit;">
      <div class="project-card-header">
        <div class="project-card-name">${escHtml(p.name)}</div>
        ${status}
      </div>
      ${p.description ? `<div class="project-card-desc">${escHtml(p.description)}</div>` : ''}
      <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-3);">
        <div style="height:6px;background:var(--surface-3);border-radius:999px;overflow:hidden;flex:1;">
          <div style="height:100%;width:${Math.max(0, Math.min(100, readiness))}%;background:${readiness >= 85 ? 'var(--green)' : readiness >= 65 ? 'var(--orange)' : 'var(--accent)'};"></div>
        </div>
        <span class="text-xs text-muted" title="Input context completeness">Input ${readiness}/100</span>
      </div>
      ${riskPills}
      <div class="project-card-meta">
        <span>${p.environment ? escHtml(p.environment) : 'No env set'}</span>
        <span>${relativeTime(p.updated_at)}</span>
      </div>
    </a>
    <div class="project-card-actions">
      <a href="${href}" class="btn btn-secondary btn-sm" style="flex:1;justify-content:center;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        View
      </a>
      <button type="button" class="btn btn-secondary btn-sm" onclick="exportProjectArchive('${escHtml(p.project_id)}')" title="Export this project and its report history">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 4v12m0 0 5-5m-5 5-5-5"/><path d="M5 16v3a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-3"/></svg>
        Export
      </button>
      <button
        class="btn btn-ghost btn-sm btn-delete"
        onclick="deleteProject('${p.project_id}', '${escHtml(p.name).replace(/'/g, "&apos;")}')"
        title="Delete project"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        Delete
      </button>
    </div>
  </div>`;
}

function filterProjects(query) {
  const filtered = query
    ? allProjects.filter(p => (p.name || '').toLowerCase().includes(query) || (p.description || '').toLowerCase().includes(query))
    : allProjects;
  renderProjects(filtered);
}

window.deleteProject = async function(projectId, projectName) {
  const confirmed = confirm(`Delete "${projectName}"?\n\nThis will permanently remove the project and all its analysis reports. This action cannot be undone.`);
  if (!confirmed) return;

  try {
    await API.projects.delete(projectId);
    showToast(`Project "${projectName}" deleted`, 'info');
    await loadDashboard();
  } catch (err) {
    showToast('Failed to delete project: ' + err.message, 'error');
  }
};

window.exportProjectArchive = async function(projectId) {
  try {
    const response = await API.projects.exportArchive(projectId);
    if (!response.ok) {
      let detail = `API error ${response.status}`;
      try {
        const payload = await response.json();
        const value = payload?.detail;
        detail = typeof value === 'string' ? value : (value?.message || detail);
      } catch {}
      throw new Error(detail);
    }
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || `5stones-project-${projectId}.zip`;
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    showToast('Project archive downloaded', 'info');
  } catch (err) {
    showToast(`Could not export project archive: ${err.message}`, 'error');
  }
};

async function importProjectArchive(event) {
  const input = event.currentTarget;
  const file = input.files?.[0];
  input.value = '';
  if (!file) return;
  try {
    const result = await API.projects.importArchive(file);
    await loadDashboard();
    showToast(`Imported "${result.project?.name || 'project'}" with its report history`, 'info');
  } catch (err) {
    showToast(`Could not import project archive: ${err.message}`, 'error');
  }
}

async function loadLegacyImportStatus() {
  const notice = document.getElementById('legacy-import-notice');
  notice.hidden = true;
  try {
    const status = await API.projects.legacyImportStatus();
    if (!status.available || !status.legacy_project_count) return;
    notice.innerHTML = `
      <div class="legacy-import-copy">
        <strong>Previous local projects are available</strong>
        <span>${status.legacy_project_count} project(s) have no account owner yet. Recovery assigns them to this account and keeps them private from other accounts.</span>
      </div>
      <button type="button" class="btn btn-secondary btn-sm" onclick="recoverLegacyProjects(${Number(status.legacy_project_count)})">Recover previous data</button>`;
    notice.hidden = false;
  } catch {
    // This action is intentionally hidden from non-admin and multi-account setups.
  }
}

window.recoverLegacyProjects = async function(projectCount) {
  const confirmed = confirm(
    `Assign ${projectCount} previous local project(s) to this account?\n\nOnly this account will be able to read them. A local backup is created before ownership metadata changes.`
  );
  if (!confirmed) return;
  try {
    const result = await API.projects.importLegacy();
    await loadDashboard();
    await loadLegacyImportStatus();
    showToast(`Recovered ${result.imported_count} previous project(s)`, 'info');
  } catch (err) {
    showToast(`Could not recover previous data: ${err.message}`, 'error');
  }
};
