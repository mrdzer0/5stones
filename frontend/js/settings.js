/**
 * Settings page — BYOK providers, Local LLM, MCP servers, Audit log
 */
document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  await loadAuditLog();

  document.getElementById('btn-add-provider').addEventListener('click', addProvider);
  document.getElementById('btn-save-local').addEventListener('click', saveLocalLLM);
  document.getElementById('btn-add-mcp').addEventListener('click', addMcpServer);
  document.getElementById('btn-refresh-audit').addEventListener('click', loadAuditLog);

  // Settings nav smooth scroll
  document.querySelectorAll('.settings-nav a').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = document.querySelector(link.getAttribute('href'));
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      document.querySelectorAll('.settings-nav a').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
    });
  });
});

let settings = {};

async function loadSettings() {
  try {
    settings = await API.settings.get();
    renderProviders(settings.providers || []);

    if (settings.local_llm_endpoint) {
      document.getElementById('local-endpoint').value = settings.local_llm_endpoint;
    }
    if (settings.local_llm_model) {
      document.getElementById('local-model').value = settings.local_llm_model;
    }
    renderMcpServers(settings.mcp_servers || []);
  } catch (err) {
    showToast('Could not load settings: ' + err.message, 'error');
  }
}

function renderProviders(providers) {
  const el = document.getElementById('providers-list');
  if (!providers.length) {
    el.innerHTML = `
      <div style="padding:var(--space-5);text-align:center;color:var(--text-muted);font-size:0.845rem;border:1px dashed var(--border);border-radius:var(--r-md);">
        No providers configured. Add your first BYOK provider below.
      </div>`;
    return;
  }

  el.innerHTML = providers.map(p => `
    <div class="provider-card ${p.is_active ? 'active' : ''}" id="provider-${p.provider_id}">
      <div class="provider-indicator"></div>
      <div class="provider-info">
        <div class="provider-name">${escHtml(p.name)}</div>
        <div class="provider-meta">${escHtml(p.model)} · ${escHtml(p.base_url)} · Key: ${escHtml(p.api_key_masked || '****')}</div>
      </div>
      <div style="display:flex;gap:var(--space-2);">
        ${!p.is_active ? `<button class="btn btn-sm btn-secondary" onclick="activateProvider('${p.provider_id}')">Set Active</button>` : `<span class="badge badge-mitigated">Active</span>`}
        <button class="btn btn-sm btn-ghost" onclick="deleteProvider('${p.provider_id}')" title="Remove">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--accent);"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        </button>
      </div>
    </div>
  `).join('');
}

async function addProvider() {
  const name = document.getElementById('p-name').value.trim();
  const type = document.getElementById('p-type').value;
  const baseUrl = document.getElementById('p-base-url').value.trim();
  const model = document.getElementById('p-model').value.trim();
  const maxTokens = parseInt(document.getElementById('p-max-tokens').value) || 4096;
  const apiKey = document.getElementById('p-api-key').value.trim();

  if (!name || !baseUrl || !model || !apiKey) {
    showToast('All required fields must be filled', 'warn');
    return;
  }

  const btn = document.getElementById('btn-add-provider');
  btn.disabled = true;
  btn.innerHTML = '<div class="loading-spinner"></div> Saving…';

  try {
    const provider = await API.settings.addProvider({ name, provider_type: type, base_url: baseUrl, model, max_tokens: maxTokens, api_key: apiKey });
    await loadSettings();

    // Clear form
    document.getElementById('p-name').value = '';
    document.getElementById('p-api-key').value = '';
    document.getElementById('p-model').value = '';

    showToast('Provider added successfully', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add Provider';
  }
}

window.activateProvider = async function(id) {
  try {
    await API.settings.activateProvider(id);
    await loadSettings();
    showToast('Provider activated', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
};

window.deleteProvider = async function(id) {
  if (!confirm('Remove this provider? The API key will be permanently deleted.')) return;
  try {
    await API.settings.deleteProvider(id);
    await loadSettings();
    showToast('Provider removed', 'info');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
};

async function saveLocalLLM() {
  const endpoint = document.getElementById('local-endpoint').value.trim();
  const model = document.getElementById('local-model').value.trim();

  const btn = document.getElementById('btn-save-local');
  btn.disabled = true;
  btn.innerHTML = '<div class="loading-spinner"></div> Saving…';

  try {
    await API.settings.update({ local_llm_endpoint: endpoint, local_llm_model: model });
    showToast('Local LLM config saved', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Local LLM Config';
  }
}

function renderMcpServers(servers) {
  const el = document.getElementById('mcp-servers-list');
  if (!servers.length) {
    el.innerHTML = `
      <div class="empty-state" style="padding:var(--space-8);border:1px dashed var(--border);border-radius:var(--r-lg);">
        <div class="empty-state-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg></div>
        <h3>No MCP servers configured</h3>
        <p>Add an MCP server to pull context from external sources.</p>
      </div>`;
    return;
  }
  el.innerHTML = servers.map(s => `
    <div class="provider-card">
      <div style="width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0;"></div>
      <div class="provider-info">
        <div class="provider-name">${escHtml(s.name)}</div>
        <div class="provider-meta">${escHtml(s.transport)} · ${escHtml(s.command_or_url || '')}</div>
      </div>
    </div>
  `).join('');
}

async function addMcpServer() {
  const name = document.getElementById('mcp-name').value.trim();
  const transport = document.getElementById('mcp-transport').value;
  const command = document.getElementById('mcp-command').value.trim();

  if (!name || !command) { showToast('Server name and command/URL are required', 'warn'); return; }

  const current = settings.mcp_servers || [];
  current.push({ name, transport, command_or_url: command });

  try {
    await API.settings.update({ mcp_servers: current });
    settings.mcp_servers = current;
    renderMcpServers(current);
    document.getElementById('mcp-name').value = '';
    document.getElementById('mcp-command').value = '';
    showToast('MCP server added', 'success');
  } catch (err) {
    showToast('Error: ' + err.message, 'error');
  }
}

async function loadAuditLog() {
  const el = document.getElementById('audit-log-list');
  try {
    const events = await API.audit.list(100);
    if (!events.length) {
      el.innerHTML = `<div style="padding:var(--space-8);text-align:center;color:var(--text-muted);font-size:0.82rem;">No audit events yet.</div>`;
      return;
    }

    const typeColors = {
      'project.created': 'badge-mitigated',
      'project.deleted': 'badge-critical',
      'analysis.started': 'badge-info',
      'analysis.completed': 'badge-mitigated',
      'artifact.upload': 'badge-info',
      'report.exported': 'badge-neutral',
      'settings.provider_added': 'badge-info',
      'settings.provider_activated': 'badge-mitigated',
      'settings.provider_deleted': 'badge-critical',
    };

    el.innerHTML = events.map(e => {
      const ts = new Date(e.timestamp + (e.timestamp?.endsWith('Z') ? '' : 'Z'));
      const detail = Object.entries(e.details || {}).map(([k, v]) => `${k}: ${v}`).join(', ');
      return `
        <div class="audit-item">
          <div class="audit-timestamp">${ts.toLocaleString()}</div>
          <div style="flex:1;">
            <span class="badge ${typeColors[e.event_type] || 'badge-neutral'}" style="margin-right:var(--space-2);">${escHtml(e.event_type)}</span>
            ${detail ? `<span style="font-size:0.78rem;color:var(--text-muted);">${escHtml(detail)}</span>` : ''}
          </div>
        </div>`;
    }).join('');
  } catch (err) {
    el.innerHTML = `<div style="padding:var(--space-4);color:var(--text-muted);font-size:0.82rem;">Could not load audit log: ${escHtml(err.message)}</div>`;
  }
}
