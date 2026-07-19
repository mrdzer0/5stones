/**
 * Settings page — BYOK providers, Local LLM, Audit log
 */

// Provider type presets
const PROVIDER_PRESETS = {
  openai:     { url: 'https://api.openai.com/v1',                                  placeholder: 'sk-…',    hint: 'OpenAI API key. Get one at platform.openai.com.' },
  gemini:     { url: 'https://generativelanguage.googleapis.com/v1beta/openai/',    placeholder: 'AIza…',  hint: 'Google AI Studio API key. Get one at aistudio.google.com.' },
  openrouter: { url: 'https://openrouter.ai/api/v1',                               placeholder: 'sk-or-…', hint: 'OpenRouter API key. Get one at openrouter.ai.' },
  azure:      { url: 'https://<resource>.openai.azure.com/openai/deployments/<dep>', placeholder: 'sk-…',  hint: 'Azure OpenAI key. Replace <resource> and <dep> in the URL.' },
  custom:     { url: '',                                                             placeholder: 'key…',   hint: 'Custom endpoint compatible with the OpenAI chat completions API.' },
};

document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  await loadAuditLog();

  document.getElementById('btn-add-provider').addEventListener('click', addProvider);
  document.getElementById('btn-check-provider').addEventListener('click', checkProviderConnection);
  document.getElementById('btn-save-local').addEventListener('click', saveLocalLLM);
  document.getElementById('btn-check-local').addEventListener('click', checkLocalConnection);
  document.getElementById('btn-refresh-audit').addEventListener('click', loadAuditLog);

  // Provider type → auto-fill URL
  document.getElementById('p-type').addEventListener('change', onProviderTypeChange);

  // API key entered → auto-fetch model list
  document.getElementById('p-api-key').addEventListener('change', fetchAndShowProviderModels);
  document.getElementById('p-api-key').addEventListener('blur',   fetchAndShowProviderModels);

  // Auto-fetch model list when Local LLM endpoint changes
  document.getElementById('local-endpoint').addEventListener('change', fetchAndShowLocalModels);
  document.getElementById('local-endpoint').addEventListener('blur',   fetchAndShowLocalModels);

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
    renderActiveBanner(settings);

    if (settings.local_llm_endpoint) {
      document.getElementById('local-endpoint').value = settings.local_llm_endpoint;
      // Auto-fetch models if endpoint already saved
      fetchAndShowLocalModels();
    }
    if (settings.local_llm_model) {
      document.getElementById('local-model').value = settings.local_llm_model;
    }
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

// ── Active Source Banner ───────────────────────────────────────────────────────
function renderActiveBanner(cfg) {
  const label  = document.getElementById('active-source-label');
  const banner = document.getElementById('active-provider-banner');
  const btnByok  = document.getElementById('btn-use-byok');
  const btnLocal = document.getElementById('btn-use-local');
  if (!label) return;

  const source = cfg.active_source || 'none';
  const hasLocal     = !!(cfg.local_llm_endpoint && cfg.local_llm_model);
  const hasProviders = (cfg.providers || []).length > 0;

  const sourceInfo = {
    byok:  { icon: '🌐', text: 'Cloud Provider (BYOK)', color: '#2563EB', border: '#2563EB' },
    local: { icon: '💻', text: 'Local LLM', color: 'var(--green)', border: 'var(--green)' },
    none:  { icon: '⚠️', text: 'Not configured — using fallback templates', color: 'var(--orange)', border: 'var(--orange)' },
  };
  const info = sourceInfo[source] || sourceInfo.none;

  label.innerHTML = `<span style="font-size:1.1em;">${info.icon}</span><span style="color:${info.color};">${info.text}</span>`;
  banner.style.borderColor = info.border;

  // Highlight active button
  btnByok.className  = source === 'byok'  ? 'btn btn-primary' : 'btn btn-secondary';
  btnLocal.className = source === 'local' ? 'btn btn-primary' : 'btn btn-secondary';

  // Disable unavailable options
  btnByok.disabled  = !hasProviders;
  btnLocal.disabled = !hasLocal;
  btnByok.title  = hasProviders ? 'Use BYOK Cloud Provider for analysis'  : 'Add a BYOK provider first';
  btnLocal.title = hasLocal     ? 'Use Local LLM for analysis'             : 'Configure Local LLM first';
}

window.switchActiveSource = async function(source) {
  try {
    const data = { source };
    if (source === 'byok' && settings.active_provider_id) {
      data.provider_id = settings.active_provider_id;
    }
    await API.settings.setActiveSource(data);
    await loadSettings();
    const label = source === 'byok' ? 'Cloud Provider (BYOK)' : 'Local LLM';
    showToast(`🔄 Switched to ${label}`, 'success');
  } catch (err) {
    showToast('Could not switch: ' + err.message, 'error');
  }
};

// ── Provider type preset handler ──────────────────────────────────────────────
function onProviderTypeChange() {
  const type = document.getElementById('p-type').value;
  const preset = PROVIDER_PRESETS[type] || PROVIDER_PRESETS.custom;
  const urlEl = document.getElementById('p-base-url');
  const keyEl = document.getElementById('p-api-key');
  const hintEl = document.getElementById('p-url-hint');

  if (preset.url) urlEl.value = preset.url;
  keyEl.placeholder = preset.placeholder;
  hintEl.textContent = preset.hint;

  // Clear model picker when type changes
  hideModelPicker();
  document.getElementById('p-model').value = '';
  hideConnResult('provider-conn-result');
}

// ── Auto-fetch models for BYOK provider ───────────────────────────────────────
async function fetchAndShowProviderModels() {
  const baseUrl = document.getElementById('p-base-url').value.trim();
  const apiKey  = document.getElementById('p-api-key').value.trim();
  if (!baseUrl || !apiKey) return;

  const picker = document.getElementById('p-model-picker');
  picker.style.display = 'block';
  picker.innerHTML = `
    <div style="padding:var(--space-3) var(--space-4);background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);font-size:0.82rem;color:var(--text-muted);display:flex;align-items:center;gap:var(--space-2);">
      <div class="loading-spinner" style="width:14px;height:14px;"></div> Fetching available models…
    </div>`;

  try {
    const res = await API.settings.listModels(baseUrl, apiKey);
    if (res.ok && res.models && res.models.length > 0) {
      const currentModel = document.getElementById('p-model').value.trim();
      picker.innerHTML = `
        <div style="padding:var(--space-3) var(--space-4);background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);font-size:0.82rem;">
          <div style="font-weight:600;margin-bottom:var(--space-2);color:var(--text);">📡 Available models — click to select:</div>
          <div style="display:flex;flex-wrap:wrap;gap:var(--space-2);">
            ${res.models.map(m => `
              <button
                class="btn btn-sm ${m === currentModel ? 'btn-primary' : 'btn-secondary'}"
                onclick="selectProviderModel('${escHtml(m)}')"
                title="${escHtml(m)}"
              >${escHtml(m.length > 40 ? m.slice(0, 38) + '…' : m)}</button>
            `).join('')}
          </div>
        </div>`;
    } else if (res.ok) {
      picker.innerHTML = `<div style="padding:var(--space-2) var(--space-3);font-size:0.82rem;color:var(--text-muted);">No models returned. Enter model name manually.</div>`;
    } else {
      // API key may be wrong
      picker.style.display = 'none';
    }
  } catch {
    picker.style.display = 'none';
  }
}

window.selectProviderModel = function(modelId) {
  document.getElementById('p-model').value = modelId;
  // Highlight selected
  document.querySelectorAll('#p-model-picker button').forEach(btn => {
    btn.className = btn.title === modelId ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-secondary';
  });
};

function hideModelPicker() {
  const picker = document.getElementById('p-model-picker');
  if (picker) { picker.style.display = 'none'; picker.innerHTML = ''; }
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
    await API.settings.addProvider({ name, provider_type: type, base_url: baseUrl, model, max_tokens: maxTokens, api_key: apiKey });
    await loadSettings();

    // Clear form
    document.getElementById('p-name').value = '';
    document.getElementById('p-api-key').value = '';
    document.getElementById('p-model').value = '';
    hideModelPicker();
    hideConnResult('provider-conn-result');

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

// ── Check Connection — AI Provider form ───────────────────────────────────────
async function checkProviderConnection() {
  const baseUrl = document.getElementById('p-base-url').value.trim();
  const model   = document.getElementById('p-model').value.trim();
  const apiKey  = document.getElementById('p-api-key').value.trim();

  if (!baseUrl || !model || !apiKey) {
    showToast('Base URL, Model, and API Key are required to test connection', 'warn');
    return;
  }

  const btn = document.getElementById('btn-check-provider');
  btn.disabled = true;
  btn.innerHTML = '<div class="loading-spinner"></div> Testing…';
  hideConnResult('provider-conn-result');

  try {
    const result = await API.settings.checkConnection({ base_url: baseUrl, model, api_key: apiKey });
    showConnResult('provider-conn-result', result);
  } catch (err) {
    showConnResult('provider-conn-result', { ok: false, error: err.message, latency_ms: 0 });
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Check Connection';
  }
}

// ── Local LLM save ────────────────────────────────────────────────────────────
async function saveLocalLLM() {
  const endpoint = document.getElementById('local-endpoint').value.trim();
  const model    = document.getElementById('local-model').value.trim();

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

// ── Check Connection — Local LLM ──────────────────────────────────────────────
async function checkLocalConnection() {
  const endpoint = document.getElementById('local-endpoint').value.trim();
  const model    = document.getElementById('local-model').value.trim();

  if (!endpoint || !model) {
    showToast('Endpoint and Model are required to test connection', 'warn');
    return;
  }

  const btn = document.getElementById('btn-check-local');
  btn.disabled = true;
  btn.innerHTML = '<div class="loading-spinner"></div> Testing…';
  hideConnResult('local-conn-result');

  try {
    const result = await API.settings.checkConnection({ base_url: endpoint, model, api_key: 'ollama' });
    showConnResult('local-conn-result', result);
  } catch (err) {
    showConnResult('local-conn-result', { ok: false, error: err.message, latency_ms: 0 });
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Check Connection';
  }
}

// Auto-fetch available models from local LLM endpoint
async function fetchAndShowLocalModels() {
  const endpoint = document.getElementById('local-endpoint').value.trim();
  if (!endpoint) return;

  const resultEl = document.getElementById('local-conn-result');
  resultEl.style.display = 'block';
  resultEl.innerHTML = `
    <div style="padding:var(--space-3) var(--space-4);background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);font-size:0.82rem;color:var(--text-muted);display:flex;align-items:center;gap:var(--space-2);">
      <div class="loading-spinner" style="width:14px;height:14px;"></div> Fetching available models…
    </div>`;

  try {
    const res = await API.settings.listModels(endpoint);
    if (res.ok && res.models.length > 0) {
      const modelInput = document.getElementById('local-model');
      const currentModel = modelInput.value.trim();
      const modelMatch = currentModel && res.models.includes(currentModel);

      resultEl.innerHTML = `
        <div style="padding:var(--space-3) var(--space-4);background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);font-size:0.82rem;">
          <div style="font-weight:600;margin-bottom:var(--space-2);color:var(--text);">📡 Models available at this endpoint:</div>
          <div style="display:flex;flex-wrap:wrap;gap:var(--space-2);">
            ${res.models.map(m => `
              <button
                class="btn btn-sm ${m === currentModel ? 'btn-primary' : 'btn-secondary'}"
                onclick="document.getElementById('local-model').value='${escHtml(m)}'"
                title="Click to use this model"
              >${escHtml(m)}</button>
            `).join('')}
          </div>
          ${!modelMatch && currentModel ? `<div style="margin-top:var(--space-2);color:var(--orange);font-size:0.8rem;">⚠️ Current model "${escHtml(currentModel)}" not found in list above.</div>` : ''}
        </div>`;
    } else if (res.ok && res.models.length === 0) {
      resultEl.innerHTML = `
        <div style="padding:var(--space-3) var(--space-4);background:rgba(217,119,6,0.10);border:1px solid rgba(217,119,6,0.35);border-radius:var(--r-md);font-size:0.82rem;color:var(--orange);">
          ⚠️ Server reachable but <strong>no models are loaded</strong>. Load a model in LM Studio → Developer tab first.
        </div>`;
    } else {
      resultEl.innerHTML = '';
      resultEl.style.display = 'none';
    }
  } catch {
    resultEl.innerHTML = '';
    resultEl.style.display = 'none';
  }
}

// ── Connection result helpers ─────────────────────────────────────────────────
function showConnResult(elementId, result) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const modelsHtml = (result.available_models && result.available_models.length)
    ? `<div style="margin-top:var(--space-2);font-size:0.8rem;color:var(--text-muted);">Available models: ${result.available_models.map(m => `<code style="background:var(--surface-3);padding:1px 6px;border-radius:4px;font-size:0.78rem;">${escHtml(m)}</code>`).join(' ')}</div>`
    : '';

  if (result.ok) {
    el.innerHTML = `
      <div style="
        display:flex;align-items:flex-start;gap:var(--space-3);
        padding:var(--space-3) var(--space-4);
        background:rgba(21,128,61,0.12);
        border:1px solid rgba(21,128,61,0.35);
        border-radius:var(--r-md);
        font-size:0.845rem;
      ">
        <svg viewBox="0 0 24 24" fill="none" stroke="#15803D" stroke-width="2.5" style="width:18px;height:18px;flex-shrink:0;margin-top:1px;">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <div>
          <span style="color:#15803D;font-weight:600;">Connected</span>
          <span style="color:var(--text-muted);margin-left:var(--space-2);">Model: <strong>${escHtml(result.model || '—')}</strong> &nbsp;·&nbsp; Latency: <strong>${result.latency_ms}ms</strong></span>
          ${modelsHtml}
        </div>
      </div>`;
  } else {
    const hintHtml = result.hint
      ? `<div style="margin-top:var(--space-2);padding:var(--space-2) var(--space-3);background:rgba(217,119,6,0.12);border-radius:var(--r-sm);color:var(--orange);font-size:0.8rem;">💡 ${escHtml(result.hint)}</div>`
      : '';
    el.innerHTML = `
      <div style="
        display:flex;align-items:flex-start;gap:var(--space-3);
        padding:var(--space-3) var(--space-4);
        background:rgba(220,38,38,0.10);
        border:1px solid rgba(220,38,38,0.35);
        border-radius:var(--r-md);
        font-size:0.845rem;
      ">
        <svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2.5" style="width:18px;height:18px;flex-shrink:0;margin-top:1px;">
          <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <div style="flex:1;">
          <span style="color:#DC2626;font-weight:600;">Connection failed</span>
          ${result.latency_ms ? `<span style="color:var(--text-muted);margin-left:var(--space-2);">(${result.latency_ms}ms)</span>` : ''}
          <div style="color:var(--text-muted);margin-top:2px;word-break:break-word;">${escHtml(result.error || 'Unknown error')}</div>
          ${hintHtml}
          ${modelsHtml}
        </div>
      </div>`;
  }

  el.style.display = 'block';
}

function hideConnResult(elementId) {
  const el = document.getElementById(elementId);
  if (el) { el.style.display = 'none'; el.innerHTML = ''; }
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
async function loadAuditLog() {
  const el = document.getElementById('audit-log-list');
  try {
    const events = await API.audit.list(100);
    if (!events.length) {
      el.innerHTML = `<div style="padding:var(--space-8);text-align:center;color:var(--text-muted);font-size:0.82rem;">No audit events yet.</div>`;
      return;
    }

    const typeColors = {
      'project.created':            'badge-mitigated',
      'project.deleted':            'badge-critical',
      'analysis.started':           'badge-info',
      'analysis.completed':         'badge-mitigated',
      'artifact.upload':            'badge-info',
      'report.exported':            'badge-neutral',
      'settings.provider_added':    'badge-info',
      'settings.provider_activated':'badge-mitigated',
      'settings.provider_deleted':  'badge-critical',
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
