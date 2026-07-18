/**
 * ThreatModelz API Client
 * All backend calls go through this module.
 */

const API_BASE = '';  // Same origin (served by FastAPI)

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    let msg = `API error ${res.status}`;
    try { const data = await res.json(); msg = data.detail || msg; } catch {}
    throw new Error(msg);
  }
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) return res.json();
  if (ct.includes('text/')) return res.text();
  return res;
}

// ── Projects ─────────────────────────────────────────────────────────────────
const API = {
  projects: {
    list:   ()           => apiFetch('/api/projects'),
    get:    (id)         => apiFetch(`/api/projects/${id}`),
    create: (data)       => apiFetch('/api/projects', { method: 'POST', body: JSON.stringify(data) }),
    update: (id, data)   => apiFetch(`/api/projects/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id)         => apiFetch(`/api/projects/${id}`, { method: 'DELETE' }),
  },
  artifacts: {
    upload: (id, data)   => apiFetch(`/api/projects/${id}/artifact`, { method: 'POST', body: JSON.stringify(data) }),
    uploadFile: (id, artifactType, file) => {
      const form = new FormData();
      form.append('artifact_type', artifactType);
      form.append('file', file);
      return fetch(`/api/projects/${id}/artifact/file`, { method: 'POST', body: form })
        .then(async res => {
          if (!res.ok) {
            let msg = `API error ${res.status}`;
            try { const data = await res.json(); msg = data.detail || msg; } catch {}
            throw new Error(msg);
          }
          return res.json();
        });
    },
    policy: () => apiFetch('/api/projects/artifact/policy'),
  },
  analysis: {
    run:     (id, types) => apiFetch(`/api/projects/${id}/analyze`, { method: 'POST', body: JSON.stringify({ analysis_types: types }) }),
    stride:  (id)        => apiFetch(`/api/projects/${id}/analyze/stride`, { method: 'POST' }),
    linddun: (id)        => apiFetch(`/api/projects/${id}/analyze/linddun`, { method: 'POST' }),
    report:  (id)        => apiFetch(`/api/projects/${id}/report`),
    updateThreat: (projectId, threatId, data) => apiFetch(`/api/projects/${projectId}/threats/${threatId}`, { method: 'PATCH', body: JSON.stringify(data) }),
    updateControl: (projectId, controlId, data) => apiFetch(`/api/projects/${projectId}/controls/${controlId}`, { method: 'PATCH', body: JSON.stringify(data) }),
  },
  export: {
    get: (id, format)    => fetch(`/api/projects/${id}/export?format=${format}`),
  },
  settings: {
    get:            ()       => apiFetch('/api/settings'),
    update:         (data)   => apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify(data) }),
    addProvider:    (data)   => apiFetch('/api/settings/providers', { method: 'POST', body: JSON.stringify(data) }),
    activateProvider: (id)   => apiFetch(`/api/settings/providers/${id}/activate`, { method: 'PUT' }),
    deleteProvider: (id)     => apiFetch(`/api/settings/providers/${id}`, { method: 'DELETE' }),
  },
  audit: {
    list: (limit = 100)  => apiFetch(`/api/settings/audit?limit=${limit}`),
  },
};

// ── URL helpers ───────────────────────────────────────────────────────────────
function getProjectId() {
  const params = new URLSearchParams(window.location.search);
  return params.get('id');
}

function setProjectId(id) {
  const url = new URL(window.location.href);
  url.searchParams.set('id', id);
  window.history.pushState({}, '', url);
}

function goToAnalysis(projectId) {
  window.location.href = `/analysis.html?id=${projectId}`;
}

function goToReport(projectId) {
  window.location.href = `/report.html?id=${projectId}`;
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

function confidenceDots(level) {
  const map = { High: 3, Medium: 2, Low: 1 };
  const n = map[level] || 1;
  const cls = level ? level.toLowerCase() : 'low';
  return `<div class="confidence-dots">${[1,2,3].map(i =>
    `<div class="confidence-dot ${i <= n ? cls : ''}"></div>`
  ).join('')}</div>`;
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
