/* Anonymous task-completion telemetry. Never send identifiers or user content. */
(function () {
  const endpoint = '/api/ux-telemetry/events';
  const storageKey = '5stones-ux-telemetry';
  const tasks = new Set(['analysis_run', 'finding_review', 'boundary_review', 'dfd_edit', 'report_export', 'evidence_review']);
  const surfaces = new Set(['analysis', 'model', 'findings', 'action-plan', 'evidence', 'report']);
  const phases = new Set(['context', 'model', 'findings', 'action-plan', 'evidence', 'signoff']);
  const outcomes = new Set(['success', 'partial', 'failed']);
  const timers = new Map();

  function enabled() {
    try {
      const preference = localStorage.getItem(storageKey);
      if (preference === 'disabled') return false;
      if (preference === 'enabled') return true;
    } catch (_) { return false; }
    return navigator.doNotTrack !== '1';
  }
  function bucket(ms) {
    if (ms < 5000) return 'lt_5s';
    if (ms < 30000) return '5_30s';
    if (ms < 120000) return '30_120s';
    return 'gt_120s';
  }
  function start(task) {
    if (tasks.has(task)) timers.set(task, Date.now());
  }
  function complete(task, surface, outcome = 'success', metadata = {}) {
    if (!enabled() || !tasks.has(task) || !surfaces.has(surface) || !outcomes.has(outcome)) return;
    const started = timers.get(task);
    timers.delete(task);
    const event = {
      event: 'task.completed', task, surface, outcome,
      ...(phases.has(metadata.phase) ? { phase: metadata.phase } : {}),
      ...(started ? { duration_bucket: bucket(Date.now() - started) } : {}),
      ...(metadata.format && ['markdown', 'csv', 'json'].includes(metadata.format) ? { format: metadata.format } : {}),
    };
    try {
      fetch(endpoint, {
        method: 'POST',
        mode: 'same-origin',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        keepalive: true,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events: [event] }),
      }).catch(() => {});
    } catch (_) { /* telemetry is best-effort and must not affect the task */ }
  }
  function preference() {
    try { return localStorage.getItem(storageKey); } catch (_) { return null; }
  }
  function setEnabled(value) {
    try { localStorage.setItem(storageKey, value ? 'enabled' : 'disabled'); } catch (_) {}
  }
  window.UXTelemetry = { start, complete, enabled, preference, setEnabled };
})();
