/* Shared filter drawer/sheet behavior for Findings, Action Plan, and Evidence. */
(function () {
  const registry = new Map();

  function capture(dialog) {
    return [...dialog.querySelectorAll('input, select, textarea')]
      .filter(element => !element.matches('[data-filter-search], [data-filter-apply], [data-filter-cancel], [type="button"]'))
      .map(element => ({
        id: element.id,
        type: element.type,
        value: element.value,
        checked: element.checked,
        values: element.matches('select[multiple]') ? [...element.selectedOptions].map(option => option.value) : undefined,
      }));
  }

  function restore(dialog, snapshot) {
    (snapshot || []).forEach(item => {
      const element = document.getElementById(item.id);
      if (!element) return;
      if (element.type === 'checkbox' || element.type === 'radio') element.checked = Boolean(item.checked);
      else if (element.matches('select[multiple]')) [...element.options].forEach(option => { option.selected = item.values.includes(option.value); });
      else element.value = item.value;
    });
  }

  function filterOptions(dialog, query) {
    const normalized = String(query || '').trim().toLowerCase();
    dialog.querySelectorAll('[data-filter-option]').forEach(option => {
      const visible = !normalized || option.textContent.toLowerCase().includes(normalized);
      option.hidden = !visible;
    });
  }

  function updateSelectionStatus(dialog) {
    const count = dialog.querySelectorAll('[data-filter-group] input[type="checkbox"]:checked').length;
    const status = dialog.querySelector('[data-filter-selection-status]');
    if (status) status.textContent = `${count} selected`;
  }

  function close(entry, reason = 'cancel') {
    if (!entry.dialog.open) return;
    if (reason !== 'apply') restore(entry.dialog, entry.snapshot);
    entry.snapshot = null;
    if (typeof entry.onClose === 'function') entry.onClose(reason);
    entry.dialog.close(reason);
  }

  function open(entry) {
    if (entry.dialog.open) return;
    entry.snapshot = capture(entry.dialog);
    entry.dialog.showModal();
    entry.trigger.setAttribute('aria-expanded', 'true');
    filterOptions(entry.dialog, '');
    const focusTarget = document.getElementById(entry.dialog.dataset.filterInitialFocus || '');
    (focusTarget || entry.dialog.querySelector('[data-filter-apply]') || entry.dialog).focus();
  }

  function register(dialog) {
    const name = dialog.dataset.workspaceFilterDialog;
    const trigger = document.getElementById(dialog.dataset.filterTrigger);
    if (!name || !trigger || registry.has(name)) return;
    const entry = {name, dialog, trigger, callbacks: [], snapshot: null};
    registry.set(name, entry);
    trigger.addEventListener('click', () => open(entry));
    dialog.querySelector('[data-filter-cancel]')?.addEventListener('click', () => close(entry));
    dialog.querySelector('[data-filter-apply]')?.addEventListener('click', () => {
      entry.callbacks.forEach(callback => callback());
      close(entry, 'apply');
    });
    dialog.querySelector('[data-filter-search]')?.addEventListener('input', event => filterOptions(dialog, event.target.value));
    dialog.querySelector('[data-filter-select-all]')?.addEventListener('click', () => {
      dialog.querySelectorAll('[data-filter-option]:not([hidden]) input[type="checkbox"]').forEach(input => { input.checked = true; });
      updateSelectionStatus(dialog);
    });
    dialog.querySelector('[data-filter-clear-all]')?.addEventListener('click', () => {
      dialog.querySelectorAll('[data-filter-group] input[type="checkbox"]').forEach(input => { input.checked = false; });
      updateSelectionStatus(dialog);
    });
    dialog.addEventListener('change', () => updateSelectionStatus(dialog));
    dialog.addEventListener('keydown', event => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      close(entry);
    });
    dialog.addEventListener('cancel', event => { event.preventDefault(); close(entry); });
    dialog.addEventListener('close', () => {
      trigger.setAttribute('aria-expanded', 'false');
      trigger.focus({preventScroll: true});
    });
    trigger.setAttribute('aria-haspopup', 'dialog');
    trigger.setAttribute('aria-expanded', 'false');
    updateSelectionStatus(dialog);
  }

  function boot() {
    document.querySelectorAll('[data-workspace-filter-dialog]').forEach(register);
  }

  function entryFor(name) { return registry.get(name); }

  window.WorkspaceFilters = {
    boot,
    bindApply(name, callback) { entryFor(name)?.callbacks.push(callback); },
    close(name, reason = 'cancel') { const entry = entryFor(name); if (entry) close(entry, reason); },
    isOpen(name) { return Boolean(entryFor(name)?.dialog.open); },
    values(id) {
      const group = document.getElementById(id);
      if (!group) return [];
      const checks = [...group.querySelectorAll('input[type="checkbox"]:checked')];
      if (checks.length || group.querySelector('input[type="checkbox"]')) return checks.map(input => input.value);
      return [...group.selectedOptions].map(option => option.value);
    },
    setValues(id, values) {
      const group = document.getElementById(id);
      if (!group) return false;
      const selected = new Set(values || []);
      const checks = group.querySelectorAll('input[type="checkbox"]');
      if (checks.length) checks.forEach(input => { input.checked = selected.has(input.value); });
      else [...group.options].forEach(option => { option.selected = selected.has(option.value); });
      return true;
    },
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, {once: true});
  else boot();
})();
