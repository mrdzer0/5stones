/* Shared keyboard and mobile-sheet focus contract for workspace inspectors (U4/U7). */
(function () {
  const focusableSelector = [
    'a[href]', 'area[href]', 'button:not([disabled])', 'input:not([disabled])',
    'select:not([disabled])', 'textarea:not([disabled])', 'iframe', 'object', 'embed',
    '[contenteditable]', '[tabindex]:not([tabindex="-1"])',
  ].join(',');

  const focusables = panel => [...panel.querySelectorAll(focusableSelector)].filter(element => {
    const style = window.getComputedStyle(element);
    return !element.hidden && !element.closest('[inert]') && style.display !== 'none' && style.visibility !== 'hidden';
  });

  function setBackgroundInert(panel, enabled) {
    if (enabled) {
      const restore = [];
      let child = panel;
      while (child && child.parentElement) {
        const parent = child.parentElement;
        [...parent.children].filter(sibling => sibling !== child && !sibling.contains(panel)).forEach(sibling => {
          restore.push({ element: sibling, inert: sibling.inert, ariaHidden: sibling.getAttribute('aria-hidden') });
          sibling.inert = true;
          sibling.setAttribute('aria-hidden', 'true');
        });
        child = parent;
        if (parent === document.body) break;
      }
      panel.__uxRestore = restore;
    } else {
      (panel.__uxRestore || []).forEach(({ element, inert, ariaHidden }) => {
        element.inert = inert;
        if (ariaHidden === null) element.removeAttribute('aria-hidden');
        else element.setAttribute('aria-hidden', ariaHidden);
      });
      delete panel.__uxRestore;
    }
  }

  function configure(panel, returnTo) {
    const mobile = window.matchMedia('(max-width: 820px)').matches;
    const wasModal = panel.dataset.uxModal === 'true';
    const heading = panel.querySelector('h2, h1, [role="heading"]');
    if (heading && !heading.id) heading.id = `${panel.id || 'workspace-inspector'}-title`;
    panel.setAttribute('role', mobile ? 'dialog' : 'region');
    if (heading?.id) panel.setAttribute('aria-labelledby', heading.id);
    if (mobile) {
      panel.setAttribute('aria-modal', 'true');
      panel.dataset.uxModal = 'true';
      if (!wasModal) setBackgroundInert(panel, true);
    } else {
      if (wasModal) setBackgroundInert(panel, false);
      panel.removeAttribute('aria-modal');
      delete panel.dataset.uxModal;
    }
    panel.__uxReturnTo = returnTo || panel.__uxReturnTo || null;
    const close = panel.querySelector('button[aria-label*="Close" i]');
    if (close) close.focus({ preventScroll: true });
    else {
      panel.setAttribute('tabindex', '-1');
      panel.focus({ preventScroll: true });
    }
  }

  function open(panel, returnTo) {
    if (!panel) return;
    const alreadyOpen = panel.dataset.uxOpen === 'true';
    if (!alreadyOpen) panel.__uxReturnTo = returnTo || document.activeElement;
    panel.dataset.uxOpen = 'true';
    configure(panel, panel.__uxReturnTo);
  }

  function close(panel, returnTo) {
    if (!panel) return;
    setBackgroundInert(panel, false);
    panel.removeAttribute('aria-modal');
    panel.setAttribute('role', 'region');
    delete panel.dataset.uxModal;
    delete panel.dataset.uxOpen;
    const target = returnTo || panel.__uxReturnTo;
    delete panel.__uxReturnTo;
    if (target && document.contains(target) && !target.disabled) target.focus({ preventScroll: true });
  }

  document.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const panel = [...document.querySelectorAll('[data-ux-modal="true"]')].find(item => item.dataset.uxOpen === 'true');
    if (!panel) return;
    const items = focusables(panel);
    if (!items.length) {
      event.preventDefault();
      panel.focus({ preventScroll: true });
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (!panel.contains(document.activeElement)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus({ preventScroll: true });
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus({ preventScroll: true });
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus({ preventScroll: true });
    }
  }, true);

  window.UXFocus = { open, close, configure };
})();
