/** Canonical global/project navigation plus shared sidebar behavior. */
try { history.scrollRestoration = 'manual'; } catch (_) {}
document.addEventListener('DOMContentLoaded', () => {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;
  renderCanonicalSidebar(sidebar);
  initializeLocalAuthSidebar(sidebar);
  installProjectWorkflowNavigation();
  const resetRouteScroll = () => window.requestAnimationFrame(() => {
    if (window.scrollY > 0) window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  });
  resetRouteScroll();
  window.addEventListener('load', resetRouteScroll, { once: true });
  // A few legacy routes finish their own async bootstrap during the same
  // lifecycle. Re-check after load so the shared navigator cannot disappear
  // or be skipped because the topbar was not ready on the first pass.
  window.addEventListener('load', installProjectWorkflowNavigation, { once: true });
  const topbarLeft = document.querySelector('.topbar-left');
  if (!sidebar || !topbarLeft) return;

  const desktopQuery = window.matchMedia('(min-width: 901px)');
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'sidebar-toggle';
  toggle.id = 'sidebar-toggle';
  toggle.setAttribute('aria-controls', 'app-sidebar');
  toggle.setAttribute('aria-label', 'Hide sidebar');
  toggle.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
      <rect x="3" y="4" width="18" height="16" rx="2"></rect>
      <path d="M9 4v16"></path>
      <path class="sidebar-toggle-chevron" d="m15 9-3 3 3 3"></path>
    </svg>`;

  sidebar.id = 'app-sidebar';
  sidebar.setAttribute('aria-label', 'Primary navigation');
  topbarLeft.prepend(toggle);

  const sidebarFocusable = () => [...sidebar.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])')];
  const closeMobile = (returnFocus = true) => {
    document.body.classList.remove('sidebar-mobile-open');
    syncState();
    if (returnFocus) toggle.focus({ preventScroll: true });
  };

  for (const link of sidebar.querySelectorAll('.sidebar-nav a')) {
    link.title = link.textContent.trim();
  }

  const syncState = () => {
    const isDesktop = desktopQuery.matches;
    const isOpen = isDesktop
      ? !document.body.classList.contains('sidebar-collapsed')
      : document.body.classList.contains('sidebar-mobile-open');
    toggle.setAttribute('aria-expanded', String(isOpen));
    toggle.setAttribute('aria-label', isOpen ? 'Hide sidebar' : 'Show sidebar');
    // A translated-offscreen mobile drawer must not remain in the tab order.
    // `inert` keeps keyboard and assistive-technology focus aligned with the
    // visual state while preserving the drawer navigation when it is opened.
    sidebar.inert = !isDesktop && !isOpen;
    sidebar.setAttribute('aria-hidden', String(!isDesktop && !isOpen));
  };

  if (desktopQuery.matches && localStorage.getItem('5stones-sidebar') === 'collapsed') {
    document.body.classList.add('sidebar-collapsed');
  }

  toggle.addEventListener('click', () => {
    if (desktopQuery.matches) {
      document.body.classList.toggle('sidebar-collapsed');
      localStorage.setItem(
        '5stones-sidebar',
        document.body.classList.contains('sidebar-collapsed') ? 'collapsed' : 'expanded'
      );
    } else {
      document.body.classList.toggle('sidebar-mobile-open');
    }
    syncState();
    if (!desktopQuery.matches && document.body.classList.contains('sidebar-mobile-open')) {
      sidebarFocusable()[0]?.focus({ preventScroll: true });
    }
  });

  document.addEventListener('click', (event) => {
    if (!desktopQuery.matches && document.body.classList.contains('sidebar-mobile-open')) {
      if (!sidebar.contains(event.target) && !toggle.contains(event.target)) {
        closeMobile();
      }
    }
  });

  document.addEventListener('keydown', (event) => {
    if (desktopQuery.matches || !document.body.classList.contains('sidebar-mobile-open')) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      closeMobile();
      return;
    }
    if (event.key === 'Tab') {
      const items = sidebarFocusable();
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus({ preventScroll: true });
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      } else if (!sidebar.contains(document.activeElement)) {
        event.preventDefault();
        first.focus({ preventScroll: true });
      }
    }
  });

  desktopQuery.addEventListener('change', () => {
    document.body.classList.remove('sidebar-mobile-open');
    syncState();
  });

  syncState();
});

function renderCanonicalSidebar(sidebar) {
  const page = document.body.dataset.page || location.pathname.split('/').pop().replace(/\.html$/, '') || 'index';
  const projectPages = new Set(['analysis', 'model', 'findings', 'action-plan', 'evidence', 'report']);
  const isProjectPage = projectPages.has(page);
  const activeId = {
    index: 'nav-dashboard',
    'project-new': 'nav-new',
    settings: 'nav-settings',
    analysis: 'nav-analysis',
    model: 'nav-model',
    findings: 'nav-findings',
    'action-plan': 'nav-action-plan',
    evidence: 'nav-evidence',
    report: 'nav-report',
  }[page];
  const icons = {
    dashboard: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    new: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>',
    overview: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
    model: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="8" y="15" width="8" height="6"/><path d="M10 6h4m-7 4 4 5m6-5-4 5"/>',
    findings: '<path d="M4 5h16M4 12h16M4 19h10"/><circle cx="18" cy="19" r="2"/>',
    action: '<path d="M5 5h14M5 12h14M5 19h8"/><path d="m16 17 2 2 4-4"/>',
    evidence: '<path d="M6 3h9l3 3v15H6z"/><path d="M15 3v4h4M9 12h6M9 16h6"/>',
    report: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M8 13h8M8 17h6"/>',
    settings: '<circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/>',
  };
  const item = ({id, href, label, icon}) => `<li><a href="${href}" id="${id}"${id === activeId ? ' class="active" aria-current="page"' : ''}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">${icons[icon]}</svg>${label}</a></li>`;
  const globalItems = [
    {id: 'nav-dashboard', href: '/index.html', label: 'Dashboard', icon: 'dashboard'},
    {id: 'nav-new', href: '/project-new.html', label: 'New project', icon: 'new'},
  ];
  const settingsItems = [{id: 'nav-settings', href: '/settings.html', label: 'Settings & BYOK', icon: 'settings'}];
  const section = (label, items) => `<div class="sidebar-section"><div class="sidebar-section-label">${label}</div><ul class="sidebar-nav">${items.map(item).join('')}</ul></div>`;
  sidebar.innerHTML = `<div class="sidebar-logo"><a href="/index.html"><img src="/static/logo.png" alt="5STONES" class="sidebar-logo-img" /><span class="sidebar-logo-badge">MVP</span></a></div>${section('Workspace', globalItems)}${section('Configuration', settingsItems)}<div class="sidebar-footer">5STONES v1.0 · Structured Threat Modeling</div>`;
}

async function initializeLocalAuthSidebar(sidebar) {
  if (!window.API?.auth) return;
  try {
    const config = await window.API.auth.config();
    if (config.auth_mode !== 'local_users') return;
    const footer = sidebar.querySelector('.sidebar-footer');
    if (!footer) return;
    const account = document.createElement('div');
    account.className = 'sidebar-auth-account';
    account.hidden = true;
    account.innerHTML = '<span class="sidebar-auth-user"></span><button type="button" class="btn btn-ghost btn-sm sidebar-auth-logout">Sign out</button>';
    footer.prepend(account);
    const identity = await window.API.auth.me();
    account.querySelector('.sidebar-auth-user').textContent = identity.user.display_name || identity.user.email || 'Local account';
    account.hidden = false;
    account.querySelector('.sidebar-auth-logout').addEventListener('click', async event => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await window.API.auth.logout();
        window.location.assign('/auth.html');
      } catch (_) {
        button.disabled = false;
        button.textContent = 'Retry sign out';
      }
    });
  } catch (error) {
    if (error.status === 401 && document.body.dataset.page !== 'auth') {
      const next = `${location.pathname}${location.search}${location.hash}`;
      location.assign(`/auth.html?next=${encodeURIComponent(next)}`);
    }
  }
}

function installProjectWorkflowNavigation() {
  const page = document.body.dataset.page || location.pathname.split('/').pop().replace(/\.html$/, '');
  const pages = [
    {page: 'analysis', id: 'nav-analysis', label: 'Overview', short: 'Overview'},
    {page: 'model', id: 'nav-model', label: 'DFD model', short: 'Model'},
    {page: 'findings', id: 'nav-findings', label: 'Findings', short: 'Findings'},
    {page: 'action-plan', id: 'nav-action-plan', label: 'Action plan', short: 'Actions'},
    {page: 'evidence', id: 'nav-evidence', label: 'Evidence', short: 'Evidence'},
    {page: 'report', id: 'nav-report', label: 'Report & sign-off', short: 'Report'},
  ];
  if (!pages.some(item => item.page === page)) return;
  if (document.getElementById('project-workflow-nav')) return;
  const topbar = document.querySelector('.topbar');
  if (!topbar) return;
  const link = item => `<a class="project-workflow-link${item.page === page ? ' active' : ''}" id="${item.id}" data-workflow-page="${item.page}" href="/${item.page}.html"${item.page === page ? ' aria-current="step"' : ''}><span class="project-workflow-index" aria-hidden="true">${pages.indexOf(item) + 1}</span><span class="project-workflow-copy"><span>${item.label}</span><small class="project-workflow-state" data-workflow-state="${item.page}">—</small></span></a>`;
  const nav = document.createElement('nav');
  nav.className = 'project-workflow-nav';
  nav.id = 'project-workflow-nav';
  nav.setAttribute('aria-label', 'Project workflow');
  nav.innerHTML = `<div class="project-workflow-links">${pages.map(link).join('')}</div><label class="project-workflow-mobile"><span>Current stage</span><select id="project-workflow-stage" aria-label="Change project workflow stage">${pages.map(item => `<option value="${item.page}"${item.page === page ? ' selected' : ''}>${pages.indexOf(item) + 1} of ${pages.length} · ${item.short}</option>`).join('')}</select></label>`;
  topbar.insertAdjacentElement('afterend', nav);

  const routeTo = targetPage => {
    const state = window.UIState?.read?.() || {};
    const project = state.project || new URLSearchParams(location.search).get('id') || '';
    if (!project || !window.UIState?.route) return `/${targetPage}.html${location.search}`;
    const phase = targetPage === 'analysis' ? '' : targetPage === 'report' ? 'signoff' : targetPage;
    const view = targetPage === 'model' ? 'diagram' : '';
    return window.UIState.route(targetPage, project, {...state, phase, view});
  };
  nav.querySelectorAll('[data-workflow-page]').forEach(anchor => {
    anchor.addEventListener('click', () => { anchor.href = routeTo(anchor.dataset.workflowPage); });
  });
  nav.querySelector('#project-workflow-stage')?.addEventListener('change', event => {
    window.location.assign(routeTo(event.target.value));
  });
  hydrateProjectWorkflowState(nav, pages, page);
}

function hydrateProjectWorkflowState(nav, pages, currentPage) {
  const project = window.UIState?.read?.().project || new URLSearchParams(location.search).get('id') || '';
  if (!project || !window.API?.projects?.get) return;
  const stageStatus = (state, ids) => {
    const records = (state?.stages || []).filter(item => ids.includes(item.id));
    if (!records.length) return state?.result_state === 'not_started' ? 'Not started' : '—';
    if (records.some(item => item.status === 'running' || item.state === 'active')) return 'Running';
    if (records.some(item => ['failed', 'blocked'].includes(item.status))) return 'Blocked';
    if (records.some(item => ['fallback', 'partial', 'stale'].includes(item.status))) return 'Needs review';
    if (records.every(item => item.status === 'completed')) return 'Completed';
    return 'Needs review';
  };
  const pageStatus = (state, page) => {
    if (!state || state.result_state === 'not_started') return 'Not started';
    if (page === 'analysis') return state.status_label || 'Needs review';
    if (page === 'model') return stageStatus(state, ['trust_boundary']);
    if (page === 'findings') return stageStatus(state, ['stride', 'linddun']);
    if (page === 'action-plan') return stageStatus(state, ['controls', 'tests']);
    if (page === 'evidence') return stageStatus(state, ['missing_info', 'assumptions']);
    if (page === 'report') return state.signoff_ready ? 'Ready' : state.status === 'running' ? 'Running' : 'Needs review';
    return '—';
  };
  window.API.projects.get(project).then(projectData => {
    const state = projectData?.analysis_state || {};
    pages.forEach(item => {
      const status = pageStatus(state, item.page);
      const marker = nav.querySelector(`[data-workflow-state="${item.page}"]`);
      const link = nav.querySelector(`[data-workflow-page="${item.page}"]`);
      if (marker) marker.textContent = status;
      if (link) {
        link.dataset.runStatus = status.toLowerCase().replace(/\s+/g, '-');
        link.title = `${item.label} · ${status}`;
        link.setAttribute('aria-label', `${item.label} · ${status}${item.page === currentPage ? ' · current stage' : ''}`);
      }
    });
    const select = nav.querySelector('#project-workflow-stage');
    const currentOption = select?.querySelector(`option[value="${currentPage}"]`);
    if (currentOption) currentOption.textContent = `${pages.findIndex(item => item.page === currentPage) + 1} of ${pages.length} · ${pages.find(item => item.page === currentPage)?.short || currentPage} · ${pageStatus(state, currentPage)}`;
  }).catch(() => {
    // Navigation remains usable when the project status request is offline.
  });
}
