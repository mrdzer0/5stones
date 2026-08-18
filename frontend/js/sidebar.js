/** Shared sidebar collapse / mobile drawer behavior. */
document.addEventListener('DOMContentLoaded', () => {
  const sidebar = document.querySelector('.sidebar');
  const topbarLeft = document.querySelector('.topbar-left');
  if (!sidebar || !topbarLeft) return;

  const desktopQuery = window.matchMedia('(min-width: 901px)');
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'sidebar-toggle';
  toggle.setAttribute('aria-controls', 'app-sidebar');
  toggle.setAttribute('aria-label', 'Hide sidebar');
  toggle.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
      <rect x="3" y="4" width="18" height="16" rx="2"></rect>
      <path d="M9 4v16"></path>
      <path class="sidebar-toggle-chevron" d="m15 9-3 3 3 3"></path>
    </svg>`;

  sidebar.id = 'app-sidebar';
  topbarLeft.prepend(toggle);

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
  });

  document.addEventListener('click', (event) => {
    if (!desktopQuery.matches && document.body.classList.contains('sidebar-mobile-open')) {
      if (!sidebar.contains(event.target) && !toggle.contains(event.target)) {
        document.body.classList.remove('sidebar-mobile-open');
        syncState();
      }
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      document.body.classList.remove('sidebar-mobile-open');
      syncState();
    }
  });

  desktopQuery.addEventListener('change', () => {
    document.body.classList.remove('sidebar-mobile-open');
    syncState();
  });

  syncState();
});
