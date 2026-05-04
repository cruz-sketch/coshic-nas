// CSRF token from <meta> tag (set in base.html)
window.CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || '';

// Wrap fetch() so every same-origin POST/PUT/DELETE/PATCH carries the CSRF
// token automatically. Lets existing fetch() callers stay simple.
(function () {
  const _fetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    init = init || {};
    const method = (init.method || (typeof input === 'string' ? 'GET' : input.method) || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      const headers = new Headers(init.headers || {});
      if (!headers.has('X-CSRFToken') && window.CSRF_TOKEN) {
        headers.set('X-CSRFToken', window.CSRF_TOKEN);
      }
      init.headers = headers;
    }
    return _fetch(input, init);
  };
})();

// Auto-dismiss success/info alerts after 5 s
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.alert-success, .alert-info').forEach(el => {
    setTimeout(() => bootstrap.Alert.getOrCreateInstance(el).close(), 5000);
  });

  // Mobile sidebar toggle
  const menuBtn  = document.getElementById('mobMenuBtn');
  const sidebar  = document.querySelector('.sidebar');
  const overlay  = document.getElementById('mobOverlay');

  function openSidebar() {
    sidebar.classList.add('mob-open');
    overlay.classList.add('show');
  }
  function closeSidebar() {
    sidebar.classList.remove('mob-open');
    overlay.classList.remove('show');
  }

  if (menuBtn) {
    menuBtn.addEventListener('click', openSidebar);
    overlay.addEventListener('click', closeSidebar);
    // Close on nav link tap so the page change feels instant
    sidebar.querySelectorAll('.nav-item').forEach(a => a.addEventListener('click', closeSidebar));
  }
});
