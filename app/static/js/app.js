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

// ─────────────────────────────────────────────────────── Clipboard helper
// Copies `text` to clipboard. The optional `container` element receives the
// hidden <textarea> when falling back to execCommand('copy') - required when
// the caller is inside a Bootstrap modal whose focus trap would otherwise
// reject focus() on a node outside it. Returns Promise<boolean>.
window.copyText = function (text, container) {
  container = container || document.body;
  return new Promise((resolve) => {
    const fallback = () => {
      const el = document.createElement('textarea');
      el.value = text;
      el.style.cssText = 'position:absolute;opacity:0;pointer-events:none;width:1px;height:1px';
      container.appendChild(el);
      el.focus();
      el.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (_) {}
      el.remove();
      resolve(ok);
    };
    if (window.isSecureContext && navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => resolve(true)).catch(fallback);
    } else {
      fallback();
    }
  });
};

// ─────────────────────────────────────────────────────── Toast helper
window.showToast = function (message, variant = 'info') {
  let stack = document.getElementById('toastStack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toastStack';
    stack.className = 'toast-stack';
    document.body.appendChild(stack);
  }
  const icons = {
    success: 'bi-check-circle-fill',
    danger:  'bi-exclamation-octagon-fill',
    warning: 'bi-exclamation-triangle-fill',
    info:    'bi-info-circle-fill',
  };
  const icon = icons[variant] || icons.info;
  const el = document.createElement('div');
  el.className = `toast align-items-center toast-${variant} border-0`;
  el.setAttribute('role', variant === 'danger' ? 'alert' : 'status');
  el.setAttribute('aria-live', variant === 'danger' ? 'assertive' : 'polite');
  el.setAttribute('aria-atomic', 'true');
  el.innerHTML = `
    <div class="d-flex">
      <div class="toast-body d-flex align-items-center gap-2">
        <i class="bi ${icon}"></i>
        <span></span>
      </div>
      <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>`;
  el.querySelector('span').textContent = message;
  stack.appendChild(el);
  const t = bootstrap.Toast.getOrCreateInstance(el, { delay: variant === 'danger' ? 6000 : 4000 });
  el.addEventListener('hidden.bs.toast', () => el.remove());
  t.show();
};

// ─────────────────────────────────────────────────────── Confirm dialog
// Returns a Promise<boolean>. Replaces window.confirm() with an accessible
// Bootstrap modal styled to match the app.
window.confirmDialog = function ({ title = 'Are you sure?', body = '', confirmLabel = 'Confirm', variant = 'danger' } = {}) {
  return new Promise((resolve) => {
    const id = 'confirmDialog_' + Math.random().toString(36).slice(2);
    const wrap = document.createElement('div');
    wrap.innerHTML = `
      <div class="modal fade" id="${id}" tabindex="-1" aria-labelledby="${id}_title" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title" id="${id}_title"></h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body"></div>
            <div class="modal-footer">
              <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
              <button type="button" class="btn btn-${variant}" data-action="confirm"></button>
            </div>
          </div>
        </div>
      </div>`;
    const modalEl = wrap.firstElementChild;
    modalEl.querySelector('.modal-title').textContent = title;
    modalEl.querySelector('.modal-body').textContent  = body;
    const btn = modalEl.querySelector('[data-action="confirm"]');
    btn.textContent = confirmLabel;
    document.body.appendChild(modalEl);

    let result = false;
    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    btn.addEventListener('click', () => { result = true; modal.hide(); });
    modalEl.addEventListener('hidden.bs.modal', () => {
      modal.dispose();
      modalEl.remove();
      resolve(result);
    });
    modal.show();
    setTimeout(() => btn.focus(), 200);
  });
};

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss success/info alerts after 5 s
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
    sidebar.querySelectorAll('.nav-item').forEach(a => a.addEventListener('click', closeSidebar));
  }

  // Bootstrap tooltips on any [data-bs-toggle="tooltip"]
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    new bootstrap.Tooltip(el, { container: 'body' });
  });

  // Confirm-on-submit forms: <form data-confirm="..." data-confirm-title="...">
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', (e) => {
      if (form.dataset._confirmed === '1') return;
      e.preventDefault();
      window.confirmDialog({
        title:        form.dataset.confirmTitle || 'Are you sure?',
        body:         form.dataset.confirm,
        confirmLabel: form.dataset.confirmLabel || 'Delete',
        variant:      form.dataset.confirmVariant || 'danger',
      }).then(ok => {
        if (ok) {
          form.dataset._confirmed = '1';
          form.submit();
        }
      });
    });
  });
});
