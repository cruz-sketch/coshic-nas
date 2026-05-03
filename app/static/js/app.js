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
