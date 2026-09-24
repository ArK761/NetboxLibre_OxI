(() => {
  if (window.__libreoxiLogHandlersInstalled) return;
  window.__libreoxiLogHandlersInstalled = true;

  document.addEventListener('click', (event) => {
    const button = event.target.closest('.libreoxi-log-toggle-btn');
    if (!button) return;

    const id = button.dataset.detailId;
    if (!id) return;

    const detail = document.getElementById(id);
    if (!detail) return;

    event.preventDefault();
    event.stopPropagation();

    const open = detail.classList.toggle('open');
    button.setAttribute('aria-expanded', open ? 'true' : 'false');
  }, true);
})();
