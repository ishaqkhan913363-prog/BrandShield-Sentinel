document.addEventListener("DOMContentLoaded", () => {
  const menu = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  if (menu && sidebar) menu.addEventListener("click", () => sidebar.classList.toggle("open"));
  document.querySelectorAll("form[data-confirm]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
  document.querySelectorAll('dialog').forEach(dialog => {
    dialog.addEventListener('click', event => {
      const rect = dialog.getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right ||
          event.clientY < rect.top || event.clientY > rect.bottom) dialog.close();
    });
  });
});
