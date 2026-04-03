document.addEventListener('DOMContentLoaded', () => {
  // Ajoute .btn-download sur les liens de téléchargement si absent
  document.querySelectorAll('.actions-cell a.btn[href^="/system/backup/"]').forEach(a => {
    if (!a.classList.contains('btn-download')) a.classList.add('btn-download');
  });
});
