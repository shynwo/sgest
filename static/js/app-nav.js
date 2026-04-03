(function(){
  function setOffcanvasTitle() {
    var hdr = document.querySelector('#offcanvasSidebar .offcanvas-header');
    if (!hdr) return;
    // Priorité au <h5 id="offcanvasSidebarLabel"> si présent (Bootstrap l'utilise pour aria-labelledby)
    var h = hdr.querySelector('#offcanvasSidebarLabel') || hdr.querySelector('.offcanvas-title');
    if (!h) {
      h = document.createElement('h5');
      h.className = 'offcanvas-title';
      h.id = 'offcanvasSidebarLabel';
      hdr.insertBefore(h, hdr.firstChild);
    }
    if (h.textContent !== 'Sgest 1.0') h.textContent = 'Sgest 1.0';
  }

  function buildMenu() {
    var sideNav = document.querySelector('aside.sidebar nav');
    var offBody = document.getElementById('offcanvasBody');
    if (!sideNav || !offBody) return;

    // Titre
    setOffcanvasTitle();

    // Corps du menu
    offBody.innerHTML = '';
    var brand = document.createElement('div');
    brand.className = 'px-3 pt-2 pb-1 fw-semibold text-light';
    brand.textContent = 'Sgest';
    offBody.appendChild(brand);

    var nav = sideNav.cloneNode(true);
    nav.className = 'list-group list-group-flush py-2';
    nav.querySelectorAll('.text-muted').forEach(function(el){
      var sep = document.createElement('div');
      sep.className = 'px-3 pt-3 pb-1 text-uppercase small text-muted';
      sep.textContent = el.textContent.trim();
      el.replaceWith(sep);
    });
    nav.querySelectorAll('a.nav-link').forEach(function(a){
      a.className = 'list-group-item list-group-item-action bg-transparent text-light border-0 py-2 px-3';
    });
    offBody.appendChild(nav);

    // Actif
    var path = location.pathname;
    offBody.querySelectorAll('a[href]').forEach(function(a){
      a.classList.toggle('active', a.getAttribute('href') === path);
    });
  }

  // 1) Au chargement
  document.addEventListener('DOMContentLoaded', function(){
    buildMenu();
    setOffcanvasTitle();
  });

  // 2) À chaque ouverture de l'offcanvas (avant rendu complet)
  var off = document.getElementById('offcanvasSidebar');
  if (off) {
    off.addEventListener('show.bs.offcanvas', function(){
      setOffcanvasTitle();
      buildMenu();
    });
    off.addEventListener('shown.bs.offcanvas', setOffcanvasTitle);
  }

  // 3) Ceinture & bretelles: si pour une raison X le titre repasse à "Menu"
  // on retente quelques fois pendant 2s.
  var tries = 0;
  var iv = setInterval(function(){
    setOffcanvasTitle();
    if (++tries > 20) clearInterval(iv);
  }, 100);
})();
