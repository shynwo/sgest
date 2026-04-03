(function(){
  function applyColWidths(){
    const table = document.getElementById('bk-table');
    if(!table) return;
    let cg = table.querySelector('colgroup');
    if(!cg){
      cg = document.createElement('colgroup');
      table.prepend(cg);
    }
    // (re)crée exactement 4 colonnes: Archive, Taille, Date, Actions
    cg.innerHTML = '<col data-col="archive"><col data-col="taille"><col data-col="date"><col data-col="actions">';

    const w = window.innerWidth || document.documentElement.clientWidth;

    // Par défaut (>=1200px)
    let W_ARCHIVE = 'auto', W_TAILLE = '120px', W_DATE = '220px', W_ACTIONS = '260px';

    if (w < 1200 && w >= 992){
      W_TAILLE = '110px'; W_DATE = '200px'; W_ACTIONS = '240px';
    } else if (w < 992 && w >= 768){
      W_TAILLE = '100px'; W_DATE = '190px'; W_ACTIONS = '230px';
    } else if (w < 768){
      // En mobile on privilégie les actions lisibles mais on garde la même base
      W_TAILLE = '90px';  W_DATE = '180px'; W_ACTIONS = '220px';
    }

    const cols = {
      archive: W_ARCHIVE,
      taille : W_TAILLE,
      date   : W_DATE,
      actions: W_ACTIONS
    };

    Object.entries(cols).forEach(([k,v])=>{
      const c = cg.querySelector(`col[data-col="${k}"]`);
      if(c){
        // width:auto n'est pas une valeur CSS valide sur <col>, on enlève la width pour laisser le reste s'étirer
        if(v === 'auto'){ c.style.removeProperty('width'); }
        else { c.style.width = v; }
      }
    });
  }

  // Applique au chargement + au resize (avec un léger debounce)
  let _t = null;
  window.addEventListener('resize', ()=>{
    clearTimeout(_t);
    _t = setTimeout(applyColWidths, 100);
  });
  document.addEventListener('DOMContentLoaded', applyColWidths);
  // Sur pages htmx/pjax éventuelles:
  window.addEventListener('pageshow', applyColWidths);
})();
