/* alerts-modal.js - modal des alertes + augmentation rapide du stock */

(function(){
  function htmlEscape(s){
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function categoryLabel(cat){
    return cat === 'broderie' ? 'Broderie' : 'Impression 3D';
  }

  function normalizeAlerts(data){
    if(Array.isArray(data && data.alerts)){
      return data.alerts;
    }
    const list3d = Array.isArray(data && data.impression3d) ? data.impression3d : [];
    const listBro = Array.isArray(data && data.broderie) ? data.broderie : [];
    return []
      .concat(list3d.map(function(a){ return Object.assign({category:'impression3d'}, a); }))
      .concat(listBro.map(function(a){ return Object.assign({category:'broderie'}, a); }));
  }

  async function refreshBadge(){
    const badge = document.getElementById('badge-alerts');
    if(!badge) return;

    try{
      const r = await fetch('/api/alerts/count', {headers:{'Accept':'application/json'}});
      if(!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      const total = Number(data.total || data.count || 0);
      if(total > 0){
        badge.textContent = String(total);
        badge.classList.remove('d-none');
      }else{
        badge.classList.add('d-none');
      }
    }catch(_e){
      // no-op
    }
  }

  function buildRow(alert){
    const id = Number(alert.id || 0);
    const cat = alert.category === 'broderie' ? 'broderie' : 'impression3d';
    const name = alert.name || alert.ref || 'Produit';
    const material = alert.material || '-';
    const color = alert.color || '-';
    const qty = Number(alert.qty || 0);
    const threshold = Number(alert.threshold || alert.min_qty || 0);

    return '' +
      '<tr data-alert-item="' + id + '" data-alert-cat="' + htmlEscape(cat) + '">' +
        '<td><span class="badge text-bg-secondary">' + htmlEscape(categoryLabel(cat)) + '</span></td>' +
        '<td class="fw-semibold">' + htmlEscape(name) + '</td>' +
        '<td>' + htmlEscape(material) + '</td>' +
        '<td>' + htmlEscape(color) + '</td>' +
        '<td class="text-end"><span class="badge text-bg-danger">' + qty + '</span></td>' +
        '<td class="text-end">' + threshold + '</td>' +
        '<td class="text-end">' +
          '<div class="input-group input-group-sm justify-content-end" style="max-width:160px; margin-left:auto;">' +
            '<input type="number" class="form-control js-bump-delta" min="1" step="1" value="1" aria-label="Quantite a ajouter" />' +
            '<button type="button" class="btn btn-primary js-bump-btn">Ajouter</button>' +
          '</div>' +
        '</td>' +
      '</tr>';
  }

  function renderTable(alerts){
    if(!alerts.length){
      return '<div class="text-muted py-3">Aucune alerte active.</div>';
    }

    return '' +
      '<div class="table-responsive">' +
        '<table class="table table-sm align-middle mb-0">' +
          '<thead>' +
            '<tr>' +
              '<th>Categorie</th>' +
              '<th>Produit</th>' +
              '<th>Matiere</th>' +
              '<th>Couleur</th>' +
              '<th class="text-end">Qte</th>' +
              '<th class="text-end">Seuil</th>' +
              '<th class="text-end">Stock +</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + alerts.map(buildRow).join('') + '</tbody>' +
        '</table>' +
      '</div>';
  }

  async function loadAlerts(){
    const body = document.getElementById('alertsModalBody');
    if(!body) return;

    body.innerHTML = '<div class="text-muted">Chargement...</div>';

    try{
      const r = await fetch('/api/alerts/list', {headers:{'Accept':'application/json'}});
      if(!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      const alerts = normalizeAlerts(data);
      body.innerHTML = renderTable(alerts);
    }catch(_e){
      body.innerHTML = '<div class="text-danger">Impossible de charger les alertes.</div>';
    }
  }

  async function bumpStock(itemId, category, delta){
    if(!itemId || delta <= 0) return;

    const endpoint = category === 'broderie'
      ? '/stock/broderie/' + itemId + '/bump'
      : '/stock/impression3d/' + itemId + '/bump';

    const fd = new FormData();
    fd.append('delta', String(delta));

    const r = await fetch(endpoint, {
      method: 'POST',
      body: fd,
      headers: {'X-Requested-With': 'fetch'}
    });

    if(!r.ok){
      throw new Error('HTTP ' + r.status);
    }
  }

  function wireBumpActions(modalEl){
    modalEl.addEventListener('click', async function(ev){
      const btn = ev.target.closest('.js-bump-btn');
      if(!btn) return;

      const row = btn.closest('tr[data-alert-item][data-alert-cat]');
      if(!row) return;

      const itemId = Number(row.getAttribute('data-alert-item') || 0);
      const category = row.getAttribute('data-alert-cat') || 'impression3d';
      const input = row.querySelector('.js-bump-delta');
      const delta = Number(input && input.value ? input.value : 1);

      if(delta <= 0){
        if(input) input.focus();
        return;
      }

      btn.disabled = true;
      const oldText = btn.textContent;
      btn.textContent = '...';

      try{
        await bumpStock(itemId, category, delta);
        await loadAlerts();
        await refreshBadge();
      }catch(_e){
        btn.textContent = 'Erreur';
        setTimeout(function(){ btn.textContent = oldText; }, 1000);
        btn.disabled = false;
        return;
      }

      btn.disabled = false;
      btn.textContent = oldText;
    });
  }

  function wireModal(){
    const btn = document.getElementById('btn-alerts');
    const modalEl = document.getElementById('alertsModal');
    if(!btn || !modalEl || !window.bootstrap || !window.bootstrap.Modal) return;

    const modal = new window.bootstrap.Modal(modalEl);
    wireBumpActions(modalEl);

    btn.addEventListener('click', function(ev){
      ev.preventDefault();
      loadAlerts().then(function(){ modal.show(); });
    }, {passive:false});
  }

  document.addEventListener('DOMContentLoaded', function(){
    refreshBadge();
    window.setInterval(refreshBadge, 60000);
    document.addEventListener('visibilitychange', function(){
      if(!document.hidden){
        refreshBadge();
      }
    });
    wireModal();
  });
})();
