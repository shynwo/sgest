/* badges.js — pastilles + modal alertes */

async function fetchJson(url){
  const r = await fetch(url, {headers:{'Accept':'application/json'}});
  if(!r.ok) throw new Error(`HTTP ${r.status}`);
  return await r.json();
}

/* ---------- Pastille alerte (cloche) ---------- */
async function refreshBadges(){
  try{
    // Prend la route combinée si dispo, sinon somme des deux
    let total = 0;
    try {
      const a = await fetchJson('/api/alerts/count');
      total = a.total || 0;
    } catch(e){
      const [a3, ab] = await Promise.allSettled([
        fetchJson('/api/impression3d/alerts'),
        fetchJson('/api/broderie/alerts')
      ]);
      const n3 = (a3.status==='fulfilled' && Array.isArray(a3.value.alerts)) ? a3.value.alerts.length : 0;
      const nb = (ab.status==='fulfilled' && Array.isArray(ab.value.alerts)) ? ab.value.alerts.length : 0;
      total = n3 + nb;
    }

    const badge = document.getElementById('badge-alerts');
    if (!badge) return;
    if (total > 0){
      badge.textContent = String(total);
      badge.classList.remove('d-none');
      badge.classList.add('bg-danger');
    } else {
      badge.classList.add('d-none');
    }
  }catch(e){
    // silencieux
  }
}

/* ---------- Modal alertes ---------- */
function renderAlertsTable(rows){
  if(!rows || rows.length===0){
    return '<div class="text-muted py-3">Aucune alerte active.</div>';
  }
  const head = `
    <div class="table-responsive">
      <table class="table table-sm align-middle mb-0">
        <thead>
          <tr>
            <th class="text-muted">Produit</th>
            <th class="text-muted">Matière</th>
            <th class="text-muted">Couleur</th>
            <th class="text-end text-muted">Qté</th>
          </tr>
        </thead>
        <tbody>`;
  const body = rows.map(r => `
          <tr>
            <td>${(r.name||r.ref||'—')}</td>
            <td>${(r.material||'—')}</td>
            <td>${(r.color||'—')}</td>
            <td class="text-end">${(r.qty ?? '0')}</td>
          </tr>`).join('');
  const tail = `
        </tbody>
      </table>
    </div>`;
  return head + body + tail;
}

async function loadAlertsIntoModal(){
  const body = document.getElementById('alertsModalBody');
  if (!body){ return; }
  body.innerHTML = '<div class="text-muted">Chargement…</div>';

  let rows = [];
  try{
    // Route combinée
    const data = await fetchJson('/api/alerts/list');
    if (Array.isArray(data.alerts)) rows = data.alerts;
  }catch(e){
    // Fallback : concat des 2 listes
    try{
      const [a3, ab] = await Promise.all([
        fetchJson('/api/impression3d/alerts'),
        fetchJson('/api/broderie/alerts'),
      ]);
      rows = []
        .concat(Array.isArray(a3.alerts) ? a3.alerts : [])
        .concat(Array.isArray(ab.alerts) ? ab.alerts : []);
    }catch(_){}
  }

  body.innerHTML = renderAlertsTable(rows);
}

function setupAlertsModal(){
  // Bouton cloche
  const btn = document.getElementById('btnShowAlerts');
  const modalEl = document.getElementById('alertsModal');
  if(!btn || !modalEl) return;

  btn.addEventListener('click', (ev)=>{
    ev.preventDefault();
    // Charge puis ouvre
    loadAlertsIntoModal().finally(()=>{
      try{
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
      }catch(e){}
    });
  });
}

/* ---------- Init ---------- */
document.addEventListener('DOMContentLoaded', ()=>{
  refreshBadges();
  setupAlertsModal();
  // rafraîchit la pastille toutes les 60s
  setInterval(refreshBadges, 60000);
});
