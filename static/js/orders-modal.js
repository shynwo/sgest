/* orders-modal.js - notifications commandes Etsy/Vinted */

(function(){
  function esc(s){
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sourceLabel(src){
    const s = String(src || "").toLowerCase();
    if(s === "etsy") return "Etsy";
    if(s === "vinted") return "Vinted";
    return "Autre";
  }

  function fmtMoney(v, currency){
    const n = Number(v || 0);
    const cur = String(currency || "EUR").toUpperCase();
    try{
      return new Intl.NumberFormat("fr-FR", {style:"currency", currency: cur}).format(n);
    }catch(_e){
      return n.toFixed(2) + " " + cur;
    }
  }

  async function refreshBadge(){
    const badge = document.getElementById("badge-orders");
    if(!badge) return;
    try{
      const r = await fetch("/api/orders/count", {headers:{Accept:"application/json"}});
      if(!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      const total = Number(data.total || data.count || 0);
      if(total > 0){
        badge.textContent = String(total);
        badge.classList.remove("d-none");
      }else{
        badge.classList.add("d-none");
      }
    }catch(_e){
      // no-op
    }
  }

  function renderOrders(orders){
    if(!orders.length){
      return '<div class="text-muted py-3">Aucune notification commande pour le moment.</div>';
    }

    const rows = orders.map(function(o){
      const unread = Number(o.is_read || 0) === 0;
      return '' +
        '<tr data-order-id="' + Number(o.id || 0) + '">' +
          '<td><span class="badge text-bg-secondary">' + esc(sourceLabel(o.source)) + '</span></td>' +
          '<td class="fw-semibold">' + esc(o.order_ref || o.external_id || "-") + '</td>' +
          '<td>' + esc(o.buyer || "-") + '</td>' +
          '<td>' + fmtMoney(o.total_amount, o.currency || "EUR") + '</td>' +
          '<td>' + esc(o.status || "new") + '</td>' +
          '<td class="small text-secondary">' + esc(o.created_at || "") + '</td>' +
          '<td class="text-end">' +
            (unread
              ? '<button type="button" class="btn btn-sm btn-outline-primary js-order-read">Lu</button>'
              : '<span class="badge text-bg-success">Lu</span>') +
          '</td>' +
        '</tr>';
    }).join("");

    return '' +
      '<div class="table-responsive">' +
        '<table class="table table-sm align-middle mb-0">' +
          '<thead><tr><th>Source</th><th>Commande</th><th>Acheteur</th><th>Total</th><th>Statut</th><th>Date</th><th class="text-end">Action</th></tr></thead>' +
          '<tbody>' + rows + '</tbody>' +
        '</table>' +
      '</div>';
  }

  async function loadOrders(){
    const body = document.getElementById("ordersModalBody");
    if(!body) return;
    body.innerHTML = '<div class="text-muted">Chargement...</div>';
    try{
      const r = await fetch("/api/orders/list?limit=80", {headers:{Accept:"application/json"}});
      if(!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      const orders = Array.isArray(data.orders) ? data.orders : [];
      body.innerHTML = renderOrders(orders);
      await refreshBadge();
    }catch(_e){
      body.innerHTML = '<div class="text-danger">Impossible de charger les commandes.</div>';
    }
  }

  async function markRead(orderId){
    const r = await fetch("/api/orders/" + orderId + "/read", {
      method: "POST",
      headers: {"X-Requested-With":"fetch"}
    });
    if(!r.ok) throw new Error("HTTP " + r.status);
  }

  async function markAllRead(){
    const r = await fetch("/api/orders/read-all", {
      method: "POST",
      headers: {"X-Requested-With":"fetch"}
    });
    if(!r.ok) throw new Error("HTTP " + r.status);
  }

  function wireModal(){
    const btn = document.getElementById("btn-orders");
    const modalEl = document.getElementById("ordersModal");
    const markAllBtn = document.getElementById("ordersMarkAllRead");
    if(!btn || !modalEl || !window.bootstrap || !window.bootstrap.Modal) return;

    const modal = new window.bootstrap.Modal(modalEl);

    btn.addEventListener("click", function(ev){
      ev.preventDefault();
      loadOrders().then(function(){ modal.show(); });
    }, {passive:false});

    modalEl.addEventListener("click", async function(ev){
      const btnRead = ev.target.closest(".js-order-read");
      if(!btnRead) return;
      const row = btnRead.closest("tr[data-order-id]");
      if(!row) return;
      const id = Number(row.getAttribute("data-order-id") || 0);
      if(id <= 0) return;

      btnRead.disabled = true;
      try{
        await markRead(id);
        await loadOrders();
      }catch(_e){
        btnRead.disabled = false;
      }
    });

    if(markAllBtn){
      markAllBtn.addEventListener("click", async function(){
        markAllBtn.disabled = true;
        try{
          await markAllRead();
          await loadOrders();
        }catch(_e){
          // no-op
        }
        markAllBtn.disabled = false;
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function(){
    refreshBadge();
    window.setInterval(refreshBadge, 60000);
    document.addEventListener("visibilitychange", function(){
      if(!document.hidden) refreshBadge();
    });
    wireModal();
  });
})();
