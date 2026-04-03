/* Inventory UI: live filters & counter */
(function(){
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));

  const table = $('#inv-table');
  if(!table) return;

  const rows = () => $$('#inv-table tbody tr[data-row="1"]');
  const countSpan = $('#inv-count');
  const search = $('#inv-search');
  const selMat = $('#inv-filter-mat');
  const selCol = $('#inv-filter-col');

  function normalize(s){ return (s||'').toString().toLowerCase().normalize('NFD').replace(/\p{Diacritic}/gu,''); }

  function apply(){
    const q = normalize(search?.value);
    const fMat = selMat?.value || '';
    const fCol = selCol?.value || '';

    let shown = 0;
    rows().forEach(tr=>{
      const mat = tr.getAttribute('data-mat');
      const col = tr.getAttribute('data-col');
      const txt = tr.innerText;
      const okQ = !q || normalize(txt).includes(q);
      const okM = !fMat || mat===fMat;
      const okC = !fCol || col===fCol;
      const show = okQ && okM && okC;
      tr.style.display = show ? '' : 'none';
      if(show) shown++;
    });
    if(countSpan) countSpan.textContent = shown.toString();
  }

  [search, selMat, selCol].forEach(el=> el && el.addEventListener('input', apply));
  apply();
})();

/* removeInvSearchAddon: force-remove the left magnifier addon */
(function removeInvSearchAddon(){
  function run() {
    document.querySelectorAll('.inv-search-addon').forEach(n => n.remove());
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true });
  } else {
    run();
  }
})();
