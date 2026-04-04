"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""
from __future__ import annotations

from flask import Blueprint

from ..repos import stock_sql as _stock_sql
from ..services import *  # noqa: F401,F403


bp = Blueprint("stock", __name__)

@bp.post("/stock/impression3d/add")
def inv_3d_add():
    f = request.form
    first = lambda *keys, default="": next((str(f.get(k)).strip() for k in keys if f.get(k) and str(f.get(k)).strip()!=""), default)
    to_float = lambda x: (lambda s: float(s.replace(",", ".")) if s else 0.0)(str(x).strip()) if x is not None else 0.0
    def to_int(x):
        try: return int(str(x).strip())
        except: return 0

    name     = first("name","nom","product_name")
    ref      = first("ref","reference","sku","id","product_id")
    material = first("material_new","new_material","material_select","material")
    color    = first("color_new","new_color","color_select","color")
    price    = to_float(first("price","prix","amount","cost","price_eur"))
    qty      = to_int(first("qty","qte","quantity","quantite","quantité"))
    if qty <= 0: qty = 1
    if not material or not color:
        flash("Sélectionne une matière et une couleur (quantité auto>=1).", "warning")
        return redirect(url_for("stock.inv_3d_page"))
    con = _con_3d()
    try:
        con.execute("INSERT INTO stock_3d(name,material,color,ref,price,qty) VALUES(?,?,?,?,?,?)",
                    (name, material, color, ref, price, qty))
        con.commit()
        flash("Produit ajouté.", "success")
    except sqlite3.IntegrityError as e:
        con.rollback()
        if "stock_3d.ref" in str(e):
            flash("Cette référence existe déjà. Modifie la référence ou augmente le stock sur la ligne existante.", "warning")
        else:
            raise
    finally:
        con.close()
    return redirect(url_for("stock.inv_3d_page"))
@bp.post("/stock/impression3d/<int:item_id>/bump")
def inv_3d_bump(item_id:int):
    try: delta = int(request.form.get('delta') or 1)
    except: delta = 1
    con = _con_3d()
    con.execute("UPDATE stock_3d SET qty = MAX(0, COALESCE(qty,0) + ?) WHERE id=?", (delta, item_id))
    con.commit(); con.close()
    flash("Stock " + ("+" if delta>=0 else "") + str(delta) + ".", "success")
    return redirect(url_for("stock.inv_3d_page"))
@bp.post("/stock/impression3d/<int:item_id>/alert")
def inv_3d_alert(item_id:int):
    try:
        thr = int(request.form.get('min_qty') or 0)
        if thr < 0:
            thr = 0
    except Exception:
        thr = 0
    con = _con_3d()
    if thr <= 0:
        con.execute("DELETE FROM stock_3d_alerts WHERE item_id=?", (item_id,))
        msg = "Alerte supprimée."
    else:
        con.execute("""
            INSERT INTO stock_3d_alerts(item_id,threshold) VALUES(?,?)
            ON CONFLICT(item_id) DO UPDATE SET threshold=excluded.threshold
        """, (item_id, thr))
        msg = f"Alerte mise à jour (seuil = {thr})."
    con.commit(); con.close()
    flash(msg, "success")
    return redirect(url_for("stock.inv_3d_page"))
@bp.post("/stock/impression3d/<int:item_id>/del")
def inv_3d_del(item_id:int):
    con = _con_3d()
    con.execute("DELETE FROM stock_3d WHERE id=?", (item_id,))
    con.commit(); con.close()
    flash("Article supprimé.", "success")
    return redirect(url_for("stock.inv_3d_page"))
@bp.get('/api/broderie/alerts', endpoint='bro_alerts_api')
def bro_alerts_api():
    con = _con_bro()
    rows = con.execute(_stock_sql.BRO_ALERTS_API_ROWS).fetchall()
    con.close()
    return jsonify(alerts=[dict(r) for r in rows])
@bp.get('/stock/broderie')
def bro_page():
    con = _con_bro()
    items = [dict(r) for r in con.execute(_stock_sql.BRO_PAGE_ITEMS)]
    mats = [r[0] for r in con.execute(_stock_sql.BRO_DISTINCT_MATERIALS)]
    cols = [r[0] for r in con.execute(_stock_sql.BRO_DISTINCT_COLORS)]
    refs = [r[0] for r in con.execute(_stock_sql.BRO_DISTINCT_REFS)]
    alerts = [dict(r) for r in con.execute(_stock_sql.BRO_ALERTS_PANEL)]
    con.close()
    return render_template('stock_broderie.html',
                           title='Broderie',
                           items=items, materials=mats, sizes=mats, colors=cols, refs=refs, alerts=alerts)
@bp.post('/stock/broderie/add', endpoint='bro_add')
def bro_add():
    f = request.form
    def first(*keys, default=""):
        for k in keys:
            v = f.get(k)
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        return default
    def to_float(x):
        try: return float(str(x).replace(",", "."))
        except: return 0.0
    def to_int(x):
        try: return int(str(x).strip())
        except: return 0
    name     = first("name","nom","product_name")
    ref      = first("ref_select","ref","reference","sku","id","product_id")
    size     = first("size_new","new_size","size_select","size",
                     "material_new","new_material","material_select","material")
    color    = first("color_new","new_color","color_select","color")
    price    = to_float(first("price","prix","amount","cost","price_eur"))
    qty      = to_int(first("qty","qte","quantity","quantite","quantité"))
    if qty <= 0: qty = 1
    if not ref:
        flash("Choisis une reference existante ou saisis une nouvelle reference.", "warning")
        return redirect(url_for("stock.bro_page"))
    if not size or not color:
        flash("Sélectionne une taille et une couleur (quantité auto>=1).", "warning")
        return redirect(url_for("stock.bro_page"))
    con = _con_bro()
    try:
        existing = con.execute(_stock_sql.BRO_FIND_VARIANT, (ref, size, color)).fetchone()

        if existing:
            con.execute(
                _stock_sql.BRO_UPDATE_VARIANT_QTY,
                (qty, price, name, name, existing["id"]),
            )
            con.commit()
            flash(f"Variante existante: stock augmenté (+{qty}).", "success")
        else:
            con.execute(
                _stock_sql.BRO_INSERT_ROW,
                (name, size, color, ref, price, qty),
            )
            con.commit()
            flash("Produit ajouté.", "success")
    except sqlite3.IntegrityError as e:
        con.rollback()
        if "stock_bro.ref" in str(e):
            flash("Contrainte legacy sur la référence détectée. Réessaie: la migration est appliquée automatiquement.", "warning")
        else:
            raise
    finally:
        con.close()
    return redirect(url_for("stock.bro_page"))
@bp.post('/stock/broderie/<int:item_id>/bump', endpoint='bro_bump')
def bro_bump(item_id:int):
    try:
        delta = int(request.form.get('delta') or 1)
    except:
        delta = 1
    con = _con_bro()
    con.execute("UPDATE stock_bro SET qty = COALESCE(qty,0) + ? WHERE id=?", (delta, item_id))
    con.commit(); con.close()
    flash(f"Stock {'+' if delta>=0 else ''}{delta}.", "success")
    return redirect(url_for('stock.bro_page'))
@bp.post('/stock/broderie/<int:item_id>/del', endpoint='bro_del')
def bro_del(item_id:int):
    con = _con_bro()
    con.execute("DELETE FROM stock_bro WHERE id=?", (item_id,))
    con.execute("DELETE FROM stock_bro_alerts WHERE item_id=?", (item_id,))
    con.commit(); con.close()
    flash("Article supprimé.", "success")
    return redirect(url_for('stock.bro_page'))
@bp.post('/stock/broderie/alert', endpoint='bro_alert_set')
def bro_alert_set():
    f = request.form
    try:
        item_id = int(f.get("item_id") or 0)
        threshold = int(f.get("threshold") or f.get("min_qty") or 0)
    except Exception:
        item_id, threshold = 0, 0

    con = _con_bro()

    if item_id <= 0:
        con.close()
        flash("Produit invalide.", "warning")
        return redirect(url_for("stock.bro_page"))

    # Si seuil <= 0 : on supprime l’alerte
    if threshold <= 0:
        con.execute("DELETE FROM stock_bro_alerts WHERE item_id=?", (item_id,))
        con.commit(); con.close()
        flash("Alerte supprimée.", "success")
        return redirect(url_for("stock.bro_page"))

    # Sinon UPSERT (comme en 3D)
    con.execute("""
        INSERT INTO stock_bro_alerts(item_id, threshold)
        VALUES(?, ?)
        ON CONFLICT(item_id) DO UPDATE SET threshold=excluded.threshold
    """, (item_id, threshold))
    con.commit(); con.close()
    flash(f"Alerte enregistrée (seuil = {threshold}).", "success")
    return redirect(url_for("stock.bro_page"))
@bp.get('/stock/impression3d')
def inv_3d_page():
    con = _con_3d()
    items = [dict(r) for r in con.execute(_stock_sql.THREED_PAGE_ITEMS)]
    mats = [r[0] for r in con.execute(_stock_sql.THREED_DISTINCT_MATERIALS)]
    cols = [r[0] for r in con.execute(_stock_sql.THREED_DISTINCT_COLORS)]
    alerts = [dict(r) for r in con.execute(_stock_sql.THREED_ALERTS_PANEL)]
    con.close()
    return render_template('stock_3D.html',
                           title='Impression 3D',
                           items=items, materials=mats, colors=cols, alerts=alerts)
@bp.post('/stock/broderie/<int:item_id>/alert', endpoint='bro_alert_item')
def bro_alert_item(item_id:int):
    f = request.form
    try:
        thr = int(f.get('threshold') or f.get('min_qty') or 0)
    except Exception:
        thr = 0

    con = _con_bro()

    # Assurer le schéma et l'unicité
    con.execute("""
        CREATE TABLE IF NOT EXISTS stock_bro_alerts(
            item_id   INTEGER PRIMARY KEY,
            threshold INTEGER NOT NULL DEFAULT 0
        );
    """)
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_bro_alert_item ON stock_bro_alerts(item_id);")

    if thr <= 0:
        con.execute("DELETE FROM stock_bro_alerts WHERE item_id=?", (item_id,))
        msg = "Alerte supprimée."
    else:
        con.execute("""
            INSERT INTO stock_bro_alerts(item_id,threshold) VALUES(?,?)
            ON CONFLICT(item_id) DO UPDATE SET threshold=excluded.threshold
        """, (item_id, thr))
        msg = "Alerte enregistrée."
    con.commit(); con.close()

    flash(msg, "success")
    return redirect(url_for('stock.bro_page'))
@bp.get("/api/impression3d/alerts")
def api_impr3d_alerts():
    return jsonify(alerts=_get_impr3d_alerts_list())
@bp.get("/api/broderie/alerts")
def api_broderie_alerts():
    return jsonify(alerts=_get_broderie_alerts_list())
@bp.get("/api/alerts/list")
def api_alerts_list():
    alerts_3d = _get_impr3d_alerts_list()
    alerts_bro = _get_broderie_alerts_list()
    merged = (
        [{"category": "impression3d", **item} for item in alerts_3d] +
        [{"category": "broderie", **item} for item in alerts_bro]
    )
    return jsonify({
        "alerts": merged,
        "impression3d": alerts_3d,
        "broderie": alerts_bro
    })
@bp.get("/api/alerts/count")
def api_alerts_count():
    total = len(_get_impr3d_alerts_list()) + len(_get_broderie_alerts_list())
    return jsonify(total=total)
@bp.get("/api/orders/count")
def api_orders_count():
    return jsonify(total=_orders_unread_count())
@bp.get("/api/orders/list")
def api_orders_list():
    limit = _safe_int(request.args.get("limit"), 60)
    orders = _orders_list(limit=limit)
    return jsonify(
        orders=orders,
        total=len(orders),
        unread_total=_orders_unread_count()
    )
@bp.post("/api/orders/<int:order_id>/read")
def api_orders_mark_read(order_id: int):
    con = _con_biz()
    try:
        con.execute("UPDATE order_notifications SET is_read=1 WHERE id=?", (order_id,))
        con.commit()
    finally:
        con.close()
    return jsonify(ok=True, unread_total=_orders_unread_count())
@bp.post("/api/orders/read-all")
def api_orders_mark_all_read():
    con = _con_biz()
    try:
        con.execute("UPDATE order_notifications SET is_read=1 WHERE is_read=0")
        con.commit()
    finally:
        con.close()
    return jsonify(ok=True, unread_total=_orders_unread_count())
@bp.post("/api/orders/mock")
def api_orders_mock():
    if not _verify_webhook_token("mock"):
        return jsonify(ok=False, error="unauthorized"), 401
    payload = request.get_json(silent=True) or {}
    source = (payload.get("source") or "mock").strip().lower()
    if source not in ("etsy", "vinted", "mock"):
        source = "mock"
    order_id = _save_order_notification(source, payload)
    return jsonify(ok=True, id=order_id, unread_total=_orders_unread_count())
