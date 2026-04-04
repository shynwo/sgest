"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""
from __future__ import annotations

from flask import Blueprint

from ..services import *  # noqa: F401,F403


bp = Blueprint("tools", __name__)

@bp.get("/outils/calculateur")
def tools_calculator_page():
    return render_template(
        "tools_calculator.html",
        title="Calculateur",
        bro_products=_load_bro_products(),
        spools=_load_3d_spools(),
    )
@bp.get("/outils/gain")
def tools_gain_page():
    period = _normalize_gain_period(request.args.get("period", "month"))
    events = _biz_events(period=period, limit=200)
    biz = _biz_totals(period=period)
    top_products = _biz_top_products(period=period, limit=5)
    best_product = top_products[0] if top_products else None

    return render_template(
        "tools_gain.html",
        title="Gain",
        bro_products=_load_bro_products(),
        spools=_load_3d_spools(),
        events=events,
        biz=biz,
        period=period,
        top_products=top_products,
        best_product=best_product,
        spool_base_grams=int(SPOOL_BASE_GRAMS),
    )
@bp.post("/outils/gain/record")
def tools_gain_record():
    f = request.form
    category = (f.get("category") or "").strip().lower()
    tx_type = (f.get("tx_type") or "sale").strip().lower()
    period = _normalize_gain_period(f.get("period") or request.args.get("period") or "month")
    item_id = _safe_int(f.get("item_id"), 0)
    qty_units = max(1, _safe_int(f.get("qty_units"), 1))
    sell_unit_price = max(0.0, _safe_float(f.get("sell_unit_price"), 0.0))
    grams_per_unit = max(0.0, _safe_float(f.get("grams_per_unit"), 0.0))

    if category not in ("broderie", "impression3d"):
        flash("Categorie invalide.", "warning")
        return redirect(url_for("tools.tools_gain_page", period=period))
    if tx_type not in ("sale", "loss"):
        tx_type = "sale"

    item = None
    total_grams = 0.0
    unit_buy_cost = 0.0
    cost = 0.0

    if category == "broderie":
        con_stock = _con_bro()
        try:
            item = con_stock.execute("""
                SELECT id, COALESCE(name,'') AS name, COALESCE(ref,'') AS ref,
                       COALESCE(material,'') AS material, COALESCE(color,'') AS color,
                       COALESCE(price,0) AS price, COALESCE(qty,0) AS qty
                FROM stock_bro WHERE id=?
            """, (item_id,)).fetchone()
            if not item:
                flash("Article broderie introuvable.", "warning")
                return redirect(url_for("tools.tools_gain_page", period=period))

            available = float(item["qty"] or 0.0)
            if qty_units > available + 1e-9:
                flash(f"Stock insuffisant (disponible: {available}).", "warning")
                return redirect(url_for("tools.tools_gain_page", period=period))

            con_stock.execute("UPDATE stock_bro SET qty=? WHERE id=?", (max(0.0, available - qty_units), item_id))
            con_stock.commit()
            unit_buy_cost = float(item["price"] or 0.0)
            cost = unit_buy_cost * qty_units
        finally:
            con_stock.close()
    else:
        con_stock = _con_3d()
        try:
            item = con_stock.execute("""
                SELECT id, COALESCE(name,'') AS name, COALESCE(ref,'') AS ref,
                       COALESCE(material,'') AS material, COALESCE(color,'') AS color,
                       COALESCE(price,0) AS price, COALESCE(qty,0) AS qty
                FROM stock_3d WHERE id=?
            """, (item_id,)).fetchone()
            if not item:
                flash("Bobine introuvable.", "warning")
                return redirect(url_for("tools.tools_gain_page", period=period))

            total_grams = grams_per_unit * qty_units
            if total_grams <= 0:
                flash("Indique un grammage > 0 pour la 3D.", "warning")
                return redirect(url_for("tools.tools_gain_page", period=period))

            available_grams = float(item["qty"] or 0.0) * SPOOL_BASE_GRAMS
            if total_grams > available_grams + 1e-9:
                flash(f"Stock insuffisant (disponible: {int(round(available_grams))} g).", "warning")
                return redirect(url_for("tools.tools_gain_page", period=period))

            new_qty = max(0.0, (available_grams - total_grams) / SPOOL_BASE_GRAMS)
            con_stock.execute("UPDATE stock_3d SET qty=? WHERE id=?", (round(new_qty, 6), item_id))
            con_stock.commit()
            cost = (float(item["price"] or 0.0) / SPOOL_BASE_GRAMS) * total_grams
            unit_buy_cost = (cost / qty_units) if qty_units else 0.0
        finally:
            con_stock.close()

    revenue = (sell_unit_price * qty_units) if tx_type == "sale" else 0.0
    urssaf = (revenue * URSSAF_RATE) if tx_type == "sale" else 0.0
    profit = (revenue - cost - urssaf) if tx_type == "sale" else (-cost)

    con = _con_biz()
    try:
        con.execute("""
            INSERT INTO gain_events(
                category, tx_type, item_id, item_name, ref, material, color,
                qty, grams_per_unit, total_grams, unit_buy_cost, unit_sell_price,
                revenue, cost, urssaf, profit
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            category, tx_type, int(item["id"]), item["name"], item["ref"], item["material"], item["color"],
            float(qty_units), float(grams_per_unit), float(total_grams), float(unit_buy_cost), float(sell_unit_price),
            float(revenue), float(cost), float(urssaf), float(profit)
        ))
        con.commit()
    finally:
        con.close()

    flash(f"{'Vente' if tx_type == 'sale' else 'Perte'} enregistree. Gain: {profit:.2f} EUR", "success")
    return redirect(url_for("tools.tools_gain_page", period=period))
@bp.post("/outils/gain/reset")
def tools_gain_reset():
    period = _normalize_gain_period(request.form.get("period") or request.args.get("period") or "month")
    con = _con_biz()
    try:
        con.execute("DELETE FROM gain_events")
        con.commit()
    finally:
        con.close()
    flash("Historique des gains vide.", "success")
    return redirect(url_for("tools.tools_gain_page", period=period))
@bp.get("/outils/gain/export.csv")
def tools_gain_export_csv():
    period = _normalize_gain_period(request.args.get("period", "month"))
    events = _biz_events(period=period, limit=200000)

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow([
        "date", "type", "categorie", "article", "ref", "matiere", "couleur",
        "quantite", "grammes_piece", "grammes_total", "prix_achat_unitaire",
        "prix_vente_unitaire", "chiffre_affaires", "cout", "urssaf", "gain_net"
    ])
    for e in reversed(events):
        writer.writerow([
            e.get("created_at") or "",
            e.get("tx_type") or "",
            e.get("category") or "",
            e.get("item_name") or "",
            e.get("ref") or "",
            e.get("material") or "",
            e.get("color") or "",
            e.get("qty") or 0,
            e.get("grams_per_unit") or 0,
            e.get("total_grams") or 0,
            e.get("unit_buy_cost") or 0,
            e.get("unit_sell_price") or 0,
            e.get("revenue") or 0,
            e.get("cost") or 0,
            e.get("urssaf") or 0,
            e.get("profit") or 0,
        ])

    csv_data = "\ufeff" + output.getvalue()
    filename = f"gain_{period}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
@bp.get("/api/gain/summary")
def api_gain_summary():
    period = _normalize_gain_period(request.args.get("period", "all"))
    return jsonify(period=period, **_biz_totals(period=period))
@bp.get("/outils/gestion")
def tools_custom_stock_page():
    selected_module_id = _safe_int(request.args.get("m"), 0)
    search_q = (request.args.get("q") or "").strip()

    con = _con_biz()
    try:
        modules = [dict(r) for r in con.execute("""
            SELECT m.*,
                   COALESCE((SELECT COUNT(1) FROM custom_stock_fields f WHERE f.module_id=m.id),0) AS fields_count,
                   COALESCE((SELECT COUNT(1) FROM custom_stock_items i WHERE i.module_id=m.id),0) AS items_count,
                   COALESCE((SELECT SUM(i.qty) FROM custom_stock_items i WHERE i.module_id=m.id),0) AS units_total,
                   COALESCE((SELECT SUM(CASE WHEN COALESCE(i.min_qty,0) > 0 AND COALESCE(i.qty,0) <= COALESCE(i.min_qty,0) THEN 1 ELSE 0 END)
                             FROM custom_stock_items i WHERE i.module_id=m.id),0) AS low_count
            FROM custom_stock_modules m
            ORDER BY m.id DESC
        """).fetchall()]
    finally:
        con.close()

    if selected_module_id <= 0 and modules:
        selected_module_id = int(modules[0]["id"])

    active_module = next((m for m in modules if int(m["id"]) == selected_module_id), None)
    fields = []
    table_fields = []
    items = []
    low_count = 0

    if active_module:
        con = _con_biz()
        try:
            fields = _custom_load_fields(con, int(active_module["id"]))
            table_fields = [f for f in fields if int(f.get("show_in_table") or 0) == 1]

            params = [int(active_module["id"])]
            where_sql = "WHERE module_id=?"
            if search_q:
                like = f"%{search_q}%"
                where_sql += " AND (COALESCE(name,'') LIKE ? OR COALESCE(ref,'') LIKE ? OR COALESCE(data_json,'') LIKE ?)"
                params.extend([like, like, like])

            rows = [dict(r) for r in con.execute(f"""
                SELECT *
                FROM custom_stock_items
                {where_sql}
                ORDER BY id DESC
                LIMIT 800
            """, params).fetchall()]
        finally:
            con.close()

        for it in rows:
            data = _custom_data_to_dict(it.get("data_json"))
            qty_raw = float(it.get("qty") or 0.0)
            min_raw = float(it.get("min_qty") or 0.0)
            it["qty_display"] = int(round(qty_raw)) if abs(qty_raw - round(qty_raw)) < 1e-9 else round(qty_raw, 3)
            it["min_qty_display"] = int(round(min_raw)) if abs(min_raw - round(min_raw)) < 1e-9 else round(min_raw, 3)
            it["is_low"] = bool(min_raw > 0 and qty_raw <= min_raw + 1e-9)
            if it["is_low"]:
                low_count += 1
            custom_values = {}
            for f in fields:
                custom_values[f["field_key"]] = _custom_display_value(data.get(f["field_key"]), f.get("field_type"))
            it["custom_values"] = custom_values
            items.append(it)

    return render_template(
        "tools_management.html",
        title="Gestion",
        modules=modules,
        active_module=active_module,
        selected_module_id=selected_module_id,
        fields=fields,
        table_fields=table_fields,
        items=items,
        low_count=low_count,
        search_q=search_q,
    )
@bp.post("/outils/gestion/modules/add")
def tools_custom_module_add():
    name = (request.form.get("name") or "").strip()
    description = (request.form.get("description") or "").strip()
    icon = (request.form.get("icon") or "").strip()
    if not name:
        flash("Nom de gestion obligatoire.", "warning")
        return redirect(url_for("tools.tools_custom_stock_page"))

    con = _con_biz()
    try:
        cur = con.execute("""
            INSERT INTO custom_stock_modules(name, description, icon, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (name[:90], description[:400], icon[:32]))
        module_id = int(cur.lastrowid)
        con.commit()
    finally:
        con.close()

    flash("Gestion personnalisee creee.", "success")
    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
@bp.post("/outils/gestion/modules/<int:module_id>/delete")
def tools_custom_module_delete(module_id: int):
    con = _con_biz()
    try:
        row = con.execute("SELECT id FROM custom_stock_modules WHERE id=?", (module_id,)).fetchone()
        if not row:
            abort(404)
        con.execute("DELETE FROM custom_stock_modules WHERE id=?", (module_id,))
        con.commit()
    finally:
        con.close()
    flash("Gestion supprimee.", "success")
    return redirect(url_for("tools.tools_custom_stock_page"))
@bp.post("/outils/gestion/modules/<int:module_id>/fields/add")
def tools_custom_field_add(module_id: int):
    label = (request.form.get("label") or "").strip()
    field_key_input = (request.form.get("field_key") or "").strip()
    field_type = (request.form.get("field_type") or "text").strip().lower()
    field_type = field_type if field_type in ("text", "number", "select", "date", "boolean") else "text"
    sort_order = _safe_int(request.form.get("sort_order"), 0)
    is_required = 1 if str(request.form.get("is_required") or "").strip().lower() in ("1", "true", "on", "yes") else 0
    show_in_table = 1 if str(request.form.get("show_in_table") or "1").strip().lower() in ("1", "true", "on", "yes") else 0
    options = _custom_parse_options(request.form.get("field_options"))

    if not label:
        flash("Libelle du champ obligatoire.", "warning")
        return redirect(url_for("tools.tools_custom_stock_page", m=module_id))

    field_key = _custom_field_key(field_key_input or label)
    if not field_key:
        field_key = f"field_{int(time.time())}"
    if field_type == "select" and not options:
        flash("Pour le type select, ajoute des options (ex: S,M,L).", "warning")
        return redirect(url_for("tools.tools_custom_stock_page", m=module_id))

    con = _con_biz()
    try:
        row = con.execute("SELECT id FROM custom_stock_modules WHERE id=?", (module_id,)).fetchone()
        if not row:
            abort(404)
        con.execute("""
            INSERT INTO custom_stock_fields(
                module_id, field_key, label, field_type, options_json,
                is_required, show_in_table, sort_order, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            int(module_id),
            field_key,
            label[:80],
            field_type,
            json.dumps(options, ensure_ascii=False) if options else "",
            int(is_required),
            int(show_in_table),
            int(sort_order),
        ))
        con.execute(
            "UPDATE custom_stock_modules SET updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (module_id,)
        )
        con.commit()
    except sqlite3.IntegrityError:
        con.rollback()
        flash("Ce code champ existe deja pour cette gestion.", "warning")
        return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
    finally:
        con.close()

    flash("Champ ajoute.", "success")
    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
@bp.post("/outils/gestion/modules/<int:module_id>/fields/<int:field_id>/delete")
def tools_custom_field_delete(module_id: int, field_id: int):
    con = _con_biz()
    try:
        row = con.execute(
            "SELECT id FROM custom_stock_fields WHERE id=? AND module_id=?",
            (field_id, module_id)
        ).fetchone()
        if not row:
            abort(404)
        con.execute("DELETE FROM custom_stock_fields WHERE id=? AND module_id=?", (field_id, module_id))
        con.execute("UPDATE custom_stock_modules SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (module_id,))
        con.commit()
    finally:
        con.close()
    flash("Champ supprime.", "success")
    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
@bp.post("/outils/gestion/modules/<int:module_id>/items/add")
def tools_custom_item_add(module_id: int):
    name = (request.form.get("name") or "").strip()
    ref = (request.form.get("ref") or "").strip()
    qty = max(0.0, _safe_float(request.form.get("qty"), 0.0))
    min_qty = max(0.0, _safe_float(request.form.get("min_qty"), 0.0))
    price = max(0.0, _safe_float(request.form.get("price"), 0.0))

    if not name:
        flash("Nom article obligatoire.", "warning")
        return redirect(url_for("tools.tools_custom_stock_page", m=module_id))

    con = _con_biz()
    try:
        module = con.execute("SELECT id FROM custom_stock_modules WHERE id=?", (module_id,)).fetchone()
        if not module:
            abort(404)
        fields = _custom_load_fields(con, module_id)

        custom_data = {}
        for field in fields:
            key = str(field.get("field_key") or "").strip()
            ftype = str(field.get("field_type") or "text").strip().lower()
            is_required = int(field.get("is_required") or 0) == 1
            form_key = f"field_{key}"

            if ftype == "boolean":
                value = 1 if str(request.form.get(form_key) or "").strip().lower() in ("1", "true", "on", "yes") else 0
                if is_required and value != 1:
                    flash(f"Le champ '{field.get('label')}' doit etre active.", "warning")
                    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
                custom_data[key] = value
                continue

            raw = (request.form.get(form_key) or "").strip()
            if is_required and not raw:
                flash(f"Le champ '{field.get('label')}' est obligatoire.", "warning")
                return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
            if not raw:
                continue

            if ftype == "number":
                try:
                    value = float(raw.replace(",", "."))
                except Exception:
                    flash(f"Le champ '{field.get('label')}' doit etre numerique.", "warning")
                    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
                custom_data[key] = value
                continue

            if ftype == "date":
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
                    flash(f"Le champ '{field.get('label')}' doit etre au format YYYY-MM-DD.", "warning")
                    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
                custom_data[key] = raw
                continue

            if ftype == "select":
                options = field.get("options") or []
                if options and raw not in options:
                    flash(f"Valeur invalide pour '{field.get('label')}'.", "warning")
                    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
                custom_data[key] = raw
                continue

            custom_data[key] = raw[:180]

        con.execute("""
            INSERT INTO custom_stock_items(
                module_id, name, ref, qty, min_qty, price, data_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            int(module_id),
            name[:120],
            ref[:80],
            float(qty),
            float(min_qty),
            float(price),
            json.dumps(custom_data, ensure_ascii=False),
        ))
        con.execute("UPDATE custom_stock_modules SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (module_id,))
        con.commit()
    finally:
        con.close()

    flash("Article ajoute dans la gestion.", "success")
    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
@bp.post("/outils/gestion/modules/<int:module_id>/items/<int:item_id>/bump")
def tools_custom_item_bump(module_id: int, item_id: int):
    delta = _safe_float(request.form.get("delta"), 1.0)
    con = _con_biz()
    try:
        row = con.execute(
            "SELECT id FROM custom_stock_items WHERE id=? AND module_id=?",
            (item_id, module_id)
        ).fetchone()
        if not row:
            abort(404)
        con.execute("""
            UPDATE custom_stock_items
            SET qty = MAX(0, COALESCE(qty,0) + ?),
                updated_at=CURRENT_TIMESTAMP
            WHERE id=? AND module_id=?
        """, (float(delta), item_id, module_id))
        con.commit()
    finally:
        con.close()
    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
@bp.post("/outils/gestion/modules/<int:module_id>/items/<int:item_id>/delete")
def tools_custom_item_delete(module_id: int, item_id: int):
    con = _con_biz()
    try:
        row = con.execute(
            "SELECT id FROM custom_stock_items WHERE id=? AND module_id=?",
            (item_id, module_id)
        ).fetchone()
        if not row:
            abort(404)
        con.execute("DELETE FROM custom_stock_items WHERE id=? AND module_id=?", (item_id, module_id))
        con.execute("UPDATE custom_stock_modules SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (module_id,))
        con.commit()
    finally:
        con.close()
    flash("Article supprime.", "success")
    return redirect(url_for("tools.tools_custom_stock_page", m=module_id))
@bp.get("/outils/gestion/modules/<int:module_id>/export.csv")
def tools_custom_export_csv(module_id: int):
    con = _con_biz()
    try:
        module = con.execute("SELECT * FROM custom_stock_modules WHERE id=?", (module_id,)).fetchone()
        if not module:
            abort(404)
        module = dict(module)
        fields = _custom_load_fields(con, module_id)
        items = [dict(r) for r in con.execute("""
            SELECT *
            FROM custom_stock_items
            WHERE module_id=?
            ORDER BY id DESC
        """, (module_id,)).fetchall()]
    finally:
        con.close()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    headers = ["id", "nom", "ref", "quantite", "seuil", "prix_eur"] + [str(f.get("label") or f.get("field_key")) for f in fields]
    writer.writerow(headers)
    for it in reversed(items):
        data = _custom_data_to_dict(it.get("data_json"))
        row = [
            int(it.get("id") or 0),
            it.get("name") or "",
            it.get("ref") or "",
            it.get("qty") or 0,
            it.get("min_qty") or 0,
            it.get("price") or 0,
        ]
        for f in fields:
            row.append(_custom_display_value(data.get(f.get("field_key")), f.get("field_type")))
        writer.writerow(row)

    csv_data = "\ufeff" + output.getvalue()
    module_slug = _custom_field_key(module.get("name") or "") or f"module_{module_id}"
    filename = f"gestion_{module_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
@bp.get("/outils/catalogues")
def tools_catalogs_page():
    con = _con_biz()
    try:
        catalogs = [dict(r) for r in con.execute("""
            SELECT c.*,
                   COALESCE((SELECT COUNT(1) FROM catalog_items i WHERE i.catalog_id=c.id),0) AS items_count,
                   COALESCE((SELECT COUNT(1) FROM catalog_files f WHERE f.catalog_id=c.id),0) AS files_count
            FROM catalogs c
            ORDER BY c.id DESC
        """).fetchall()]
    finally:
        con.close()
    return render_template("tools_catalogs.html", title="Catalogues", catalogs=catalogs)
@bp.post("/outils/catalogues/add")
def tools_catalogs_add():
    name = (request.form.get("name") or "").strip()
    business_type = (request.form.get("business_type") or "").strip()
    description = (request.form.get("description") or "").strip()

    if not name or not business_type:
        flash("Nom et type de boutique obligatoires.", "warning")
        return redirect(url_for("tools.tools_catalogs_page"))

    token = _new_catalog_token()
    con = _con_biz()
    try:
        cur = con.execute("""
            INSERT INTO catalogs(name, business_type, description, is_public, public_token, updated_at)
            VALUES (?, ?, ?, 0, ?, CURRENT_TIMESTAMP)
        """, (name, business_type, description, token))
        catalog_id = int(cur.lastrowid)
        con.commit()
    finally:
        con.close()

    flash("Catalogue cree.", "success")
    return redirect(url_for("tools.tools_catalog_detail_page", catalog_id=catalog_id))
@bp.get("/outils/catalogues/<int:catalog_id>")
def tools_catalog_detail_page(catalog_id: int):
    catalog = _get_catalog(catalog_id)
    if not catalog:
        abort(404)
    items = _catalog_items_with_files(catalog_id)
    public_url = url_for("catalog_public.catalog_public_page", token=catalog["public_token"], _external=True)
    return render_template(
        "tools_catalog_detail.html",
        title=f"Catalogue - {catalog['name']}",
        catalog=catalog,
        items=items,
        public_url=public_url,
    )
@bp.post("/outils/catalogues/<int:catalog_id>/toggle-public")
def tools_catalog_toggle_public(catalog_id: int):
    catalog = _get_catalog(catalog_id)
    if not catalog:
        abort(404)
    desired = 1 if str(request.form.get("is_public") or "0").strip() in ("1", "true", "on", "yes") else 0
    con = _con_biz()
    try:
        con.execute(
            "UPDATE catalogs SET is_public=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (desired, catalog_id)
        )
        con.commit()
    finally:
        con.close()
    flash("Partage public active." if desired else "Partage public desactive.", "success")
    return redirect(url_for("tools.tools_catalog_detail_page", catalog_id=catalog_id))
@bp.post("/outils/catalogues/<int:catalog_id>/items/add")
def tools_catalog_item_add(catalog_id: int):
    catalog = _get_catalog(catalog_id)
    if not catalog:
        abort(404)

    title = (request.form.get("title") or "").strip()
    sku = (request.form.get("sku") or "").strip()
    sale_sheet = (request.form.get("sale_sheet") or "").strip()
    description = (request.form.get("description") or "").strip()
    tags = (request.form.get("tags") or "").strip()
    status = (request.form.get("status") or "draft").strip().lower()
    status = status if status in ("draft", "ready", "published") else "draft"
    price = max(0.0, _safe_float(request.form.get("price"), 0.0))

    if not title:
        flash("Titre de fiche obligatoire.", "warning")
        return redirect(url_for("tools.tools_catalog_detail_page", catalog_id=catalog_id))

    con = _con_biz()
    try:
        cur = con.execute("""
            INSERT INTO catalog_items(
                catalog_id, title, sku, sale_sheet, description, tags, price, status, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (catalog_id, title, sku, sale_sheet, description, tags, price, status))
        item_id = int(cur.lastrowid)

        saved_count = 0
        files = request.files.getlist("files")
        for f in files:
            if not f or not getattr(f, "filename", ""):
                continue
            original_name = (f.filename or "").strip()
            if not _catalog_allowed_file(original_name):
                continue
            safe_name = secure_filename(original_name)
            if not safe_name:
                continue
            unique_name = f"{catalog_id}/{item_id}/{uuid.uuid4().hex}_{safe_name}"
            abs_path = _catalog_file_abs_path(unique_name)
            if not abs_path:
                continue
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            f.save(abs_path)
            size_bytes = os.path.getsize(abs_path) if os.path.isfile(abs_path) else 0
            mime = (getattr(f, "mimetype", "") or "").strip()
            kind = "photo" if _catalog_is_image(original_name, mime) else "file"
            con.execute("""
                INSERT INTO catalog_files(
                    catalog_id, item_id, file_kind, file_name, original_name, mime_type, size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (catalog_id, item_id, kind, unique_name, original_name, mime, int(size_bytes)))
            saved_count += 1

        con.commit()
    finally:
        con.close()

    flash(f"Fiche ajoutee. Fichiers enregistres: {saved_count}.", "success")
    return redirect(url_for("tools.tools_catalog_detail_page", catalog_id=catalog_id))
@bp.post("/outils/catalogues/<int:catalog_id>/items/<int:item_id>/delete")
def tools_catalog_item_delete(catalog_id: int, item_id: int):
    con = _con_biz()
    try:
        row = con.execute(
            "SELECT id FROM catalog_items WHERE id=? AND catalog_id=?",
            (item_id, catalog_id)
        ).fetchone()
        if not row:
            abort(404)
        file_rows = con.execute(
            "SELECT file_name FROM catalog_files WHERE item_id=? AND catalog_id=?",
            (item_id, catalog_id)
        ).fetchall()
        con.execute("DELETE FROM catalog_items WHERE id=? AND catalog_id=?", (item_id, catalog_id))
        con.commit()
    finally:
        con.close()

    for f in file_rows:
        try:
            abs_path = _catalog_file_abs_path(f["file_name"])
            if abs_path and os.path.isfile(abs_path):
                os.remove(abs_path)
        except Exception:
            pass

    flash("Fiche supprimee.", "success")
    return redirect(url_for("tools.tools_catalog_detail_page", catalog_id=catalog_id))
@bp.post("/outils/catalogues/<int:catalog_id>/files/<int:file_id>/delete")
def tools_catalog_file_delete(catalog_id: int, file_id: int):
    con = _con_biz()
    try:
        row = con.execute(
            "SELECT id FROM catalog_files WHERE id=? AND catalog_id=?",
            (file_id, catalog_id)
        ).fetchone()
    finally:
        con.close()
    if not row:
        abort(404)
    _catalog_delete_file_record(file_id)
    flash("Fichier supprime.", "success")
    return redirect(url_for("tools.tools_catalog_detail_page", catalog_id=catalog_id))
@bp.post("/outils/catalogues/<int:catalog_id>/delete")
def tools_catalog_delete(catalog_id: int):
    catalog = _get_catalog(catalog_id)
    if not catalog:
        abort(404)

    con = _con_biz()
    try:
        file_rows = con.execute(
            "SELECT file_name FROM catalog_files WHERE catalog_id=?",
            (catalog_id,)
        ).fetchall()
        con.execute("DELETE FROM catalogs WHERE id=?", (catalog_id,))
        con.commit()
    finally:
        con.close()

    for f in file_rows:
        try:
            abs_path = _catalog_file_abs_path(f["file_name"])
            if abs_path and os.path.isfile(abs_path):
                os.remove(abs_path)
        except Exception:
            pass

    try:
        catalog_dir = _catalog_file_abs_path(str(catalog_id))
        if catalog_dir and os.path.isdir(catalog_dir):
            shutil.rmtree(catalog_dir, ignore_errors=True)
    except Exception:
        pass

    flash("Catalogue supprime.", "success")
    return redirect(url_for("tools.tools_catalogs_page"))
@bp.get("/outils/catalogues/files/<int:file_id>")
def tools_catalog_file(file_id: int):
    con = _con_biz()
    try:
        row = con.execute("SELECT * FROM catalog_files WHERE id=?", (file_id,)).fetchone()
    finally:
        con.close()
    if not row:
        abort(404)
    abs_path = _catalog_file_abs_path(row["file_name"])
    if not abs_path or not os.path.isfile(abs_path):
        abort(404)
    return send_file(abs_path, as_attachment=False, download_name=row["original_name"])
