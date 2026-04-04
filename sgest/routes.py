"""Enregistrement des routes (extrait de l’ancien app.py monolithique)."""
from __future__ import annotations

from .services import *  # noqa: F401,F403


def register_routes(app) -> None:
    """Attache les vues à ``app`` ; les noms d’endpoints restent identiques."""
    @app.get("/login")
    def login():
        if _session_is_authenticated():
            return redirect(url_for("dashboard"))
        return render_template("login.html", title="Connexion", next_path=_safe_next_path(), weak_default=_is_default_admin_password())
    @app.post("/login")
    def login_post():
        ip = _current_user_ip()
        key = f"{ip}:{(request.form.get('username') or '').strip().lower()}"
        if _rate_limited(_LOGIN_RATE_BUCKET, key, limit=8, window_sec=300, consume=False):
            return ("Trop de tentatives. Reessaie dans 5 minutes.", 429)

        if str(request.form.get("login_slide") or "0").strip() != "1":
            flash("Fais glisser le bouton de connexion pour valider.", "warning")
            return render_template("login.html", title="Connexion", next_path=_safe_next_path(), weak_default=_is_default_admin_password()), 400

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = _get_auth_user_by_username(username)
        auth_ok = False
        if user and int(user.get("is_active") or 0) == 1:
            try:
                auth_ok = check_password_hash(str(user.get("password_hash") or ""), str(password or ""))
            except Exception:
                auth_ok = False

        # Backward compatibility with legacy single-admin auth.
        if not auth_ok:
            legacy_ok = (hmac.compare_digest(username, _admin_username()) and _check_admin_password(password))
            if legacy_ok:
                legacy_user = _get_auth_user_by_username(username)
                if not legacy_user:
                    con = _con_biz()
                    try:
                        con.execute("""
                            INSERT OR IGNORE INTO auth_users(username, password_hash, role, is_active, updated_at)
                            VALUES (?, ?, 'admin', 1, CURRENT_TIMESTAMP)
                        """, (_normalize_username(username) or "admin", generate_password_hash(password)))
                        con.commit()
                    finally:
                        con.close()
                    legacy_user = _get_auth_user_by_username(username)
                if legacy_user and int(legacy_user.get("is_active") or 0) == 1:
                    user = legacy_user
                    auth_ok = True

        if not auth_ok or not user:
            _rate_limited(_LOGIN_RATE_BUCKET, key, limit=8, window_sec=300, consume=True)
            flash("Identifiants invalides.", "warning")
            return render_template("login.html", title="Connexion", next_path=_safe_next_path(), weak_default=_is_default_admin_password()), 401

        if int(user.get("is_active") or 1) != 1:
            _rate_limited(_LOGIN_RATE_BUCKET, key, limit=8, window_sec=300, consume=True)
            flash("Compte desactive.", "warning")
            return render_template("login.html", title="Connexion", next_path=_safe_next_path(), weak_default=_is_default_admin_password()), 401

        if key in _LOGIN_RATE_BUCKET:
            _LOGIN_RATE_BUCKET.pop(key, None)
        _auth_login_user(user)

        if _is_default_admin_password():
            flash("Securite: change SGEST_ADMIN_PASSWORD rapidement.", "warning")
        return redirect(_safe_next_path())
    @app.post("/auth/recovery/request")
    def auth_recovery_request():
        ip = _current_user_ip()
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        key = f"{ip}:{_normalize_username(username)}"
        if _rate_limited(_RECOVERY_RATE_BUCKET, key, limit=5, window_sec=900, consume=False):
            flash("Trop de demandes de recuperation. Reessaie plus tard.", "warning")
            return redirect(url_for("login"))

        user = _get_auth_user_by_username(username)
        if user and int(user.get("is_active") or 0) == 1:
            user_email = str(user.get("email") or "").strip().lower()
            if user_email and hmac.compare_digest(user_email, email):
                code = f"{secrets.randbelow(1000000):06d}"
                exp = datetime.now() + timedelta(minutes=15)
                _set_recovery_code_for_user(int(user["id"]), code, exp)
                sent, err = _send_recovery_email(user_email, user.get("username") or "", code)
                if not sent:
                    _rate_limited(_RECOVERY_RATE_BUCKET, key, limit=5, window_sec=900, consume=True)
                    flash("Email non envoye (SMTP a configurer dans Systeme > Integrations).", "warning")
                    return redirect(url_for("login"))
        flash("Si le compte existe, un code de recuperation a ete envoye par email.", "success")
        return redirect(url_for("login"))
    @app.post("/auth/recovery/reset")
    def auth_recovery_reset():
        username = (request.form.get("username") or "").strip()
        code = (request.form.get("code") or "").strip()
        new_pw = request.form.get("new_password") or ""
        confirm_pw = request.form.get("confirm_password") or ""

        user = _get_auth_user_by_username(username)
        if not user or int(user.get("is_active") or 0) != 1:
            flash("Demande invalide.", "warning")
            return redirect(url_for("login"))
        if new_pw != confirm_pw:
            flash("La confirmation du mot de passe ne correspond pas.", "warning")
            return redirect(url_for("login"))
        errs = _password_strength_errors(new_pw)
        if errs:
            flash("Mot de passe trop faible: " + " ".join(errs), "warning")
            return redirect(url_for("login"))

        code_hash = str(user.get("recovery_code_hash") or "")
        exp_txt = str(user.get("recovery_code_expires_at") or "").strip()
        if not code_hash or not exp_txt:
            flash("Code invalide ou expire.", "warning")
            return redirect(url_for("login"))
        try:
            exp_dt = datetime.strptime(exp_txt, "%Y-%m-%d %H:%M:%S")
        except Exception:
            exp_dt = datetime.fromtimestamp(0)
        if datetime.now() > exp_dt:
            _clear_recovery_code_for_user(int(user["id"]))
            flash("Code expire. Redemande un nouveau code.", "warning")
            return redirect(url_for("login"))
        ok = False
        try:
            ok = check_password_hash(code_hash, code)
        except Exception:
            ok = False
        if not ok:
            flash("Code invalide.", "warning")
            return redirect(url_for("login"))

        _set_auth_user_password(int(user["id"]), new_pw)
        _clear_recovery_code_for_user(int(user["id"]))
        flash("Mot de passe reinitialise. Connecte-toi.", "success")
        return redirect(url_for("login"))
    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
    @app.get("/ping")
    def ping(): return jsonify(ok=True, t=int(time.time()))
    @app.route("/")
    def dashboard():
        bro = _dashboard_stock_summary("broderie")
        impr = _dashboard_stock_summary("impression3d")
        stocks = [bro, impr]
        biz = _biz_totals()

        return render_template(
            "index.html",
            title="Dashboard",
            stocks=stocks,
            total_refs=bro["refs"] + impr["refs"],
            total_units=round(float(bro["units"]) + float(impr["units"]), 3),
            total_low_alerts=bro["low_count"] + impr["low_count"],
            total_gain=biz["profit"],
            total_sales=biz["sale_count"],
        )
    @app.get("/outils/calculateur")
    def tools_calculator_page():
        return render_template(
            "tools_calculator.html",
            title="Calculateur",
            bro_products=_load_bro_products(),
            spools=_load_3d_spools(),
        )
    @app.get("/outils/gain")
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
    @app.post("/outils/gain/record")
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
            return redirect(url_for("tools_gain_page", period=period))
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
                    return redirect(url_for("tools_gain_page", period=period))

                available = float(item["qty"] or 0.0)
                if qty_units > available + 1e-9:
                    flash(f"Stock insuffisant (disponible: {available}).", "warning")
                    return redirect(url_for("tools_gain_page", period=period))

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
                    return redirect(url_for("tools_gain_page", period=period))

                total_grams = grams_per_unit * qty_units
                if total_grams <= 0:
                    flash("Indique un grammage > 0 pour la 3D.", "warning")
                    return redirect(url_for("tools_gain_page", period=period))

                available_grams = float(item["qty"] or 0.0) * SPOOL_BASE_GRAMS
                if total_grams > available_grams + 1e-9:
                    flash(f"Stock insuffisant (disponible: {int(round(available_grams))} g).", "warning")
                    return redirect(url_for("tools_gain_page", period=period))

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
        return redirect(url_for("tools_gain_page", period=period))
    @app.post("/outils/gain/reset")
    def tools_gain_reset():
        period = _normalize_gain_period(request.form.get("period") or request.args.get("period") or "month")
        con = _con_biz()
        try:
            con.execute("DELETE FROM gain_events")
            con.commit()
        finally:
            con.close()
        flash("Historique des gains vide.", "success")
        return redirect(url_for("tools_gain_page", period=period))
    @app.get("/outils/gain/export.csv")
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
    @app.get("/api/gain/summary")
    def api_gain_summary():
        period = _normalize_gain_period(request.args.get("period", "all"))
        return jsonify(period=period, **_biz_totals(period=period))
    @app.get("/outils/gestion")
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
    @app.post("/outils/gestion/modules/add")
    def tools_custom_module_add():
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        icon = (request.form.get("icon") or "").strip()
        if not name:
            flash("Nom de gestion obligatoire.", "warning")
            return redirect(url_for("tools_custom_stock_page"))

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
        return redirect(url_for("tools_custom_stock_page", m=module_id))
    @app.post("/outils/gestion/modules/<int:module_id>/delete")
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
        return redirect(url_for("tools_custom_stock_page"))
    @app.post("/outils/gestion/modules/<int:module_id>/fields/add")
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
            return redirect(url_for("tools_custom_stock_page", m=module_id))

        field_key = _custom_field_key(field_key_input or label)
        if not field_key:
            field_key = f"field_{int(time.time())}"
        if field_type == "select" and not options:
            flash("Pour le type select, ajoute des options (ex: S,M,L).", "warning")
            return redirect(url_for("tools_custom_stock_page", m=module_id))

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
            return redirect(url_for("tools_custom_stock_page", m=module_id))
        finally:
            con.close()

        flash("Champ ajoute.", "success")
        return redirect(url_for("tools_custom_stock_page", m=module_id))
    @app.post("/outils/gestion/modules/<int:module_id>/fields/<int:field_id>/delete")
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
        return redirect(url_for("tools_custom_stock_page", m=module_id))
    @app.post("/outils/gestion/modules/<int:module_id>/items/add")
    def tools_custom_item_add(module_id: int):
        name = (request.form.get("name") or "").strip()
        ref = (request.form.get("ref") or "").strip()
        qty = max(0.0, _safe_float(request.form.get("qty"), 0.0))
        min_qty = max(0.0, _safe_float(request.form.get("min_qty"), 0.0))
        price = max(0.0, _safe_float(request.form.get("price"), 0.0))

        if not name:
            flash("Nom article obligatoire.", "warning")
            return redirect(url_for("tools_custom_stock_page", m=module_id))

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
                        return redirect(url_for("tools_custom_stock_page", m=module_id))
                    custom_data[key] = value
                    continue

                raw = (request.form.get(form_key) or "").strip()
                if is_required and not raw:
                    flash(f"Le champ '{field.get('label')}' est obligatoire.", "warning")
                    return redirect(url_for("tools_custom_stock_page", m=module_id))
                if not raw:
                    continue

                if ftype == "number":
                    try:
                        value = float(raw.replace(",", "."))
                    except Exception:
                        flash(f"Le champ '{field.get('label')}' doit etre numerique.", "warning")
                        return redirect(url_for("tools_custom_stock_page", m=module_id))
                    custom_data[key] = value
                    continue

                if ftype == "date":
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
                        flash(f"Le champ '{field.get('label')}' doit etre au format YYYY-MM-DD.", "warning")
                        return redirect(url_for("tools_custom_stock_page", m=module_id))
                    custom_data[key] = raw
                    continue

                if ftype == "select":
                    options = field.get("options") or []
                    if options and raw not in options:
                        flash(f"Valeur invalide pour '{field.get('label')}'.", "warning")
                        return redirect(url_for("tools_custom_stock_page", m=module_id))
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
        return redirect(url_for("tools_custom_stock_page", m=module_id))
    @app.post("/outils/gestion/modules/<int:module_id>/items/<int:item_id>/bump")
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
        return redirect(url_for("tools_custom_stock_page", m=module_id))
    @app.post("/outils/gestion/modules/<int:module_id>/items/<int:item_id>/delete")
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
        return redirect(url_for("tools_custom_stock_page", m=module_id))
    @app.get("/outils/gestion/modules/<int:module_id>/export.csv")
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
    @app.get("/outils/catalogues")
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
    @app.post("/outils/catalogues/add")
    def tools_catalogs_add():
        name = (request.form.get("name") or "").strip()
        business_type = (request.form.get("business_type") or "").strip()
        description = (request.form.get("description") or "").strip()

        if not name or not business_type:
            flash("Nom et type de boutique obligatoires.", "warning")
            return redirect(url_for("tools_catalogs_page"))

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
        return redirect(url_for("tools_catalog_detail_page", catalog_id=catalog_id))
    @app.get("/outils/catalogues/<int:catalog_id>")
    def tools_catalog_detail_page(catalog_id: int):
        catalog = _get_catalog(catalog_id)
        if not catalog:
            abort(404)
        items = _catalog_items_with_files(catalog_id)
        public_url = url_for("catalog_public_page", token=catalog["public_token"], _external=True)
        return render_template(
            "tools_catalog_detail.html",
            title=f"Catalogue - {catalog['name']}",
            catalog=catalog,
            items=items,
            public_url=public_url,
        )
    @app.post("/outils/catalogues/<int:catalog_id>/toggle-public")
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
        return redirect(url_for("tools_catalog_detail_page", catalog_id=catalog_id))
    @app.post("/outils/catalogues/<int:catalog_id>/items/add")
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
            return redirect(url_for("tools_catalog_detail_page", catalog_id=catalog_id))

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
        return redirect(url_for("tools_catalog_detail_page", catalog_id=catalog_id))
    @app.post("/outils/catalogues/<int:catalog_id>/items/<int:item_id>/delete")
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
        return redirect(url_for("tools_catalog_detail_page", catalog_id=catalog_id))
    @app.post("/outils/catalogues/<int:catalog_id>/files/<int:file_id>/delete")
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
        return redirect(url_for("tools_catalog_detail_page", catalog_id=catalog_id))
    @app.post("/outils/catalogues/<int:catalog_id>/delete")
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
        return redirect(url_for("tools_catalogs_page"))
    @app.get("/outils/catalogues/files/<int:file_id>")
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
    @app.get("/catalogue/public/<token>")
    def catalog_public_page(token: str):
        con = _con_biz()
        try:
            cat = con.execute("""
                SELECT * FROM catalogs
                WHERE public_token=? AND is_public=1
                LIMIT 1
            """, (token,)).fetchone()
            if not cat:
                abort(404)
            catalog = dict(cat)
        finally:
            con.close()

        items = _catalog_items_with_files(int(catalog["id"]))
        return render_template("catalog_public.html", title=f"Catalogue {catalog['name']}", catalog=catalog, items=items)
    @app.get("/catalogue/public/<token>/files/<int:file_id>")
    def catalog_public_file(token: str, file_id: int):
        con = _con_biz()
        try:
            row = con.execute("""
                SELECT f.*
                FROM catalog_files f
                JOIN catalogs c ON c.id = f.catalog_id
                WHERE f.id=? AND c.public_token=? AND c.is_public=1
                LIMIT 1
            """, (file_id, token)).fetchone()
        finally:
            con.close()
        if not row:
            abort(404)
        abs_path = _catalog_file_abs_path(row["file_name"])
        if not abs_path or not os.path.isfile(abs_path):
            abort(404)
        return send_file(abs_path, as_attachment=False, download_name=row["original_name"])
    @app.route("/system")
    def system_page():
        return render_template("system.html", title="Systeme", disk=get_disk_stats("/"), ram=get_ram_stats(),
                               last_backup=last_backup_dt(), machine=get_machine_specs(),
                               backups=list_backups(BACKUP_KEEP_MAX),
                               backups_limit=BACKUP_KEEP_MAX,
                               backup_timer=backup_scheduler_status(),
                               backup_monitor=backup_monitor_summary())
    @app.get("/system/integrations")
    def system_integrations_page():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/integrations"))
        smtp = _smtp_config()
        return render_template(
            "system_integrations.html",
            title="Integrations",
            smtp_host=smtp["host"],
            smtp_port=smtp["port"],
            smtp_user=smtp["user"],
            smtp_from=smtp["from_email"],
            smtp_tls=smtp["use_tls"],
            smtp_password_set=bool(smtp["pwd"]),
            smtp_ready=_smtp_ready(),
            require_webhook_token=_setting_get_bool("require_webhook_token", _env_bool("SGEST_REQUIRE_WEBHOOK_TOKEN", True)),
            webhook_token_set=bool(_integration_api_value("webhook_token")),
            etsy_webhook_token_set=bool(_integration_api_value("etsy_webhook_token")),
            vinted_webhook_token_set=bool(_integration_api_value("vinted_webhook_token")),
            etsy_api_key_set=bool(_integration_api_value("etsy_api_key")),
            etsy_api_secret_set=bool(_integration_api_value("etsy_api_secret")),
            vinted_api_key_set=bool(_integration_api_value("vinted_api_key")),
            vinted_api_secret_set=bool(_integration_api_value("vinted_api_secret")),
        )
    @app.post("/system/integrations/smtp")
    def system_integrations_smtp_update():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/integrations"))
        host = (request.form.get("smtp_host") or "").strip()
        port = _safe_int(request.form.get("smtp_port") or "587", 587)
        smtp_user = (request.form.get("smtp_user") or "").strip()
        smtp_from = (request.form.get("smtp_from") or "").strip()
        smtp_tls = "1" if str(request.form.get("smtp_tls") or "").strip().lower() in ("1", "true", "yes", "on") else "0"
        smtp_password = str(request.form.get("smtp_password") or "").strip()

        _setting_set("smtp_host", host)
        _setting_set("smtp_port", str(port))
        _setting_set("smtp_user", smtp_user)
        _setting_set("smtp_from", smtp_from)
        _setting_set("smtp_tls", smtp_tls)
        if smtp_password:
            _setting_set("smtp_password", smtp_password)

        flash("SMTP mis a jour.", "success")
        return redirect(url_for("system_integrations_page"))
    @app.post("/system/integrations/apis")
    def system_integrations_apis_update():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/integrations"))

        require_token = "1" if str(request.form.get("require_webhook_token") or "").strip().lower() in ("1", "true", "yes", "on") else "0"
        _setting_set("require_webhook_token", require_token)

        updates = {
            "webhook_token": request.form.get("webhook_token"),
            "etsy_webhook_token": request.form.get("etsy_webhook_token"),
            "vinted_webhook_token": request.form.get("vinted_webhook_token"),
            "etsy_api_key": request.form.get("etsy_api_key"),
            "etsy_api_secret": request.form.get("etsy_api_secret"),
            "vinted_api_key": request.form.get("vinted_api_key"),
            "vinted_api_secret": request.form.get("vinted_api_secret"),
        }
        for k, v in updates.items():
            vv = str(v or "").strip()
            if vv:
                _setting_set(k, vv)

        flash("Integrations mises a jour.", "success")
        return redirect(url_for("system_integrations_page"))
    @app.get("/system/profile")
    def system_profile_page():
        current_user = _current_auth_user()
        if not current_user:
            return redirect(url_for("login", next="/system/profile"))
        local = _local_admin_record()
        is_admin = _auth_user_can_manage_users(current_user)
        return render_template(
            "system_profile.html",
            title="Profil",
            admin_user=current_user.get("username") or _admin_username(),
            current_user=current_user,
            users=_list_auth_users(200) if is_admin else [],
            is_admin=is_admin,
            theme_color=_valid_hex_color(current_user.get("theme_color") or "#14b8a6"),
            theme_color_secondary=_valid_hex_color(
                current_user.get("theme_color_secondary") or "",
                _shade_hex(_valid_hex_color(current_user.get("theme_color") or "#14b8a6"), 1.18),
            ),
            local_auth_enabled=bool(local and str(local.get("password_hash") or "").strip()),
            default_password=_is_default_admin_password(),
        )
    @app.post("/system/profile/password")
    def system_profile_password_update():
        current_user = _current_auth_user()
        if not current_user:
            return redirect(url_for("login", next="/system/profile"))
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("new_password") or ""
        confirm_pw = request.form.get("confirm_password") or ""

        pw_ok = False
        try:
            pw_ok = check_password_hash(str(current_user.get("password_hash") or ""), current_pw)
        except Exception:
            pw_ok = False
        if not pw_ok and str(current_user.get("username") or "") == _admin_username():
            pw_ok = _check_admin_password(current_pw)
        if not pw_ok:
            flash("Mot de passe actuel invalide.", "warning")
            return redirect(url_for("system_profile_page"))
        if new_pw != confirm_pw:
            flash("La confirmation ne correspond pas.", "warning")
            return redirect(url_for("system_profile_page"))
        if hmac.compare_digest(current_pw, new_pw):
            flash("Le nouveau mot de passe doit etre different de l'actuel.", "warning")
            return redirect(url_for("system_profile_page"))

        errs = _password_strength_errors(new_pw)
        if errs:
            flash("Mot de passe trop faible: " + " ".join(errs), "warning")
            return redirect(url_for("system_profile_page"))

        _set_auth_user_password(int(current_user["id"]), new_pw)
        if str(current_user.get("username") or "") == _admin_username():
            _set_local_admin_password(new_pw)
        flash("Mot de passe mis a jour avec succes.", "success")
        return redirect(url_for("system_profile_page"))
    @app.post("/system/profile/theme")
    def system_profile_theme_update():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/profile"))
        color = request.form.get("theme_color") or "#14b8a6"
        secondary = request.form.get("theme_color_secondary") or ""
        _set_auth_user_theme(int(user["id"]), color, secondary)
        flash("Theme mis a jour.", "success")
        return redirect(url_for("system_profile_page"))
    @app.post("/system/profile/avatar")
    def system_profile_avatar_update():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/profile"))
        f = request.files.get("avatar")
        if not f or not str(f.filename or "").strip():
            flash("Selectionne une image.", "warning")
            return redirect(url_for("system_profile_page"))

        filename = secure_filename(str(f.filename or ""))
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_AVATAR_EXT:
            flash("Format image invalide (png, jpg, jpeg, webp, gif).", "warning")
            return redirect(url_for("system_profile_page"))

        uid = int(user["id"])
        out_name = f"user_{uid}_{uuid.uuid4().hex[:12]}.{ext}"
        out_rel = f"{AVATAR_UPLOAD_REL}/{out_name}"
        out_abs = _avatar_storage_dir() / out_name
        try:
            f.save(str(out_abs))
            old_rel = str(user.get("avatar_path") or "").strip()
            _set_auth_user_avatar(uid, out_rel)
            _delete_avatar_file(old_rel)
            flash("Photo de profil mise a jour.", "success")
        except Exception:
            flash("Impossible de mettre a jour la photo.", "warning")
        return redirect(url_for("system_profile_page"))
    @app.post("/system/profile/avatar/reset")
    def system_profile_avatar_reset():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/profile"))
        uid = int(user["id"])
        old_rel = str(user.get("avatar_path") or "").strip()
        _set_auth_user_avatar(uid, "")
        _delete_avatar_file(old_rel)
        flash("Photo de profil reinitialisee.", "success")
        return redirect(url_for("system_profile_page"))
    @app.post("/system/profile/recovery-email")
    def system_profile_recovery_email_update():
        user = _current_auth_user()
        if not user:
            return redirect(url_for("login", next="/system/profile"))
        email = (request.form.get("recovery_email") or "").strip()
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Email invalide.", "warning")
            return redirect(url_for("system_profile_page"))
        _set_auth_user_recovery_email(int(user["id"]), email)
        flash("Email de recuperation mis a jour.", "success")
        return redirect(url_for("system_profile_page"))
    @app.post("/system/profile/users/add")
    def system_profile_users_add():
        user = _current_auth_user()
        if not _auth_user_can_manage_users(user):
            abort(403)
        username = request.form.get("username") or ""
        email = request.form.get("email") or ""
        role = request.form.get("role") or "user"
        password = request.form.get("password") or ""
        ok, msg = _create_auth_user(username, password, email, role)
        flash(msg, "success" if ok else "warning")
        return redirect(url_for("system_profile_page"))
    @app.get("/api/system/disk")
    def api_disk(): return jsonify(get_disk_stats("/"))
    @app.get("/api/backups")
    def api_backups(): return jsonify(backups=list_backups(BACKUP_KEEP_MAX), limit=BACKUP_KEEP_MAX)
    @app.post("/system/backup-now")
    def backup_now():
        try:
            subprocess.Popen(
                ["sudo", "/bin/systemctl", "start", "stockdash-backup.service"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return jsonify(ok=True)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 500
    @app.post("/system/backup-health-now")
    def backup_health_now():
        try:
            subprocess.Popen(
                ["sudo", "/bin/systemctl", "start", "stockdash-backup-health.service"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return jsonify(ok=True)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 500
    @app.post("/system/restore-test-now")
    def restore_test_now():
        try:
            subprocess.Popen(
                ["sudo", "/bin/systemctl", "start", "stockdash-restore-test.service"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return jsonify(ok=True)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 500
    @app.post("/system/backup-delete")
    def backup_delete():
        data = request.get_json(silent=True) or {}; name = data.get("name","")
        if not re.fullmatch(r"stockdash_.*\.tgz", name): return jsonify(ok=False, error="invalid name"), 400
        target = BACKUP_DIR / name
        if target.exists(): target.unlink(); return jsonify(ok=True, deleted=name)
        return jsonify(ok=False, error="not found"), 404
    @app.get("/system/backup/<path:name>")
    def download_backup(name):
        if not re.fullmatch(r"stockdash_.*\.tgz", name or ""): return "Invalid name", 400
        return send_from_directory(BACKUP_DIR, name, as_attachment=True)
    @app.post("/system/restore")
    def restore_backup():
        data = request.get_json(silent=True) or {}; name = data.get("name", "")
        if not re.fullmatch(r"stockdash_.*\.tgz", name): return jsonify(ok=False, error="invalid name"), 400
        archive = BACKUP_DIR / name
        if not archive.exists(): return jsonify(ok=False, error="not found"), 404
        try:
            subprocess.run(["tar","-xzf",str(archive),"-C",str(Path.home())], check=True)
            return jsonify(ok=True, restored=name)
        except Exception as e:
            return jsonify(ok=False, error=str(e)), 500
    @app.post("/stock/impression3d/add")
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
            return redirect(url_for("inv_3d_page"))
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
        return redirect(url_for("inv_3d_page"))
    @app.post("/stock/impression3d/<int:item_id>/bump")
    def inv_3d_bump(item_id:int):
        try: delta = int(request.form.get('delta') or 1)
        except: delta = 1
        con = _con_3d()
        con.execute("UPDATE stock_3d SET qty = MAX(0, COALESCE(qty,0) + ?) WHERE id=?", (delta, item_id))
        con.commit(); con.close()
        flash("Stock " + ("+" if delta>=0 else "") + str(delta) + ".", "success")
        return redirect(url_for("inv_3d_page"))
    @app.post("/stock/impression3d/<int:item_id>/alert")
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
        return redirect(url_for("inv_3d_page"))
    @app.post("/stock/impression3d/<int:item_id>/del")
    def inv_3d_del(item_id:int):
        con = _con_3d()
        con.execute("DELETE FROM stock_3d WHERE id=?", (item_id,))
        con.commit(); con.close()
        flash("Article supprimé.", "success")
        return redirect(url_for("inv_3d_page"))
    @app.get('/api/broderie/alerts', endpoint='bro_alerts_api')
    def bro_alerts_api():
        import json
        con = _con_bro()
        rows = con.execute("""
            SELECT b.id,b.name,b.ref,b.material,b.color,b.qty,a.threshold
            FROM stock_bro b
            JOIN stock_bro_alerts a ON a.item_id=b.id
            WHERE a.threshold>0 AND IFNULL(b.qty,0) <= a.threshold
            ORDER BY b.id DESC
        """).fetchall()
        con.close()
        return jsonify(alerts=[dict(r) for r in rows])
    @app.get('/stock/broderie')
    def bro_page():
        con = _con_bro()
        items = [dict(r) for r in con.execute(
            "SELECT i.id, i.material, i.color, i.ref, i.price, i.qty, "
            "COALESCE(i.name,'') AS name, COALESCE(a.threshold,0) AS min_qty "
            "FROM stock_bro i "
            "LEFT JOIN stock_bro_alerts a ON a.item_id = i.id "
            "ORDER BY i.id DESC"
        )]
        mats  = [r[0] for r in con.execute(
            "SELECT DISTINCT material FROM stock_bro WHERE material IS NOT NULL AND material<>'' ORDER BY 1"
        )]
        cols  = [r[0] for r in con.execute(
            "SELECT DISTINCT color FROM stock_bro WHERE color IS NOT NULL AND color<>'' ORDER BY 1"
        )]
        refs  = [r[0] for r in con.execute(
            "SELECT DISTINCT ref FROM stock_bro WHERE ref IS NOT NULL AND TRIM(ref)<>'' ORDER BY 1"
        )]
        alerts = [dict(r) for r in con.execute(
            "SELECT i.id, COALESCE(i.name,'') AS name, i.material, i.color, i.qty, "
            "COALESCE(a.threshold,0) AS min_qty "
            "FROM stock_bro i JOIN stock_bro_alerts a ON a.item_id = i.id "
            "ORDER BY i.id DESC"
        )]
        con.close()
        return render_template('stock_broderie.html',
                               title='Broderie',
                               items=items, materials=mats, sizes=mats, colors=cols, refs=refs, alerts=alerts)
    @app.post('/stock/broderie/add', endpoint='bro_add')
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
            return redirect(url_for("bro_page"))
        if not size or not color:
            flash("Sélectionne une taille et une couleur (quantité auto>=1).", "warning")
            return redirect(url_for("bro_page"))
        con = _con_bro()
        try:
            existing = con.execute("""
                SELECT id
                FROM stock_bro
                WHERE ref=? AND COALESCE(material,'')=? AND COALESCE(color,'')=?
                LIMIT 1
            """, (ref, size, color)).fetchone()

            if existing:
                con.execute("""
                    UPDATE stock_bro
                    SET qty = COALESCE(qty,0) + ?,
                        price = ?,
                        name = CASE WHEN TRIM(?)<>'' THEN ? ELSE name END
                    WHERE id=?
                """, (qty, price, name, name, existing["id"]))
                con.commit()
                flash(f"Variante existante: stock augmenté (+{qty}).", "success")
            else:
                con.execute("INSERT INTO stock_bro(name,material,color,ref,price,qty) VALUES (?,?,?,?,?,?)",
                            (name, size, color, ref, price, qty))
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
        return redirect(url_for("bro_page"))
    @app.post('/stock/broderie/<int:item_id>/bump', endpoint='bro_bump')
    def bro_bump(item_id:int):
        try:
            delta = int(request.form.get('delta') or 1)
        except:
            delta = 1
        con = _con_bro()
        con.execute("UPDATE stock_bro SET qty = COALESCE(qty,0) + ? WHERE id=?", (delta, item_id))
        con.commit(); con.close()
        flash(f"Stock {'+' if delta>=0 else ''}{delta}.", "success")
        return redirect(url_for('bro_page'))
    @app.post('/stock/broderie/<int:item_id>/del', endpoint='bro_del')
    def bro_del(item_id:int):
        con = _con_bro()
        con.execute("DELETE FROM stock_bro WHERE id=?", (item_id,))
        con.execute("DELETE FROM stock_bro_alerts WHERE item_id=?", (item_id,))
        con.commit(); con.close()
        flash("Article supprimé.", "success")
        return redirect(url_for('bro_page'))
    @app.post('/stock/broderie/alert', endpoint='bro_alert_set')
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
            return redirect(url_for("bro_page"))

        # Si seuil <= 0 : on supprime l’alerte
        if threshold <= 0:
            con.execute("DELETE FROM stock_bro_alerts WHERE item_id=?", (item_id,))
            con.commit(); con.close()
            flash("Alerte supprimée.", "success")
            return redirect(url_for("bro_page"))

        # Sinon UPSERT (comme en 3D)
        con.execute("""
            INSERT INTO stock_bro_alerts(item_id, threshold)
            VALUES(?, ?)
            ON CONFLICT(item_id) DO UPDATE SET threshold=excluded.threshold
        """, (item_id, threshold))
        con.commit(); con.close()
        flash(f"Alerte enregistrée (seuil = {threshold}).", "success")
        return redirect(url_for("bro_page"))
    @app.get('/stock/impression3d')
    def inv_3d_page():
        con = _con_3d()
        items = [dict(r) for r in con.execute(
            "SELECT i.id, i.material, i.color, i.ref, i.price, i.qty, "
            "COALESCE(i.name,'') AS name, COALESCE(a.threshold,0) AS min_qty "
            "FROM stock_3d i "
            "LEFT JOIN stock_3d_alerts a ON a.item_id = i.id "
            "ORDER BY i.id DESC"
        )]
        mats  = [r[0] for r in con.execute(
            "SELECT DISTINCT material FROM stock_3d WHERE material IS NOT NULL AND material<>'' ORDER BY 1"
        )]
        cols  = [r[0] for r in con.execute(
            "SELECT DISTINCT color FROM stock_3d WHERE color IS NOT NULL AND color<>'' ORDER BY 1"
        )]
        alerts = [dict(r) for r in con.execute(
            "SELECT i.id, COALESCE(i.name,'') AS name, i.material, i.color, i.qty, "
            "COALESCE(a.threshold,0) AS min_qty "
            "FROM stock_3d i JOIN stock_3d_alerts a ON a.item_id = i.id "
            "ORDER BY i.id DESC"
        )]
        con.close()
        return render_template('stock_3D.html',
                               title='Impression 3D',
                               items=items, materials=mats, colors=cols, alerts=alerts)
    @app.post('/stock/broderie/<int:item_id>/alert', endpoint='bro_alert_item')
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
        return redirect(url_for('bro_page'))
    @app.get("/api/impression3d/alerts")
    def api_impr3d_alerts():
        return jsonify(alerts=_get_impr3d_alerts_list())
    @app.get("/api/broderie/alerts")
    def api_broderie_alerts():
        return jsonify(alerts=_get_broderie_alerts_list())
    @app.get("/api/alerts/list")
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
    @app.get("/api/alerts/count")
    def api_alerts_count():
        total = len(_get_impr3d_alerts_list()) + len(_get_broderie_alerts_list())
        return jsonify(total=total)
    @app.get("/api/orders/count")
    def api_orders_count():
        return jsonify(total=_orders_unread_count())
    @app.get("/api/orders/list")
    def api_orders_list():
        limit = _safe_int(request.args.get("limit"), 60)
        orders = _orders_list(limit=limit)
        return jsonify(
            orders=orders,
            total=len(orders),
            unread_total=_orders_unread_count()
        )
    @app.post("/api/orders/<int:order_id>/read")
    def api_orders_mark_read(order_id: int):
        con = _con_biz()
        try:
            con.execute("UPDATE order_notifications SET is_read=1 WHERE id=?", (order_id,))
            con.commit()
        finally:
            con.close()
        return jsonify(ok=True, unread_total=_orders_unread_count())
    @app.post("/api/orders/read-all")
    def api_orders_mark_all_read():
        con = _con_biz()
        try:
            con.execute("UPDATE order_notifications SET is_read=1 WHERE is_read=0")
            con.commit()
        finally:
            con.close()
        return jsonify(ok=True, unread_total=_orders_unread_count())
    @app.post("/api/orders/mock")
    def api_orders_mock():
        if not _verify_webhook_token("mock"):
            return jsonify(ok=False, error="unauthorized"), 401
        payload = request.get_json(silent=True) or {}
        source = (payload.get("source") or "mock").strip().lower()
        if source not in ("etsy", "vinted", "mock"):
            source = "mock"
        order_id = _save_order_notification(source, payload)
        return jsonify(ok=True, id=order_id, unread_total=_orders_unread_count())
    @app.post("/webhooks/orders/etsy")
    def webhook_orders_etsy():
        return _webhook_receive("etsy")
    @app.post("/webhooks/orders/vinted")
    def webhook_orders_vinted():
        return _webhook_receive("vinted")
