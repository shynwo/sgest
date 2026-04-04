"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""
from __future__ import annotations

from ..services import *  # noqa: F401,F403


def register_system_routes(app) -> None:
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
