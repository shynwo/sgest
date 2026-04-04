"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""
from __future__ import annotations

from flask import Blueprint

from ..services import *  # noqa: F401,F403


bp = Blueprint("auth", __name__)

@bp.get("/login")
def login():
    if _session_is_authenticated():
        return redirect(url_for("main.dashboard"))
    return render_template("login.html", title="Connexion", next_path=_safe_next_path(), weak_default=_is_default_admin_password())
@bp.post("/login")
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
@bp.post("/auth/recovery/request")
def auth_recovery_request():
    ip = _current_user_ip()
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    key = f"{ip}:{_normalize_username(username)}"
    if _rate_limited(_RECOVERY_RATE_BUCKET, key, limit=5, window_sec=900, consume=False):
        flash("Trop de demandes de recuperation. Reessaie plus tard.", "warning")
        return redirect(url_for("auth.login"))

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
                return redirect(url_for("auth.login"))
    flash("Si le compte existe, un code de recuperation a ete envoye par email.", "success")
    return redirect(url_for("auth.login"))
@bp.post("/auth/recovery/reset")
def auth_recovery_reset():
    username = (request.form.get("username") or "").strip()
    code = (request.form.get("code") or "").strip()
    new_pw = request.form.get("new_password") or ""
    confirm_pw = request.form.get("confirm_password") or ""

    user = _get_auth_user_by_username(username)
    if not user or int(user.get("is_active") or 0) != 1:
        flash("Demande invalide.", "warning")
        return redirect(url_for("auth.login"))
    if new_pw != confirm_pw:
        flash("La confirmation du mot de passe ne correspond pas.", "warning")
        return redirect(url_for("auth.login"))
    errs = _password_strength_errors(new_pw)
    if errs:
        flash("Mot de passe trop faible: " + " ".join(errs), "warning")
        return redirect(url_for("auth.login"))

    code_hash = str(user.get("recovery_code_hash") or "")
    exp_txt = str(user.get("recovery_code_expires_at") or "").strip()
    if not code_hash or not exp_txt:
        flash("Code invalide ou expire.", "warning")
        return redirect(url_for("auth.login"))
    try:
        exp_dt = datetime.strptime(exp_txt, "%Y-%m-%d %H:%M:%S")
    except Exception:
        exp_dt = datetime.fromtimestamp(0)
    if datetime.now() > exp_dt:
        _clear_recovery_code_for_user(int(user["id"]))
        flash("Code expire. Redemande un nouveau code.", "warning")
        return redirect(url_for("auth.login"))
    ok = False
    try:
        ok = check_password_hash(code_hash, code)
    except Exception:
        ok = False
    if not ok:
        flash("Code invalide.", "warning")
        return redirect(url_for("auth.login"))

    _set_auth_user_password(int(user["id"]), new_pw)
    _clear_recovery_code_for_user(int(user["id"]))
    flash("Mot de passe reinitialise. Connecte-toi.", "success")
    return redirect(url_for("auth.login"))
@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
