"""
Logique métier et hooks (ex-app.py). Utiliser current_app, pas d’instance Flask globale.
"""
from flask import current_app, render_template, jsonify, send_from_directory, redirect, url_for, request, flash, Response, session, abort, send_file
from datetime import datetime, timedelta
from pathlib import Path
import shutil, platform, subprocess, os, time, re, sqlite3, io, csv, json, hmac, uuid, secrets, smtplib
from email.message import EmailMessage
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
URSSAF_RATE = 0.21
SPOOL_BASE_GRAMS = 1000.0
AVATAR_UPLOAD_REL = "uploads/avatars"
DEFAULT_AVATAR_REL = "img/avatar-default.svg"
ALLOWED_AVATAR_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
_LOGIN_RATE_BUCKET = {}
_WEBHOOK_RATE_BUCKET = {}
_RECOVERY_RATE_BUCKET = {}
def _env_bool(name: str, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")
def _rate_limited(bucket: dict, key: str, limit: int, window_sec: int, consume=False):
    now = time.time()
    values = [t for t in bucket.get(key, []) if now - t < window_sec]
    if consume:
        values.append(now)
    if values:
        bucket[key] = values
    else:
        bucket.pop(key, None)
    return len(values) >= limit
def _current_user_ip():
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return fwd or (request.remote_addr or "unknown")
def _normalize_username(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower())
def _valid_hex_color(value: str, default="#14b8a6") -> str:
    v = str(value or "").strip().lower()
    if re.fullmatch(r"#[0-9a-f]{6}", v):
        return v
    return default
def _hex_to_rgb(hex_color: str):
    c = _valid_hex_color(hex_color)
    return (int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16))
def _rgb_to_hex(r: int, g: int, b: int) -> str:
    rr = max(0, min(255, int(r)))
    gg = max(0, min(255, int(g)))
    bb = max(0, min(255, int(b)))
    return f"#{rr:02x}{gg:02x}{bb:02x}"
def _mix_hex(color_a: str, color_b: str, weight=0.5) -> str:
    a = _hex_to_rgb(color_a)
    b = _hex_to_rgb(color_b)
    w = max(0.0, min(1.0, float(weight)))
    return _rgb_to_hex(
        a[0] * (1.0 - w) + b[0] * w,
        a[1] * (1.0 - w) + b[1] * w,
        a[2] * (1.0 - w) + b[2] * w,
    )
def _shade_hex(hex_color: str, factor: float) -> str:
    c = _valid_hex_color(hex_color)
    r = int(c[1:3], 16)
    g = int(c[3:5], 16)
    b = int(c[5:7], 16)
    f = max(0.2, min(1.5, float(factor)))
    rr = max(0, min(255, int(r * f)))
    gg = max(0, min(255, int(g * f)))
    bb = max(0, min(255, int(b * f)))
    return f"#{rr:02x}{gg:02x}{bb:02x}"
def _theme_palette(primary: str, secondary: str):
    base = _valid_hex_color(primary)
    alt = _valid_hex_color(secondary, _shade_hex(base, 1.18))
    deep = _mix_hex("#050914", base, 0.32)
    mid = _mix_hex("#091020", alt, 0.30)
    high = _mix_hex("#111a2f", alt, 0.52)
    panel_border = _mix_hex(base, alt, 0.5)
    btn_text = _mix_hex("#061211", base, 0.22)
    primary_rgb = _hex_to_rgb(base)
    secondary_rgb = _hex_to_rgb(alt)
    return {
        "btn": base,
        "btn_hover": _shade_hex(base, 0.82),
        "btn_text": btn_text,
        "primary": base,
        "secondary": alt,
        "primary_rgb": f"{primary_rgb[0]}, {primary_rgb[1]}, {primary_rgb[2]}",
        "secondary_rgb": f"{secondary_rgb[0]}, {secondary_rgb[1]}, {secondary_rgb[2]}",
        "app_bg_0": _shade_hex(deep, 0.72),
        "app_bg_1": _shade_hex(mid, 0.86),
        "app_bg_2": _shade_hex(high, 0.92),
        "panel_border": panel_border,
        "panel_bg": _mix_hex("#0b1322", base, 0.28),
        "panel_bg_strong": _mix_hex("#0d1829", alt, 0.33),
        "text_soft": _mix_hex("#9fb0c8", alt, 0.22),
    }
def _admin_username():
    local = _local_admin_record()
    if local and str(local.get("username") or "").strip():
        return str(local["username"]).strip()
    return (os.getenv("SGEST_ADMIN_USER") or "admin").strip()
def _admin_password_hash():
    local = _local_admin_record()
    if local and str(local.get("password_hash") or "").strip():
        return str(local["password_hash"]).strip()
    return (os.getenv("SGEST_ADMIN_PASSWORD_HASH") or "").strip()
def _admin_password_plain():
    return (os.getenv("SGEST_ADMIN_PASSWORD") or "change-me-now").strip()
def _is_default_admin_password():
    local = _local_admin_record()
    if local and str(local.get("password_hash") or "").strip():
        return False
    return _admin_password_hash() == "" and _admin_password_plain() == "change-me-now"
def _check_admin_password(raw_password: str):
    p = str(raw_password or "")
    hashed = _admin_password_hash()
    if hashed:
        try:
            return check_password_hash(hashed, p)
        except Exception:
            return False
    expected = _admin_password_plain()
    return bool(expected) and hmac.compare_digest(p, expected)
def _session_is_authenticated():
    return bool(session.get("auth_ok") == 1)
def _ensure_csrf_token():
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok
def _safe_next_path():
    nxt = (request.args.get("next") or request.form.get("next") or "").strip()
    if not nxt:
        return "/"
    parsed = urlparse(nxt)
    if parsed.scheme or parsed.netloc:
        return "/"
    if not nxt.startswith("/"):
        return "/"
    return nxt
def _is_api_request():
    return request.path.startswith("/api/") or "application/json" in (request.headers.get("Accept") or "")
def _safe_float(value, default=0.0):
    try:
        return float(str(value).replace(",", ".").strip())
    except Exception:
        return default
def _safe_int(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default
def _safe_avatar_rel_path(rel_path: str):
    p = str(rel_path or "").strip().replace("\\", "/").lstrip("/")
    if not p or not p.startswith(AVATAR_UPLOAD_REL + "/"):
        return ""
    if ".." in p:
        return ""
    return p
def _avatar_storage_dir():
    d = Path(current_app.root_path) / "static" / AVATAR_UPLOAD_REL
    d.mkdir(parents=True, exist_ok=True)
    return d
def _avatar_url_for_user(user):
    rel = _safe_avatar_rel_path((user or {}).get("avatar_path") if isinstance(user, dict) else "")
    if rel:
        abs_path = Path(current_app.root_path) / "static" / rel
        if abs_path.is_file():
            return url_for("static", filename=rel)
    return url_for("static", filename=DEFAULT_AVATAR_REL)
def _delete_avatar_file(rel_path: str):
    rel = _safe_avatar_rel_path(rel_path)
    if not rel:
        return
    try:
        abs_path = Path(current_app.root_path) / "static" / rel
        if abs_path.is_file():
            abs_path.unlink()
    except Exception:
        pass
def _stockdash_data_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), "stockdash", "data")
    os.makedirs(d, exist_ok=True)
    return d
def _sqlite_connect(db_path: str, *, timeout: float = 30.0) -> sqlite3.Connection:
    """Connexion SQLite homogène : Row, clés étrangères, WAL (lectures concurrentes), timeouts."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    con = sqlite3.connect(db_path, timeout=timeout)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA cache_size=-8000")
        con.execute("PRAGMA temp_store=MEMORY")
    except sqlite3.Error:
        pass
    return con
def _con_biz():
    db_path = os.path.join(_stockdash_data_dir(), "business.db")
    con = _sqlite_connect(db_path)
    con.execute("""
    CREATE TABLE IF NOT EXISTS gain_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        category TEXT NOT NULL,
        tx_type TEXT NOT NULL,
        item_id INTEGER,
        item_name TEXT,
        ref TEXT,
        material TEXT,
        color TEXT,
        qty REAL NOT NULL DEFAULT 0,
        grams_per_unit REAL NOT NULL DEFAULT 0,
        total_grams REAL NOT NULL DEFAULT 0,
        unit_buy_cost REAL NOT NULL DEFAULT 0,
        unit_sell_price REAL NOT NULL DEFAULT 0,
        revenue REAL NOT NULL DEFAULT 0,
        cost REAL NOT NULL DEFAULT 0,
        urssaf REAL NOT NULL DEFAULT 0,
        profit REAL NOT NULL DEFAULT 0
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_gain_created_at ON gain_events(created_at DESC)")
    con.execute("""
    CREATE TABLE IF NOT EXISTS order_notifications(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source TEXT NOT NULL,
        external_id TEXT NOT NULL,
        order_ref TEXT,
        buyer TEXT,
        total_amount REAL DEFAULT 0,
        currency TEXT,
        status TEXT,
        payload_json TEXT,
        is_read INTEGER NOT NULL DEFAULT 0,
        note TEXT
    );
    """)
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_order_source_external ON order_notifications(source, external_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_order_created_at ON order_notifications(created_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_order_unread ON order_notifications(is_read, created_at DESC)")
    con.execute("""
    CREATE TABLE IF NOT EXISTS backup_monitor_runs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        check_type TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS backup_alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'error',
        message TEXT NOT NULL,
        details TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        occurrences INTEGER NOT NULL DEFAULT 1,
        resolved_at TIMESTAMP
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_backup_runs_type_created ON backup_monitor_runs(check_type, created_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_backup_alerts_status_updated ON backup_alerts(status, updated_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_backup_alerts_kind_status ON backup_alerts(kind, status)")
    con.execute("""
    CREATE TABLE IF NOT EXISTS auth_admin(
        id INTEGER PRIMARY KEY CHECK(id = 1),
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS auth_users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT,
        role TEXT NOT NULL DEFAULT 'user',
        is_active INTEGER NOT NULL DEFAULT 1,
        theme_color TEXT,
        theme_color_secondary TEXT,
        avatar_path TEXT,
        recovery_code_hash TEXT,
        recovery_code_expires_at TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    auth_cols = {str(r["name"]) for r in con.execute("PRAGMA table_info(auth_users)").fetchall()}
    if "theme_color_secondary" not in auth_cols:
        con.execute("ALTER TABLE auth_users ADD COLUMN theme_color_secondary TEXT")
    if "avatar_path" not in auth_cols:
        con.execute("ALTER TABLE auth_users ADD COLUMN avatar_path TEXT")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_auth_users_username ON auth_users(username)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_auth_users_active ON auth_users(is_active, role)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email)")
    con.execute("""
    CREATE TABLE IF NOT EXISTS app_settings(
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS catalogs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        business_type TEXT NOT NULL,
        description TEXT,
        is_public INTEGER NOT NULL DEFAULT 0,
        public_token TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS catalog_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        catalog_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        sku TEXT,
        sale_sheet TEXT,
        description TEXT,
        tags TEXT,
        price REAL DEFAULT 0,
        status TEXT DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(catalog_id) REFERENCES catalogs(id) ON DELETE CASCADE
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS catalog_files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        catalog_id INTEGER NOT NULL,
        item_id INTEGER NOT NULL,
        file_kind TEXT NOT NULL DEFAULT 'file',
        file_name TEXT NOT NULL,
        original_name TEXT NOT NULL,
        mime_type TEXT,
        size_bytes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(catalog_id) REFERENCES catalogs(id) ON DELETE CASCADE,
        FOREIGN KEY(item_id) REFERENCES catalog_items(id) ON DELETE CASCADE
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_catalog_items_catalog ON catalog_items(catalog_id, id DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_catalog_files_item ON catalog_files(item_id, id DESC)")
    con.execute("""
    CREATE TABLE IF NOT EXISTS custom_stock_modules(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        icon TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS custom_stock_fields(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        module_id INTEGER NOT NULL,
        field_key TEXT NOT NULL,
        label TEXT NOT NULL,
        field_type TEXT NOT NULL DEFAULT 'text',
        options_json TEXT,
        is_required INTEGER NOT NULL DEFAULT 0,
        show_in_table INTEGER NOT NULL DEFAULT 1,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(module_id) REFERENCES custom_stock_modules(id) ON DELETE CASCADE
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS custom_stock_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        module_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        ref TEXT,
        qty REAL NOT NULL DEFAULT 0,
        min_qty REAL NOT NULL DEFAULT 0,
        price REAL NOT NULL DEFAULT 0,
        data_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(module_id) REFERENCES custom_stock_modules(id) ON DELETE CASCADE
    );
    """)
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_custom_stock_field_key ON custom_stock_fields(module_id, field_key)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_custom_stock_fields_module ON custom_stock_fields(module_id, sort_order, id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_custom_stock_items_module ON custom_stock_items(module_id, id DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_custom_stock_items_ref ON custom_stock_items(module_id, ref)")

    # Seed local users from legacy admin config for backward compatibility.
    users_count_row = con.execute("SELECT COUNT(1) AS c FROM auth_users").fetchone()
    users_count = int(users_count_row["c"] or 0)
    if users_count == 0:
        local_admin = con.execute("SELECT username, password_hash FROM auth_admin WHERE id=1").fetchone()
        seed_username = _normalize_username((local_admin["username"] if local_admin else "") or (os.getenv("SGEST_ADMIN_USER") or "admin"))
        seed_hash = (local_admin["password_hash"] if local_admin else "") or (os.getenv("SGEST_ADMIN_PASSWORD_HASH") or "").strip()
        if not seed_hash:
            seed_plain = (os.getenv("SGEST_ADMIN_PASSWORD") or "change-me-now").strip()
            seed_hash = generate_password_hash(seed_plain)
        con.execute("""
            INSERT INTO auth_users(username, password_hash, role, is_active, updated_at)
            VALUES (?, ?, 'admin', 1, CURRENT_TIMESTAMP)
        """, (seed_username or "admin", seed_hash))
    else:
        local_admin = con.execute("SELECT username, password_hash FROM auth_admin WHERE id=1").fetchone()
        if local_admin and str(local_admin["username"] or "").strip():
            seed_username = _normalize_username(local_admin["username"])
            row = con.execute("SELECT id FROM auth_users WHERE username=?", (seed_username,)).fetchone()
            if not row:
                seed_hash = str(local_admin["password_hash"] or "").strip()
                if not seed_hash:
                    seed_plain = (os.getenv("SGEST_ADMIN_PASSWORD") or "change-me-now").strip()
                    seed_hash = generate_password_hash(seed_plain)
                con.execute("""
                    INSERT INTO auth_users(username, password_hash, role, is_active, updated_at)
                    VALUES (?, ?, 'admin', 1, CURRENT_TIMESTAMP)
                """, (seed_username, seed_hash))

    con.commit()
    return con
def _local_admin_record():
    try:
        con = _con_biz()
        try:
            row = con.execute(
                "SELECT username, password_hash, updated_at FROM auth_admin WHERE id=1"
            ).fetchone()
            return dict(row) if row else None
        finally:
            con.close()
    except Exception:
        return None
def _setting_get(key: str, default=""):
    k = str(key or "").strip().lower()
    if not k:
        return default
    con = _con_biz()
    try:
        row = con.execute("SELECT value FROM app_settings WHERE key=? LIMIT 1", (k,)).fetchone()
        if not row or row["value"] is None:
            return default
        return str(row["value"])
    finally:
        con.close()
def _setting_set(key: str, value: str):
    k = str(key or "").strip().lower()
    if not k:
        return False
    con = _con_biz()
    try:
        con.execute("""
            INSERT INTO app_settings(key, value, updated_at)
            VALUES(?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
              value=excluded.value,
              updated_at=CURRENT_TIMESTAMP
        """, (k, str(value or "")))
        con.commit()
        return True
    finally:
        con.close()
def _setting_get_bool(key: str, default=False):
    sentinel = "__MISSING__"
    raw = _setting_get(key, sentinel)
    if raw == sentinel:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")
def _smtp_config():
    host = _setting_get("smtp_host", os.getenv("SGEST_SMTP_HOST") or "").strip()
    port = _safe_int(_setting_get("smtp_port", os.getenv("SGEST_SMTP_PORT") or "587"), 587)
    user = _setting_get("smtp_user", os.getenv("SGEST_SMTP_USER") or "").strip()
    pwd = _setting_get("smtp_password", os.getenv("SGEST_SMTP_PASSWORD") or "").strip()
    from_email = _setting_get("smtp_from", os.getenv("SGEST_SMTP_FROM") or user or "").strip()
    use_tls = _setting_get_bool("smtp_tls", _env_bool("SGEST_SMTP_TLS", True))
    return {
        "host": host,
        "port": port,
        "user": user,
        "pwd": pwd,
        "from_email": from_email,
        "use_tls": use_tls,
    }
def _smtp_ready():
    cfg = _smtp_config()
    return bool(cfg["host"] and cfg["from_email"])
def _integration_api_value(key: str):
    env_key = f"SGEST_{str(key or '').upper()}"
    return _setting_get(str(key or "").lower(), os.getenv(env_key) or "").strip()
def _set_local_admin_password(new_password: str):
    username = _admin_username() or "admin"
    pw_hash = generate_password_hash(str(new_password or ""))
    con = _con_biz()
    try:
        con.execute("""
            INSERT INTO auth_admin(id, username, password_hash, updated_at)
            VALUES (1, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
                username=excluded.username,
                password_hash=excluded.password_hash,
                updated_at=CURRENT_TIMESTAMP
        """, (username, pw_hash))
        con.commit()
    finally:
        con.close()
    con2 = _con_biz()
    try:
        uname = _normalize_username(username)
        row = con2.execute("SELECT id FROM auth_users WHERE username=? LIMIT 1", (uname,)).fetchone()
        if row:
            con2.execute("""
                UPDATE auth_users
                SET password_hash=?, role='admin', is_active=1, updated_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (pw_hash, int(row["id"])))
        else:
            con2.execute("""
                INSERT INTO auth_users(username, password_hash, role, is_active, updated_at)
                VALUES (?, ?, 'admin', 1, CURRENT_TIMESTAMP)
            """, (uname or "admin", pw_hash))
        con2.commit()
    finally:
        con2.close()
def _get_auth_user_by_username(username: str):
    uname = _normalize_username(username)
    if not uname:
        return None
    con = _con_biz()
    try:
        row = con.execute("""
            SELECT *
            FROM auth_users
            WHERE username=?
            LIMIT 1
        """, (uname,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()
def _get_auth_user_by_id(user_id: int):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return None
    con = _con_biz()
    try:
        row = con.execute("SELECT * FROM auth_users WHERE id=? LIMIT 1", (uid,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()
def _list_auth_users(limit=200):
    lim = max(1, min(500, _safe_int(limit, 200)))
    con = _con_biz()
    try:
        rows = con.execute("""
            SELECT id, username, email, role, is_active, theme_color, theme_color_secondary, created_at, updated_at
            FROM auth_users
            ORDER BY role DESC, username ASC
            LIMIT ?
        """, (lim,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _current_auth_user():
    if not _session_is_authenticated():
        return None
    uid = _safe_int(session.get("auth_user_id"), 0)
    user = _get_auth_user_by_id(uid) if uid > 0 else None
    if user and int(user.get("is_active") or 0) == 1:
        return user
    uname = session.get("auth_user") or ""
    user = _get_auth_user_by_username(uname)
    if user and int(user.get("is_active") or 0) == 1:
        session["auth_user_id"] = int(user["id"])
        session["auth_role"] = user.get("role") or "user"
        session["auth_user"] = user.get("username") or ""
        return user
    return None
def _auth_user_can_manage_users(user: dict):
    if not user:
        return False
    return (str(user.get("role") or "").strip().lower() == "admin")
def _auth_login_user(user: dict):
    session.clear()
    session["auth_ok"] = 1
    session["auth_user_id"] = int(user["id"])
    session["auth_user"] = user.get("username") or ""
    session["auth_role"] = user.get("role") or "user"
    session["auth_at"] = int(time.time())
    session["csrf_token"] = secrets.token_urlsafe(32)
    session.permanent = True
def _set_auth_user_password(user_id: int, new_password: str):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return False
    pw_hash = generate_password_hash(str(new_password or ""))
    con = _con_biz()
    try:
        con.execute("""
            UPDATE auth_users
            SET password_hash=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (pw_hash, uid))
        con.commit()
        return True
    finally:
        con.close()
def _set_auth_user_theme(user_id: int, color: str, secondary: str):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return False
    safe_color = _valid_hex_color(color)
    safe_secondary = _valid_hex_color(secondary, _shade_hex(safe_color, 1.18))
    con = _con_biz()
    try:
        con.execute("""
            UPDATE auth_users
            SET theme_color=?, theme_color_secondary=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (safe_color, safe_secondary, uid))
        con.commit()
        return True
    finally:
        con.close()
def _set_auth_user_avatar(user_id: int, avatar_rel_path: str):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return False
    rel = _safe_avatar_rel_path(avatar_rel_path)
    con = _con_biz()
    try:
        con.execute("""
            UPDATE auth_users
            SET avatar_path=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (rel or None, uid))
        con.commit()
        return True
    finally:
        con.close()
def _set_auth_user_recovery_email(user_id: int, email: str):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return False
    e = str(email or "").strip().lower()
    if e and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e):
        return False
    con = _con_biz()
    try:
        con.execute("""
            UPDATE auth_users
            SET email=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (e, uid))
        con.commit()
        return True
    finally:
        con.close()
def _create_auth_user(username: str, password: str, email: str, role: str = "user"):
    uname = _normalize_username(username)
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", uname or ""):
        return False, "Nom utilisateur invalide (3-32, a-z 0-9 . _ -)."
    mail = str(email or "").strip().lower()
    if mail and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", mail):
        return False, "Email invalide."
    r = str(role or "user").strip().lower()
    r = "admin" if r == "admin" else "user"
    errs = _password_strength_errors(password)
    if errs:
        return False, "Mot de passe trop faible: " + " ".join(errs)
    con = _con_biz()
    try:
        exists = con.execute("SELECT id FROM auth_users WHERE username=?", (uname,)).fetchone()
        if exists:
            return False, "Ce compte existe deja."
        con.execute("""
            INSERT INTO auth_users(username, password_hash, email, role, is_active, updated_at)
            VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
        """, (uname, generate_password_hash(password), mail, r))
        con.commit()
        return True, "Compte cree."
    finally:
        con.close()
def _current_theme_colors():
    user = _current_auth_user()
    if not user:
        return ("#14b8a6", "#22d3ee")
    primary = _valid_hex_color(user.get("theme_color") or "#14b8a6")
    secondary = _valid_hex_color(user.get("theme_color_secondary") or "", _shade_hex(primary, 1.18))
    return (primary, secondary)
def _set_recovery_code_for_user(user_id: int, code: str, expires_dt: datetime):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return False
    code_hash = generate_password_hash(str(code or ""))
    expires = expires_dt.strftime("%Y-%m-%d %H:%M:%S")
    con = _con_biz()
    try:
        con.execute("""
            UPDATE auth_users
            SET recovery_code_hash=?, recovery_code_expires_at=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (code_hash, expires, uid))
        con.commit()
        return True
    finally:
        con.close()
def _clear_recovery_code_for_user(user_id: int):
    uid = _safe_int(user_id, 0)
    if uid <= 0:
        return False
    con = _con_biz()
    try:
        con.execute("""
            UPDATE auth_users
            SET recovery_code_hash=NULL, recovery_code_expires_at=NULL, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (uid,))
        con.commit()
        return True
    finally:
        con.close()
def _send_recovery_email(to_email: str, username: str, code: str):
    cfg = _smtp_config()
    host = cfg["host"]
    port = cfg["port"]
    user = cfg["user"]
    pwd = cfg["pwd"]
    from_email = cfg["from_email"]
    use_tls = cfg["use_tls"]
    if not host or not from_email:
        return False, "SMTP non configure"

    msg = EmailMessage()
    msg["Subject"] = "Code de recuperation Sgest"
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(
        f"Bonjour,\n\nVotre code de recuperation est: {code}\n"
        "Ce code expire dans 15 minutes.\n\n"
        f"Compte: {username}\n"
        "Si vous n'etes pas a l'origine de cette demande, ignorez cet email.\n"
    )
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            if use_tls:
                smtp.starttls()
                smtp.ehlo()
            if user and pwd:
                smtp.login(user, pwd)
            smtp.send_message(msg)
        return True, ""
    except Exception as e:
        return False, str(e)
def _normalize_gain_period(period: str) -> str:
    p = (period or "").strip().lower()
    return p if p in ("day", "week", "month", "all") else "month"
def _period_start(period: str):
    now = datetime.now()
    p = _normalize_gain_period(period)
    if p == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if p == "week":
        start = now - timedelta(days=now.weekday())
        return start.replace(hour=0, minute=0, second=0, microsecond=0)
    if p == "month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return None
def _period_sql_clause(period: str):
    start = _period_start(period)
    if start is None:
        return "", []
    return " WHERE created_at >= ? ", [start.strftime("%Y-%m-%d %H:%M:%S")]
def _biz_totals(period: str = "all"):
    where_sql, params = _period_sql_clause(period)
    con = _con_biz()
    try:
        row = con.execute(f"""
            SELECT
                COALESCE(SUM(revenue),0) AS revenue,
                COALESCE(SUM(cost),0) AS cost,
                COALESCE(SUM(urssaf),0) AS urssaf,
                COALESCE(SUM(profit),0) AS profit,
                COALESCE(SUM(CASE WHEN tx_type='sale' THEN 1 ELSE 0 END),0) AS sale_count,
                COALESCE(SUM(CASE WHEN tx_type='loss' THEN 1 ELSE 0 END),0) AS loss_count
            FROM gain_events
            {where_sql}
        """, params).fetchone()
        return {
            "revenue": float(row["revenue"] or 0.0),
            "cost": float(row["cost"] or 0.0),
            "urssaf": float(row["urssaf"] or 0.0),
            "profit": float(row["profit"] or 0.0),
            "sale_count": int(row["sale_count"] or 0),
            "loss_count": int(row["loss_count"] or 0),
        }
    finally:
        con.close()
def _biz_events(period: str = "all", limit: int = 120):
    where_sql, params = _period_sql_clause(period)
    con = _con_biz()
    try:
        rows = con.execute(f"""
            SELECT *
            FROM gain_events
            {where_sql}
            ORDER BY id DESC
            LIMIT ?
        """, [*params, int(limit)]).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _biz_top_products(period: str = "all", limit: int = 5):
    where_sql, params = _period_sql_clause(period)
    con = _con_biz()
    try:
        rows = con.execute(f"""
            SELECT
                category,
                item_id,
                COALESCE(item_name,'') AS item_name,
                COALESCE(material,'') AS material,
                COALESCE(color,'') AS color,
                COALESCE(SUM(revenue),0) AS revenue,
                COALESCE(SUM(cost),0) AS cost,
                COALESCE(SUM(urssaf),0) AS urssaf,
                COALESCE(SUM(profit),0) AS profit,
                COALESCE(SUM(CASE WHEN tx_type='sale' THEN qty ELSE 0 END),0) AS sold_units,
                COALESCE(SUM(CASE WHEN tx_type='loss' THEN qty ELSE 0 END),0) AS loss_units,
                CASE
                    WHEN COALESCE(SUM(revenue),0) > 0 THEN (COALESCE(SUM(profit),0) * 100.0 / SUM(revenue))
                    ELSE 0
                END AS margin_pct
            FROM gain_events
            {where_sql}
            GROUP BY category, item_id, item_name, material, color
            ORDER BY profit DESC, margin_pct DESC, revenue DESC
            LIMIT ?
        """, [*params, int(limit)]).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _order_path_get(data, path: str):
    cur = data
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur.get(part)
        else:
            return None
    return cur
def _order_first(data, paths):
    for p in paths:
        v = _order_path_get(data, p)
        if v is None:
            continue
        if isinstance(v, str):
            if v.strip() == "":
                continue
            return v.strip()
        return v
    return None
def _order_money(value):
    if value is None:
        return 0.0, None
    if isinstance(value, (int, float, str)):
        return _safe_float(value, 0.0), None
    if isinstance(value, dict):
        amount = value.get("amount")
        if amount is None:
            amount = value.get("value")
        amount = _safe_float(amount, 0.0)
        divisor = _safe_float(value.get("divisor"), 0.0)
        if divisor > 0:
            amount = amount / divisor
        currency = (
            value.get("currency_code")
            or value.get("currency")
            or value.get("currencyCode")
        )
        return amount, (str(currency).strip() if currency else None)
    return 0.0, None
def _extract_order_notification(source: str, payload: dict):
    source = (source or "").strip().lower()
    source = source if source in ("etsy", "vinted") else "other"
    p = payload if isinstance(payload, dict) else {}

    external_id = _order_first(p, [
        "id", "order_id", "receipt_id", "transaction_id", "resource_id",
        "data.id", "data.order_id", "data.receipt_id", "data.resource_id", "payload.id"
    ])
    if external_id is None:
        external_id = f"evt-{uuid.uuid4().hex[:16]}"
    external_id = str(external_id)

    order_ref = _order_first(p, [
        "order_ref", "order_number", "receipt_id", "order_id", "id",
        "data.order_ref", "data.order_number", "data.receipt_id"
    ]) or external_id
    order_ref = str(order_ref)

    buyer = _order_first(p, [
        "buyer", "buyer_name", "username", "customer_name",
        "buyer.login", "buyer.username", "user.login", "user.username",
        "data.buyer", "data.buyer_name"
    ]) or ""
    buyer = str(buyer)

    status = _order_first(p, [
        "status", "state", "payment_status", "fulfillment_status",
        "data.status", "data.state"
    ]) or "new"
    status = str(status)

    currency = _order_first(p, [
        "currency", "currency_code", "currencyCode",
        "data.currency", "data.currency_code"
    ])
    total_amount = 0.0
    for amount_path in [
        "total_amount", "amount", "total", "price", "total_price",
        "grandtotal", "data.total_amount", "data.total", "data.price", "data.grandtotal"
    ]:
        val = _order_path_get(p, amount_path)
        if val is None:
            continue
        amt, cur = _order_money(val)
        if abs(amt) > 0:
            total_amount = amt
            if cur and not currency:
                currency = cur
            break

    if currency:
        currency = str(currency).upper().strip()
    else:
        currency = "EUR"

    return {
        "source": source,
        "external_id": external_id,
        "order_ref": order_ref,
        "buyer": buyer,
        "total_amount": float(total_amount),
        "currency": currency,
        "status": status,
        "payload_json": json.dumps(p, ensure_ascii=False),
    }
def _webhook_expected_token(source: str):
    s = str(source or "").strip().lower()
    if s in ("etsy", "vinted"):
        token = _integration_api_value(f"{s}_webhook_token")
        if token:
            return token
    return _integration_api_value("webhook_token")
def _webhook_provided_token():
    tok = (request.headers.get("X-Webhook-Token") or "").strip()
    if tok:
        return tok
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    tok = (request.args.get("token") or "").strip()
    return tok
def _verify_webhook_token(source: str):
    expected = _webhook_expected_token(source)
    require_token = _setting_get_bool("require_webhook_token", _env_bool("SGEST_REQUIRE_WEBHOOK_TOKEN", True))
    if expected == "":
        return not require_token
    provided = _webhook_provided_token()
    return bool(provided) and hmac.compare_digest(provided, expected)
def _save_order_notification(source: str, payload: dict):
    data = _extract_order_notification(source, payload)
    con = _con_biz()
    try:
        con.execute("""
            INSERT INTO order_notifications(
                source, external_id, order_ref, buyer, total_amount, currency, status, payload_json, is_read
            ) VALUES (?,?,?,?,?,?,?,?,0)
            ON CONFLICT(source, external_id) DO UPDATE SET
                received_at=CURRENT_TIMESTAMP,
                order_ref=excluded.order_ref,
                buyer=excluded.buyer,
                total_amount=excluded.total_amount,
                currency=excluded.currency,
                status=excluded.status,
                payload_json=excluded.payload_json,
                is_read=0
        """, (
            data["source"], data["external_id"], data["order_ref"], data["buyer"],
            data["total_amount"], data["currency"], data["status"], data["payload_json"]
        ))
        con.commit()
        row = con.execute(
            "SELECT id FROM order_notifications WHERE source=? AND external_id=?",
            (data["source"], data["external_id"])
        ).fetchone()
        return int(row["id"]) if row else 0
    finally:
        con.close()
def _orders_unread_count():
    con = _con_biz()
    try:
        row = con.execute(
            "SELECT COALESCE(SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END),0) AS c FROM order_notifications"
        ).fetchone()
        return int(row["c"] or 0)
    finally:
        con.close()
def _orders_list(limit=60):
    lim = max(1, min(300, _safe_int(limit, 60)))
    con = _con_biz()
    try:
        rows = con.execute("""
            SELECT id, created_at, received_at, source, external_id, order_ref, buyer,
                   total_amount, currency, status, is_read, note
            FROM order_notifications
            ORDER BY id DESC
            LIMIT ?
        """, (lim,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _catalog_files_root():
    root = os.path.join(_stockdash_data_dir(), "catalog_files")
    os.makedirs(root, exist_ok=True)
    return root
def _catalog_allowed_file(filename: str):
    ext = (os.path.splitext(filename or "")[1] or "").lower()
    allowed = {
        ".jpg", ".jpeg", ".png", ".webp", ".gif",
        ".pdf", ".txt", ".csv",
        ".stl", ".obj", ".3mf", ".zip"
    }
    return ext in allowed
def _catalog_is_image(filename: str, mime: str = ""):
    m = (mime or "").strip().lower()
    if m.startswith("image/"):
        return True
    ext = (os.path.splitext(filename or "")[1] or "").lower()
    return ext in {".jpg", ".jpeg", ".png", ".webp", ".gif"}
def _new_catalog_token():
    return uuid.uuid4().hex + uuid.uuid4().hex
def _get_catalog(catalog_id: int):
    con = _con_biz()
    try:
        row = con.execute("SELECT * FROM catalogs WHERE id=?", (catalog_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()
def _catalog_items_with_files(catalog_id: int):
    con = _con_biz()
    try:
        items = [dict(r) for r in con.execute("""
            SELECT i.*,
                   COALESCE((SELECT COUNT(1) FROM catalog_files f WHERE f.item_id=i.id),0) AS file_count
            FROM catalog_items i
            WHERE i.catalog_id=?
            ORDER BY i.id DESC
        """, (catalog_id,)).fetchall()]
        file_rows = [dict(r) for r in con.execute("""
            SELECT *
            FROM catalog_files
            WHERE catalog_id=?
            ORDER BY id DESC
        """, (catalog_id,)).fetchall()]
    finally:
        con.close()

    files_by_item = {}
    for f in file_rows:
        f["is_image"] = 1 if _catalog_is_image(f.get("original_name") or "", f.get("mime_type") or "") else 0
        files_by_item.setdefault(int(f["item_id"]), []).append(f)
    for it in items:
        it["files"] = files_by_item.get(int(it["id"]), [])
        it["cover"] = next((f for f in it["files"] if int(f.get("is_image") or 0) == 1), None)
    return items
def _catalog_file_abs_path(file_name: str):
    root = os.path.realpath(_catalog_files_root())
    abs_path = os.path.realpath(os.path.join(root, file_name or ""))
    if abs_path == root or not abs_path.startswith(root + os.sep):
        return None
    return abs_path
def _catalog_delete_file_record(file_id: int):
    con = _con_biz()
    try:
        row = con.execute("SELECT * FROM catalog_files WHERE id=?", (file_id,)).fetchone()
        if not row:
            return False
        rel = row["file_name"]
        con.execute("DELETE FROM catalog_files WHERE id=?", (file_id,))
        con.commit()
    finally:
        con.close()
    try:
        abs_path = _catalog_file_abs_path(rel)
        if abs_path and os.path.isfile(abs_path):
            os.remove(abs_path)
    except Exception:
        pass
    return True
def _custom_field_key(raw: str):
    base = str(raw or "").strip().lower()
    if not base:
        return ""
    key = re.sub(r"[^a-z0-9]+", "_", base).strip("_")
    if key and key[0].isdigit():
        key = f"f_{key}"
    return key[:48]
def _custom_parse_options(raw: str):
    text = str(raw or "").strip()
    if not text:
        return []
    values = []
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                values = [str(x).strip() for x in arr]
        except Exception:
            values = []
    if not values:
        text = text.replace("\n", ",").replace(";", ",")
        values = [v.strip() for v in text.split(",")]
    out = []
    seen = set()
    for v in values:
        if not v:
            continue
        vv = v[:80]
        if vv.lower() in seen:
            continue
        seen.add(vv.lower())
        out.append(vv)
    return out
def _custom_field_options(field):
    try:
        arr = json.loads(str((field or {}).get("options_json") or "[]"))
        if not isinstance(arr, list):
            return []
        return [str(x).strip() for x in arr if str(x).strip()]
    except Exception:
        return []
def _custom_load_fields(con, module_id: int):
    rows = con.execute("""
        SELECT *
        FROM custom_stock_fields
        WHERE module_id=?
        ORDER BY sort_order ASC, id ASC
    """, (int(module_id),)).fetchall()
    fields = []
    for r in rows:
        d = dict(r)
        d["options"] = _custom_field_options(d)
        fields.append(d)
    return fields
def _custom_data_to_dict(data_json: str):
    try:
        data = json.loads(str(data_json or "{}"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
def _custom_display_value(value, field_type: str):
    ftype = str(field_type or "text").strip().lower()
    if value is None:
        return ""
    if ftype == "number":
        n = _safe_float(value, 0.0)
        if abs(n - round(n)) < 1e-9:
            return str(int(round(n)))
        return f"{n:.3f}".rstrip("0").rstrip(".")
    if ftype == "boolean":
        return "Oui" if str(value).strip().lower() in ("1", "true", "yes", "on") else "Non"
    return str(value)
def human_size(n: int) -> str:
    units = ["B","KB","MB","GB","TB","PB"]
    s = 0; f = float(n)
    while f >= 1024 and s < len(units)-1:
        f /= 1024.0; s += 1
    return f"{int(f)} {units[s]}" if s == 0 else f"{f:.1f} {units[s]}"
def get_disk_stats(path="/"):
    total, used, free = shutil.disk_usage(path)
    return {
        "total": total, "used": used, "free": free,
        "total_human": human_size(total),
        "used_human": human_size(used),
        "free_human": human_size(free),
        "used_pct": round((used/total)*100, 1) if total else 0.0,
    }
def get_ram_stats():
    total = 0
    available = 0
    try:
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            rows = meminfo.read_text(errors="ignore").splitlines()
            for line in rows:
                if line.startswith("MemTotal:"):
                    total = _safe_int(line.split()[1], 0) * 1024
                elif line.startswith("MemAvailable:"):
                    available = _safe_int(line.split()[1], 0) * 1024
    except Exception:
        total = 0
        available = 0

    used = max(0, total - available)
    return {
        "total": total,
        "used": used,
        "free": max(0, available),
        "total_human": human_size(total) if total else "Inconnue",
        "used_human": human_size(used) if total else "Inconnue",
        "free_human": human_size(available) if total else "Inconnue",
        "used_pct": round((used / total) * 100, 1) if total else 0.0,
    }
def get_machine_specs():
    cpu_model = "Inconnu"
    try:
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.exists():
            for line in cpuinfo.read_text(errors="ignore").splitlines():
                if ":" not in line:
                    continue
                key, val = [x.strip() for x in line.split(":", 1)]
                lk = key.lower()
                if lk in ("model name", "hardware", "processor"):
                    cpu_model = val or cpu_model
                    if lk == "model name":
                        break
    except Exception:
        pass

    return {
        "model": pi_model(),
        "cpu": cpu_model,
        "arch": platform.machine() or "Inconnu",
        "cores": os.cpu_count() or 0,
        "kernel": platform.release() or "Inconnu",
    }
BACKUP_DIR = Path.home() / "backups"
LOG_DIR = BACKUP_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_KEEP_MAX = 20
def list_backups(max_items=BACKUP_KEEP_MAX):
    files = sorted(BACKUP_DIR.glob("stockdash_*.tgz"), key=lambda p: p.stat().st_mtime, reverse=True)
    out = []
    for p in files[:max_items]:
        st = p.stat()
        out.append({"name": p.name, "size": human_size(st.st_size),
                    "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "mtime": st.st_mtime})
    return out
def last_backup_dt():
    b = list_backups(1)
    return b[0]["date"] if b else "Jamais"
def _backup_open_alerts(limit=8):
    con = _con_biz()
    try:
        rows = con.execute("""
            SELECT id, created_at, updated_at, kind, severity, message, details, occurrences
            FROM backup_alerts
            WHERE status='open'
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
        """, (max(1, int(limit)),)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _backup_last_run(check_type: str):
    con = _con_biz()
    try:
        row = con.execute("""
            SELECT id, created_at, check_type, status, message, details
            FROM backup_monitor_runs
            WHERE check_type=?
            ORDER BY id DESC
            LIMIT 1
        """, (check_type,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()
def backup_monitor_summary():
    open_alerts = _backup_open_alerts(limit=8)
    return {
        "open_alerts": open_alerts,
        "open_count": len(open_alerts),
        "last_backup_job": _backup_last_run("backup_job"),
        "last_timer_check": _backup_last_run("timer_check"),
        "last_restore_test": _backup_last_run("restore_test"),
    }
def backup_scheduler_status():
    def _fr_next_label(raw: str):
        txt = str(raw or "").strip()
        if not txt:
            return "Inconnue"
        txt = txt.split(";", 1)[0].strip()
        txt = re.sub(r"^[A-Za-z]{3}\s+", "", txt)
        m = re.search(r"(\d{4})-(\d{2})-(\d{2})\s+(\d{2}:\d{2}:\d{2})", txt)
        if m:
            yyyy, mm, dd, hhmmss = m.groups()
            return f"{dd}/{mm}/{yyyy} {hhmmss} (heure France)"
        return txt

    status = {
        "enabled": False,
        "active": False,
        "next_run": "Inconnue",
    }
    try:
        en = subprocess.run(
            ["systemctl", "is-enabled", "stockdash-backup.timer"],
            capture_output=True,
            text=True,
            check=False,
        )
        status["enabled"] = (en.returncode == 0 and (en.stdout or "").strip() == "enabled")
    except Exception:
        pass

    try:
        ac = subprocess.run(
            ["systemctl", "is-active", "stockdash-backup.timer"],
            capture_output=True,
            text=True,
            check=False,
        )
        status["active"] = (ac.returncode == 0 and (ac.stdout or "").strip() == "active")
    except Exception:
        pass

    try:
        nx = subprocess.run(
            ["systemctl", "show", "-p", "NextElapseUSecRealtime", "stockdash-backup.timer"],
            capture_output=True,
            text=True,
            check=False,
        )
        value = (nx.stdout or "").strip()
        if "=" in value:
            value = value.split("=", 1)[1].strip()
        if nx.returncode == 0 and value and value.lower() not in ("n/a", "0"):
            status["next_run"] = _fr_next_label(value)
    except Exception:
        pass

    if status["next_run"] == "Inconnue":
        try:
            st = subprocess.run(
                ["systemctl", "status", "stockdash-backup.timer", "--no-pager", "-n", "0"],
                capture_output=True,
                text=True,
                check=False,
            )
            txt = (st.stdout or "")
            m = re.search(r"Trigger:\s*(.+)", txt)
            if m:
                status["next_run"] = _fr_next_label(m.group(1).strip())
        except Exception:
            pass

    if status["next_run"] == "Inconnue":
        try:
            nx2 = subprocess.run(
                ["systemctl", "show", "-p", "NextElapseUSecMonotonic", "--value", "stockdash-backup.timer"],
                capture_output=True,
                text=True,
                check=False,
            )
            value2 = (nx2.stdout or "").strip()
            if nx2.returncode == 0 and value2 and value2.lower() not in ("n/a", "0"):
                status["next_run"] = value2
        except Exception:
            pass
    return status
def pi_model():
    try:
        mf = Path("/proc/device-tree/model")
        if mf.exists(): return mf.read_text(errors="ignore").strip("\x00 \n")
    except Exception: pass
    return platform.platform()
def inject_asset_ver():
    theme = _theme_palette(*_current_theme_colors())
    user = _current_auth_user()
    return {
        "ASSET_VER": current_app.config["ASSET_VER"],
        "csrf_token": _ensure_csrf_token,
        "is_authenticated": _session_is_authenticated(),
        "current_user": user,
        "current_user_avatar_url": _avatar_url_for_user(user or {}),
        "current_user_role_label": "Admin" if str((user or {}).get("role") or "").lower() == "admin" else "User",
        "theme_primary": theme["primary"],
        "theme_secondary": theme["secondary"],
        "theme_primary_rgb": theme["primary_rgb"],
        "theme_secondary_rgb": theme["secondary_rgb"],
        "theme_bg_0": theme["app_bg_0"],
        "theme_bg_1": theme["app_bg_1"],
        "theme_bg_2": theme["app_bg_2"],
        "theme_panel_border": theme["panel_border"],
        "theme_panel_bg": theme["panel_bg"],
        "theme_panel_bg_strong": theme["panel_bg_strong"],
        "theme_text_soft": theme["text_soft"],
        "theme_btn": theme["btn"],
        "theme_btn_hover": theme["btn_hover"],
        "theme_btn_text": theme["btn_text"],
    }
def apply_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    csp = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp
def security_gate():
    host_allow = (os.getenv("SGEST_ALLOWED_HOSTS") or "").strip()
    if host_allow:
        allowed = {h.strip().lower() for h in host_allow.split(",") if h.strip()}
        req_host = (request.host.split(":")[0] if request.host else "").lower()
        if req_host not in allowed:
            return ("Host non autorise.", 400)

    endpoint = request.endpoint or ""
    public_endpoints = {
        "login",
        "login_post",
        "auth_recovery_request",
        "auth_recovery_reset",
        "webhook_orders_etsy",
        "webhook_orders_vinted",
        "catalog_public_page",
        "catalog_public_file",
        "ping",
        "static",
    }
    if endpoint == "static" or endpoint.startswith("static"):
        return None
    if endpoint in public_endpoints:
        return None

    if not _session_is_authenticated():
        if _is_api_request():
            return jsonify(ok=False, error="auth_required"), 401
        return redirect(url_for("login", next=request.path))
    if not _current_auth_user():
        session.clear()
        if _is_api_request():
            return jsonify(ok=False, error="auth_required"), 401
        return redirect(url_for("login", next=request.path))

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        csrf_exempt = {"login", "login_post", "webhook_orders_etsy", "webhook_orders_vinted"}
        if endpoint not in csrf_exempt:
            sent = (
                (request.form.get("_csrf") or "").strip()
                or (request.headers.get("X-CSRF-Token") or "").strip()
            )
            expected = (session.get("csrf_token") or "").strip()
            if not sent or not expected or not hmac.compare_digest(sent, expected):
                if _is_api_request():
                    return jsonify(ok=False, error="csrf_invalid"), 400
                abort(400)
    return None
def _dashboard_stock_summary(kind: str):
    configs = {
        "broderie": {
            "label": "Broderie",
            "icon": "bi-scissors",
            "url": "/stock/broderie",
            "bump_path": "/stock/broderie",
            "dimension_label": "tailles",
            "spotlight_title": "T-shirts par taille",
            "spotlight_group_col": "material",
            "spotlight_unit_label": "t-shirts",
            "table": "stock_bro",
            "alerts": "stock_bro_alerts",
            "connector": _con_bro,
        },
        "impression3d": {
            "label": "Impression 3D",
            "icon": "bi-printer",
            "url": "/stock/impression3d",
            "bump_path": "/stock/impression3d",
            "dimension_label": "matieres",
            "spotlight_title": "Bobines par couleur",
            "spotlight_group_col": "color",
            "spotlight_unit_label": "bobines",
            "table": "stock_3d",
            "alerts": "stock_3d_alerts",
            "connector": _con_3d,
        },
    }
    cfg = configs[kind]
    con = cfg["connector"]()
    table = cfg["table"]
    alerts = cfg["alerts"]
    spotlight_group_col = cfg["spotlight_group_col"]

    try:
        stats = con.execute(f"""
            SELECT
                COUNT(1) AS refs,
                COALESCE(SUM(CASE WHEN IFNULL(qty,0) > 0 THEN IFNULL(qty,0) ELSE 0 END), 0) AS units,
                COALESCE(SUM(CASE WHEN IFNULL(qty,0) > 0 THEN IFNULL(price,0) * IFNULL(qty,0) ELSE 0 END), 0) AS stock_value,
                COALESCE(SUM(CASE WHEN IFNULL(qty,0) <= 0 THEN 1 ELSE 0 END), 0) AS empty_refs
            FROM {table}
        """).fetchone()

        materials = con.execute(f"""
            SELECT COUNT(DISTINCT material) AS c
            FROM {table}
            WHERE material IS NOT NULL AND TRIM(material) <> ''
        """).fetchone()[0]

        colors = con.execute(f"""
            SELECT COUNT(DISTINCT color) AS c
            FROM {table}
            WHERE color IS NOT NULL AND TRIM(color) <> ''
        """).fetchone()[0]

        alert_cfg = con.execute(f"""
            SELECT COUNT(1) AS c
            FROM {alerts} a
            JOIN {table} i ON i.id = a.item_id
            WHERE IFNULL(a.threshold,0) > 0
        """).fetchone()[0]

        low_count = con.execute(f"""
            SELECT COUNT(1) AS c
            FROM {table} i
            JOIN {alerts} a ON a.item_id = i.id
            WHERE IFNULL(a.threshold,0) > 0 AND IFNULL(i.qty,0) <= a.threshold
        """).fetchone()[0]

        top_rows = con.execute(f"""
            SELECT
                i.id,
                COALESCE(i.name, '') AS name,
                COALESCE(i.material, '') AS material,
                COALESCE(i.color, '') AS color,
                IFNULL(i.qty,0) AS qty,
                IFNULL(a.threshold,0) AS threshold,
                (IFNULL(a.threshold,0) - IFNULL(i.qty,0)) AS gap
            FROM {table} i
            JOIN {alerts} a ON a.item_id = i.id
            WHERE IFNULL(a.threshold,0) > 0 AND IFNULL(i.qty,0) <= a.threshold
            ORDER BY gap DESC, i.id DESC
            LIMIT 5
        """).fetchall()

        spotlight_rows = con.execute(f"""
            SELECT
                COALESCE(NULLIF(TRIM({spotlight_group_col}), ''), 'Non defini') AS label,
                COALESCE(SUM(CASE WHEN IFNULL(qty,0) > 0 THEN IFNULL(qty,0) ELSE 0 END), 0) AS units
            FROM {table}
            GROUP BY COALESCE(NULLIF(TRIM({spotlight_group_col}), ''), 'Non defini')
            HAVING COALESCE(SUM(CASE WHEN IFNULL(qty,0) > 0 THEN IFNULL(qty,0) ELSE 0 END), 0) > 0
            ORDER BY units DESC, label ASC
            LIMIT 8
        """).fetchall()
    finally:
        con.close()

    refs = int(stats["refs"] or 0)
    units_raw = float(stats["units"] or 0.0)
    units = int(round(units_raw)) if kind == "broderie" else round(units_raw, 3)
    stock_value = float(stats["stock_value"] or 0.0)
    empty_refs = int(stats["empty_refs"] or 0)
    materials = int(materials or 0)
    colors = int(colors or 0)
    alert_cfg = int(alert_cfg or 0)
    low_count = int(low_count or 0)
    spotlight = [dict(r) for r in spotlight_rows]
    spotlight_total = sum(float(s["units"] or 0) for s in spotlight)
    spotlight_max = max((float(s["units"] or 0) for s in spotlight), default=0)
    for s in spotlight:
        raw_u = float(s["units"] or 0)
        u = int(round(raw_u)) if kind == "broderie" else round(raw_u, 3)
        s["units"] = u
        ratio = 0.0 if spotlight_max <= 0 else (raw_u / spotlight_max)
        s["pct"] = 0 if spotlight_max <= 0 else max(4, int(round(ratio * 100)))
        s["heat_alpha"] = round(0.16 + (0.56 * ratio), 3)
        s["heat_alpha_low"] = round(0.06 + (0.26 * ratio), 3)
        s["heat_border_alpha"] = round(0.24 + (0.50 * ratio), 3)
        s["badge_light"] = int(round(89 - (34 * ratio)))
        s["bar_start"] = int(round(90 - (20 * ratio)))
        s["bar_end"] = int(round(78 - (34 * ratio)))

    health_pct = 100 if refs == 0 else max(0, min(100, int(round(((refs - low_count) / refs) * 100))))
    alert_coverage_pct = 0 if refs == 0 else int(round((alert_cfg / refs) * 100))

    return {
        "kind": kind,
        "label": cfg["label"],
        "icon": cfg["icon"],
        "url": cfg["url"],
        "bump_path": cfg["bump_path"],
        "dimension_label": cfg["dimension_label"],
        "spotlight_title": cfg["spotlight_title"],
        "spotlight_unit_label": cfg["spotlight_unit_label"],
        "refs": refs,
        "units": units,
        "stock_value": stock_value,
        "empty_refs": empty_refs,
        "materials": materials,
        "colors": colors,
        "alert_cfg": alert_cfg,
        "alert_coverage_pct": alert_coverage_pct,
        "low_count": low_count,
        "spotlight_total": spotlight_total,
        "spotlight": spotlight,
        "health_pct": health_pct,
        "top_critical": [dict(r) for r in top_rows],
    }
def _load_bro_products():
    con = _con_bro()
    try:
        return [dict(r) for r in con.execute("""
            SELECT id, COALESCE(name,'') AS name, COALESCE(ref,'') AS ref,
                   COALESCE(material,'') AS material, COALESCE(color,'') AS color,
                   COALESCE(price,0) AS price, COALESCE(qty,0) AS qty
            FROM stock_bro
            ORDER BY id DESC
        """).fetchall()]
    finally:
        con.close()
def _load_3d_spools():
    con = _con_3d()
    try:
        return [dict(r) for r in con.execute("""
            SELECT id, COALESCE(name,'') AS name, COALESCE(ref,'') AS ref,
                   COALESCE(material,'') AS material, COALESCE(color,'') AS color,
                   COALESCE(price,0) AS price, COALESCE(qty,0) AS qty
            FROM stock_3d
            ORDER BY id DESC
        """).fetchall()]
    finally:
        con.close()
def _password_strength_errors(pw: str):
    p = str(pw or "")
    errs = []
    if len(p) < 12:
        errs.append("12 caracteres minimum.")
    if not re.search(r"[A-Z]", p):
        errs.append("au moins 1 majuscule.")
    if not re.search(r"[a-z]", p):
        errs.append("au moins 1 minuscule.")
    if not re.search(r"\d", p):
        errs.append("au moins 1 chiffre.")
    if not re.search(r"[^A-Za-z0-9]", p):
        errs.append("au moins 1 caractere special.")
    return errs
def not_found(e): return render_template("404.html", title="404 – Page introuvable"), 404
def server_error(e): return render_template("500.html", title="500 – Erreur interne"), 500
def _con_3d():
    db_path = os.path.join(_stockdash_data_dir(), "impression3d.db")
    con = _sqlite_connect(db_path)
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_3d(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        material TEXT NOT NULL,
        color    TEXT NOT NULL,
        ref      TEXT NOT NULL,
        price    REAL DEFAULT 0,
        qty      INTEGER DEFAULT 0,
        name     TEXT
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_3d_alerts(
        item_id   INTEGER PRIMARY KEY,
        threshold INTEGER NOT NULL DEFAULT 0
    );
    """)
    return con
def _ensure_bro_ref_not_unique(con):
    """
    Legacy migration:
    old DBs may have UNIQUE(ref) on stock_bro.
    Broderie needs same ref for multiple sizes/colors.
    """
    table_row = con.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='stock_bro'"
    ).fetchone()
    table_sql = ((table_row["sql"] if table_row and table_row["sql"] else "")).lower()

    has_table_ref_unique = bool(
        re.search(r"\bref\b[^,)]*\bunique\b", table_sql) or
        re.search(r"unique\s*\(\s*ref\s*\)", table_sql)
    )

    needs_rebuild = has_table_ref_unique

    idx_rows = con.execute("PRAGMA index_list('stock_bro')").fetchall()
    for idx in idx_rows:
        idx_name = idx["name"]
        is_unique = bool(idx["unique"])
        if not is_unique:
            continue

        idx_cols = [c["name"] for c in con.execute(f"PRAGMA index_info('{idx_name}')").fetchall()]
        if len(idx_cols) == 1 and idx_cols[0] == "ref":
            if idx_name.startswith("sqlite_autoindex_"):
                needs_rebuild = True
            else:
                con.execute(f'DROP INDEX IF EXISTS "{idx_name}"')

    if not needs_rebuild:
        return

    fk_on = int(con.execute("PRAGMA foreign_keys").fetchone()[0] or 0)
    con.execute("PRAGMA foreign_keys=OFF")
    con.execute("DROP TABLE IF EXISTS stock_bro__new")
    con.execute("""
    CREATE TABLE stock_bro__new(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        material TEXT NOT NULL,
        color    TEXT NOT NULL,
        ref      TEXT NOT NULL,
        price    REAL DEFAULT 0,
        qty      INTEGER DEFAULT 0,
        name     TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cols = {r["name"] for r in con.execute("PRAGMA table_info(stock_bro)").fetchall()}
    if "created_at" in cols:
        con.execute("""
            INSERT INTO stock_bro__new(id,material,color,ref,price,qty,name,created_at)
            SELECT
                id,
                COALESCE(material,''),
                COALESCE(color,''),
                COALESCE(ref,''),
                COALESCE(price,0),
                COALESCE(qty,0),
                name,
                COALESCE(created_at, CURRENT_TIMESTAMP)
            FROM stock_bro
        """)
    else:
        con.execute("""
            INSERT INTO stock_bro__new(id,material,color,ref,price,qty,name,created_at)
            SELECT
                id,
                COALESCE(material,''),
                COALESCE(color,''),
                COALESCE(ref,''),
                COALESCE(price,0),
                COALESCE(qty,0),
                name,
                CURRENT_TIMESTAMP
            FROM stock_bro
        """)

    con.execute("DROP TABLE stock_bro")
    con.execute("ALTER TABLE stock_bro__new RENAME TO stock_bro")
    con.execute("CREATE INDEX IF NOT EXISTS idx_bro_ref ON stock_bro(ref)")
    if fk_on:
        con.execute("PRAGMA foreign_keys=ON")
def _con_bro():
    db_path = os.path.join(_stockdash_data_dir(), "broderie.db")
    con = _sqlite_connect(db_path)

    # Schéma des articles
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_bro(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        material TEXT NOT NULL,
        color    TEXT NOT NULL,
        ref      TEXT NOT NULL,
        price    REAL DEFAULT 0,
        qty      INTEGER DEFAULT 0,
        name     TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Schéma des alertes
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_bro_alerts(
        item_id   INTEGER PRIMARY KEY,
        threshold INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(item_id) REFERENCES stock_bro(id) ON DELETE CASCADE
    );
    """)

    # Assurer l'unicité sur item_id (si table existait avec mauvais index)
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_bro_alert_item ON stock_bro_alerts(item_id);")
    _ensure_bro_ref_not_unique(con)
    con.commit()
    return con
from flask import jsonify
def api_alerts_count():
    total = 0
    # 3D alerts
    try:
        con = _con_3d()
        cur = con.execute("""
            SELECT COUNT(1)
            FROM stock_3d i
            JOIN stock_3d_alerts a ON a.item_id=i.id
            WHERE a.threshold>0 AND IFNULL(i.qty,0) <= a.threshold
        """)
        row = cur.fetchone()
        total += int(row[0] if row and row[0] is not None else 0)
        con.close()
    except Exception:
        pass
    # Broderie alerts
    try:
        con = _con_bro()
        cur = con.execute("""
            SELECT COUNT(1)
            FROM stock_bro i
            JOIN stock_bro_alerts a ON a.item_id=i.id
            WHERE a.threshold>0 AND IFNULL(i.qty,0) <= a.threshold
        """)
        row = cur.fetchone()
        total += int(row[0] if row and row[0] is not None else 0)
        con.close()
    except Exception:
        pass
    return jsonify(count=total)
def _legacy_api_orders_count_placeholder():
    # kept only for backward compatibility during transition
    return jsonify(count=0)
from flask import jsonify
def _get_impr3d_alerts_list():
    con = _con_3d()
    try:
        rows = con.execute("""
            SELECT i.id,
                   COALESCE(i.name,'') AS name,
                   i.material, i.color, i.qty,
                   COALESCE(a.threshold,0) AS threshold
            FROM stock_3d i
            JOIN stock_3d_alerts a ON a.item_id=i.id
            WHERE a.threshold>0 AND IFNULL(i.qty,0) <= a.threshold
            ORDER BY i.id DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _get_broderie_alerts_list():
    con = _con_bro()
    try:
        rows = con.execute("""
            SELECT b.id,
                   COALESCE(b.name,'') AS name,
                   b.material, b.color, b.qty,
                   COALESCE(a.threshold,0) AS threshold
            FROM stock_bro b
            JOIN stock_bro_alerts a ON a.item_id=b.id
            WHERE a.threshold>0 AND IFNULL(b.qty,0) <= a.threshold
            ORDER BY b.id DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
def _webhook_payload():
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        return payload
    raw = request.get_data(as_text=True) or ""
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"raw": raw}
    except Exception:
        return {"raw": raw}
def _webhook_receive(source: str):
    ip = _current_user_ip()
    if _rate_limited(_WEBHOOK_RATE_BUCKET, f"{source}:{ip}", limit=180, window_sec=60, consume=True):
        return jsonify(ok=False, error="rate_limited"), 429
    if not _verify_webhook_token(source):
        return jsonify(ok=False, error="unauthorized"), 401
    payload = _webhook_payload()
    order_id = _save_order_notification(source, payload)
    return jsonify(ok=True, id=order_id)
