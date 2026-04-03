from flask import Flask, render_template, jsonify, send_from_directory, redirect, url_for, request, flash, Response, session, abort, send_file
from datetime import datetime, timedelta
from pathlib import Path
import shutil, platform, subprocess, os, time, re, sqlite3, io, csv, json, hmac, uuid, secrets, smtplib
from email.message import EmailMessage
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = (os.getenv("SGEST_SECRET_KEY") or "dev-sgest-key-change-me")
app.config["ASSET_VER"] = int(time.time())
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = str(os.getenv("SGEST_COOKIE_SECURE", "0")).strip().lower() in ("1", "true", "yes", "on")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
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
    bucket[key] = values
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
    d = Path(app.root_path) / "static" / AVATAR_UPLOAD_REL
    d.mkdir(parents=True, exist_ok=True)
    return d

def _avatar_url_for_user(user):
    rel = _safe_avatar_rel_path((user or {}).get("avatar_path") if isinstance(user, dict) else "")
    if rel:
        abs_path = Path(app.root_path) / "static" / rel
        if abs_path.is_file():
            return url_for("static", filename=rel)
    return url_for("static", filename=DEFAULT_AVATAR_REL)

def _delete_avatar_file(rel_path: str):
    rel = _safe_avatar_rel_path(rel_path)
    if not rel:
        return
    try:
        abs_path = Path(app.root_path) / "static" / rel
        if abs_path.is_file():
            abs_path.unlink()
    except Exception:
        pass

def _con_biz():
    db_dir = os.path.expanduser('~/stockdash/data')
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'business.db')
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
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
    root = os.path.expanduser("~/stockdash/data/catalog_files")
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

@app.context_processor
def inject_asset_ver():
    theme = _theme_palette(*_current_theme_colors())
    user = _current_auth_user()
    return {
        "ASSET_VER": app.config["ASSET_VER"],
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

@app.after_request
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

@app.before_request
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

@app.errorhandler(404)
def not_found(e): return render_template("404.html", title="404 – Page introuvable"), 404

@app.errorhandler(500)
def server_error(e): return render_template("500.html", title="500 – Erreur interne"), 500

# ---- DB helper + migration douce (min_qty) ----
def _con_3d():
    import os, sqlite3
    db_dir = os.path.expanduser('~/stockdash/data')
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'impression3d.db')
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
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

# === Broderie (même logique que Impression 3D) ===
def _con_bro_old():
    import os, sqlite3
    db_dir = os.path.expanduser('~/stockdash/data')
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'broderie.db')
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
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
    CREATE TABLE IF NOT EXISTS stock_bro_alerts(
        item_id   INTEGER PRIMARY KEY,
        threshold INTEGER NOT NULL DEFAULT 0
    );
    """)
    return con
# ==== BRODERIE (auto-added) ===============================================
def _con_bro_old():
    import os, sqlite3
    db_dir = os.path.expanduser('~/stockdash/data')
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'broderie.db')
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
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
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_bro_alerts(
      item_id INTEGER PRIMARY KEY,
      threshold INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(item_id) REFERENCES stock_bro(id) ON DELETE CASCADE
    );
    """)
    return con

# ==== /BRODERIE =============================================================





# <<BRODERIE-START>>
# Broderie: DB + routes + API alerts

def _con_bro_old():
    import os, sqlite3
    db_dir = os.path.expanduser('~/stockdash/data')
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'broderie.db')
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_bro(
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        name     TEXT,
        ref      TEXT,
        material TEXT,
        color    TEXT,
        price    REAL DEFAULT 0,
        qty      INTEGER DEFAULT 0
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS stock_bro_alerts(
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id   INTEGER UNIQUE NOT NULL,
        threshold INTEGER NOT NULL DEFAULT 0
    );
    """)
    return con






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
# <<BRODERIE-END>>

# ==== BRODERIE AUTO START ====
# Bloc généré automatiquement : logique identique à la 3D, base dédiée broderie.db
from flask import request, redirect, url_for, flash, render_template

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
    import os, sqlite3
    db_dir = os.path.expanduser('~/stockdash/data')
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, 'broderie.db')
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row

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

if __name__ == "__main__":
    app.run("127.0.0.1", 8000, debug=True)

# === Toolbar counters (alerts & orders) ===
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

# --- Compat: POST /stock/broderie/<int:item_id>/alert ---
# Permet au front de poster une alerte pour un article précis.
# Accepte "threshold" ou "min_qty" et fait un UPSERT.
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

# === Alerts count API (3D + Broderie) ===
from flask import jsonify

# === ALERTES: Helpers + Routes (version sûre) ===

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

@app.post("/webhooks/orders/etsy")
def webhook_orders_etsy():
    return _webhook_receive("etsy")

@app.post("/webhooks/orders/vinted")
def webhook_orders_vinted():
    return _webhook_receive("vinted")

