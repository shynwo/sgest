#!/usr/bin/env python3
import argparse
import os
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

HOME = Path.home()
DATA_DIR = HOME / "stockdash" / "data"
DB_PATH = DATA_DIR / "business.db"
BACKUP_DIR = HOME / "backups"
MAX_BACKUP_AGE_HOURS = int(os.getenv("SGEST_BACKUP_MAX_AGE_HOURS", "14"))


def _con():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS backup_monitor_runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            check_type TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT
        );
        """
    )
    con.execute(
        """
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
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_backup_runs_type_created ON backup_monitor_runs(check_type, created_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_backup_alerts_status_updated ON backup_alerts(status, updated_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_backup_alerts_kind_status ON backup_alerts(kind, status)")
    con.commit()
    return con


def _run_log(con, check_type: str, status: str, message: str, details: str = ""):
    con.execute(
        """
        INSERT INTO backup_monitor_runs(check_type, status, message, details)
        VALUES (?, ?, ?, ?)
        """,
        (check_type, status, message, details or ""),
    )
    con.commit()


def _open_alert(con, kind: str, severity: str, message: str, details: str = ""):
    row = con.execute(
        """
        SELECT id, occurrences
        FROM backup_alerts
        WHERE status='open' AND kind=? AND message=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (kind, message),
    ).fetchone()
    if row:
        con.execute(
            """
            UPDATE backup_alerts
            SET updated_at=CURRENT_TIMESTAMP,
                details=?,
                occurrences=COALESCE(occurrences,1)+1
            WHERE id=?
            """,
            (details or "", int(row["id"])),
        )
    else:
        con.execute(
            """
            INSERT INTO backup_alerts(kind, severity, message, details, status, occurrences)
            VALUES (?, ?, ?, ?, 'open', 1)
            """,
            (kind, severity, message, details or ""),
        )
    con.commit()


def _resolve_kind(con, kind: str):
    con.execute(
        """
        UPDATE backup_alerts
        SET status='resolved',
            updated_at=CURRENT_TIMESTAMP,
            resolved_at=CURRENT_TIMESTAMP
        WHERE kind=? AND status='open'
        """,
        (kind,),
    )
    con.commit()


def _latest_backup_path():
    files = sorted(BACKUP_DIR.glob("stockdash_*.tgz"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def cmd_backup_hook(args):
    con = _con()
    try:
        if args.status == "success":
            details = str(args.archive or "")
            _run_log(con, "backup_job", "ok", "Sauvegarde automatique OK", details)
            _resolve_kind(con, "backup_job")
            return 0

        details = str(args.error or "").strip()
        if not details:
            details = "Echec non detaille."
        _run_log(con, "backup_job", "error", "Sauvegarde automatique en echec", details)
        _open_alert(con, "backup_job", "error", "Sauvegarde automatique en echec", details)
        return 1
    finally:
        con.close()


def cmd_timer_check(_args):
    con = _con()
    issues = []
    try:
        enabled = subprocess.run(
            ["systemctl", "is-enabled", "stockdash-backup.timer"],
            capture_output=True,
            text=True,
            check=False,
        )
        active = subprocess.run(
            ["systemctl", "is-active", "stockdash-backup.timer"],
            capture_output=True,
            text=True,
            check=False,
        )
        is_enabled = enabled.returncode == 0 and (enabled.stdout or "").strip() == "enabled"
        is_active = active.returncode == 0 and (active.stdout or "").strip() == "active"

        if not (is_enabled and is_active):
            msg = f"Timer backup inactif (enabled={is_enabled}, active={is_active})"
            issues.append(msg)
            _open_alert(con, "backup_timer", "error", "Timer de sauvegarde inactif", msg)
        else:
            _resolve_kind(con, "backup_timer")

        latest = _latest_backup_path()
        if not latest:
            msg = "Aucune archive stockdash_*.tgz detectee."
            issues.append(msg)
            _open_alert(con, "backup_stale", "error", "Aucune sauvegarde detectee", msg)
        else:
            age_sec = max(0, int(time.time() - latest.stat().st_mtime))
            max_age_sec = max(1, MAX_BACKUP_AGE_HOURS) * 3600
            if age_sec > max_age_sec:
                age_h = round(age_sec / 3600.0, 1)
                msg = f"Derniere sauvegarde trop ancienne ({age_h}h): {latest.name}"
                issues.append(msg)
                _open_alert(con, "backup_stale", "error", "Derniere sauvegarde trop ancienne", msg)
            else:
                _resolve_kind(con, "backup_stale")

        if issues:
            _run_log(con, "timer_check", "error", "Echec verification backup", " | ".join(issues))
            return 1

        ok_msg = "Timer backup OK et sauvegarde recente."
        _run_log(con, "timer_check", "ok", ok_msg, "")
        return 0
    finally:
        con.close()


def cmd_restore_test(_args):
    con = _con()
    try:
        latest = _latest_backup_path()
        if not latest:
            msg = "Aucune archive disponible pour le test de restauration."
            _run_log(con, "restore_test", "error", "Test restauration hebdo en echec", msg)
            _open_alert(con, "backup_restore_test", "error", "Echec test restauration hebdo", msg)
            return 1

        try:
            with tempfile.TemporaryDirectory(prefix="stockdash_restore_test_") as tmp:
                tmp_path = Path(tmp)
                with tarfile.open(latest, "r:gz") as tar:
                    tar.extractall(path=tmp_path)

                extracted_root = tmp_path / "stockdash"
                app_py = extracted_root / "app.py"
                tpl = extracted_root / "templates" / "system.html"
                if not app_py.exists():
                    raise RuntimeError("Archive invalide: app.py introuvable.")
                if not tpl.exists():
                    raise RuntimeError("Archive invalide: templates/system.html introuvable.")

                pyc = subprocess.run(
                    ["python3", "-m", "py_compile", str(app_py)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if pyc.returncode != 0:
                    raise RuntimeError((pyc.stderr or pyc.stdout or "").strip() or "py_compile failed")

            _run_log(con, "restore_test", "ok", "Test restauration hebdo OK", latest.name)
            _resolve_kind(con, "backup_restore_test")
            return 0
        except Exception as exc:
            details = f"{latest.name}: {exc}"
            _run_log(con, "restore_test", "error", "Test restauration hebdo en echec", details)
            _open_alert(con, "backup_restore_test", "error", "Echec test restauration hebdo", details)
            return 1
    finally:
        con.close()


def main():
    parser = argparse.ArgumentParser(description="StockDash backup monitor")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_hook = sub.add_parser("backup-hook", help="Hook for backup success/failure")
    p_hook.add_argument("--status", choices=["success", "error"], required=True)
    p_hook.add_argument("--archive", default="")
    p_hook.add_argument("--error", default="")
    p_hook.set_defaults(func=cmd_backup_hook)

    p_check = sub.add_parser("timer-check", help="Validate backup timer and recency")
    p_check.set_defaults(func=cmd_timer_check)

    p_restore = sub.add_parser("restore-test", help="Run weekly restore validation")
    p_restore.set_defaults(func=cmd_restore_test)

    args = parser.parse_args()
    raise SystemExit(int(args.func(args)))


if __name__ == "__main__":
    main()
