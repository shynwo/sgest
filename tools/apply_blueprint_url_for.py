#!/usr/bin/env python3
"""Préfixe les endpoints dans url_for(...) pour les blueprints Flask."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (endpoint_court, blueprint.endpoint) — ordre géré par longueur décroissante
PAIRS: list[tuple[str, str]] = [
    ("catalog_public_file", "catalog_public.catalog_public_file"),
    ("catalog_public_page", "catalog_public.catalog_public_page"),
    ("auth_recovery_request", "auth.auth_recovery_request"),
    ("auth_recovery_reset", "auth.auth_recovery_reset"),
    ("system_integrations_smtp_update", "system.system_integrations_smtp_update"),
    ("system_integrations_apis_update", "system.system_integrations_apis_update"),
    ("system_integrations_page", "system.system_integrations_page"),
    ("system_profile_password_update", "system.system_profile_password_update"),
    ("system_profile_recovery_email_update", "system.system_profile_recovery_email_update"),
    ("system_profile_avatar_update", "system.system_profile_avatar_update"),
    ("system_profile_avatar_reset", "system.system_profile_avatar_reset"),
    ("system_profile_theme_update", "system.system_profile_theme_update"),
    ("system_profile_users_add", "system.system_profile_users_add"),
    ("system_profile_page", "system.system_profile_page"),
    ("tools_custom_export_csv", "tools.tools_custom_export_csv"),
    ("tools_custom_field_delete", "tools.tools_custom_field_delete"),
    ("tools_custom_stock_page", "tools.tools_custom_stock_page"),
    ("tools_custom_module_delete", "tools.tools_custom_module_delete"),
    ("tools_catalog_detail_page", "tools.tools_catalog_detail_page"),
    ("tools_catalog_file_delete", "tools.tools_catalog_file_delete"),
    ("tools_catalog_toggle_public", "tools.tools_catalog_toggle_public"),
    ("tools_catalog_item_delete", "tools.tools_catalog_item_delete"),
    ("tools_custom_module_add", "tools.tools_custom_module_add"),
    ("tools_custom_field_add", "tools.tools_custom_field_add"),
    ("tools_custom_item_delete", "tools.tools_custom_item_delete"),
    ("tools_gain_export_csv", "tools.tools_gain_export_csv"),
    ("tools_calculator_page", "tools.tools_calculator_page"),
    ("tools_catalog_item_add", "tools.tools_catalog_item_add"),
    ("tools_custom_item_bump", "tools.tools_custom_item_bump"),
    ("tools_custom_item_add", "tools.tools_custom_item_add"),
    ("api_orders_mark_all_read", "stock.api_orders_mark_all_read"),
    ("api_orders_mark_read", "stock.api_orders_mark_read"),
    ("api_broderie_alerts", "stock.api_broderie_alerts"),
    ("api_impr3d_alerts", "stock.api_impr3d_alerts"),
    ("api_alerts_list", "stock.api_alerts_list"),
    ("api_alerts_count", "stock.api_alerts_count"),
    ("api_orders_count", "stock.api_orders_count"),
    ("api_orders_list", "stock.api_orders_list"),
    ("api_orders_mock", "stock.api_orders_mock"),
    ("api_gain_summary", "tools.api_gain_summary"),
    ("backup_health_now", "system.backup_health_now"),
    ("restore_test_now", "system.restore_test_now"),
    ("tools_catalogs_page", "tools.tools_catalogs_page"),
    ("tools_catalogs_add", "tools.tools_catalogs_add"),
    ("tools_catalog_delete", "tools.tools_catalog_delete"),
    ("tools_catalog_file", "tools.tools_catalog_file"),
    ("tools_gain_page", "tools.tools_gain_page"),
    ("tools_gain_record", "tools.tools_gain_record"),
    ("tools_gain_reset", "tools.tools_gain_reset"),
    ("webhook_orders_etsy", "webhooks.webhook_orders_etsy"),
    ("webhook_orders_vinted", "webhooks.webhook_orders_vinted"),
    ("bro_alert_item", "stock.bro_alert_item"),
    ("bro_alert_set", "stock.bro_alert_set"),
    ("bro_alerts_api", "stock.bro_alerts_api"),
    ("inv_3d_page", "stock.inv_3d_page"),
    ("inv_3d_add", "stock.inv_3d_add"),
    ("inv_3d_bump", "stock.inv_3d_bump"),
    ("inv_3d_alert", "stock.inv_3d_alert"),
    ("inv_3d_del", "stock.inv_3d_del"),
    ("backup_delete", "system.backup_delete"),
    ("restore_backup", "system.restore_backup"),
    ("download_backup", "system.download_backup"),
    ("system_page", "system.system_page"),
    ("api_backups", "system.api_backups"),
    ("bro_page", "stock.bro_page"),
    ("bro_add", "stock.bro_add"),
    ("bro_bump", "stock.bro_bump"),
    ("bro_del", "stock.bro_del"),
    ("api_disk", "system.api_disk"),
    ("dashboard", "main.dashboard"),
    ("login_post", "auth.login_post"),
    ("logout", "auth.logout"),
    ("backup_now", "system.backup_now"),
    ("login", "auth.login"),
    ("ping", "main.ping"),
]

PAIRS.sort(key=lambda x: len(x[0]), reverse=True)


def patch_text(s: str) -> str:
    for old, new in PAIRS:
        pat = rf"url_for\(\s*([\'\"]){re.escape(old)}\1"

        def _repl(m: re.Match, n: str = new) -> str:
            return f"url_for({m.group(1)}{n}{m.group(1)}"

        s = re.sub(pat, _repl, s)
    return s


def main() -> None:
    paths: list[Path] = []
    paths += list((ROOT / "templates").rglob("*.html"))
    paths += list((ROOT / "sgest").rglob("*.py"))
    for p in paths:
        raw = p.read_text(encoding="utf-8")
        out = patch_text(raw)
        if out != raw:
            p.write_text(out, encoding="utf-8")
            print("patched", p.relative_to(ROOT))


if __name__ == "__main__":
    main()
