#!/usr/bin/env python3
"""Convertit sgest/views/*.py en sgest/blueprints/*.py (Flask Blueprint)."""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / "sgest" / "views"
OUT = ROOT / "sgest" / "blueprints"

SPECS: list[tuple[str, str, str]] = [
    ("auth", "register_auth_routes", "auth"),
    ("main", "register_main_routes", "main"),
    ("tools", "register_tools_routes", "tools"),
    ("catalog_public", "register_catalog_public_routes", "catalog_public"),
    ("system", "register_system_routes", "system"),
]


def transform(text: str, fn_name: str, bp_name: str) -> str:
    if "from flask import Blueprint" not in text:
        text = text.replace(
            "from __future__ import annotations\n\n",
            "from __future__ import annotations\n\nfrom flask import Blueprint\n\n",
            1,
        )
    text = re.sub(
        rf"^def {re.escape(fn_name)}\(app\) -> None:\n",
        f'bp = Blueprint("{bp_name}", __name__)\n\n',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = text.replace("@app.", "@bp.")
    marker = f'bp = Blueprint("{bp_name}", __name__)\n\n'
    if marker in text:
        a, b = text.split(marker, 1)
        text = a + marker + textwrap.dedent(b)
    return text


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for stem, fn_name, bp_name in SPECS:
        p = VIEWS / f"{stem}.py"
        text = transform(p.read_text(encoding="utf-8"), fn_name, bp_name)
        (OUT / f"{stem}.py").write_text(text, encoding="utf-8")
        print("wrote", stem)

    stock_path = VIEWS / "stock.py"
    stock_txt = stock_path.read_text(encoding="utf-8")
    idx = stock_txt.find('    @app.post("/webhooks/orders/etsy")')
    if idx == -1:
        raise SystemExit("webhooks marker not found in stock.py")
    head = transform(stock_txt[:idx], "register_stock_routes", "stock")
    tail_raw = stock_txt[idx:].replace("@app.", "@bp.")
    tail_raw = textwrap.dedent(tail_raw)
    webhooks_hdr = (
        '"""Webhooks commandes (Etsy, Vinted)."""\n'
        "from __future__ import annotations\n\n"
        "from flask import Blueprint\n\n"
        "from ..services import *  # noqa: F401,F403\n\n\n"
        'bp = Blueprint("webhooks", __name__)\n\n'
    )
    (OUT / "stock.py").write_text(head, encoding="utf-8")
    (OUT / "webhooks.py").write_text(webhooks_hdr + tail_raw.lstrip(), encoding="utf-8")
    print("wrote stock + webhooks")

    init = OUT / "__init__.py"
    init.write_text(
        '"""Blueprints Flask Sgest."""\n'
        "from __future__ import annotations\n\n"
        "from flask import Flask\n\n\n"
        "def register_blueprints(app: Flask) -> None:\n"
        "    from . import auth, catalog_public, main, stock, system, tools, webhooks\n\n"
        "    app.register_blueprint(auth.bp)\n"
        "    app.register_blueprint(main.bp)\n"
        "    app.register_blueprint(tools.bp)\n"
        "    app.register_blueprint(catalog_public.bp)\n"
        "    app.register_blueprint(system.bp)\n"
        "    app.register_blueprint(stock.bp)\n"
        "    app.register_blueprint(webhooks.bp)\n",
        encoding="utf-8",
    )
    print("wrote __init__.py")


if __name__ == "__main__":
    main()
