#!/usr/bin/env python3
"""Découpe sgest/routes.py en sgest/views/*.py (une fois)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ranges: list[tuple[str, str, int, int]] = [
    ("auth", "register_auth_routes", 9, 144),
    ("main", "register_main_routes", 145, 163),
    ("tools", "register_tools_routes", 164, 922),
    ("catalog_public", "register_catalog_public_routes", 923, 958),
    ("system", "register_system_routes", 959, 1229),
]


def main() -> None:
    lines = (ROOT / "sgest" / "routes.py").read_text(encoding="utf-8").splitlines()
    stock_hi = len(lines)
    all_ranges = ranges + [("stock", "register_stock_routes", 1230, stock_hi)]

    header = (
        '"""Vues Sgest — routes par domaine (auth, stock, systeme, …)."""\n'
        "from __future__ import annotations\n\n"
        "from ..services import *  # noqa: F401,F403\n\n\n"
    )

    for stem, fn, lo, hi in all_ranges:
        body = "\n".join(lines[lo - 1 : hi])
        content = header + f"def {fn}(app) -> None:\n" + body + "\n"
        out = ROOT / "sgest" / "views" / f"{stem}.py"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        print("wrote", out.relative_to(ROOT), len(body.splitlines()), "lines")

    init = ROOT / "sgest" / "views" / "__init__.py"
    init.write_text(
        '"""Enregistrement de toutes les routes (ordre = ancien monolithe)."""\n'
        "from __future__ import annotations\n\n"
        "from .auth import register_auth_routes\n"
        "from .catalog_public import register_catalog_public_routes\n"
        "from .main import register_main_routes\n"
        "from .stock import register_stock_routes\n"
        "from .system import register_system_routes\n"
        "from .tools import register_tools_routes\n\n\n"
        "def register_routes(app) -> None:\n"
        '    """Attache les vues ; noms d\'endpoints inchangés."""\n'
        "    register_auth_routes(app)\n"
        "    register_main_routes(app)\n"
        "    register_tools_routes(app)\n"
        "    register_catalog_public_routes(app)\n"
        "    register_system_routes(app)\n"
        "    register_stock_routes(app)\n",
        encoding="utf-8",
    )
    print("wrote", init.relative_to(ROOT))


if __name__ == "__main__":
    main()
