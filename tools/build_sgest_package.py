#!/usr/bin/env python3
"""
Extrait app.py en sgest/services.py (helpers + hooks) et sgest/routes.py (register_routes).
Pipeline optionnel : python tools/split_routes_to_views.py puis python tools/views_to_blueprints.py
(puis tools/apply_blueprint_url_for.py si les templates repassent aux noms courts).
À exécuter depuis la racine du dépôt : python tools/build_sgest_package.py
"""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app.py"


def is_app_route_decorator(d: ast.expr) -> bool:
    if isinstance(d, ast.Call):
        d = d.func
    if isinstance(d, ast.Attribute):
        if isinstance(d.value, ast.Name) and d.value.id == "app":
            return d.attr in ("route", "get", "post", "put", "delete", "patch")
    return False


def is_route_function(node: ast.FunctionDef) -> bool:
    return any(is_app_route_decorator(d) for d in node.decorator_list)


def func_body_start_line(node: ast.FunctionDef) -> int:
    """Première ligne du décorateur ou du def (AST 1-based)."""
    if node.decorator_list:
        return min(getattr(d, "lineno", node.lineno) for d in node.decorator_list)
    return node.lineno


def finalize_services_body(body: str) -> str:
    """Retire la config Flask globale, les décorateurs de hooks et remplace app par current_app."""
    body = re.sub(
        r"^app = Flask\(__name__\)\s*\n",
        "",
        body,
        flags=re.MULTILINE,
    )
    body = re.sub(
        r"^app\.(secret_key|config\[.*\])\s*=.*\n",
        "",
        body,
        flags=re.MULTILINE,
    )
    body = re.sub(
        r"^@app\.(context_processor|after_request|before_request|errorhandler\([^)]*\))\s*\n",
        "",
        body,
        flags=re.MULTILINE,
    )
    body = body.replace(
        "from flask import Flask, render_template,",
        "from flask import current_app, render_template,",
        1,
    )
    body = body.replace("Path(app.root_path)", "Path(current_app.root_path)")
    body = body.replace('"ASSET_VER": app.config["ASSET_VER"]', '"ASSET_VER": current_app.config["ASSET_VER"]')
    return body


def main() -> None:
    raw = APP.read_text(encoding="utf-8-sig")
    lines = raw.splitlines(keepends=True)
    tree = ast.parse(raw)

    route_ranges: list[tuple[int, int]] = []
    keep_segments: list[tuple[int, int]] = []

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            lo, hi = func_body_start_line(node), node.end_lineno
            if is_route_function(node):
                route_ranges.append((lo, hi))
            else:
                keep_segments.append((lo, hi))
        elif isinstance(node, ast.ClassDef):
            keep_segments.append((node.lineno, node.end_lineno))
        elif isinstance(
            node,
            (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.Expr),
        ):
            # Skip Flask app instance + config (handled in factory)
            if isinstance(node, ast.Assign):
                t = node.targets[0]
                if isinstance(t, ast.Name) and t.id == "app":
                    continue
                if isinstance(t, ast.Attribute):
                    if isinstance(t.value, ast.Name) and t.value.id == "app":
                        continue
            keep_segments.append((node.lineno, node.end_lineno))

    def emit_range(lo: int, hi: int) -> str:
        # ast lineno 1-based inclusive
        return "".join(lines[lo - 1 : hi])

    # Header for services: imports will be fixed manually if needed
    services_parts: list[str] = []
    services_parts.append(
        '"""\n'
        "Logique métier et hooks (ex-app.py). Utiliser current_app, pas d’instance Flask globale.\n"
        '"""\n'
    )

    for lo, hi in sorted(keep_segments):
        chunk = emit_range(lo, hi)
        if not chunk.strip():
            continue
        services_parts.append(chunk)
        if not chunk.endswith("\n"):
            services_parts.append("\n")

    services_out = ROOT / "sgest" / "services.py"
    services_out.parent.mkdir(parents=True, exist_ok=True)
    body = finalize_services_body("".join(services_parts))
    services_out.write_text(body, encoding="utf-8")

    routes_inner = []
    for lo, hi in sorted(route_ranges):
        routes_inner.append(emit_range(lo, hi))
        if not routes_inner[-1].endswith("\n"):
            routes_inner.append("\n")
    routes_body = "".join(routes_inner)
    routes_wrapped = (
        '"""Enregistrement des routes (extrait de l’ancien app.py monolithique)."""\n'
        "from __future__ import annotations\n\n"
        "from .services import *  # noqa: F401,F403\n\n\n"
        "def register_routes(app) -> None:\n"
        '    """Attache les vues à ``app`` ; les noms d’endpoints restent identiques."""\n'
    )
    routes_wrapped += textwrap.indent(routes_body, "    ")

    routes_out = ROOT / "sgest" / "routes.py"
    routes_out.write_text(routes_wrapped, encoding="utf-8")

    print("Wrote", services_out, "and", routes_out)
    print("route blocks:", len(route_ranges), "keep segments:", len(keep_segments))


if __name__ == "__main__":
    main()
