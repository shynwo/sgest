"""Analyse app.py : liste des fonctions de routes vs helpers (AST)."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _is_app_route_decorator(d: ast.expr) -> bool:
    if isinstance(d, ast.Call):
        d = d.func
    if isinstance(d, ast.Attribute):
        if isinstance(d.value, ast.Name) and d.value.id == "app":
            return d.attr in ("route", "get", "post", "put", "delete", "patch")
    return False


def main() -> None:
    path = ROOT / "app.py"
    src = path.read_text(encoding="utf-8-sig")
    tree = ast.parse(src)

    route_funcs: list[str] = []
    other_funcs: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            is_route = any(_is_app_route_decorator(d) for d in node.decorator_list)
            (route_funcs if is_route else other_funcs).append(node.name)

    print("ROUTES", len(route_funcs))
    for n in route_funcs:
        print(n)
    print("\nHOOKS/other top-level", len(other_funcs))
    for n in other_funcs[:40]:
        print(n)
    if len(other_funcs) > 40:
        print(f"... +{len(other_funcs) - 40}")


if __name__ == "__main__":
    main()
