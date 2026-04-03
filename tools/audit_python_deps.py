#!/usr/bin/env python3
import os, ast, sys, subprocess, json, re
from pathlib import Path

ROOT = Path(os.environ.get("STOCKDASH_ROOT", str(Path.home()/ "stockdash")))

def find_py_files(root: Path):
    for p in root.rglob("*.py"):
        # ignore venv
        if ".venv" in p.parts:
            continue
        yield p

def top_level_imports(py: Path):
    mods = set()
    try:
        tree = ast.parse(py.read_text(encoding="utf-8"))
    except Exception:
        return mods
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                mods.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mods.add(node.module.split(".")[0])
    return mods

def pip_list():
    try:
        out = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format", "json"], text=True)
        pkgs = json.loads(out)
        return {p["name"].lower(): p["version"] for p in pkgs}
    except Exception:
        return {}

# mapping fréquent module -> package PyPI
COMMON_MAP = {
    "flask": "flask",
    "jinja2": "jinja2",
    "werkzeug": "werkzeug",
    "gunicorn": "gunicorn",
    "click": "click",
    "blinker": "blinker",
    "pkg_resources": "setuptools",
    "setuptools": "setuptools",
    "pip": "pip",
    "packaging": "packaging",
    "markupsafe": "markupsafe",
    "itsdangerous": "itsdangerous",
}

def guess_pypi_name(mod):
    # si déjà mappé
    if mod.lower() in COMMON_MAP:
        return COMMON_MAP[mod.lower()]
    # heuristique simple
    return mod.lower()

def main():
    if not ROOT.exists():
        print(f"ERR: Projet introuvable: {ROOT}", file=sys.stderr)
        sys.exit(1)

    used_mods = set()
    files = list(find_py_files(ROOT))
    for f in files:
        used_mods |= top_level_imports(f)

    # retire modules stdlib probables (heuristique simple)
    # tu peux enrichir au besoin
    stdlib_like = {
        "os","sys","re","json","time","pathlib","subprocess","shutil","datetime","typing","hashlib","logging",
        "tarfile","tempfile","threading","itertools","functools","base64","zipfile","importlib","glob",
        "argparse","getpass","uuid","urllib","http","socket","signal"
    }
    used_third = sorted(m for m in used_mods if m not in stdlib_like)

    installed = pip_list()
    installed_names = set(installed.keys())

    # convertit modules -> noms pypi supposés
    used_pkgs_guess = set(guess_pypi_name(m) for m in used_third)

    missing = sorted(p for p in used_pkgs_guess if p not in installed_names)
    unused = sorted(p for p in installed_names if p not in used_pkgs_guess)

    print("=== AUDIT PYTHON DEPS ===")
    print(f"Projet: {ROOT}")
    print("\n-- Imports détectés (hors stdlib) --")
    for m in used_third:
        print("  -", m)

    print("\n-- Paquets installés (pip) --")
    for name in sorted(installed):
        print(f"  - {name}=={installed[name]}")

    print("\n-- Paquets MANQUANTS (à installer si besoin) --")
    if missing:
        for m in missing:
            print("  -", m)
    else:
        print("  (aucun)")

    print("\n-- Paquets NON UTILISÉS (peuvent être désinstallés) --")
    if unused:
        for u in unused:
            print("  -", u)
    else:
        print("  (aucun)")

if __name__ == "__main__":
    main()
