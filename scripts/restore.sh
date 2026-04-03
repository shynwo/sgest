#!/usr/bin/env bash
set -Eeuo pipefail
APP="${APP:-$HOME/stockdash}"
BKDIR="${BKDIR:-$HOME/backups}"
BK="${1:-}"

if [ -z "$BK" ]; then
  echo "Usage: $0 /chemin/vers/stockdash_YYYY-mm-ddTHH-MM-SS.tgz"
  exit 2
fi
[ -f "$BK" ] || { echo "Archive introuvable: $BK"; exit 2; }

ts() { date +%F-%H%M%S; }
echo "== Stop service =="
sudo systemctl stop stockdash || true

echo "== Sauvegarde de l'état courant =="
if [ -d "$APP" ]; then
  mkdir -p "$BKDIR"
  tar -C "$HOME" -czf "$BKDIR/rollback_$(ts).tgz" stockdash || true
  mv "$APP" "${APP}.bak.$(ts)"
fi

echo "== Restauration =="
# Les archives sont créées depuis \$HOME avec un dossier stockdash/
tar -xzf "$BK" -C "$HOME"

echo "== Permissions =="
chown -R "$USER:$USER" "$APP"

echo "== Réinstalle venv si absent =="
if [ ! -x "$APP/.venv/bin/python" ]; then
  python3 -m venv "$APP/.venv"
  "$APP/.venv/bin/pip" install --upgrade pip wheel
  # dépendances minimales connues
  "$APP/.venv/bin/pip" install 'flask<3' gunicorn jinja2
fi

echo "== Restart service =="
sudo systemctl daemon-reload || true
sudo systemctl start stockdash
sleep 1
curl -sI http://127.0.0.1:8000/ | head -n1 || true
echo "Restauration OK"
