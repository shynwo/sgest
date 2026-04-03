#!/usr/bin/env bash
set -Eeuo pipefail
APP="${APP:-$HOME/stockdash}"
BKDIR="${BKDIR:-$HOME/backups}"
WITH_VENV="${WITH_VENV:-0}"   # 0 by default, set 1 to include .venv
KEEP="${KEEP:-20}"            # keep latest N archives
MONITOR="${MONITOR:-$APP/scripts/backup_monitor.py}"

ts() { date +%FT%H-%M-%S%z; }
name="stockdash_$(ts).tgz"
tmp="$(mktemp -d)"
archive_path=""

notify_hook() {
  local status="${1:-error}"
  local archive="${2:-}"
  local reason="${3:-}"
  if command -v python3 >/dev/null 2>&1 && [ -f "$MONITOR" ]; then
    python3 "$MONITOR" backup-hook --status "$status" --archive "$archive" --error "$reason" >/dev/null 2>&1 || true
  fi
}

on_err() {
  local line="${1:-?}"
  notify_hook "error" "$archive_path" "backup.sh failed at line ${line}"
}

trap 'on_err $LINENO' ERR
trap 'rm -rf "$tmp"' EXIT

echo "== Snapshot to tar =="
cd "$HOME"
ex=( "--exclude=stockdash/backups" )
if [ "$WITH_VENV" = "0" ]; then
  ex+=( "--exclude=stockdash/.venv" )
fi
tar -czf "$tmp/$name" "${ex[@]}" stockdash

echo "== Move archive =="
mkdir -p "$BKDIR"
mv "$tmp/$name" "$BKDIR/$name"
archive_path="$BKDIR/$name"
ls -lh "$archive_path"

echo "== Prune (keep $KEEP latest) =="
ls -1t "$BKDIR"/stockdash_*.tgz 2>/dev/null | tail -n +$((KEEP+1)) | xargs -r rm -f

notify_hook "success" "$archive_path" ""
echo "OK -> $archive_path"
