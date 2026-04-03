#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

OUT_DIR="${HOME}/backups"
LOG_DIR="${OUT_DIR}/logs"
mkdir -p "${LOG_DIR}"

die(){ echo "ERR: $*" >&2; exit 1; }

ARCHIVE="${1:-}"
[[ -f "${ARCHIVE}" ]] || die "Archive introuvable: ${ARCHIVE}"

# Test lecture
tar -tzf "${ARCHIVE}" >/dev/null || die "Archive corrompue (tar -tzf)."

# Vérif sha256 si présent
if [[ -f "${ARCHIVE}.sha256" ]]; then
  calc=$(sha256sum "${ARCHIVE}" | awk '{print $1}')
  ref=$(cat "${ARCHIVE}.sha256" | tr -d ' \t\r\n')
  [[ "${calc}" == "${ref}" ]] || die "SHA256 mismatch (attendu=${ref}, calculé=${calc})"
fi

echo "OK: ${ARCHIVE} lisible et checksum valide."
