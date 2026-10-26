#!/usr/bin/env bash
# =============================================================================
# Scheduled / CI-friendly host audit producing timestamped JSON + PDF + HTML.
#
#   sudo ./scripts/run_audit.sh                 # report only
#   sudo ./scripts/run_audit.sh --fail-on high  # exit 2 if high+ findings (CI gate)
#
# Cron example (daily 06:00):
#   0 6 * * * root /opt/CyberShield/scripts/run_audit.sh >> /var/log/cybershield-audit.log 2>&1
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${ROOT}/.venv/bin/cybershield"
[ -x "${CLI}" ] || { echo "Run ./scripts/install.sh first." >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || echo "Warning: not root - shadow/sudoers/firewall checks will report 'unknown'." >&2

OUT="${CYBERSHIELD_AUDIT_OUTPUT:-${ROOT}/reports/host-audits}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${OUT}"
cd "${ROOT}"

"${CLI}" audit host \
  --json "${OUT}/host-audit-${STAMP}.json" \
  --pdf "${OUT}/host-audit-${STAMP}.pdf" \
  --html "${OUT}/host-audit-${STAMP}.html" \
  "$@"
