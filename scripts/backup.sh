#!/usr/bin/env bash
# Back up a Docker deployment: PostgreSQL dump + generated reports + secrets.
#   ./scripts/backup.sh [output-dir]
# Restore the database with:
#   gunzip -c cybershield-db-<stamp>.sql.gz | docker compose exec -T db psql -U cybershield cybershield
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${ROOT}/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${OUT}"
chmod 700 "${OUT}"
cd "${ROOT}"

docker compose exec -T db pg_dump -U cybershield --clean --if-exists cybershield | gzip > "${OUT}/cybershield-db-${STAMP}.sql.gz"
docker compose exec -T api tar -C /var/lib/cybershield -czf - reports > "${OUT}/cybershield-reports-${STAMP}.tar.gz"
# Secrets keep the database password, JWT key and admin password valid after a restore.
docker compose exec -T api tar -C /run/cybershield-secrets -czf - . > "${OUT}/cybershield-secrets-${STAMP}.tar.gz"
chmod 600 "${OUT}"/*-"${STAMP}".*

echo "Backup written to ${OUT} (stamp ${STAMP}). Keep the secrets archive offline and encrypted."
