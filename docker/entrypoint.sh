#!/usr/bin/env bash
# CyberShield container entrypoint: selects the role of this container.
#   api           FastAPI backend (initialises the database first)
#   dashboard     Streamlit SOC dashboard
#   sensor        passive capture loop (needs CAP_NET_RAW + host network)
#   init-secrets  generate missing secrets into the shared secrets volume
#   cli ...       run any `cybershield` CLI command
set -euo pipefail

role="${1:-api}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "${role}" in
  api)
    python -m app.cli init-db
    exec uvicorn app.main:app \
      --host 0.0.0.0 \
      --port "${PORT:-8000}" \
      --workers "${WEB_CONCURRENCY:-1}" \
      --proxy-headers \
      --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
      --no-server-header
    ;;
  dashboard)
    exec streamlit run /app/app/dashboard/streamlit_app.py \
      --server.port "${PORT:-8501}" \
      --server.address 0.0.0.0
    ;;
  sensor)
    python -m app.cli init-db
    exec python -m app.cli sensor
    ;;
  init-secrets)
    exec python -m app.cli secrets init \
      --dir "${CYBERSHIELD_SECRETS_DIR:-/run/cybershield-secrets}" \
      --app-owner "${CYBERSHIELD_APP_OWNER:-10001:10001}"
    ;;
  cli | cybershield)
    exec python -m app.cli "$@"
    ;;
  *)
    exec "${role}" "$@"
    ;;
esac
