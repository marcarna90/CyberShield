#!/usr/bin/env bash
# Start the API (uvicorn) and the dashboard (Streamlit) without Docker.
# Stop with Ctrl+C (both processes are terminated).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${ROOT}/.venv"
[ -x "${VENV}/bin/uvicorn" ] || { echo "Run ./scripts/install.sh first." >&2; exit 1; }
cd "${ROOT}"

API_PORT="${CYBERSHIELD_API_PORT:-8000}"
UI_PORT="${CYBERSHIELD_DASHBOARD_PORT:-8501}"
export CYBERSHIELD_API_URL="${CYBERSHIELD_API_URL:-http://127.0.0.1:${API_PORT}}"

"${VENV}/bin/uvicorn" app.main:app --host 127.0.0.1 --port "${API_PORT}" &
API_PID=$!
"${VENV}/bin/streamlit" run app/dashboard/streamlit_app.py --server.address 127.0.0.1 --server.port "${UI_PORT}" &
UI_PID=$!

cleanup() { kill "${API_PID}" "${UI_PID}" 2>/dev/null || true; }
trap cleanup INT TERM EXIT

echo "API:       http://127.0.0.1:${API_PORT}/docs"
echo "Dashboard: http://127.0.0.1:${UI_PORT}"
wait
