#!/usr/bin/env bash
# =============================================================================
# CyberShield native installer - Kali Linux, Parrot OS, Ubuntu 24.04+, Debian 12+
#
#   ./scripts/install.sh            # runtime install into ./.venv
#   ./scripts/install.sh --dev      # + test / lint / security tooling
#
# Idempotent: safe to re-run after `git pull`.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${ROOT}/.venv"
DEV=0
[ "${1:-}" = "--dev" ] && DEV=1

info() { printf '\033[1;34m[cybershield]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[cybershield]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[cybershield]\033[0m %s\n' "$*"; exit 1; }

# ------------------------------------------------------------------ platform
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  info "Detected ${PRETTY_NAME:-unknown OS}"
  case "${ID:-}:${ID_LIKE:-}" in
    *kali*|*parrot*|*debian*|*ubuntu*) ;;
    *) warn "Untested distribution - continuing (Debian-family packages expected)." ;;
  esac
else
  warn "Cannot detect the distribution - continuing."
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail "Run as root or install sudo."
  SUDO="sudo"
fi

# ---------------------------------------------------------- system packages
info "Installing system packages (python3, venv, nmap, libpcap)..."
$SUDO apt-get update -qq
PCAP_PKG="libpcap0.8"
if apt-cache show libpcap0.8t64 >/dev/null 2>&1; then
  PCAP_PKG="libpcap0.8t64"
fi
$SUDO apt-get install -y -qq python3 python3-venv python3-pip nmap "${PCAP_PKG}" ca-certificates >/dev/null

PYTHON="$(command -v python3.12 || command -v python3)"
"${PYTHON}" - <<'PY' || fail "Python 3.12+ is required (found an older interpreter)."
import sys
sys.exit(0 if sys.version_info >= (3, 12) else 1)
PY

# ------------------------------------------------------------ virtualenv
info "Creating virtual environment in ${VENV}..."
"${PYTHON}" -m venv "${VENV}"
"${VENV}/bin/pip" install -q --upgrade pip
if [ "${DEV}" -eq 1 ]; then
  "${VENV}/bin/pip" install -q -r "${ROOT}/requirements-dev.txt"
else
  "${VENV}/bin/pip" install -q -r "${ROOT}/requirements.txt"
fi
"${VENV}/bin/pip" install -q --no-deps -e "${ROOT}"

# ------------------------------------------------------------ first run
cd "${ROOT}"
"${VENV}/bin/cybershield" init-db

cat <<EOF

  CyberShield is installed.

  Activate:           source ${VENV}/bin/activate
  Host audit:         sudo ${VENV}/bin/cybershield audit host --pdf host-audit.pdf
  Authorised scan:    cybershield scan network 192.168.1.0/24 --i-am-authorized
  Start API + UI:     ./scripts/start_native.sh
  Admin password:     cat ${ROOT}/data/initial_admin_password   (if generated)

EOF
