#!/usr/bin/env bash
# =============================================================================
# CyberShield uninstaller (Docker and/or native installation)
#
#   ./scripts/uninstall.sh                 # detect what is installed, ask, remove everything
#   ./scripts/uninstall.sh --docker        # only the Docker deployment
#   ./scripts/uninstall.sh --native        # only the native install (.venv, data, logs, reports)
#
# Options:
#   --keep-data   remove containers / virtualenv but KEEP data (volumes, data/, reports/, logs/)
#   --backup      run ./scripts/backup.sh before removing a Docker deployment
#   --yes, -y     do not ask for confirmation
#   --dry-run     only print what would be removed
#
# Never removed: the source code itself, ./backups, and shared system packages
# (docker, nmap, python3, libpcap) that other tools may need.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="cybershield"
IMAGE="cybershield:1.0.0"

MODE="auto"
KEEP_DATA=0
BACKUP=0
ASSUME_YES=0
DRY_RUN=0

usage() { sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) MODE="docker" ;;
    --native) MODE="native" ;;
    --all) MODE="all" ;;
    --keep-data) KEEP_DATA=1 ;;
    --backup) BACKUP=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

info() { printf '\033[1;34m[uninstall]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[uninstall]\033[0m %s\n' "$*"; }

run() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '  would run: %s\n' "$*"
  else
    "$@"
  fi
}

remove_path() {
  local target="$1"
  if [ -e "${target}" ] || [ -L "${target}" ]; then
    if [ "${DRY_RUN}" -eq 1 ]; then
      printf '  would remove: %s\n' "${target}"
    else
      rm -rf -- "${target}"
      printf '  removed: %s\n' "${target}"
    fi
  fi
}

# Empty a directory but keep its .gitkeep placeholder.
empty_dir() {
  local dir="$1"
  [ -d "${dir}" ] || return 0
  local entry
  for entry in "${dir}"/* "${dir}"/.[!.]*; do
    [ -e "${entry}" ] || continue
    [ "$(basename "${entry}")" = ".gitkeep" ] && continue
    remove_path "${entry}"
  done
}

# ------------------------------------------------------------------ detection
docker_ok() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

has_docker_install() {
  docker_ok || return 1
  [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT}" 2>/dev/null)" ] && return 0
  [ -n "$(docker volume ls -q --filter "name=${PROJECT}_" 2>/dev/null)" ] && return 0
  docker image inspect "${IMAGE}" >/dev/null 2>&1
}

has_native_install() {
  [ -d "${ROOT}/.venv" ] || [ -d "${ROOT}/data" ] \
    || ls /etc/systemd/system/cybershield-*.service >/dev/null 2>&1
}

DO_DOCKER=0
DO_NATIVE=0
case "${MODE}" in
  docker) DO_DOCKER=1 ;;
  native) DO_NATIVE=1 ;;
  all) DO_DOCKER=1; DO_NATIVE=1 ;;
  auto)
    if has_docker_install; then DO_DOCKER=1; fi
    if has_native_install; then DO_NATIVE=1; fi
    ;;
esac

if [ "${DO_DOCKER}" -eq 0 ] && [ "${DO_NATIVE}" -eq 0 ]; then
  if ! docker_ok && command -v docker >/dev/null 2>&1; then
    warn "Docker is installed but not accessible: re-run with sudo or after 'newgrp docker' to remove the Docker deployment."
  fi
  info "Nothing to uninstall (no CyberShield containers, volumes, image or native install found)."
  exit 0
fi

# ------------------------------------------------------------------- summary
echo
info "CyberShield will be uninstalled from ${ROOT}"
if [ "${DO_DOCKER}" -eq 1 ]; then
  echo "  Docker : containers (api, dashboard, db, sensor, init), networks, image ${IMAGE}"
  if [ "${KEEP_DATA}" -eq 1 ]; then
    echo "           volumes KEPT (database, reports, logs, secrets)"
  else
    echo "           volumes DELETED: database, reports, logs and generated secrets"
  fi
fi
if [ "${DO_NATIVE}" -eq 1 ]; then
  echo "  Native : virtualenv .venv, packaging leftovers, systemd units cybershield-*.service"
  if [ "${KEEP_DATA}" -eq 1 ]; then
    echo "           data/, reports/, logs/ KEPT"
  else
    echo "           data/ (SQLite database, admin password, caches), reports/, logs/ DELETED"
  fi
fi
echo "  Kept   : source code, ./backups, system packages (docker, nmap, python3, libpcap)"
[ "${DRY_RUN}" -eq 1 ] && info "Dry run: nothing will be changed."
echo

if [ "${ASSUME_YES}" -eq 0 ] && [ "${DRY_RUN}" -eq 0 ]; then
  read -r -p "Type 'yes' to continue: " answer
  [ "${answer}" = "yes" ] || { info "Aborted."; exit 1; }
fi

cd "${ROOT}"

# -------------------------------------------------------------------- docker
if [ "${DO_DOCKER}" -eq 1 ]; then
  if ! docker_ok; then
    warn "Docker is not reachable: skipping the Docker part (try with sudo)."
  else
    if [ "${BACKUP}" -eq 1 ] && [ -n "$(docker ps -q --filter "label=com.docker.compose.project=${PROJECT}")" ]; then
      info "Backing up before removal..."
      run "${ROOT}/scripts/backup.sh"
    fi
    info "Stopping and removing containers..."
    if [ "${KEEP_DATA}" -eq 1 ]; then
      run compose --profile sensor down --remove-orphans
    else
      run compose --profile sensor down --volumes --remove-orphans
    fi
    if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
      info "Removing image ${IMAGE}..."
      run docker image rm "${IMAGE}"
    fi
  fi
fi

# -------------------------------------------------------------------- native
if [ "${DO_NATIVE}" -eq 1 ]; then
  SUDO=""
  [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"
  for unit in /etc/systemd/system/cybershield-*.service; do
    [ -e "${unit}" ] || continue
    name="$(basename "${unit}")"
    info "Removing systemd unit ${name}..."
    run ${SUDO} systemctl disable --now "${name}" || true
    run ${SUDO} rm -f "${unit}"
    run ${SUDO} systemctl daemon-reload || true
  done

  info "Removing the native installation..."
  remove_path "${ROOT}/.venv"
  remove_path "${ROOT}/build"
  remove_path "${ROOT}/dist"
  for egg in "${ROOT}"/*.egg-info; do
    remove_path "${egg}"
  done
  remove_path "${ROOT}/.pytest_cache"
  remove_path "${ROOT}/.ruff_cache"
  remove_path "${ROOT}/.coverage"
  if [ "${KEEP_DATA}" -eq 0 ]; then
    remove_path "${ROOT}/data"
    empty_dir "${ROOT}/reports"
    empty_dir "${ROOT}/logs"
  fi

  if crontab -l 2>/dev/null | grep -q "${ROOT}"; then
    warn "Your crontab still references CyberShield - remove these lines with 'crontab -e':"
    crontab -l 2>/dev/null | grep "${ROOT}" | sed 's/^/    /'
  fi
fi

echo
if [ "${DRY_RUN}" -eq 1 ]; then
  info "Dry run complete."
else
  info "CyberShield has been uninstalled."
  [ -d "${ROOT}/backups" ] && info "Backups kept in ${ROOT}/backups (contains secrets: store or delete them securely)."
  info "To delete the source code as well:  cd \"$(dirname "${ROOT}")\" && rm -rf \"$(basename "${ROOT}")\""
fi
