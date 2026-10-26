"""scripts/uninstall.sh: native and Docker removal, dry-run, keep-data, confirmation."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "uninstall.sh"

FAKE_DOCKER = """#!/usr/bin/env bash
echo "docker $*" >> "$FAKE_DOCKER_LOG"
state="${FAKE_DOCKER_STATE:-installed}"
[ "$state" = "unreachable" ] && exit 1
case "$1 $2" in
  "info "*) exit 0 ;;
  "compose version") exit 0 ;;
  "compose "*) exit 0 ;;
  "ps "*) [ "$state" = "installed" ] && echo abc123; exit 0 ;;
  "volume ls") [ "$state" = "installed" ] && echo cybershield_pg-data; exit 0 ;;
  "image inspect") [ "$state" = "installed" ] && exit 0; exit 1 ;;
  "image rm") exit 0 ;;
esac
exit 0
"""

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A fake checkout with a native install, data, reports, logs and backups."""
    root = tmp_path / "CyberShield"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / "uninstall.sh")
    for relative in (
        ".venv/bin/python",
        "data/cybershield.db",
        "data/initial_admin_password",
        "reports/.gitkeep",
        "reports/executive.pdf",
        "logs/.gitkeep",
        "logs/cybershield.log",
        "backups/cybershield-db.sql.gz",
        "cybershield.egg-info/PKG-INFO",
        "app/main.py",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
    return root


def run(project: Path, *args: str, state: str = "empty", stdin: str = "") -> tuple[subprocess.CompletedProcess, str]:
    bin_dir = project.parent / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    log = project.parent / "docker.log"
    log.write_text("")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_DOCKER_STATE": state,
        "FAKE_DOCKER_LOG": str(log),
    }
    proc = subprocess.run(
        ["bash", str(project / "scripts" / "uninstall.sh"), *args],
        capture_output=True,
        text=True,
        env=env,
        input=stdin,
        timeout=60,
        check=False,
    )
    return proc, log.read_text()


def test_native_dry_run_changes_nothing(project: Path) -> None:
    proc, _ = run(project, "--native", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert "would remove" in proc.stdout and "Dry run complete" in proc.stdout
    assert (project / ".venv").exists() and (project / "data").exists()


def test_native_uninstall_removes_install_but_keeps_code_and_backups(project: Path) -> None:
    proc, _ = run(project, "--native", "--yes")
    assert proc.returncode == 0, proc.stderr
    for gone in (".venv", "data", "reports/executive.pdf", "logs/cybershield.log", "cybershield.egg-info"):
        assert not (project / gone).exists(), gone
    for kept in ("reports/.gitkeep", "logs/.gitkeep", "backups/cybershield-db.sql.gz", "app/main.py"):
        assert (project / kept).exists(), kept
    assert "has been uninstalled" in proc.stdout and "rm -rf" in proc.stdout


def test_native_keep_data(project: Path) -> None:
    proc, _ = run(project, "--native", "--keep-data", "-y")
    assert proc.returncode == 0
    assert not (project / ".venv").exists()
    assert (project / "data" / "cybershield.db").exists() and (project / "reports" / "executive.pdf").exists()


def test_docker_uninstall_removes_volumes_and_image(project: Path) -> None:
    proc, calls = run(project, "--docker", "--yes", state="installed")
    assert proc.returncode == 0, proc.stderr
    assert "docker compose --profile sensor down --volumes --remove-orphans" in calls
    assert "docker image rm cybershield:1.0.0" in calls
    assert (project / ".venv").exists()  # native part untouched


def test_docker_keep_data_and_dry_run(project: Path) -> None:
    _, calls = run(project, "--docker", "--keep-data", "--yes", state="installed")
    assert "down --remove-orphans" in calls and "--volumes" not in calls
    proc, calls = run(project, "--docker", "--dry-run", state="installed")
    assert "would run: compose --profile sensor down --volumes --remove-orphans" in proc.stdout
    assert "down" not in calls


def test_auto_detects_both(project: Path) -> None:
    proc, calls = run(project, "--yes", state="installed")
    assert proc.returncode == 0
    assert "down --volumes" in calls and not (project / ".venv").exists()


def test_nothing_to_uninstall(tmp_path: Path) -> None:
    root = tmp_path / "Empty"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / "uninstall.sh")
    proc, _ = run(root, state="empty")
    assert proc.returncode == 0 and "Nothing to uninstall" in proc.stdout


def test_docker_unreachable_is_reported(tmp_path: Path) -> None:
    root = tmp_path / "Empty"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / "uninstall.sh")
    proc, _ = run(root, state="unreachable")
    assert proc.returncode == 0 and "not accessible" in proc.stdout


def test_confirmation_required(project: Path) -> None:
    proc, _ = run(project, "--native", stdin="no\n")
    assert proc.returncode == 1 and "Aborted" in proc.stdout
    assert (project / ".venv").exists()
    proc, _ = run(project, "--native", stdin="yes\n")
    assert proc.returncode == 0 and not (project / ".venv").exists()


def test_bad_option_and_help(project: Path) -> None:
    proc, _ = run(project, "--explode")
    assert proc.returncode == 1 and "Unknown option" in proc.stderr
    proc, _ = run(project, "--help")
    assert proc.returncode == 0 and "--keep-data" in proc.stdout
