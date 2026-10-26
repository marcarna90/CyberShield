"""Individual host configuration checks.

Every check is a pure function of an :class:`AuditContext`, which abstracts
the filesystem root and command execution. This makes checks:

* usable on a live host (``host_root=/``),
* usable from a container where the host ``/etc`` is mounted under ``/host``,
* fully unit-testable against a fake directory tree and a mocked runner.

Checks never modify the system. Commands are executed without a shell, with a
timeout, and only from a fixed list of read-only invocations.
"""

from __future__ import annotations

import glob
import ipaddress
import re
import shutil
import socket
import subprocess  # fixed read-only commands, no shell  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

from app.core.models import CheckResult, CheckStatus, Severity

# =============================================================================
# Context
# =============================================================================


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


Runner = Callable[[list[str]], CommandResult | None]


def default_runner(args: list[str], timeout: int = 15) -> CommandResult | None:
    """Run a read-only command without a shell. Returns ``None`` if unavailable."""
    executable = shutil.which(args[0])
    if executable is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, absolute executable # nosec B603
            [executable, *args[1:]], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


@dataclass
class AuditContext:
    """Where and how the audit runs."""

    host_root: Path = Path("/")
    runner: Runner = default_runner
    cache: dict[str, Any] = field(default_factory=dict)

    @property
    def is_live(self) -> bool:
        """``True`` when auditing the running system itself (commands are meaningful)."""
        return self.host_root.resolve() == Path("/")

    def path(self, relative: str) -> Path:
        return self.host_root / relative.lstrip("/")

    def read(self, relative: str) -> str | None:
        """Read a file below the root; ``None`` if missing. ``PermissionError`` propagates."""
        target = self.path(relative)
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return None
        except IsADirectoryError:
            return None

    def exists(self, relative: str) -> bool:
        return self.path(relative).exists()


Outcome = tuple[CheckStatus, str]
CheckFn = Callable[[AuditContext], Outcome]


@dataclass(frozen=True)
class CheckMeta:
    check_id: str
    title: str
    category: str
    severity: Severity
    recommendation: str
    references: tuple[str, ...] = ()


REGISTRY: list[tuple[CheckMeta, CheckFn]] = []


def check(
    check_id: str,
    title: str,
    category: str,
    severity: Severity,
    recommendation: str,
    references: tuple[str, ...] = (),
) -> Callable[[CheckFn], CheckFn]:
    """Register a check function with its metadata."""

    def decorator(fn: CheckFn) -> CheckFn:
        REGISTRY.append((CheckMeta(check_id, title, category, severity, recommendation, references), fn))
        return fn

    return decorator


def run_check(meta: CheckMeta, fn: CheckFn, ctx: AuditContext) -> CheckResult:
    """Execute a check, converting permission problems and crashes into UNKNOWN."""
    try:
        status, evidence = fn(ctx)
    except PermissionError as exc:
        target = exc.filename or "resource"
        status, evidence = CheckStatus.UNKNOWN, f"Insufficient privileges to read {target} (run as root)"
    except Exception as exc:  # defensive: one broken check must not abort the audit
        status, evidence = CheckStatus.UNKNOWN, f"Check error: {type(exc).__name__}: {exc}"
    return CheckResult(
        check_id=meta.check_id,
        title=meta.title,
        category=meta.category,
        status=status,
        severity=meta.severity,
        evidence=evidence[:4000],
        recommendation=meta.recommendation,
        references=list(meta.references),
    )


# =============================================================================
# Parsers (pure functions, unit tested)
# =============================================================================

NOLOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")


def parse_passwd(text: str) -> list[dict[str, Any]]:
    entries = []
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        try:
            uid = int(parts[2])
        except ValueError:
            continue
        entries.append({"name": parts[0], "uid": uid, "home": parts[5], "shell": parts[6]})
    return entries


def parse_key_values(text: str, separator: str | None = None) -> dict[str, str]:
    """Parse ``KEY value`` / ``key = value`` files, ignoring comments. First key wins."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if separator and separator in line:
            key, _, value = line.partition(separator)
        else:
            parts = line.split(None, 1)
            key, value = parts[0], parts[1] if len(parts) > 1 else ""
        values.setdefault(key.strip().lower(), value.strip().strip('"'))
    return values


def decode_proc_address(hex_addr: str) -> tuple[str, int]:
    """Decode ``0100007F:0CEA`` (``/proc/net/tcp`` format) into ``("127.0.0.1", 3306)``."""
    ip_hex, port_hex = hex_addr.split(":")
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        ip = str(ipaddress.IPv4Address(raw[::-1]))
    else:
        words = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        ip = str(ipaddress.IPv6Address(words))
    return ip, int(port_hex, 16)


def parse_proc_net(text: str, protocol: str) -> list[tuple[str, str, int]]:
    """Return listening sockets ``(protocol, ip, port)`` from ``/proc/net/{tcp,udp}[6]``."""
    listen_state = "0A" if protocol.startswith("tcp") else "07"
    sockets = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3].upper() != listen_state:
            continue
        if protocol.startswith("udp") and not fields[2].endswith(":0000"):
            continue  # connected UDP socket, not a listener
        try:
            ip, port = decode_proc_address(fields[1])
        except ValueError:
            continue
        sockets.append((protocol.rstrip("6"), ip, port))
    return sockets


def parse_duration_seconds(value: str) -> int | None:
    """Parse sshd time format (``60``, ``2m``, ``1h30m``)."""
    if not value:
        return None
    total = 0
    for amount, unit in re.findall(r"(\d+)\s*([smhdwSMHDW]?)", value):
        multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit.lower()]
        total += int(amount) * multiplier
    return total if re.fullmatch(r"(\d+\s*[smhdwSMHDW]?)+", value.strip()) else None


def parse_sshd_config(ctx: AuditContext) -> dict[str, str] | None:
    """Effective global sshd settings. Prefers ``sshd -T`` on a live host."""
    if "sshd" in ctx.cache:
        return ctx.cache["sshd"]
    result: dict[str, str] | None = None
    if ctx.is_live:
        proc = ctx.runner(["sshd", "-T"])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            result = {}
            for line in proc.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if parts:
                    result.setdefault(parts[0].lower(), parts[1] if len(parts) > 1 else "")
    if result is None and ctx.read("etc/ssh/sshd_config") is not None:
        result = {}
        _parse_sshd_file(ctx, "etc/ssh/sshd_config", result, depth=0)
    ctx.cache["sshd"] = result
    return result


def _parse_sshd_file(ctx: AuditContext, relative: str, values: dict[str, str], depth: int) -> None:
    text = ctx.read(relative)
    if text is None or depth > 5:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$", line)
        key, value = (match.group(1), match.group(2)) if match else (line, "")
        key = key.lower()
        if key == "match":
            break  # only the global section is evaluated
        if key == "include":
            for pattern in value.split():
                absolute = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                for candidate in sorted(glob.glob(str(ctx.path(absolute)))):
                    rel = str(Path(candidate).relative_to(ctx.host_root))
                    _parse_sshd_file(ctx, rel, values, depth + 1)
            continue
        values.setdefault(key, value.strip().strip('"'))


def read_sudoers(ctx: AuditContext) -> list[tuple[str, str]] | None:
    """Return ``(file, line)`` pairs for sudoers and sudoers.d (``None`` if sudo absent)."""
    main = ctx.read("etc/sudoers")
    if main is None:
        return None
    lines = [("/etc/sudoers", line) for line in main.splitlines()]
    include_dir = ctx.path("etc/sudoers.d")
    if include_dir.is_dir():
        for entry in sorted(include_dir.iterdir()):
            # sudo ignores files containing '.' or ending with '~' in includedir.
            if "." in entry.name or entry.name.endswith("~") or not entry.is_file():
                continue
            content = entry.read_text(encoding="utf-8", errors="replace")
            lines.extend((f"/etc/sudoers.d/{entry.name}", line) for line in content.splitlines())
    return [(f, line.strip()) for f, line in lines if line.strip() and not line.strip().startswith("#")]


def listening_sockets(ctx: AuditContext) -> list[tuple[str, str, int]] | None:
    """Listening sockets via psutil on a live host, ``/proc/net`` otherwise.

    Returns ``None`` when no data source is available (e.g. auditing a mounted
    ``/etc`` from a container), so callers can report UNKNOWN instead of a
    misleading PASS.
    """
    if "sockets" in ctx.cache:
        return ctx.cache["sockets"]
    sockets: list[tuple[str, str, int]] = []
    used_psutil = False
    if ctx.is_live:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.laddr:
                    continue
                proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                if (proto == "tcp" and conn.status == psutil.CONN_LISTEN) or (proto == "udp" and not conn.raddr):
                    sockets.append((proto, conn.laddr.ip, conn.laddr.port))
            used_psutil = True
        except (psutil.AccessDenied, PermissionError):
            used_psutil = False
    if not used_psutil:
        sources = 0
        for name in ("tcp", "tcp6", "udp", "udp6"):
            text = ctx.read(f"proc/net/{name}")
            if text is not None:
                sources += 1
                sockets.extend(parse_proc_net(text, name))
        if sources == 0:
            ctx.cache["sockets"] = None
            return None
    unique = sorted(set(sockets), key=lambda s: (s[0], s[2], s[1]))
    ctx.cache["sockets"] = unique
    return unique


# =============================================================================
# Firewall
# =============================================================================

_PRIV_ERRORS = ("permission denied", "must be root", "operation not permitted", "you need to be root")


@check(
    "FW-001",
    "Host firewall is enabled",
    "firewall",
    Severity.HIGH,
    "Enable a default-deny host firewall (e.g. `ufw default deny incoming && ufw enable`, or nftables "
    "with an input chain policy of drop) and allow only required services.",
    ("CIS Controls v8 4.4", "CIS Debian/Ubuntu Benchmark 3.5"),
)
def check_firewall(ctx: AuditContext) -> Outcome:
    if not ctx.is_live:
        ufw_conf = ctx.read("etc/ufw/ufw.conf")
        if ufw_conf is not None:
            enabled = parse_key_values(ufw_conf, "=").get("enabled", "no").lower()
            if enabled == "yes":
                return CheckStatus.PASS, "ufw is enabled in /etc/ufw/ufw.conf"
            return CheckStatus.FAIL, "ufw is installed but disabled (ENABLED=no in /etc/ufw/ufw.conf)"
        nft_conf = ctx.read("etc/nftables.conf")
        if nft_conf and re.search(r"policy\s+drop", nft_conf):
            return CheckStatus.PASS, "/etc/nftables.conf defines a default-drop policy"
        return (
            CheckStatus.UNKNOWN,
            "Runtime firewall state cannot be inspected offline/from a container. Run "
            "`cybershield audit host` directly on the host as root.",
        )

    privilege_issue = False
    inactive_notes: list[str] = []
    ufw = ctx.runner(["ufw", "status"])
    if ufw is not None:
        output = (ufw.stdout + ufw.stderr).lower()
        if "status: active" in output:
            return CheckStatus.PASS, "ufw status: active"
        if any(err in output for err in _PRIV_ERRORS):
            privilege_issue = True
        elif "inactive" in output:
            inactive_notes.append("ufw is installed but inactive")
    firewalld = ctx.runner(["firewall-cmd", "--state"])
    if firewalld is not None and firewalld.stdout.strip() == "running":
        return CheckStatus.PASS, "firewalld is running"
    nft = ctx.runner(["nft", "list", "ruleset"])
    if nft is not None:
        if nft.returncode == 0 and re.search(r"\b(drop|reject)\b", nft.stdout):
            return CheckStatus.PASS, "nftables ruleset contains drop/reject rules"
        if any(err in (nft.stderr or "").lower() for err in _PRIV_ERRORS):
            privilege_issue = True
    iptables = ctx.runner(["iptables", "-S"])
    if iptables is not None:
        if iptables.returncode == 0:
            rules = iptables.stdout
            if re.search(r"-P INPUT (DROP|REJECT)", rules) or re.search(r"-A INPUT .*-j (DROP|REJECT)", rules):
                return CheckStatus.PASS, "iptables INPUT chain filters traffic"
            inactive_notes.append("iptables INPUT policy is ACCEPT with no drop rules")
        elif any(err in (iptables.stderr or "").lower() for err in _PRIV_ERRORS):
            privilege_issue = True
    if privilege_issue and not inactive_notes:
        return CheckStatus.UNKNOWN, "Firewall state requires root privileges to inspect (re-run with sudo)"
    if ufw is None and firewalld is None and nft is None and iptables is None:
        return CheckStatus.FAIL, "No firewall tooling found (ufw, firewalld, nftables, iptables)"
    return CheckStatus.FAIL, "; ".join(inactive_notes) or "No active firewall rules detected"


# =============================================================================
# Users & sessions
# =============================================================================


@check(
    "USR-001",
    "No duplicate UID 0 (root-equivalent) accounts",
    "accounts",
    Severity.CRITICAL,
    "Only 'root' may have UID 0. Investigate and remove/renumber other UID 0 accounts immediately.",
    ("CIS Debian/Ubuntu Benchmark 7.2.x", "NIST CSF PR.AA-05"),
)
def check_uid0(ctx: AuditContext) -> Outcome:
    text = ctx.read("etc/passwd")
    if text is None:
        return CheckStatus.UNKNOWN, "/etc/passwd not found"
    extra = [e["name"] for e in parse_passwd(text) if e["uid"] == 0 and e["name"] != "root"]
    if extra:
        return CheckStatus.FAIL, f"Accounts with UID 0 besides root: {', '.join(extra)}"
    return CheckStatus.PASS, "Only root has UID 0"


@check(
    "USR-002",
    "No accounts with empty passwords",
    "accounts",
    Severity.CRITICAL,
    "Lock or set a strong password on every account with an empty password field (`passwd -l <user>`).",
    ("CIS Debian/Ubuntu Benchmark 7.2.x", "ISO 27001 A.5.17"),
)
def check_empty_passwords(ctx: AuditContext) -> Outcome:
    text = ctx.read("etc/shadow")
    if text is None:
        return CheckStatus.UNKNOWN, "/etc/shadow not found"
    empty = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            empty.append(parts[0])
    if empty:
        return CheckStatus.FAIL, f"Accounts with empty password: {', '.join(empty)}"
    return CheckStatus.PASS, "No account has an empty password hash"


@check(
    "USR-003",
    "System accounts have no interactive shell",
    "accounts",
    Severity.LOW,
    "Set the shell of service/system accounts to /usr/sbin/nologin (`usermod -s /usr/sbin/nologin <user>`).",
    ("CIS Debian/Ubuntu Benchmark 5.4.2",),
)
def check_system_account_shells(ctx: AuditContext) -> Outcome:
    text = ctx.read("etc/passwd")
    if text is None:
        return CheckStatus.UNKNOWN, "/etc/passwd not found"
    entries = parse_passwd(text)
    interactive = [e for e in entries if not e["shell"].endswith(NOLOGIN_SHELLS)]
    offenders = [e["name"] for e in interactive if 0 < e["uid"] < 1000]
    humans = sorted(e["name"] for e in interactive if e["uid"] >= 1000 or e["uid"] == 0)
    inventory = f"Interactive accounts: {', '.join(humans) or 'none'}"
    if offenders:
        return CheckStatus.WARN, f"System accounts with a login shell: {', '.join(offenders)}. {inventory}"
    return CheckStatus.PASS, inventory


@check(
    "USR-004",
    "Active user sessions inventory",
    "accounts",
    Severity.INFO,
    "Review active sessions regularly and terminate unexpected ones.",
)
def check_active_sessions(ctx: AuditContext) -> Outcome:
    if not ctx.is_live:
        return CheckStatus.NOT_APPLICABLE, "Session inventory is only available on a live host"
    users = psutil.users()
    if not users:
        return CheckStatus.PASS, "No interactive sessions"
    sessions = sorted({f"{u.name}@{u.host or 'local'} ({u.terminal or '-'})" for u in users})
    return CheckStatus.PASS, f"{len(sessions)} active session(s): {', '.join(sessions)}"


# =============================================================================
# Network exposure
# =============================================================================

RISKY_PORTS = {
    21: "FTP (cleartext)",
    23: "Telnet (cleartext)",
    69: "TFTP",
    111: "rpcbind",
    139: "NetBIOS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh/syslog",
    2049: "NFS",
    2375: "Docker API (unauthenticated)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
_NO_SOCKETS = (
    CheckStatus.UNKNOWN,
    "Socket table not available under the audit root; run `cybershield audit host` on the host itself.",
)


_WILDCARDS = ("0.0.0.0", "::", "*")  # noqa: S104 - matching, not binding # nosec B104


@check(
    "NET-001",
    "No high-risk services listening on all interfaces",
    "network",
    Severity.HIGH,
    "Bind databases and admin services to localhost or a management interface, disable cleartext "
    "protocols (Telnet/FTP/rsh) and restrict access with the host firewall.",
    ("CIS Controls v8 4.8", "NIST CSF PR.IR-01"),
)
def check_risky_listeners(ctx: AuditContext) -> Outcome:
    sockets = listening_sockets(ctx)
    if sockets is None:
        return _NO_SOCKETS
    exposed = sorted(
        {
            f"{proto}/{port} {RISKY_PORTS[port]}"
            for proto, ip, port in sockets
            if port in RISKY_PORTS and ip in _WILDCARDS
        }
    )
    if exposed:
        return CheckStatus.FAIL, "Exposed on all interfaces: " + "; ".join(exposed)
    return CheckStatus.PASS, "No high-risk service bound to a wildcard address"


@check(
    "NET-002",
    "Listening ports inventory",
    "network",
    Severity.INFO,
    "Verify every listening port is expected and documented; disable unused services.",
    ("CIS Controls v8 4.8",),
)
def check_listening_inventory(ctx: AuditContext) -> Outcome:
    sockets = listening_sockets(ctx)
    if sockets is None:
        return _NO_SOCKETS
    if not sockets:
        return CheckStatus.PASS, "No listening sockets detected"
    listing = ", ".join(f"{proto}/{port}@{ip}" for proto, ip, port in sockets[:80])
    return CheckStatus.PASS, f"{len(sockets)} listening socket(s): {listing}"


# =============================================================================
# Password policy
# =============================================================================


@check(
    "PWD-001",
    "Password aging policy is enforced",
    "password_policy",
    Severity.MEDIUM,
    "In /etc/login.defs set PASS_MAX_DAYS 365 (or less), PASS_MIN_DAYS 1 and PASS_WARN_AGE 7.",
    ("CIS Debian/Ubuntu Benchmark 5.4.1", "ISO 27001 A.5.17"),
)
def check_password_aging(ctx: AuditContext) -> Outcome:
    text = ctx.read("etc/login.defs")
    if text is None:
        return CheckStatus.UNKNOWN, "/etc/login.defs not found"
    values = parse_key_values(text)

    def _int(key: str, default: int) -> int:
        try:
            return int(values.get(key, default))
        except ValueError:
            return default

    max_days, min_days, warn_age = _int("pass_max_days", 99999), _int("pass_min_days", 0), _int("pass_warn_age", 0)
    problems = []
    if max_days > 365:
        problems.append(f"PASS_MAX_DAYS={max_days} (> 365)")
    if min_days < 1:
        problems.append(f"PASS_MIN_DAYS={min_days} (< 1)")
    if warn_age < 7:
        problems.append(f"PASS_WARN_AGE={warn_age} (< 7)")
    evidence = f"PASS_MAX_DAYS={max_days}, PASS_MIN_DAYS={min_days}, PASS_WARN_AGE={warn_age}"
    if problems:
        return CheckStatus.FAIL, "; ".join(problems)
    return CheckStatus.PASS, evidence


@check(
    "PWD-002",
    "Strong password hashing algorithm",
    "password_policy",
    Severity.HIGH,
    "Set ENCRYPT_METHOD to YESCRYPT or SHA512 in /etc/login.defs and force affected users to change passwords.",
    ("CIS Debian/Ubuntu Benchmark 5.4.1.4",),
)
def check_password_hashing(ctx: AuditContext) -> Outcome:
    text = ctx.read("etc/login.defs")
    if text is None:
        return CheckStatus.UNKNOWN, "/etc/login.defs not found"
    method = parse_key_values(text).get("encrypt_method", "").upper()
    if method in ("SHA512", "YESCRYPT"):
        return CheckStatus.PASS, f"ENCRYPT_METHOD={method}"
    if method in ("MD5", "DES", "SHA256"):
        return CheckStatus.FAIL, f"Weak ENCRYPT_METHOD={method}"
    return CheckStatus.WARN, "ENCRYPT_METHOD not set explicitly (PAM default applies)"


@check(
    "PWD-003",
    "Password complexity is enforced (pam_pwquality)",
    "password_policy",
    Severity.MEDIUM,
    "Install libpam-pwquality, reference pam_pwquality.so in the PAM password stack and set minlen = 14 "
    "in /etc/security/pwquality.conf.",
    ("CIS Debian/Ubuntu Benchmark 5.3.3.2", "CIS Controls v8 5.2"),
)
def check_password_complexity(ctx: AuditContext) -> Outcome:
    pam = ""
    for candidate in ("etc/pam.d/common-password", "etc/pam.d/system-auth", "etc/pam.d/password-auth"):
        pam += ctx.read(candidate) or ""
    module = re.search(r"^\s*password\s+\S+\s+(pam_pwquality|pam_cracklib)\.so(.*)$", pam, re.M)
    if not module:
        return CheckStatus.FAIL, "No pam_pwquality/pam_cracklib module in the PAM password stack"
    minlen = None
    arg = re.search(r"minlen=(\d+)", module.group(2))
    if arg:
        minlen = int(arg.group(1))
    conf = ctx.read("etc/security/pwquality.conf")
    if conf:
        configured = parse_key_values(conf, "=").get("minlen")
        if configured and configured.isdigit():
            minlen = int(configured)
    if minlen is None or minlen < 14:
        return CheckStatus.WARN, f"{module.group(1)} enabled but minlen={minlen or 'default (8)'} (< 14)"
    return CheckStatus.PASS, f"{module.group(1)} enabled with minlen={minlen}"


# =============================================================================
# sudo
# =============================================================================


@check(
    "SUDO-001",
    "sudo always requires authentication (no NOPASSWD)",
    "privilege",
    Severity.HIGH,
    "Remove NOPASSWD and !authenticate from sudoers rules (use `visudo`); grant passwordless sudo only "
    "to narrowly scoped automation commands.",
    ("CIS Debian/Ubuntu Benchmark 5.2.4", "ISO 27001 A.8.2"),
)
def check_sudo_nopasswd(ctx: AuditContext) -> Outcome:
    lines = read_sudoers(ctx)
    if lines is None:
        return CheckStatus.NOT_APPLICABLE, "sudo is not installed"
    offenders = [f"{f}: {line}" for f, line in lines if "NOPASSWD" in line or "!authenticate" in line]
    if offenders:
        return CheckStatus.FAIL, "Passwordless sudo rules: " + " | ".join(offenders[:10])
    return CheckStatus.PASS, "No NOPASSWD / !authenticate rules found"


@check(
    "SUDO-002",
    "sudo uses a pseudo-terminal and logs to a file",
    "privilege",
    Severity.LOW,
    'Add `Defaults use_pty` and `Defaults logfile="/var/log/sudo.log"` to /etc/sudoers.d/hardening.',
    ("CIS Debian/Ubuntu Benchmark 5.2.2-5.2.3",),
)
def check_sudo_defaults(ctx: AuditContext) -> Outcome:
    lines = read_sudoers(ctx)
    if lines is None:
        return CheckStatus.NOT_APPLICABLE, "sudo is not installed"
    defaults = " ".join(line for _, line in lines if line.startswith("Defaults"))
    missing = []
    if "use_pty" not in defaults:
        missing.append("use_pty")
    if "logfile" not in defaults:
        missing.append("logfile")
    if missing:
        return CheckStatus.WARN, f"Missing sudo Defaults: {', '.join(missing)}"
    return CheckStatus.PASS, "use_pty and logfile are configured"


# =============================================================================
# SSH hardening
# =============================================================================

_SSH_REF = ("CIS Debian/Ubuntu Benchmark 5.1", "ISO 27001 A.8.5")
_NO_SSH = (CheckStatus.NOT_APPLICABLE, "OpenSSH server is not installed")


def _ssh(ctx: AuditContext, key: str, default: str) -> str | None:
    config = parse_sshd_config(ctx)
    if config is None:
        return None
    return config.get(key, default).strip().lower()


@check(
    "SSH-001",
    "SSH root login is disabled",
    "ssh",
    Severity.HIGH,
    "Set `PermitRootLogin no` in /etc/ssh/sshd_config and administer via named accounts + sudo.",
    _SSH_REF,
)
def check_ssh_root_login(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "permitrootlogin", "prohibit-password")
    if value is None:
        return _NO_SSH
    if value == "no":
        return CheckStatus.PASS, "PermitRootLogin no"
    if value in ("prohibit-password", "without-password", "forced-commands-only"):
        return CheckStatus.WARN, f"PermitRootLogin {value} (key-based root login still allowed)"
    return CheckStatus.FAIL, f"PermitRootLogin {value}"


@check(
    "SSH-002",
    "SSH password authentication is disabled",
    "ssh",
    Severity.MEDIUM,
    "Deploy SSH keys, then set `PasswordAuthentication no` and `KbdInteractiveAuthentication no`.",
    _SSH_REF,
)
def check_ssh_password_auth(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "passwordauthentication", "yes")
    if value is None:
        return _NO_SSH
    if value == "no":
        return CheckStatus.PASS, "PasswordAuthentication no"
    return CheckStatus.FAIL, f"PasswordAuthentication {value} (brute-force exposure)"


@check(
    "SSH-003",
    "SSH empty passwords are prohibited",
    "ssh",
    Severity.CRITICAL,
    "Set `PermitEmptyPasswords no`.",
    _SSH_REF,
)
def check_ssh_empty_passwords(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "permitemptypasswords", "no")
    if value is None:
        return _NO_SSH
    if value == "no":
        return CheckStatus.PASS, "PermitEmptyPasswords no"
    return CheckStatus.FAIL, f"PermitEmptyPasswords {value}"


@check(
    "SSH-004",
    "SSH MaxAuthTries is 4 or less",
    "ssh",
    Severity.LOW,
    "Set `MaxAuthTries 4` to slow down online guessing.",
    _SSH_REF,
)
def check_ssh_max_auth_tries(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "maxauthtries", "6")
    if value is None:
        return _NO_SSH
    tries = int(value) if value.isdigit() else 6
    if tries <= 4:
        return CheckStatus.PASS, f"MaxAuthTries {tries}"
    return CheckStatus.FAIL, f"MaxAuthTries {tries} (> 4)"


@check(
    "SSH-005",
    "SSH X11 forwarding is disabled",
    "ssh",
    Severity.LOW,
    "Set `X11Forwarding no` unless strictly required.",
    _SSH_REF,
)
def check_ssh_x11(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "x11forwarding", "no")
    if value is None:
        return _NO_SSH
    if value == "no":
        return CheckStatus.PASS, "X11Forwarding no"
    return CheckStatus.FAIL, f"X11Forwarding {value}"


WEAK_SSH_ALGORITHMS = {
    "ciphers": ("cbc", "arcfour", "3des", "blowfish", "cast128"),
    "macs": ("hmac-md5", "hmac-sha1-96", "umac-64@openssh.com", "hmac-ripemd160"),
    "kexalgorithms": (
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ),
}


@check(
    "SSH-006",
    "SSH uses strong cryptographic algorithms only",
    "ssh",
    Severity.MEDIUM,
    "Remove CBC/arcfour/3DES ciphers, MD5/SHA1-96 MACs and SHA-1 key exchanges from Ciphers, MACs "
    "and KexAlgorithms (or rely on modern OpenSSH defaults).",
    (*_SSH_REF, "CIS Controls v8 3.10"),
)
def check_ssh_crypto(ctx: AuditContext) -> Outcome:
    config = parse_sshd_config(ctx)
    if config is None:
        return _NO_SSH
    weak = []
    for key, patterns in WEAK_SSH_ALGORITHMS.items():
        for raw in config.get(key, "").lower().split(","):
            algorithm = raw.strip().lstrip("+")
            if algorithm and any(p in algorithm for p in patterns):
                weak.append(f"{key}: {algorithm}")
    if weak:
        return CheckStatus.FAIL, "Weak algorithms enabled: " + ", ".join(weak)
    return CheckStatus.PASS, "No weak Ciphers/MACs/KexAlgorithms configured"


@check(
    "SSH-007",
    "SSH idle session timeout is configured",
    "ssh",
    Severity.LOW,
    "Set `ClientAliveInterval 300` and `ClientAliveCountMax 3` (idle sessions closed after ~15 min).",
    (*_SSH_REF, "CIS Controls v8 4.3"),
)
def check_ssh_idle_timeout(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "clientaliveinterval", "0")
    if value is None:
        return _NO_SSH
    seconds = parse_duration_seconds(value) or 0
    if 0 < seconds <= 900:
        return CheckStatus.PASS, f"ClientAliveInterval {value}"
    return CheckStatus.FAIL, f"ClientAliveInterval {value} (idle sessions never time out)"


@check(
    "SSH-008",
    "SSH LoginGraceTime is 60 seconds or less",
    "ssh",
    Severity.LOW,
    "Set `LoginGraceTime 60` to limit unauthenticated connection slots (also mitigates some DoS/race attacks).",
    _SSH_REF,
)
def check_ssh_grace_time(ctx: AuditContext) -> Outcome:
    value = _ssh(ctx, "logingracetime", "120")
    if value is None:
        return _NO_SSH
    seconds = parse_duration_seconds(value)
    if seconds is not None and 0 < seconds <= 60:
        return CheckStatus.PASS, f"LoginGraceTime {value}"
    return CheckStatus.FAIL, f"LoginGraceTime {value}"


# =============================================================================
# Filesystem & kernel
# =============================================================================

_SENSITIVE_FILES = {
    "etc/passwd": (0o022, "must not be group/world writable"),
    "etc/group": (0o022, "must not be group/world writable"),
    "etc/shadow": (0o007, "must not be accessible by others"),
    "etc/gshadow": (0o007, "must not be accessible by others"),
    "etc/sudoers": (0o027, "must not be writable by group or accessible by others"),
    "etc/ssh/sshd_config": (0o022, "must not be group/world writable"),
}


@check(
    "FS-001",
    "Critical system files have restrictive permissions",
    "filesystem",
    Severity.HIGH,
    "Restore permissions: `chmod 644 /etc/passwd /etc/group; chmod 640 /etc/shadow /etc/gshadow; "
    "chmod 440 /etc/sudoers; chmod 600 /etc/ssh/sshd_config`.",
    ("CIS Debian/Ubuntu Benchmark 7.1",),
)
def check_file_permissions(ctx: AuditContext) -> Outcome:
    problems, checked = [], 0
    for relative, (forbidden, message) in _SENSITIVE_FILES.items():
        target = ctx.path(relative)
        try:
            mode = target.stat().st_mode & 0o777
        except FileNotFoundError:
            continue
        checked += 1
        if mode & forbidden:
            problems.append(f"/{relative} mode {oct(mode)} {message}")
    if problems:
        return CheckStatus.FAIL, "; ".join(problems)
    if checked == 0:
        return CheckStatus.UNKNOWN, "No critical files found under the audit root"
    return CheckStatus.PASS, f"{checked} critical files have compliant permissions"


@check(
    "KRN-001",
    "Address space layout randomisation (ASLR) is fully enabled",
    "kernel",
    Severity.MEDIUM,
    "Set `kernel.randomize_va_space = 2` in /etc/sysctl.d/60-hardening.conf and run `sysctl --system`.",
    ("CIS Debian/Ubuntu Benchmark 1.5.1",),
)
def check_aslr(ctx: AuditContext) -> Outcome:
    value = ctx.read("proc/sys/kernel/randomize_va_space")
    if value is None:
        return CheckStatus.UNKNOWN, "Kernel parameters not available under the audit root"
    value = value.strip()
    if value == "2":
        return CheckStatus.PASS, "kernel.randomize_va_space = 2"
    if value == "1":
        return CheckStatus.WARN, "kernel.randomize_va_space = 1 (partial)"
    return CheckStatus.FAIL, f"kernel.randomize_va_space = {value}"


@check(
    "KRN-002",
    "IPv4 forwarding is disabled (non-router hosts)",
    "kernel",
    Severity.LOW,
    "Set `net.ipv4.ip_forward = 0` unless the host is a router or container host (Docker requires it).",
    ("CIS Debian/Ubuntu Benchmark 3.3.1",),
)
def check_ip_forward(ctx: AuditContext) -> Outcome:
    value = ctx.read("proc/sys/net/ipv4/ip_forward")
    if value is None:
        return CheckStatus.UNKNOWN, "Kernel parameters not available under the audit root"
    if value.strip() == "0":
        return CheckStatus.PASS, "net.ipv4.ip_forward = 0"
    return CheckStatus.WARN, "net.ipv4.ip_forward = 1 (expected only on routers/container hosts)"


# =============================================================================
# Patching & logging
# =============================================================================


@check(
    "UPD-001",
    "Automatic security updates are configured",
    "patching",
    Severity.LOW,
    "Debian/Ubuntu: `apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`. "
    "RHEL family: enable dnf-automatic with apply_updates = yes. On rolling distributions (Kali/Parrot) "
    "schedule regular `apt full-upgrade` instead.",
    ("CIS Controls v8 7.3", "NIST CSF PR.PS-02"),
)
def check_auto_updates(ctx: AuditContext) -> Outcome:
    apt = ctx.read("etc/apt/apt.conf.d/20auto-upgrades")
    if apt and re.search(r'Unattended-Upgrade\s+"1"', apt):
        return CheckStatus.PASS, "unattended-upgrades enabled (20auto-upgrades)"
    dnf = ctx.read("etc/dnf/automatic.conf")
    if dnf and re.search(r"^\s*apply_updates\s*=\s*(yes|true|1)", dnf, re.M | re.I):
        return CheckStatus.PASS, "dnf-automatic applies updates"
    return CheckStatus.WARN, "No automatic security update mechanism detected"


@check(
    "LOG-001",
    "System auditing (auditd) is installed",
    "logging",
    Severity.LOW,
    "Install and enable auditd (`apt install auditd && systemctl enable --now auditd`) with rules for "
    "identity, sudoers and authentication events.",
    ("CIS Controls v8 8.2", "ISO 27001 A.8.15"),
)
def check_auditd(ctx: AuditContext) -> Outcome:
    if not ctx.exists("etc/audit/auditd.conf"):
        return CheckStatus.FAIL, "auditd configuration not found"
    if ctx.is_live:
        state = ctx.runner(["systemctl", "is-active", "auditd"])
        if state is not None and state.stdout.strip() != "active":
            return CheckStatus.WARN, f"auditd installed but service state is '{state.stdout.strip() or 'unknown'}'"
    return CheckStatus.PASS, "auditd is installed"
