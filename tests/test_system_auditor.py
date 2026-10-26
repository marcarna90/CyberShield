"""Host security auditor: parsers, every check, live-mode command handling and scoring."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from app.core.models import CheckStatus, Severity
from app.modules.system_auditor import checks as C
from app.modules.system_auditor.auditor import HostAuditor, hardening_score
from app.modules.system_auditor.checks import AuditContext, CommandResult
from tests.conftest import write_tree


def statuses(root: Path, runner=None) -> dict[str, CheckStatus]:
    ctx = AuditContext(host_root=root, runner=runner or (lambda args: None))
    return HostAuditor(ctx).run().check_statuses()


class TestParsers:
    def test_parse_passwd_skips_garbage(self) -> None:
        entries = C.parse_passwd("root:x:0:0:r:/root:/bin/bash\nbad line\n#c:x:1:1::/:/bin/sh\nx:x:NaN:0::/:/bin/sh\n")
        assert [e["name"] for e in entries] == ["root"]

    def test_parse_key_values(self) -> None:
        values = C.parse_key_values("# c\nKEY value # comment\nkey other\nEMPTY\n")
        assert values == {"key": "value", "empty": ""}
        assert C.parse_key_values('A = "1"\n', "=") == {"a": "1"}

    def test_decode_proc_addresses(self) -> None:
        assert C.decode_proc_address("0100007F:0CEA") == ("127.0.0.1", 3306)
        assert C.decode_proc_address("00000000000000000000000001000000:0016") == ("::1", 22)
        assert C.decode_proc_address("00000000000000000000000000000000:01BB") == ("::", 443)

    def test_parse_proc_net(self) -> None:
        tcp = "hdr\n 0: 00000000:0016 00000000:0000 0A x\n 1: 0100007F:0050 0100007F:9C40 01 x\n bad\n 2: ZZ:0016 0:0 0A\n"
        assert C.parse_proc_net(tcp, "tcp") == [("tcp", "0.0.0.0", 22)]
        udp = "hdr\n 0: 00000000:0035 00000000:0000 07 x\n 1: 0100007F:0035 0100007F:0035 07 x\n"
        assert C.parse_proc_net(udp, "udp6") == [("udp", "0.0.0.0", 53)]

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("60", 60),
            ("2m", 120),
            ("1h30m", 5400),
            ("", None),
            ("abc", None),
            ("10x", None),
        ],
    )
    def test_duration(self, value: str, expected: int | None) -> None:
        assert C.parse_duration_seconds(value) == expected

    def test_sshd_config_include_first_match_and_match_block(self, tmp_path: Path) -> None:
        root = write_tree(
            tmp_path,
            {
                "etc/ssh/sshd_config": "Include sshd_config.d/*.conf\nPermitRootLogin yes\nX11Forwarding=yes\n"
                "Match User bob\nPasswordAuthentication no\n",
                "etc/ssh/sshd_config.d/00-hardening.conf": "PermitRootLogin no\nMatch all\nMaxAuthTries 99\n",
            },
        )
        config = C.parse_sshd_config(AuditContext(host_root=root))
        assert config["permitrootlogin"] == "no"  # first value wins (include processed first)
        assert config["x11forwarding"] == "yes"
        assert "passwordauthentication" not in config  # inside Match block
        assert "maxauthtries" not in config

    def test_sshd_t_preferred_on_live_host(self) -> None:
        runner = lambda args: CommandResult(0, "permitrootlogin no\npasswordauthentication no\nbanner\n")  # noqa: E731
        config = C.parse_sshd_config(AuditContext(host_root=Path("/"), runner=runner))
        assert config == {"permitrootlogin": "no", "passwordauthentication": "no", "banner": ""}

    def test_sudoers_include_dir_rules(self, tmp_path: Path) -> None:
        root = write_tree(
            tmp_path,
            {
                "etc/sudoers": "# comment\nroot ALL=(ALL) ALL\n",
                "etc/sudoers.d/ops": "ops ALL=(ALL) NOPASSWD: ALL\n",
                "etc/sudoers.d/README.txt": "x ALL=(ALL) NOPASSWD: ALL\n",
                "etc/sudoers.d/backup~": "y ALL=(ALL) NOPASSWD: ALL\n",
            },
        )
        lines = C.read_sudoers(AuditContext(host_root=root))
        assert ("/etc/sudoers.d/ops", "ops ALL=(ALL) NOPASSWD: ALL") in lines
        assert all("README" not in f and "~" not in f for f, _ in lines)
        assert C.read_sudoers(AuditContext(host_root=tmp_path / "nothing")) is None


class TestOfflineAudit:
    def test_weak_host_findings(self, weak_root: Path) -> None:
        report = HostAuditor(AuditContext(host_root=weak_root)).run()
        result = report.check_statuses()
        assert report.hostname == "web-prod-01" and "Debian" in report.os_name
        expected_fail = {
            "FW-001",
            "USR-001",
            "USR-002",
            "NET-001",
            "PWD-001",
            "PWD-003",
            "SUDO-001",
            "SSH-001",
            "SSH-002",
            "SSH-004",
            "SSH-005",
            "SSH-006",
            "SSH-007",
            "SSH-008",
            "FS-001",
            "LOG-001",
        }
        for check_id in expected_fail:
            assert result[check_id] is CheckStatus.FAIL, check_id
        assert result["USR-003"] is CheckStatus.WARN  # postgres has a shell
        assert result["SUDO-002"] is CheckStatus.WARN
        assert result["UPD-001"] is CheckStatus.WARN
        assert result["USR-004"] is CheckStatus.NOT_APPLICABLE
        assert result["KRN-001"] is CheckStatus.PASS
        assert report.score < 40
        assert report.findings[0].severity is Severity.CRITICAL
        assert report.summary["status"]["fail"] == len(expected_fail)
        evidence = {c.check_id: c.evidence for c in report.checks}
        assert "svc-backup" in evidence["USR-001"]
        assert "3306" in evidence["NET-001"] and "6379" not in evidence["NET-001"]  # redis bound to loopback
        assert "aes128-cbc" in evidence["SSH-006"]

    def test_hardened_host_passes(self, hardened_root: Path) -> None:
        report = HostAuditor(AuditContext(host_root=hardened_root)).run()
        failing = {
            c.check_id: c.evidence
            for c in report.checks
            if c.status not in (CheckStatus.PASS, CheckStatus.NOT_APPLICABLE)
        }
        assert failing == {}
        assert report.score == 100.0 and report.findings == []

    def test_empty_root_is_unknown_not_crash(self, tmp_path: Path) -> None:
        result = statuses(tmp_path)
        assert result["USR-001"] is CheckStatus.UNKNOWN
        assert result["SSH-001"] is CheckStatus.NOT_APPLICABLE
        assert result["SUDO-001"] is CheckStatus.NOT_APPLICABLE
        assert result["FW-001"] is CheckStatus.UNKNOWN
        assert result["NET-001"] is CheckStatus.UNKNOWN and result["NET-002"] is CheckStatus.UNKNOWN
        assert result["FS-001"] is CheckStatus.UNKNOWN
        assert result["KRN-001"] is CheckStatus.UNKNOWN and result["KRN-002"] is CheckStatus.UNKNOWN
        assert result["PWD-001"] is CheckStatus.UNKNOWN and result["PWD-002"] is CheckStatus.UNKNOWN

    @pytest.mark.parametrize(
        "files,check_id,status",
        [
            ({"etc/login.defs": "ENCRYPT_METHOD MD5\n"}, "PWD-002", CheckStatus.FAIL),
            ({"etc/login.defs": "PASS_MAX_DAYS abc\n"}, "PWD-001", CheckStatus.FAIL),
            (
                {"etc/pam.d/common-password": "password requisite pam_pwquality.so minlen=8\n"},
                "PWD-003",
                CheckStatus.WARN,
            ),
            ({"etc/pam.d/system-auth": "password requisite pam_cracklib.so minlen=16\n"}, "PWD-003", CheckStatus.PASS),
            ({"etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n"}, "SSH-001", CheckStatus.WARN),
            ({"etc/ssh/sshd_config": "PermitEmptyPasswords yes\n"}, "SSH-003", CheckStatus.FAIL),
            ({"etc/ssh/sshd_config": "MaxAuthTries lots\n"}, "SSH-004", CheckStatus.FAIL),
            ({"etc/ssh/sshd_config": "LoginGraceTime 0\n"}, "SSH-008", CheckStatus.FAIL),
            (
                {"etc/ssh/sshd_config": "MACs hmac-md5\nKexAlgorithms diffie-hellman-group1-sha1\n"},
                "SSH-006",
                CheckStatus.FAIL,
            ),
            ({"proc/sys/kernel/randomize_va_space": "1"}, "KRN-001", CheckStatus.WARN),
            ({"proc/sys/kernel/randomize_va_space": "0"}, "KRN-001", CheckStatus.FAIL),
            ({"proc/sys/net/ipv4/ip_forward": "1"}, "KRN-002", CheckStatus.WARN),
            ({"etc/dnf/automatic.conf": "[commands]\napply_updates = yes\n"}, "UPD-001", CheckStatus.PASS),
            (
                {
                    "etc/nftables.conf": "table inet f { chain input { type filter hook input priority 0; policy drop; } }"
                },
                "FW-001",
                CheckStatus.PASS,
            ),
            ({"etc/ufw/ufw.conf": "ENABLED=no\n"}, "FW-001", CheckStatus.FAIL),
            (
                {"etc/passwd": "svc:x:500:500::/srv:/usr/sbin/nologin\nbob:x:1001:1001::/home/bob:/bin/zsh\n"},
                "USR-003",
                CheckStatus.PASS,
            ),
            ({"etc/shadow": "root:$6$abc:1:0:99999:7:::\n"}, "USR-002", CheckStatus.PASS),
            ({"etc/sudoers": "Defaults use_pty\nroot ALL=(ALL) ALL\n"}, "SUDO-001", CheckStatus.PASS),
        ],
    )
    def test_individual_checks(self, tmp_path: Path, files: dict[str, str], check_id: str, status: CheckStatus) -> None:
        assert statuses(write_tree(tmp_path, files))[check_id] is status

    def test_unreadable_file_reported_as_unknown(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        root = write_tree(tmp_path, {"etc/shadow": "root:x:::::::\n"})
        original = AuditContext.read

        def deny(self, relative: str):
            if relative == "etc/shadow":
                raise PermissionError(13, "denied", str(self.path(relative)))
            return original(self, relative)

        monkeypatch.setattr(AuditContext, "read", deny)
        report = HostAuditor(AuditContext(host_root=root), only={"USR-002"}).run()
        assert report.checks[0].status is CheckStatus.UNKNOWN
        assert "privileges" in report.checks[0].evidence

    def test_crashing_check_is_contained(self, tmp_path: Path) -> None:
        meta = C.CheckMeta("T-1", "t", "c", Severity.LOW, "r")
        result = C.run_check(meta, lambda ctx: 1 / 0, AuditContext(host_root=tmp_path))
        assert result.status is CheckStatus.UNKNOWN and "ZeroDivisionError" in result.evidence

    def test_directory_instead_of_file(self, tmp_path: Path) -> None:
        (tmp_path / "etc" / "passwd").mkdir(parents=True)
        assert AuditContext(host_root=tmp_path).read("etc/passwd") is None


class TestLiveMode:
    @staticmethod
    def runner_for(responses: dict[str, CommandResult | None]):
        return lambda args: responses.get(args[0])

    @pytest.mark.parametrize(
        "responses,status",
        [
            ({"ufw": CommandResult(0, "Status: active\n")}, CheckStatus.PASS),
            ({"firewall-cmd": CommandResult(0, "running\n")}, CheckStatus.PASS),
            ({"nft": CommandResult(0, "table inet filter { chain input { drop } }")}, CheckStatus.PASS),
            ({"iptables": CommandResult(0, "-P INPUT DROP\n")}, CheckStatus.PASS),
            ({"iptables": CommandResult(0, "-P INPUT ACCEPT\n-A INPUT -p tcp -j REJECT\n")}, CheckStatus.PASS),
            (
                {"ufw": CommandResult(0, "Status: inactive\n"), "iptables": CommandResult(0, "-P INPUT ACCEPT\n")},
                CheckStatus.FAIL,
            ),
            (
                {
                    "ufw": CommandResult(1, "", "ERROR: You need to be root to run this script"),
                    "nft": CommandResult(1, "", "Operation not permitted"),
                    "iptables": CommandResult(4, "", "Permission denied (you must be root)"),
                },
                CheckStatus.UNKNOWN,
            ),
            ({}, CheckStatus.FAIL),
        ],
    )
    def test_firewall(self, responses, status: CheckStatus) -> None:
        ctx = AuditContext(host_root=Path("/"), runner=self.runner_for(responses))
        assert C.check_firewall(ctx)[0] is status

    def test_sessions_and_auditd_service(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        live = AuditContext(host_root=Path("/"), runner=lambda a: CommandResult(3, "inactive\n"))
        monkeypatch.setattr(psutil, "users", lambda: [SimpleNamespace(name="alice", host="10.0.0.9", terminal="pts/0")])
        status, evidence = C.check_active_sessions(live)
        assert status is CheckStatus.PASS and "alice@10.0.0.9" in evidence
        monkeypatch.setattr(psutil, "users", lambda: [])
        assert "No interactive" in C.check_active_sessions(live)[1]
        monkeypatch.setattr(AuditContext, "exists", lambda self, rel: True)
        assert C.check_auditd(live)[0] is CheckStatus.WARN

    def test_listening_sockets_via_psutil(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket

        conns = [
            SimpleNamespace(
                laddr=SimpleNamespace(ip="0.0.0.0", port=23),
                raddr=(),
                type=socket.SOCK_STREAM,
                status=psutil.CONN_LISTEN,
            ),
            SimpleNamespace(
                laddr=SimpleNamespace(ip="0.0.0.0", port=53), raddr=(), type=socket.SOCK_DGRAM, status=psutil.CONN_NONE
            ),
            SimpleNamespace(laddr=(), raddr=(), type=socket.SOCK_STREAM, status=psutil.CONN_LISTEN),
        ]
        monkeypatch.setattr(psutil, "net_connections", lambda kind: conns)
        ctx = AuditContext(host_root=Path("/"))
        assert C.listening_sockets(ctx) == [("tcp", "0.0.0.0", 23), ("udp", "0.0.0.0", 53)]
        assert C.check_risky_listeners(AuditContext(host_root=Path("/")))[0] is CheckStatus.FAIL

    def test_psutil_access_denied_falls_back_to_proc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def deny(kind):
            raise psutil.AccessDenied()

        monkeypatch.setattr(psutil, "net_connections", deny)
        sockets = C.listening_sockets(AuditContext(host_root=Path("/")))
        assert isinstance(sockets, list)

    def test_default_runner(self) -> None:
        assert C.default_runner(["definitely-not-a-binary-xyz"]) is None
        result = C.default_runner(["true"])
        assert result is not None and result.returncode == 0
        assert C.default_runner(["sleep", "5"], timeout=1) is None

    def test_live_audit_runs(self) -> None:
        report = HostAuditor(AuditContext(runner=lambda args: None)).run()
        assert report.host_root == "/" and len(report.checks) == len(C.REGISTRY)


def test_hardening_score_weights() -> None:
    from app.core.models import CheckResult

    def r(status: CheckStatus, sev: Severity = Severity.HIGH) -> CheckResult:
        return CheckResult(check_id="x", title="x", category="x", status=status, severity=sev)

    assert hardening_score([]) == 100.0
    assert hardening_score([r(CheckStatus.PASS), r(CheckStatus.FAIL)]) == 50.0
    assert hardening_score([r(CheckStatus.WARN), r(CheckStatus.UNKNOWN), r(CheckStatus.PASS, Severity.INFO)]) == 50.0
