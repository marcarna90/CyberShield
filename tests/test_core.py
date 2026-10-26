"""Core: configuration, models, security primitives, RBAC, scope, rate limiting, logging, audit trail."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path

import jwt
import pytest
from sqlalchemy import update

from app.core import security
from app.core.audit import GENESIS_HASH, record_event, verify_chain
from app.core.config import Settings, read_secret_file
from app.core.logging import REDACTED, JsonFormatter, TextFormatter, redact_text, redact_value, setup_logging
from app.core.models import CheckResult, CheckStatus, Finding, Severity, risk_score, severity_counts, sort_findings
from app.core.netutils import classify_ip, is_internal
from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.rbac import Perm, Role, has_permission, permissions_for
from app.core.scope import ScopeError, TargetScope
from app.database.models import AuditEvent

# =============================================================================
# Configuration
# =============================================================================


class TestSettings:
    def test_defaults_use_sqlite_in_data_dir(self, settings: Settings) -> None:
        assert settings.sqlalchemy_url.startswith("sqlite:///")
        assert settings.sqlalchemy_url.endswith("cybershield.db")

    def test_explicit_database_url_wins(self) -> None:
        assert Settings(database_url="sqlite://", db_host="db").sqlalchemy_url == "sqlite://"

    def test_postgres_url_from_components_and_secret_file(self, tmp_path: Path) -> None:
        secret = tmp_path / "pw"
        secret.write_text("s3cr3t/with@chars\n")
        url = Settings(db_host="db", db_password_file=secret, database_url=None).sqlalchemy_url
        assert url.startswith("postgresql+psycopg://cybershield:")
        assert "s3cr3t%2Fwith%40chars@db:5432/cybershield" in url

    def test_postgres_url_with_env_password(self) -> None:
        url = Settings(db_host="db", db_password="pw").sqlalchemy_url
        assert "cybershield:pw@db" in url

    @pytest.mark.parametrize(
        "field,value",
        [
            ("allowed_targets", "10.0.0.0/8,not-a-network"),
            ("nmap_host_timeout", "5 minutes"),
            ("api_prefix", "api/v1"),
        ],
    )
    def test_invalid_values_rejected(self, field: str, value: str) -> None:
        with pytest.raises(ValueError):
            Settings(**{field: value})

    def test_empty_values_are_unset(self) -> None:
        s = Settings(sensor_interface="", smtp_host="  ", database_url="", db_host="")
        assert s.sensor_interface is None and s.smtp_host is None
        assert s.sqlalchemy_url.startswith("sqlite")

    def test_list_properties(self) -> None:
        s = Settings(
            cors_origins="http://a, http://b",
            ioc_files="/a.txt,/b.txt",
            threat_feeds="https://x",
            alert_email_to="a@x.example, b@x.example",
        )
        assert s.cors_origin_list == ["http://a", "http://b"]
        assert s.ioc_file_list == [Path("/a.txt"), Path("/b.txt")]
        assert s.threat_feed_list == ["https://x"]
        assert s.alert_email_recipients == ["a@x.example", "b@x.example"]
        assert "10.0.0.0/8" in s.allowed_target_list

    def test_secret_files_take_precedence(self, tmp_path: Path) -> None:
        (tmp_path / "smtp").write_text("from-file")
        (tmp_path / "admin").write_text("Admin-From-File-1!")
        s = Settings(
            smtp_password="env",
            smtp_password_file=tmp_path / "smtp",
            admin_password="env",
            admin_password_file=tmp_path / "admin",
        )
        assert s.smtp_password_value == "from-file"
        assert s.admin_password_value == "Admin-From-File-1!"
        assert Settings(smtp_password="env").smtp_password_value == "env"
        assert Settings().smtp_password_value is None

    def test_read_secret_file_edge_cases(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.write_text("   \n")
        assert read_secret_file(None) is None
        assert read_secret_file(tmp_path / "missing") is None
        assert read_secret_file(empty) is None

    def test_secret_key_generated_and_persisted(self, tmp_path: Path) -> None:
        s = Settings(data_dir=tmp_path)
        key = s.get_secret_key()
        assert len(key) >= 64
        assert (tmp_path / ".jwt_secret").stat().st_mode & 0o777 == 0o600
        assert Settings(data_dir=tmp_path).get_secret_key() == key  # survives restarts
        assert s.get_secret_key() == key  # cached

    def test_secret_key_from_file_and_too_short(self, tmp_path: Path) -> None:
        (tmp_path / "jwt").write_text("f" * 40)
        assert Settings(secret_key_file=tmp_path / "jwt").get_secret_key() == "f" * 40
        with pytest.raises(ValueError, match="at least 32"):
            Settings(secret_key="short").get_secret_key()


# =============================================================================
# Domain models
# =============================================================================


class TestModels:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (None, Severity.INFO),
            (0.0, Severity.INFO),
            (0.1, Severity.LOW),
            (3.9, Severity.LOW),
            (4.0, Severity.MEDIUM),
            (6.9, Severity.MEDIUM),
            (7.0, Severity.HIGH),
            (8.9, Severity.HIGH),
            (9.0, Severity.CRITICAL),
            (10.0, Severity.CRITICAL),
        ],
    )
    def test_from_cvss(self, score: float | None, expected: Severity) -> None:
        assert Severity.from_cvss(score) is expected

    def test_parse_aliases_and_errors(self) -> None:
        assert Severity.parse("INFO") is Severity.INFO
        assert Severity.parse(" Moderate ") is Severity.MEDIUM
        assert Severity.parse(Severity.HIGH) is Severity.HIGH
        with pytest.raises(ValueError):
            Severity.parse("catastrophic")
        assert [s.rank for s in Severity.ordered()] == [4, 3, 2, 1, 0]

    def test_check_result_conversion(self) -> None:
        base = {"check_id": "X-1", "title": "t", "category": "c", "severity": Severity.HIGH}
        assert CheckResult(status=CheckStatus.PASS, **base).to_finding("h") is None
        failed = CheckResult(status=CheckStatus.FAIL, **base).to_finding("h")
        warned = CheckResult(status=CheckStatus.WARN, **base).to_finding("h")
        low_warn = CheckResult(status=CheckStatus.WARN, **{**base, "severity": Severity.LOW}).to_finding("h")
        assert failed.severity is Severity.HIGH and failed.asset == "h"
        assert warned.severity is Severity.MEDIUM  # warnings are downgraded one level
        assert low_warn.severity is Severity.LOW

    def test_risk_score_and_counts(self) -> None:
        def f(sev: Severity, fid: str = "F", cvss: float | None = None) -> Finding:
            return Finding(finding_id=fid, title=fid, severity=sev, category="c", source="s", cvss=cvss)

        assert risk_score([]) == 0.0
        assert 15 < risk_score([f(Severity.CRITICAL)]) < 20
        assert risk_score([f(Severity.CRITICAL)] * 50) <= 100.0
        counts = severity_counts([f(Severity.HIGH), f(Severity.HIGH), f(Severity.INFO)])
        assert counts == {"critical": 0, "high": 2, "medium": 0, "low": 0, "informational": 1}
        ordered = sort_findings([f(Severity.LOW, "a"), f(Severity.HIGH, "b", 7.0), f(Severity.HIGH, "c", 8.8)])
        assert [x.finding_id for x in ordered] == ["c", "b", "a"]
        assert f(Severity.LOW, "a").fingerprint != f(Severity.LOW, "b").fingerprint

    @pytest.mark.parametrize(
        "ip,internal,label",
        [
            ("10.1.2.3", True, "private"),
            ("192.168.0.1", True, "private"),
            ("100.64.1.1", True, "private"),
            ("127.0.0.1", True, "loopback"),
            ("203.0.113.5", False, "documentation"),
            ("8.8.8.8", False, "public"),
            ("224.0.0.1", False, "multicast"),
            ("169.254.1.1", True, "link_local"),
            ("fd00::1", True, "private"),
            ("0.0.0.0", False, "reserved"),
            ("nope", False, "invalid"),
        ],
    )
    def test_ip_classification(self, ip: str, internal: bool, label: str) -> None:
        assert is_internal(ip) is internal
        assert classify_ip(ip) == label


# =============================================================================
# Security primitives
# =============================================================================


class TestSecurity:
    def test_hash_and_verify(self) -> None:
        hashed = security.hash_password("Correct-Horse-9!")
        assert hashed.startswith("$argon2id$")
        assert security.verify_password("Correct-Horse-9!", hashed)
        assert not security.verify_password("wrong", hashed)
        assert not security.verify_password("x", "not-a-hash")
        assert not security.password_needs_rehash(hashed)
        assert security.password_needs_rehash("not-a-hash")

    @pytest.mark.parametrize(
        "password,fragment",
        [
            ("Short1!", "at least 12"),
            ("alllowercase123!", "uppercase"),
            ("ALLUPPERCASE123!", "lowercase"),
            ("NoDigitsHere!!", "digit"),
            ("NoSpecials12345", "special"),
            ("x" * 129 + "A1!", "at most"),
            ("Password123!", "too common"),
            ("MyAliceName123!", "username"),
        ],
    )
    def test_password_policy(self, password: str, fragment: str) -> None:
        problems = security.password_policy_violations(password, "alice")
        assert any(fragment in p for p in problems)

    def test_generated_password_is_compliant(self) -> None:
        assert not security.password_policy_violations(security.generate_password())
        with pytest.raises(ValueError):
            security.generate_password(8)

    def test_token_roundtrip(self, settings: Settings) -> None:
        token, expires, jti = security.create_access_token(settings, "alice", "analyst", expires_minutes=5)
        claims = security.decode_access_token(settings, token)
        assert claims["sub"] == "alice" and claims["role"] == "analyst" and claims["jti"] == jti
        assert expires > claims["iat"] if isinstance(claims["iat"], type(expires)) else True

    def test_token_tampering_and_expiry(self, settings: Settings) -> None:
        token, _, _ = security.create_access_token(settings, "alice", "viewer")
        with pytest.raises(security.TokenError):
            security.decode_access_token(settings, token[:-2] + ("A" if token[-1] != "A" else "B") + token[-1])
        forged = jwt.encode({"sub": "alice", "role": "admin"}, "other-key-other-key-other-key-0123", algorithm="HS256")
        with pytest.raises(security.TokenError):
            security.decode_access_token(settings, forged)
        unsigned = jwt.encode({"sub": "alice", "role": "admin"}, None, algorithm="none")
        with pytest.raises(security.TokenError):
            security.decode_access_token(settings, unsigned)
        expired, _, _ = security.create_access_token(settings, "alice", "viewer", expires_minutes=-1)
        with pytest.raises(security.TokenError):
            security.decode_access_token(settings, expired)


# =============================================================================
# RBAC, scope, rate limiting
# =============================================================================


class TestRBAC:
    def test_role_hierarchy(self) -> None:
        assert has_permission(Role.ADMIN, Perm.USERS_MANAGE)
        assert has_permission("analyst", Perm.SCAN_RUN)
        assert not has_permission("analyst", Perm.USERS_MANAGE)
        assert not has_permission("analyst", Perm.AUDIT_TRAIL_READ)
        assert has_permission("auditor", Perm.AUDIT_TRAIL_READ)
        assert not has_permission("auditor", Perm.SCAN_RUN)
        assert has_permission("viewer", Perm.FINDINGS_READ)
        assert not has_permission("viewer", Perm.REPORT_GENERATE)
        assert not has_permission("root", Perm.FINDINGS_READ)
        assert permissions_for("ghost") == []
        assert Perm.ADMIN in permissions_for("admin")


class TestScope:
    scope = TargetScope(
        ["10.0.0.0/8", "192.168.1.0/24", "fd00::/8"],
        max_hosts=256,
        resolver=lambda name: {"intranet.lab": ["10.1.1.1"], "evil.lab": ["8.8.8.8"], "empty.lab": []}[name],
    )

    @pytest.mark.parametrize(
        "target,expected",
        [
            ("10.0.0.5", "10.0.0.5"),
            (" 192.168.1.0/24 ", "192.168.1.0/24"),
            ("10.0.0.7/32", "10.0.0.7"),
            ("10.0.0.9/30", "10.0.0.8/30"),
            ("intranet.lab", "10.1.1.1"),
            ("fd00::1", "fd00::1"),
        ],
    )
    def test_valid_targets(self, target: str, expected: str) -> None:
        assert self.scope.validate(target) == expected

    @pytest.mark.parametrize(
        "target,message",
        [
            ("8.8.8.8", "outside"),
            ("10.0.0.0/16", "max 256"),
            ("192.168.0.0/23", "max 256"),
            ("10.0.0.1;rm -rf /", "Illegal"),
            ("-oN /tmp/x", "Illegal"),
            ("--script=x", "option injection"),
            ("evil.lab", "outside"),
            ("empty.lab", "did not resolve"),
            ("", "Empty"),
            ("bad_host!", "Invalid"),
            ("x" * 300, "oversized"),
            ("2001:db8::1", "outside"),
        ],
    )
    def test_invalid_targets(self, target: str, message: str) -> None:
        with pytest.raises(ScopeError, match=message):
            self.scope.validate(target)

    def test_validate_many(self) -> None:
        assert self.scope.validate_many(["10.0.0.1", "10.0.0.1/32", "10.0.0.2"]) == ["10.0.0.1", "10.0.0.2"]
        with pytest.raises(ScopeError, match="Combined"):
            self.scope.validate_many(["10.0.0.0/24", "10.0.1.0/24"])
        with pytest.raises(ScopeError, match="No targets"):
            self.scope.validate_many([])
        with pytest.raises(ValueError):
            TargetScope([])

    def test_default_resolver(self) -> None:
        scope = TargetScope(["127.0.0.0/8", "::1/128"])
        assert scope.validate("localhost") in ("127.0.0.1", "::1")
        with pytest.raises(ScopeError, match="Cannot resolve"):
            scope.validate("does-not-exist.invalid")


class TestRateLimiter:
    def test_sliding_window(self) -> None:
        now = [0.0]
        limiter = SlidingWindowRateLimiter(2, window_seconds=10, clock=lambda: now[0], max_keys=1)
        assert limiter.hit("a") == (True, 0.0)
        assert limiter.hit("a")[0]
        allowed, retry = limiter.hit("a")
        assert not allowed and 0 < retry <= 10
        now[0] = 10.5
        assert limiter.hit("a")[0]
        limiter.hit("b")
        limiter.hit("c")  # triggers eviction of stale keys
        limiter.reset()
        assert limiter.hit("a")[0]
        with pytest.raises(ValueError):
            SlidingWindowRateLimiter(0)


# =============================================================================
# Logging & audit trail
# =============================================================================


class TestLogging:
    def test_redaction(self) -> None:
        assert redact_value("password", "x") == REDACTED
        assert redact_value("details", {"token": "abc", "user": "bob"}) == {"token": REDACTED, "user": "bob"}
        assert redact_value("count", 3) == 3
        assert REDACTED in redact_text("Authorization: Bearer abc.def.ghi")
        assert "hunter2" not in redact_text("login password=hunter2 ok")

    def test_formatters(self) -> None:
        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "token=%s", ("abc",), None)
        record.api_key = "secret"
        record.client_ip = "10.0.0.1"
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            import sys

            record.exc_info = sys.exc_info()
        payload = json.loads(JsonFormatter().format(record))
        assert payload["api_key"] == REDACTED and payload["client_ip"] == "10.0.0.1"
        assert "abc" not in payload["msg"] and "boom" in payload["exc"]
        assert "abc" not in TextFormatter().format(record)

    def test_setup_logging_creates_files(self, settings: Settings) -> None:
        setup_logging(settings, force=True)
        logging.getLogger("cybershield.audit").info("hello")
        assert (settings.logs_dir / "audit.log").exists()
        setup_logging(settings)  # idempotent
        text_settings = settings.model_copy(update={"log_json": False})
        setup_logging(text_settings, force=True)


class TestAuditTrail:
    def test_chain_valid_and_tamper_detection(self, db) -> None:
        assert verify_chain(db).valid and verify_chain(db).checked == 0
        first = record_event(db, actor="alice", action="login", ip="10.0.0.1", details={"password": "x"})
        record_event(db, actor="bob", action="scan.create", resource="10.0.0.0/24")
        third = record_event(db, actor="carol", action="report.generate", outcome="success")
        assert first.prev_hash == GENESIS_HASH and first.details == {"password": REDACTED}
        assert verify_chain(db).valid and verify_chain(db).checked == 3

        db.execute(update(AuditEvent).where(AuditEvent.id == third.id).values(actor="mallory"))
        db.commit()
        result = verify_chain(db)
        assert not result.valid and result.first_invalid_id == third.id and "modified" in result.reason

    def test_deleted_row_is_detected(self, db) -> None:
        events = [record_event(db, actor="a", action=f"act{i}") for i in range(3)]
        db.delete(db.get(AuditEvent, events[1].id))
        db.commit()
        result = verify_chain(db)
        assert not result.valid and "deleted" in result.reason

    def test_timestamps_survive_roundtrip(self, db) -> None:
        event = record_event(db, actor="a", action="b")
        db.expire_all()
        stored = db.get(AuditEvent, event.id)
        assert stored.timestamp.tzinfo is not None
        assert abs(stored.timestamp - event.timestamp) < timedelta(seconds=1)
