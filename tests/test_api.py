"""REST API: authentication, RBAC, every resource, security controls."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.database.models import AuditEvent
from app.database.session import session_scope
from app.modules.traffic_monitor.synthetic import write_sample_pcap
from tests.conftest import ADMIN_PASSWORD, API, USER_PASSWORD, login


def audit_actions(outcome: str | None = None) -> list[str]:
    with session_scope() as db:
        query = select(AuditEvent)
        if outcome:
            query = query.where(AuditEvent.outcome == outcome)
        return [e.action for e in db.scalars(query)]


# =============================================================================
# Infrastructure & hardening
# =============================================================================


class TestInfrastructure:
    def test_health_root_and_headers(self, client: TestClient) -> None:
        response = client.get(f"{API}/health")
        assert response.json()["status"] == "ok"
        for header in (
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-Request-ID",
            "Referrer-Policy",
            "Cache-Control",
        ):
            assert header in response.headers
        assert client.get(f"{API}/health/ready").json() == {"status": "ready"}
        assert client.get("/").json()["docs"] == "/docs"
        assert "cdn.jsdelivr.net" in client.get("/docs").headers["Content-Security-Policy"]

    def test_request_id_propagation(self, client: TestClient) -> None:
        assert (
            client.get(f"{API}/health", headers={"X-Request-ID": "abcdef123456"}).headers["X-Request-ID"]
            == "abcdef123456"
        )
        assert client.get(f"{API}/health", headers={"X-Request-ID": "bad id!"}).headers["X-Request-ID"] != "bad id!"

    def test_hsts_on_https(self, client: TestClient) -> None:
        assert "Strict-Transport-Security" in client.get(f"https://testserver{API}/health").headers

    def test_unauthenticated_requests_rejected(self, client: TestClient) -> None:
        for path in ("/dashboard/overview", "/findings", "/assets", "/alerts", "/reports", "/audit-trail"):
            assert client.get(f"{API}{path}").status_code == 401
        bad = client.get(f"{API}/findings", headers={"Authorization": "Bearer not.a.token"})
        assert bad.status_code == 401 and bad.headers["WWW-Authenticate"] == "Bearer"

    def test_body_size_limit(self, client: TestClient, admin_headers) -> None:
        response = client.post(
            f"{API}/reports", headers={**admin_headers, "Content-Length": str(10**12)}, content=b"{}"
        )
        assert response.status_code == 413
        invalid = client.post(f"{API}/reports", headers={**admin_headers, "Content-Length": "abc"}, content=b"{}")
        assert invalid.status_code == 400

    def test_unhandled_errors_are_masked(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.database import repository
        from app.main import create_app

        def explode(db):
            raise RuntimeError("secret internals")

        monkeypatch.setattr(repository, "overview", explode)
        with TestClient(create_app(settings), raise_server_exceptions=False) as test_client:
            response = test_client.get(f"{API}/dashboard/overview", headers=login(test_client))
        assert response.status_code == 500 and "secret" not in response.text and "request_id" in response.json()

    def test_docs_can_be_disabled_and_demo_seeded_at_startup(self, settings: Settings) -> None:
        from app.main import create_app

        custom = settings.model_copy(update={"enable_docs": False, "seed_demo": True})
        with TestClient(create_app(custom)) as test_client:
            assert test_client.get("/docs").status_code == 404
            assert test_client.get("/").json()["docs"] == "disabled"
            overview = test_client.get(f"{API}/dashboard/overview", headers=login(test_client)).json()
            assert overview["assets"] == 8

    def test_rate_limiting(self, settings: Settings) -> None:
        from app.main import create_app

        strict = settings.model_copy(update={"auth_rate_limit_per_minute": 3, "rate_limit_per_minute": 5})
        with TestClient(create_app(strict)) as test_client:
            codes = [
                test_client.post(f"{API}/auth/token", data={"username": "x", "password": "y"}).status_code
                for _ in range(4)
            ]
            assert codes == [401, 401, 401, 429]
            throttled = test_client.post(f"{API}/auth/token", data={"username": "x", "password": "y"})
            assert int(throttled.headers["Retry-After"]) >= 1
            api_codes = [test_client.get(f"{API}/findings").status_code for _ in range(6)]
            assert api_codes[-1] == 429
            assert test_client.get(f"{API}/health").status_code == 200  # exempt


# =============================================================================
# Authentication
# =============================================================================


class TestAuth:
    def test_login_me_logout(self, client: TestClient) -> None:
        response = client.post(f"{API}/auth/token", data={"username": "admin", "password": ADMIN_PASSWORD})
        body = response.json()
        assert body["token_type"] == "bearer" and body["role"] == "admin" and body["expires_in"] > 0
        headers = {"Authorization": f"Bearer {body['access_token']}"}
        me = client.get(f"{API}/auth/me", headers=headers).json()
        assert me["username"] == "admin" and "users:manage" in me["permissions"]
        assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204
        assert client.get(f"{API}/auth/me", headers=headers).status_code == 401  # revoked
        assert "auth.login" in audit_actions() and "auth.logout" in audit_actions()

    def test_failed_login_is_generic_and_audited(self, client: TestClient) -> None:
        unknown = client.post(f"{API}/auth/token", data={"username": "ghost", "password": "x"})
        wrong = client.post(f"{API}/auth/token", data={"username": "admin", "password": "wrong"})
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() == wrong.json()  # no user enumeration
        assert audit_actions("failure").count("auth.login") == 2

    def test_account_lockout(self, client: TestClient) -> None:
        for _ in range(5):
            client.post(f"{API}/auth/token", data={"username": "admin", "password": "wrong"})
        locked = client.post(f"{API}/auth/token", data={"username": "admin", "password": ADMIN_PASSWORD})
        assert locked.status_code == 401
        assert "locked" in audit_actions_outcomes()

    def test_change_password(self, client: TestClient, admin_headers) -> None:
        url = f"{API}/auth/change-password"
        assert (
            client.post(
                url, headers=admin_headers, json={"current_password": "nope", "new_password": "N3w-Passw0rd-Long!"}
            ).status_code
            == 400
        )
        weak = client.post(
            url, headers=admin_headers, json={"current_password": ADMIN_PASSWORD, "new_password": "aaaaaaaaaaaaaaaa"}
        )
        assert weak.status_code == 422
        ok = client.post(
            url, headers=admin_headers, json={"current_password": ADMIN_PASSWORD, "new_password": "N3w-Passw0rd-Long!"}
        )
        assert ok.status_code == 204
        assert client.get(f"{API}/auth/me", headers=admin_headers).status_code == 401  # token revoked
        login(client, "admin", "N3w-Passw0rd-Long!")

    def test_inactive_or_role_changed_tokens_invalidated(self, client: TestClient, admin_headers, make_user) -> None:
        analyst = make_user("analyst")
        users = client.get(f"{API}/users", headers=admin_headers).json()
        analyst_id = next(u["id"] for u in users if u["username"] == "analyst_user")
        client.patch(f"{API}/users/{analyst_id}", headers=admin_headers, json={"role": "viewer"})
        assert client.get(f"{API}/auth/me", headers=analyst).status_code == 401
        client.patch(f"{API}/users/{analyst_id}", headers=admin_headers, json={"is_active": False})
        assert (
            client.post(f"{API}/auth/token", data={"username": "analyst_user", "password": USER_PASSWORD}).status_code
            == 401
        )


def audit_actions_outcomes() -> list[str]:
    with session_scope() as db:
        return [e.outcome for e in db.scalars(select(AuditEvent))]


# =============================================================================
# Users & RBAC
# =============================================================================


class TestUsersAndRBAC:
    def test_user_management(self, client: TestClient, admin_headers) -> None:
        url = f"{API}/users"
        body = {"username": "bob", "email": "bob@corp.example", "password": USER_PASSWORD, "role": "auditor"}
        assert client.post(url, headers=admin_headers, json=body).status_code == 201
        assert client.post(url, headers=admin_headers, json=body).status_code == 409
        weak = {**body, "username": "carol", "password": "bobbobbobbob"}
        assert client.post(url, headers=admin_headers, json=weak).status_code == 422
        assert client.post(url, headers=admin_headers, json={**body, "username": "x y"}).status_code == 422
        assert client.post(url, headers=admin_headers, json={**body, "username": "d", "extra": 1}).status_code == 422
        assert client.patch(f"{url}/9999", headers=admin_headers, json={"role": "viewer"}).status_code == 404
        admin_id = next(u["id"] for u in client.get(url, headers=admin_headers).json() if u["username"] == "admin")
        assert client.patch(f"{url}/{admin_id}", headers=admin_headers, json={"role": "viewer"}).status_code == 409
        assert client.patch(f"{url}/{admin_id}", headers=admin_headers, json={"is_active": False}).status_code == 409

    @pytest.mark.parametrize(
        "role,method,path,allowed",
        [
            ("viewer", "get", "/findings", True),
            ("viewer", "post", "/compliance/evaluate", False),
            ("viewer", "post", "/reports", False),
            ("viewer", "get", "/users", False),
            ("viewer", "get", "/audit-trail", False),
            ("auditor", "get", "/audit-trail", True),
            ("auditor", "post", "/reports", True),
            ("auditor", "post", "/audits/host", False),
            ("analyst", "post", "/audits/host", True),
            ("analyst", "get", "/users", False),
            ("analyst", "post", "/admin/demo-data", False),
            ("analyst", "get", "/intel/stats", True),
            ("viewer", "get", "/intel/stats", False),
        ],
    )
    def test_permission_matrix(
        self, client: TestClient, make_user, role: str, method: str, path: str, allowed: bool
    ) -> None:
        headers = make_user(role)
        kwargs = {"json": {"report_type": "executive", "formats": ["json"]}} if path == "/reports" else {}
        status = getattr(client, method)(f"{API}{path}", headers=headers, **kwargs).status_code
        assert (status != 403) is allowed, status


# =============================================================================
# Scans, assets, findings
# =============================================================================


class TestScanning:
    def test_scope_violation_is_rejected_and_audited(self, client: TestClient, admin_headers) -> None:
        response = client.post(
            f"{API}/scans", headers=admin_headers, json={"targets": ["8.8.8.8"], "authorization_confirmed": True}
        )
        assert response.status_code == 422 and "outside the authorised scope" in response.json()["detail"]
        assert "scan.create" in audit_actions("denied")

    @pytest.mark.parametrize(
        "payload",
        [
            {"targets": ["10.0.0.1"], "authorization_confirmed": False},
            {"targets": ["10.0.0.1"]},
            {"targets": [], "authorization_confirmed": True},
            {"targets": ["10.0.0.1"], "authorization_confirmed": True, "profile": "insane"},
            {"targets": ["10.0.0.1"], "authorization_confirmed": True, "arguments": "-sS --script vuln"},
            {"targets": [" "], "authorization_confirmed": True},
        ],
    )
    def test_invalid_scan_requests(self, client: TestClient, admin_headers, payload) -> None:
        assert client.post(f"{API}/scans", headers=admin_headers, json=payload).status_code == 422

    def test_scan_lifecycle(self, client: TestClient, admin_headers, fake_nmap) -> None:
        response = client.post(
            f"{API}/scans",
            headers=admin_headers,
            json={"targets": ["10.0.0.0/29"], "profile": "standard", "authorization_confirmed": True},
        )
        assert response.status_code == 202
        scan = client.get(f"{API}/scans/{response.json()['id']}", headers=admin_headers).json()
        assert scan["status"] == "completed" and scan["summary"]["hosts_up"] == 2
        assert fake_nmap.calls[0][0] == "10.0.0.0/29"
        assets = client.get(f"{API}/assets", headers=admin_headers).json()
        assert assets["total"] == 2 and assets["items"][0]["risk_score"] > 0
        asset_id = assets["items"][0]["id"]
        assert client.get(f"{API}/assets/{asset_id}", headers=admin_headers).json()["services"]
        assert client.get(f"{API}/assets/9999", headers=admin_headers).status_code == 404
        assert client.get(f"{API}/assets?q=web&min_risk=1", headers=admin_headers).json()["total"] == 1
        listed = client.get(f"{API}/scans?scan_type=network&status=completed", headers=admin_headers).json()
        assert listed["total"] == 1
        assert client.get(f"{API}/scans/9999", headers=admin_headers).status_code == 404
        assert len(client.get(f"{API}/scans/profiles", headers=admin_headers).json()) == 4
        alerts = client.get(f"{API}/alerts", headers=admin_headers).json()
        assert any(a["trigger"] == "vulnerability_discovered" for a in alerts["items"])

    def test_failed_scan_is_recorded(self, client: TestClient, admin_headers, fake_nmap) -> None:
        import nmap

        fake_nmap.error = nmap.PortScannerError("nmap crashed")
        scan_id = client.post(
            f"{API}/scans", headers=admin_headers, json={"targets": ["10.0.0.1"], "authorization_confirmed": True}
        ).json()["id"]
        scan = client.get(f"{API}/scans/{scan_id}", headers=admin_headers).json()
        assert scan["status"] == "failed" and "nmap crashed" in scan["error"]

    def test_crashing_scan_job_never_stays_running(self, client: TestClient, admin_headers, monkeypatch) -> None:
        from app.services import operations

        def boom(*args, **kwargs):
            raise KeyError("unexpected")

        monkeypatch.setattr(operations, "execute_network_scan", boom)
        scan_id = client.post(
            f"{API}/scans", headers=admin_headers, json={"targets": ["10.0.0.1"], "authorization_confirmed": True}
        ).json()["id"]
        scan = client.get(f"{API}/scans/{scan_id}", headers=admin_headers).json()
        assert scan["status"] == "failed" and scan["error"] == "Internal error: KeyError"

    def test_findings_filter_and_triage(self, client: TestClient, admin_headers, fake_nmap) -> None:
        client.post(
            f"{API}/scans", headers=admin_headers, json={"targets": ["10.0.0.0/29"], "authorization_confirmed": True}
        )
        everything = client.get(f"{API}/findings", headers=admin_headers).json()
        assert everything["items"][0]["severity"] == "critical"
        crit = client.get(
            f"{API}/findings?severity=critical&source=vulnerability_analyzer", headers=admin_headers
        ).json()
        assert crit["total"] >= 1 and all(f["severity"] == "critical" for f in crit["items"])
        assert client.get(f"{API}/findings?asset=10.0.0.6&q=Telnet", headers=admin_headers).json()["total"] == 1
        target = crit["items"][0]
        patched = client.patch(
            f"{API}/findings/{target['id']}",
            headers=admin_headers,
            json={"status": "accepted_risk", "comment": "compensating control"},
        )
        assert patched.json()["status"] == "accepted_risk" and patched.json()["resolved_at"]
        assert client.get(f"{API}/findings/{target['id']}", headers=admin_headers).json()["status"] == "accepted_risk"
        reopened = client.patch(f"{API}/findings/{target['id']}", headers=admin_headers, json={"status": "open"})
        assert reopened.json()["resolved_at"] is None
        assert (
            client.patch(
                f"{API}/findings/{target['id']}", headers=admin_headers, json={"status": "deleted"}
            ).status_code
            == 422
        )
        assert client.get(f"{API}/findings/9999", headers=admin_headers).status_code == 404
        assert client.patch(f"{API}/findings/9999", headers=admin_headers, json={"status": "open"}).status_code == 404


# =============================================================================
# Audit, traffic, compliance, alerts, reports, intel, admin
# =============================================================================


class TestOperations:
    def test_host_audit(self, client: TestClient, admin_headers) -> None:
        assert client.get(f"{API}/audits/host/latest", headers=admin_headers).status_code == 404
        result = client.post(f"{API}/audits/host", headers=admin_headers).json()
        assert result["hostname"] == "web-prod-01" and result["score"] < 50 and result["scan_id"]
        latest = client.get(f"{API}/audits/host/latest", headers=admin_headers).json()
        assert latest["hostname"] == "web-prod-01"
        compliance = client.get(f"{API}/compliance/latest", headers=admin_headers).json()
        assert compliance["overall_score"] < 50  # re-evaluated automatically

    def test_pcap_upload(self, client: TestClient, admin_headers, tmp_path: Path) -> None:
        assert client.get(f"{API}/traffic/latest", headers=admin_headers).status_code == 404
        pcap = write_sample_pcap(tmp_path / "s.pcap").read_bytes()
        response = client.post(
            f"{API}/traffic/pcap",
            headers=admin_headers,
            files={"file": ("../../evil name.pcap", pcap, "application/octet-stream")},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["source"] == "upload:evil name.pcap" and body["summary"]["anomalies"]
        assert client.get(f"{API}/traffic/latest", headers=admin_headers).json()["id"] == body["id"]
        assert client.get(f"{API}/traffic/snapshots", headers=admin_headers).json()["total"] == 1
        assert client.get(f"{API}/traffic/snapshots/{body['id']}", headers=admin_headers).status_code == 200
        assert client.get(f"{API}/traffic/snapshots/999", headers=admin_headers).status_code == 404
        assert not list((tmp_path / "data" / "tmp").glob("*"))  # temp file removed

    @pytest.mark.parametrize(
        "content,status",
        [
            (b"MZ\x90\x00 not a pcap", 415),
            (b"", 400),
            (b"\xd4\xc3\xb2\xa1" + b"\x00" * 10, 422),
        ],
    )
    def test_pcap_upload_rejections(self, client: TestClient, admin_headers, content: bytes, status: int) -> None:
        response = client.post(f"{API}/traffic/pcap", headers=admin_headers, files={"file": ("x.pcap", content)})
        assert response.status_code == status

    def test_pcap_too_large(self, settings: Settings, tmp_path: Path) -> None:
        from app.main import create_app

        small = settings.model_copy(update={"max_upload_mb": 1})
        pcap = write_sample_pcap(tmp_path / "big.pcap").read_bytes()
        pcap += b"\x00" * (1024 * 1024)
        with TestClient(create_app(small)) as test_client:
            response = test_client.post(
                f"{API}/traffic/pcap", headers=login(test_client), files={"file": ("big.pcap", pcap)}
            )
        assert response.status_code == 413

    def test_compliance_endpoints(self, client: TestClient, admin_headers) -> None:
        assert client.get(f"{API}/compliance/latest", headers=admin_headers).status_code == 404
        report = client.post(f"{API}/compliance/evaluate", headers=admin_headers).json()
        assert len(report["frameworks"]) == 3
        assert (
            client.get(f"{API}/compliance/latest", headers=admin_headers).json()["overall_score"]
            == report["overall_score"]
        )
        history = client.get(f"{API}/compliance/history", headers=admin_headers).json()
        assert {row["framework"] for row in history} == {"CIS", "NIST_CSF", "ISO27001"}

    def test_alerts_ack(self, client: TestClient, admin_headers, make_user) -> None:
        client.post(f"{API}/audits/host", headers=admin_headers)
        open_alerts = client.get(f"{API}/alerts?acknowledged=false", headers=admin_headers).json()
        assert open_alerts["total"] > 0
        first = open_alerts["items"][0]
        assert client.get(f"{API}/alerts?severity=critical", headers=admin_headers).json()["total"] >= 1
        viewer = make_user("viewer")
        assert client.post(f"{API}/alerts/{first['id']}/ack", headers=viewer).status_code == 403
        acked = client.post(f"{API}/alerts/{first['id']}/ack", headers=admin_headers).json()
        assert acked["acknowledged"] and acked["acknowledged_by"] == "admin"
        assert client.post(f"{API}/alerts/{first['id']}/ack", headers=admin_headers).status_code == 200
        assert client.post(f"{API}/alerts/9999/ack", headers=admin_headers).status_code == 404
        assert client.get(f"{API}/alerts?severity=info", headers=admin_headers).status_code == 422

    def test_reports(self, client: TestClient, admin_headers, settings: Settings) -> None:
        client.post(f"{API}/audits/host", headers=admin_headers)
        created = client.post(
            f"{API}/reports",
            headers=admin_headers,
            json={"report_type": "technical", "formats": ["pdf", "html", "json"]},
        )
        assert created.status_code == 201 and len(created.json()) == 3
        listing = client.get(f"{API}/reports", headers=admin_headers).json()
        assert listing["total"] == 3
        pdf = next(r for r in created.json() if r["format"] == "pdf")
        download = client.get(f"{API}/reports/{pdf['id']}/download", headers=admin_headers)
        assert download.status_code == 200 and download.content.startswith(b"%PDF")
        assert download.headers["X-Content-SHA256"] == pdf["sha256"]
        assert client.get(f"{API}/reports/9999/download", headers=admin_headers).status_code == 404
        (settings.reports_dir / pdf["filename"]).unlink()
        assert client.get(f"{API}/reports/{pdf['id']}/download", headers=admin_headers).status_code == 410
        assert (
            client.post(
                f"{API}/reports", headers=admin_headers, json={"report_type": "weird", "formats": ["pdf"]}
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"{API}/reports", headers=admin_headers, json={"report_type": "executive", "formats": []}
            ).status_code
            == 422
        )

    def test_report_with_tampered_filename(self, client: TestClient, admin_headers) -> None:
        from app.database.models import ReportRecord

        with session_scope() as db:
            record = ReportRecord(
                report_type="x",
                format="pdf",
                filename="../../etc/passwd",
                sha256="0" * 64,
                size_bytes=1,
                created_by="mallory",
            )
            db.add(record)
            db.flush()
            record_id = record.id
        assert client.get(f"{API}/reports/{record_id}/download", headers=admin_headers).status_code == 400

    def test_intel(self, client: TestClient, admin_headers) -> None:
        stats = client.get(f"{API}/intel/stats", headers=admin_headers).json()
        assert stats["ips"] >= 2 and stats["feeds_configured"] == 0
        hit = client.get(f"{API}/intel/lookup?indicator=malware-c2.example", headers=admin_headers).json()
        assert hit["malicious"] is True
        assert client.get(f"{API}/intel/lookup?indicator=<script>", headers=admin_headers).status_code == 422
        assert client.post(f"{API}/intel/refresh", headers=admin_headers).status_code == 409

    def test_intel_refresh_with_feed(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.main import create_app
        from app.modules.threat_intelligence.intel import IOCDatabase

        monkeypatch.setattr(IOCDatabase, "refresh_from_feeds", lambda self, urls, cache: {urls[0]: 5})
        configured = settings.model_copy(update={"threat_feeds": "https://feeds.example/list.txt"})
        with TestClient(create_app(configured)) as test_client:
            result = test_client.post(f"{API}/intel/refresh", headers=login(test_client)).json()
        assert result == {"https://feeds.example/list.txt": 5}

    def test_audit_trail_endpoints(self, client: TestClient, admin_headers) -> None:
        client.post(f"{API}/compliance/evaluate", headers=admin_headers)
        events = client.get(f"{API}/audit-trail?actor=admin&action=compliance.evaluate", headers=admin_headers).json()
        assert events["total"] == 1 and len(events["items"][0]["hash"]) == 64
        assert client.get(f"{API}/audit-trail/verify", headers=admin_headers).json()["valid"] is True

    def test_dashboard_and_demo_admin(self, client: TestClient, admin_headers) -> None:
        empty = client.get(f"{API}/dashboard/overview", headers=admin_headers).json()
        assert empty["open_findings"] == 0 and empty["traffic"] is None
        assert client.get(f"{API}/admin/demo-data", headers=admin_headers).json() == {"present": False}
        seeded = client.post(f"{API}/admin/demo-data", headers=admin_headers).json()
        assert seeded["assets"] == 8 and seeded["open_findings"] > 30 and seeded["alerts"] > 10
        overview = client.get(f"{API}/dashboard/overview", headers=admin_headers).json()
        assert overview["traffic"]["health_score"] < 50 and len(overview["trend"]) == 14
        assert overview["trend"][0]["critical"] < overview["trend"][-1]["critical"]
        assert set(overview["compliance"]) == {"CIS", "NIST_CSF", "ISO27001"}
        purged = client.delete(f"{API}/admin/demo-data", headers=admin_headers).json()
        assert purged["assets"] == 8 and purged["findings"] > 30
        assert client.get(f"{API}/dashboard/overview", headers=admin_headers).json()["assets"] == 0
