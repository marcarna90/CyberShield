"""Dashboard: chart builders, API client, and a Streamlit smoke test against the real API."""

from __future__ import annotations

from pathlib import Path

import httpx
import plotly.graph_objects as go
import pytest

from app.dashboard import charts
from app.dashboard.client import APIError, CyberShieldClient

APP_FILE = Path(__file__).resolve().parents[1] / "app" / "dashboard" / "streamlit_app.py"


class TestCharts:
    def test_all_builders_return_figures(self) -> None:
        trend = [{"date": "2026-01-01", "critical": 1, "high": 2, "medium": 0, "low": 1}]
        history = [
            {"framework": "CIS", "score": 40.0, "created_at": "2026-01-01T00:00:00"},
            {"framework": "CIS", "score": 60.0, "created_at": "2026-01-02T00:00:00"},
            {"framework": "NIST", "score": 30.0, "created_at": "2026-01-02T00:00:00"},
        ]
        matrix = {
            "likelihood_labels": list("12345"),
            "impact_labels": list("abcde"),
            "cells": [[0, 0, 0, 0, 0], [0, 2, 0, 0, 0], [0, 0, 5, 0, 0], [0, 0, 0, 1, 0], [0, 0, 0, 0, 9]],
        }
        figures = [
            charts.risk_gauge(10),
            charts.risk_gauge(30),
            charts.risk_gauge(60),
            charts.risk_gauge(90),
            charts.severity_donut({"critical": 2, "low": 1}),
            charts.severity_bars({"high": 3}),
            charts.findings_trend(trend),
            charts.compliance_bars({"CIS": 55.0}),
            charts.compliance_trend(history),
            charts.protocol_bars({"TLS": 10, "DNS": 3}),
            charts.top_talkers(
                [{"ip": "10.0.0.1", "bytes": 10, "internal": True}, {"ip": "192.0.2.1", "bytes": 5, "internal": False}]
            ),
            charts.traffic_trend([{"ts": "2026-01-01T00:00:00", "bytes": 2048}]),
            charts.asset_risk([{"ip": "10.0.0.1", "hostname": "a.b", "risk_score": 50}]),
            charts.risk_matrix(matrix),
        ]
        assert all(isinstance(f, go.Figure) for f in figures)
        assert figures[0].data[0].gauge.bar.color == charts.STATUS["good"]
        assert figures[3].data[0].gauge.bar.color == charts.STATUS["critical"]
        donut = figures[4].data[0]
        assert list(donut.labels) == ["Critical", "Low"]  # severity order, empty slices dropped
        assert len(figures[6].data) == 4 and figures[6].layout.barmode == "stack"
        assert len(figures[8].data) == 2  # one line per framework
        assert len(figures[13].layout.annotations) == 4  # one label per non-empty cell

    def test_empty_states(self) -> None:
        for figure in (
            charts.severity_donut({}),
            charts.findings_trend([]),
            charts.compliance_bars({}),
            charts.compliance_trend([]),
            charts.traffic_trend([]),
            charts.risk_matrix(None),
            charts.horizontal_bars([], [], "x"),
        ):
            assert figure.layout.annotations[0].text


def mock_client(handler) -> CyberShieldClient:
    return CyberShieldClient("http://api.test", transport=httpx.MockTransport(handler))


class TestClient:
    def test_login_and_reads(self) -> None:
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append((request.method, request.url.path, request.headers.get("Authorization")))
            path = request.url.path
            if path.endswith("/auth/token"):
                return httpx.Response(200, json={"access_token": "tok", "role": "admin"})
            if path.endswith("/auth/logout"):
                return httpx.Response(204)
            if path.endswith("/compliance/latest") or path.endswith("/traffic/latest"):
                return httpx.Response(404, json={"detail": "none"})
            if path.endswith("/download"):
                return httpx.Response(200, content=b"%PDF", headers={"content-type": "application/pdf"})
            if path.endswith("/admin/demo-data") and request.method == "GET":
                return httpx.Response(200, json={"present": True})
            return httpx.Response(200, json={"items": [{"id": 1}], "total": 1, "ok": True})

        api = mock_client(handler)
        api.login("admin", "pw")
        assert api.token == "tok"
        assert api.findings(severity="critical") == [{"id": 1}]
        assert api.assets() == [{"id": 1}] and api.scans() == [{"id": 1}] and api.alerts() == [{"id": 1}]
        assert api.reports() == [{"id": 1}] and api.traffic_snapshots() == [{"id": 1}]
        assert api.compliance_latest() is None and api.traffic_latest() is None
        assert api.download_report(1) == b"%PDF" and api.demo_status() is True
        for call in (
            api.overview,
            api.me,
            api.compliance_history,
            api.run_host_audit,
            api.evaluate_compliance,
            api.seed_demo,
            api.purge_demo,
        ):
            call()
        api.start_scan(["10.0.0.1"], "quick")
        api.upload_pcap("x.pcap", b"\xd4\xc3\xb2\xa1")
        api.update_finding(1, "resolved", "ok")
        api.ack_alert(1)
        api.generate_report("executive", ["pdf"])
        api.logout()
        assert api.token is None
        assert seen[1][2] == "Bearer tok"

    def test_errors(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path.endswith("/findings"):
                return httpx.Response(422, json={"detail": [{"msg": "bad severity"}, {"other": 1}]})
            if path.endswith("/assets"):
                return httpx.Response(500, text="plain failure")
            if path.endswith("/compliance/latest"):
                return httpx.Response(403, json={"detail": "Insufficient permissions"})
            return httpx.Response(503, json={"detail": "down"})

        api = mock_client(handler)
        with pytest.raises(APIError, match="bad severity"):
            api.findings()
        with pytest.raises(APIError, match="plain failure"):
            api.assets()
        with pytest.raises(APIError) as error:
            api.compliance_latest()
        assert error.value.status_code == 403
        with pytest.raises(APIError):
            api.traffic_latest()

    def test_unreachable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        with pytest.raises(APIError, match="unreachable") as error:
            mock_client(handler).overview()
        assert error.value.status_code == 0


def test_streamlit_login_page_renders() -> None:
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(APP_FILE), default_timeout=60).run()
    assert not app.exception
    assert any("Sign in" in title.value for title in app.title)
    assert len(app.text_input) == 2
