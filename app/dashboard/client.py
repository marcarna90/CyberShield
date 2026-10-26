"""Thin, typed HTTP client for the CyberShield API (used by the dashboard)."""

from __future__ import annotations

import os
from typing import Any

import httpx

DEFAULT_API_URL = os.getenv("CYBERSHIELD_API_URL", "http://localhost:8000")
API_PREFIX = os.getenv("CYBERSHIELD_API_PREFIX", "/api/v1")


class APIError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"{status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class CyberShieldClient:
    def __init__(
        self,
        base_url: str = DEFAULT_API_URL,
        token: str | None = None,
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") + API_PREFIX
        self.token = token
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)

    # ---------------------------------------------------------------- plumbing
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._http.request(method, path, headers=self._headers(), **kwargs)
        except httpx.HTTPError as exc:
            raise APIError(0, f"API unreachable at {self.base_url}: {exc}") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            if isinstance(detail, list):  # pydantic validation errors
                detail = "; ".join(str(d.get("msg", d)) for d in detail)
            raise APIError(response.status_code, str(detail))
        if response.status_code == 204:
            return None
        if "application/json" in response.headers.get("content-type", ""):
            return response.json()
        return response.content

    # ------------------------------------------------------------------- auth
    def login(self, username: str, password: str) -> dict[str, Any]:
        data = self._request("POST", "/auth/token", data={"username": username, "password": password})
        self.token = data["access_token"]
        return data

    def logout(self) -> None:
        self._request("POST", "/auth/logout")
        self.token = None

    def me(self) -> dict[str, Any]:
        return self._request("GET", "/auth/me")

    # ------------------------------------------------------------------- reads
    def overview(self) -> dict[str, Any]:
        return self._request("GET", "/dashboard/overview")

    def assets(self, limit: int = 500) -> list[dict[str, Any]]:
        return self._request("GET", "/assets", params={"limit": limit})["items"]

    def findings(self, **params: Any) -> list[dict[str, Any]]:
        params.setdefault("limit", 1000)
        return self._request("GET", "/findings", params=params)["items"]

    def scans(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._request("GET", "/scans", params={"limit": limit})["items"]

    def compliance_latest(self) -> dict[str, Any] | None:
        try:
            return self._request("GET", "/compliance/latest")
        except APIError as exc:
            if exc.status_code == 404:
                return None
            raise

    def compliance_history(self) -> list[dict[str, Any]]:
        return self._request("GET", "/compliance/history")

    def traffic_latest(self) -> dict[str, Any] | None:
        try:
            return self._request("GET", "/traffic/latest")
        except APIError as exc:
            if exc.status_code == 404:
                return None
            raise

    def traffic_snapshots(self) -> list[dict[str, Any]]:
        return self._request("GET", "/traffic/snapshots", params={"limit": 200})["items"]

    def alerts(self, **params: Any) -> list[dict[str, Any]]:
        params.setdefault("limit", 500)
        return self._request("GET", "/alerts", params=params)["items"]

    def reports(self) -> list[dict[str, Any]]:
        return self._request("GET", "/reports", params={"limit": 200})["items"]

    def download_report(self, report_id: int) -> bytes:
        return self._request("GET", f"/reports/{report_id}/download")

    def demo_status(self) -> bool:
        return bool(self._request("GET", "/admin/demo-data")["present"])

    # ------------------------------------------------------------------ writes
    def start_scan(self, targets: list[str], profile: str) -> dict[str, Any]:
        return self._request(
            "POST", "/scans", json={"targets": targets, "profile": profile, "authorization_confirmed": True}
        )

    def run_host_audit(self) -> dict[str, Any]:
        return self._request("POST", "/audits/host")

    def evaluate_compliance(self) -> dict[str, Any]:
        return self._request("POST", "/compliance/evaluate")

    def upload_pcap(self, filename: str, content: bytes) -> dict[str, Any]:
        return self._request(
            "POST", "/traffic/pcap", files={"file": (filename, content, "application/vnd.tcpdump.pcap")}
        )

    def update_finding(self, finding_pk: int, status: str, comment: str | None = None) -> dict[str, Any]:
        return self._request("PATCH", f"/findings/{finding_pk}", json={"status": status, "comment": comment})

    def ack_alert(self, alert_id: int) -> dict[str, Any]:
        return self._request("POST", f"/alerts/{alert_id}/ack")

    def generate_report(self, report_type: str, formats: list[str]) -> list[dict[str, Any]]:
        return self._request("POST", "/reports", json={"report_type": report_type, "formats": formats})

    def seed_demo(self) -> dict[str, Any]:
        return self._request("POST", "/admin/demo-data")

    def purge_demo(self) -> dict[str, Any]:
        return self._request("DELETE", "/admin/demo-data")
