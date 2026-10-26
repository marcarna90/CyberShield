"""CyberShield SOC dashboard (Streamlit).

Run: ``streamlit run app/dashboard/streamlit_app.py`` (Docker: the ``dashboard`` service).
All data comes from the API with the logged-in user's token, so RBAC and the
audit trail apply to everything done here.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
# Streamlit puts the script directory first on sys.path; make sure the project
# root wins so `import app...` always resolves to the package.
sys.path[:] = [str(ROOT), *[p for p in sys.path if p != str(ROOT)]]

import pandas as pd
import streamlit as st

from app.dashboard import charts
from app.dashboard.client import DEFAULT_API_URL, APIError, CyberShieldClient

st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

SHORT_NAMES = {"CIS": "CIS v8", "NIST_CSF": "NIST CSF 2.0", "ISO27001": "ISO 27001:2022"}
PAGES = ["Overview", "Assets", "Vulnerabilities", "Compliance", "Traffic Monitoring", "Reports", "Alerts"]
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}
STATUS_ICON = {
    "pass": "✅ pass",  # UI label  # nosec B105
    "partial": "🟡 partial",
    "fail": "❌ fail",
    "not_assessed": "➖ n/a",
    "warn": "🟡 warn",
    "unknown": "❔ unknown",
    "not_applicable": "➖ n/a",
}

st.markdown(
    """
    <style>
      [data-testid="stMetric"] { background: #1a1a19; border: 1px solid rgba(255,255,255,0.08);
                                  border-radius: 10px; padding: 12px 14px; }
      [data-testid="stMetricLabel"] p { color: #c3c2b7; font-size: 0.8rem; text-transform: uppercase;
                                         letter-spacing: .04em; }
      .cs-brand { font-weight: 700; letter-spacing: .08em; color: #3987e5; font-size: .8rem; }
      .cs-muted { color: #898781; font-size: .85rem; }
      .block-container { padding-top: 2rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


# =============================================================================
# Session & data access
# =============================================================================


def client() -> CyberShieldClient:
    return CyberShieldClient(DEFAULT_API_URL, st.session_state.get("token"))


def can(permission: str) -> bool:
    return permission in st.session_state.get("me", {}).get("permissions", [])


@st.cache_data(ttl=20, show_spinner=False)
def fetch(name: str, token: str, **kwargs: Any) -> Any:
    """Cached API read keyed by endpoint, token and parameters."""
    return getattr(CyberShieldClient(DEFAULT_API_URL, token), name)(**kwargs)


def load(name: str, **kwargs: Any) -> Any:
    try:
        return fetch(name, st.session_state["token"], **kwargs)
    except APIError as exc:
        if exc.status_code == 401:
            st.session_state.clear()
            st.rerun()
        st.error(f"API error: {exc.detail}")
        st.stop()


def refresh() -> None:
    fetch.clear()


def run_action(label: str, fn, *args: Any, **kwargs: Any) -> Any:
    try:
        with st.spinner(label):
            result = fn(*args, **kwargs)
    except APIError as exc:
        st.error(exc.detail)
        return None
    refresh()
    return result


def sev_label(severity: str) -> str:
    return f"{SEVERITY_ICON.get(severity, '')} {severity}"


# =============================================================================
# Login
# =============================================================================


def login_page() -> None:
    _, center, _ = st.columns([1, 1.2, 1])
    with center:
        st.markdown("<div class='cs-brand'>CYBERSHIELD ENTERPRISE SECURITY PLATFORM</div>", unsafe_allow_html=True)
        st.title("🛡️ Sign in")
        st.caption("Defensive security operations: audit, detect, prevent, comply.")
        with st.form("login"):
            username = st.text_input("Username", max_chars=64)
            password = st.text_input("Password", type="password", max_chars=128)
            submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
        if submitted:
            api = CyberShieldClient(DEFAULT_API_URL)
            try:
                api.login(username, password)
                st.session_state["token"] = api.token
                st.session_state["me"] = api.me()
                st.rerun()
            except APIError as exc:
                st.error("Invalid credentials or account locked." if exc.status_code in (401, 429) else exc.detail)
        st.markdown(
            "<p class='cs-muted'>First run with Docker? Read the generated admin password with "
            "<code>docker compose exec api cat /run/cybershield-secrets/admin_password</code>.</p>",
            unsafe_allow_html=True,
        )


# =============================================================================
# Pages
# =============================================================================


def page_overview() -> None:
    data = load("overview")
    st.header("Security overview")
    if data["open_findings"] == 0 and data["assets"] == 0 and not data["compliance"]:
        st.info(
            "No data yet. Run a host audit or an authorised network scan from **Vulnerabilities**, "
            "or upload a PCAP in **Traffic Monitoring**."
        )
        if can("admin:manage") and st.button("Load demo dataset", type="primary"):
            result = run_action("Replaying 14-day demo scenario through the real pipelines...", client().seed_demo)
            if result:
                st.success(f"Demo loaded: {result}")
                st.rerun()
        return
    counts = data["severity_counts"]
    traffic = data.get("traffic") or {}
    compliance = data.get("compliance") or {}
    overall = sum(compliance.values()) / len(compliance) if compliance else None
    cols = st.columns(7)
    cols[0].metric("Risk (0-100)", f"{data['risk_score']:.0f}")
    cols[1].metric("Posture (0-100)", f"{data['posture_score']:.0f}")
    cols[2].metric("Assets", data["assets"])
    cols[3].metric("Open findings", data["open_findings"])
    cols[4].metric("Critical / High", f"{counts['critical']} / {counts['high']}")
    cols[5].metric("Compliance", f"{overall:.0f}%" if overall is not None else "-")
    cols[6].metric("Net health (0-100)", f"{traffic['health_score']:.0f}" if traffic else "-")

    left, mid, right = st.columns([1, 1, 1.3])
    left.plotly_chart(charts.risk_gauge(data["risk_score"]), width="stretch")
    mid.plotly_chart(charts.severity_donut(counts), width="stretch")
    right.plotly_chart(
        charts.compliance_bars({SHORT_NAMES.get(k, k): v for k, v in compliance.items()}), width="stretch"
    )
    left, right = st.columns([1.6, 1])
    left.plotly_chart(charts.findings_trend(data["trend"]), width="stretch")
    by_source = data.get("findings_by_source", {})
    right.plotly_chart(
        charts.horizontal_bars(
            [k.replace("_", " ") for k in by_source], list(by_source.values()), "Open findings by source", height=320
        ),
        width="stretch",
    )
    st.subheader("Recent activity")
    scans = pd.DataFrame(data["recent_scans"])
    if not scans.empty:
        scans["started_at"] = pd.to_datetime(scans["started_at"]).dt.strftime("%Y-%m-%d %H:%M")
        st.dataframe(
            scans[["id", "type", "status", "target", "requested_by", "started_at"]], hide_index=True, width="stretch"
        )


def page_assets() -> None:
    st.header("Assets")
    assets = load("assets")
    if not assets:
        st.info("No assets discovered yet - launch an authorised scan from **Vulnerabilities**.")
        return
    left, right = st.columns([1, 1.4])
    left.plotly_chart(charts.asset_risk(assets), width="stretch")
    table = pd.DataFrame(
        [
            {
                "IP": a["ip"],
                "Hostname": a.get("hostname") or "",
                "OS": a.get("os_guess") or "",
                "Risk": round(a["risk_score"], 1),
                "Open services": len(a["services"]),
                "Tags": ", ".join(a.get("tags") or []),
                "Last seen": a["last_seen"][:16].replace("T", " "),
            }
            for a in assets
        ]
    )
    right.dataframe(
        table,
        hide_index=True,
        width="stretch",
        height=380,
        column_config={"Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%.0f")},
    )
    st.subheader("Services")
    for asset in assets:
        with st.expander(f"{asset['ip']}  {asset.get('hostname') or ''}  -  risk {asset['risk_score']:.0f}"):
            services = pd.DataFrame(asset["services"])
            if services.empty:
                st.caption("No open services recorded.")
            else:
                st.dataframe(
                    services[["port", "protocol", "name", "product", "version", "extrainfo"]],
                    hide_index=True,
                    width="stretch",
                )


def _scan_panel() -> None:
    with st.expander("Launch an authorised scan or host audit", expanded=False):
        with st.form("scan"):
            targets = st.text_input("Targets (IP, CIDR or hostname; comma-separated)", placeholder="192.168.1.0/24")
            profile = st.selectbox("Profile", ["standard", "quick", "discovery", "full"])
            authorised = st.checkbox("I confirm I am authorised to scan these targets.")
            submitted = st.form_submit_button("Start scan", type="primary")
        if submitted:
            if not authorised:
                st.warning("Authorisation confirmation is required.")
            else:
                result = run_action(
                    "Queuing scan...",
                    client().start_scan,
                    [t.strip() for t in targets.split(",") if t.strip()],
                    profile,
                )
                if result:
                    st.success(f"Scan #{result['id']} queued - results appear when it completes.")
        if st.button("Run host audit now"):
            result = run_action("Auditing host configuration...", client().run_host_audit)
            if result:
                st.success(f"Host audit complete: hardening score {result['score']}/100 on {result['hostname']}.")


def page_vulnerabilities() -> None:
    st.header("Vulnerabilities & findings")
    if can("scan:run"):
        _scan_panel()
    findings = load("findings", status="open")
    f1, f2, f3, f4 = st.columns([1.3, 1, 1, 1.2])
    severities = f1.multiselect("Severity", charts.SEVERITY_ORDER, default=charts.SEVERITY_ORDER[:4])
    sources = sorted({f["source"] for f in findings})
    source = f2.selectbox("Source", ["all", *sources])
    assets = sorted({f["asset"] for f in findings})
    asset = f3.selectbox("Asset", ["all", *assets])
    query = f4.text_input("Search", placeholder="CVE, title...")
    rows = [
        f
        for f in findings
        if f["severity"] in severities
        and (source == "all" or f["source"] == source)
        and (asset == "all" or f["asset"] == asset)
        and (not query or query.lower() in (f["title"] + f["finding_id"]).lower())
    ]
    counts = {s: sum(1 for f in rows if f["severity"] == s) for s in charts.SEVERITY_ORDER}
    left, right = st.columns([1, 1.6])
    left.plotly_chart(charts.severity_bars(counts), width="stretch")
    cves = [f for f in rows if f.get("cvss") is not None]
    right.plotly_chart(
        charts.horizontal_bars(
            [f"{f['finding_id']} @ {f['asset']}" for f in cves[:12]],
            [f["cvss"] for f in cves[:12]],
            "Highest CVSS findings",
            ",.1f",
            height=320,
        ),
        width="stretch",
    )
    table = pd.DataFrame(
        [
            {
                "ID": f["id"],
                "Severity": sev_label(f["severity"]),
                "Finding": f["finding_id"],
                "Title": f["title"],
                "Asset": f["asset"],
                "Port": f.get("port"),
                "CVSS": f.get("cvss"),
                "Source": f["source"],
                "Confidence": f["confidence"],
                "First seen": f["first_seen"][:10],
            }
            for f in rows
        ]
    )
    st.caption(f"{len(rows)} open finding(s)")
    st.dataframe(table, hide_index=True, width="stretch", height=420)
    if rows:
        choice = st.selectbox("Finding details", [f"#{f['id']} {f['finding_id']} - {f['title']}" for f in rows])
        selected = rows[[f"#{f['id']} {f['finding_id']} - {f['title']}" for f in rows].index(choice)]
        with st.container(border=True):
            st.markdown(f"**{sev_label(selected['severity'])} - {selected['title']}**")
            st.markdown(
                f"**Asset:** `{selected['asset']}`  **Port:** {selected.get('port') or '-'}  "
                f"**CVSS:** {selected.get('cvss') or '-'}  **Confidence:** {selected['confidence']}"
            )
            if selected["description"]:
                st.markdown(f"**Description:** {selected['description']}")
            if selected["evidence"]:
                st.markdown("**Evidence**")
                st.code(selected["evidence"], language=None)
            st.markdown(f"**Recommendation:** {selected['recommendation']}")
            for ref in selected.get("references", [])[:5]:
                st.markdown(f"- {ref}")
            if can("findings:update"):
                c1, c2, c3 = st.columns([1, 2, 1])
                status = c1.selectbox("Set status", ["resolved", "accepted_risk", "false_positive", "open"])
                comment = c2.text_input("Comment", max_chars=500)
                apply = c3.button("Apply", type="primary")
                if apply and run_action(
                    "Updating...", client().update_finding, selected["id"], status, comment or None
                ):
                    st.success("Finding updated.")
                    st.rerun()


def page_compliance() -> None:
    st.header("Compliance")
    report = load("compliance_latest")
    if can("compliance:run") and st.button("Re-evaluate now"):
        run_action("Evaluating CIS / NIST CSF / ISO 27001...", client().evaluate_compliance)
        st.rerun()
    if not report:
        st.info("No compliance evaluation yet. Run a host audit or scan first.")
        return
    scores = {SHORT_NAMES.get(fw["framework"], fw["framework"]): fw["score"] for fw in report["frameworks"]}
    cols = st.columns(len(scores) + 1)
    cols[0].metric("Overall", f"{report['overall_score']:.0f}%")
    for col, (name, score) in zip(cols[1:], scores.items(), strict=True):
        col.metric(name, f"{score:.0f}%")
    st.info(report["executive_summary"])
    left, right = st.columns(2)
    left.plotly_chart(charts.compliance_bars(scores), width="stretch")
    history = [
        {**row, "framework": SHORT_NAMES.get(row["framework"], row["framework"])} for row in load("compliance_history")
    ]
    right.plotly_chart(charts.compliance_trend(history), width="stretch")
    left, right = st.columns([1, 1])
    left.plotly_chart(charts.risk_matrix(report.get("risk_matrix")), width="stretch")
    with right:
        st.subheader("Top risks")
        top = pd.DataFrame(report.get("risk_matrix", {}).get("top_risks", []))
        if not top.empty:
            st.dataframe(top[["score", "finding_id", "title", "asset"]], hide_index=True, width="stretch", height=300)
    tabs = st.tabs([SHORT_NAMES.get(fw["framework"], fw["name"]) for fw in report["frameworks"]])
    for tab, fw in zip(tabs, report["frameworks"], strict=True):
        with tab:
            st.markdown(
                f"**Score {fw['score']:.0f}%** - {fw['passed']} passed, {fw['partial']} partial, "
                f"{fw['failed']} failed, {fw['not_assessed']} not assessed"
            )
            controls = pd.DataFrame(
                [
                    {
                        "Control": c["control_id"],
                        "Title": c["title"],
                        "Status": STATUS_ICON[c["status"]],
                        "Weight": c["weight"],
                        "Evidence": ", ".join(f"{k}:{v}" for k, v in c["evidence"].items()),
                    }
                    for c in fw["controls"]
                ]
            )
            st.dataframe(controls, hide_index=True, width="stretch")
            if fw["gaps"]:
                st.markdown("**Gap analysis**")
                st.dataframe(
                    pd.DataFrame(fw["gaps"])[["priority", "control_id", "title", "status", "recommendation"]],
                    hide_index=True,
                    width="stretch",
                )
    if report.get("recommendations"):
        st.subheader("Recommendations")
        for index, rec in enumerate(report["recommendations"], start=1):
            st.markdown(f"{index}. {rec}")


def page_traffic() -> None:
    st.header("Traffic monitoring")
    st.caption(
        "Passive analysis only: metadata (addresses, ports, DNS names, HTTP host/path, TLS SNI/version). "
        "No payloads, cookies or credentials are stored."
    )
    if can("traffic:run"):
        with st.expander("Analyse a capture file (PCAP / PCAPNG)"):
            upload = st.file_uploader("Capture file", type=["pcap", "pcapng", "cap"])
            if upload is not None and st.button("Analyse", type="primary"):
                result = run_action("Analysing capture...", client().upload_pcap, upload.name, upload.getvalue())
                if result:
                    st.success(f"Analysed {result['packets']} packets - health {result['health_score']:.0f}/100.")
                    st.rerun()
    snapshot = load("traffic_latest")
    if not snapshot:
        st.info(
            "No traffic analysed yet. Upload a PCAP above or enable the sensor "
            "(`docker compose --profile sensor up -d`)."
        )
        return
    summary = snapshot["summary"]
    cols = st.columns(5)
    cols[0].metric("Health score", f"{summary['health_score']:.0f}/100")
    cols[1].metric("Packets", f"{summary['total_packets']:,}")
    cols[2].metric("Volume", f"{summary['total_bytes'] / 1_048_576:,.1f} MB")
    cols[3].metric("Anomalies", len(summary["anomalies"]))
    cols[4].metric("DNS queries", summary["dns"]["queries"])
    st.caption(f"Source: {snapshot['source']} - captured {snapshot['created_at'][:16].replace('T', ' ')} UTC")
    st.plotly_chart(charts.traffic_trend(summary["trends"]), width="stretch")
    left, right = st.columns(2)
    left.plotly_chart(charts.protocol_bars(summary["protocols"]), width="stretch")
    right.plotly_chart(charts.top_talkers(summary["top_talkers"]), width="stretch")
    st.subheader("Anomalies")
    anomalies = pd.DataFrame(
        [
            {
                "Severity": sev_label(a["severity"]),
                "Detection": a["finding_id"],
                "Title": a["title"],
                "Host": a["asset"],
                "Evidence": a["evidence"],
            }
            for a in summary["anomalies"]
        ]
    )
    if anomalies.empty:
        st.success("No anomalies detected in the latest capture.")
    else:
        st.dataframe(anomalies, hide_index=True, width="stretch")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Top DNS domains**")
        st.dataframe(pd.DataFrame(summary["dns"]["top_domains"]), hide_index=True, width="stretch")
    with c2:
        st.markdown("**TLS versions / SNI**")
        st.dataframe(
            pd.DataFrame([{"version": k, "handshakes": v} for k, v in summary["tls"]["versions"].items()]),
            hide_index=True,
            width="stretch",
        )
        st.dataframe(pd.DataFrame(summary["tls"]["top_sni"]), hide_index=True, width="stretch")
    with c3:
        st.markdown("**HTTP hosts (cleartext)**")
        st.dataframe(pd.DataFrame(summary["http"]["top_hosts"]), hide_index=True, width="stretch")
    history = pd.DataFrame(load("traffic_snapshots"))
    if len(history) > 1:
        st.subheader("Capture history")
        st.dataframe(history, hide_index=True, width="stretch")


def page_reports() -> None:
    st.header("Reports")
    if can("report:generate"):
        with st.form("report"):
            c1, c2 = st.columns(2)
            report_type = c1.selectbox("Report type", ["executive", "technical", "vulnerability", "compliance"])
            formats = c2.multiselect("Formats", ["pdf", "html", "json"], default=["pdf", "html"])
            submitted = st.form_submit_button("Generate", type="primary")
        if submitted and formats:
            result = run_action("Generating report...", client().generate_report, report_type, formats)
            if result:
                st.success(f"Generated {len(result)} file(s).")
    reports = load("reports")
    if not reports:
        st.info("No reports generated yet.")
        return
    for report in reports[:50]:
        c1, c2, c3, c4 = st.columns([2.5, 1, 1.4, 1])
        c1.markdown(f"**{report['report_type'].capitalize()}** - `{report['filename']}`")
        c2.markdown(f"{report['size_bytes'] / 1024:,.0f} KB")
        c3.markdown(f"{report['created_at'][:16].replace('T', ' ')} by {report['created_by']}")
        if c4.button("Prepare download", key=f"dl-{report['id']}"):
            content = run_action("Fetching...", client().download_report, report["id"])
            if content is not None:
                mime = {"pdf": "application/pdf", "html": "text/html", "json": "application/json"}[report["format"]]
                st.download_button(
                    f"Save {report['format'].upper()}",
                    content,
                    file_name=report["filename"],
                    mime=mime,
                    key=f"save-{report['id']}",
                )


def page_alerts() -> None:
    st.header("Alerts")
    c1, c2 = st.columns([1, 3])
    show = c1.radio("Show", ["Open", "Acknowledged", "All"], horizontal=True)
    params: dict[str, Any] = {}
    if show != "All":
        params["acknowledged"] = show == "Acknowledged"
    alerts = load("alerts", **params)
    if not alerts:
        st.success("No alerts in this view.")
        return
    counts = {s: sum(1 for a in alerts if a["severity"] == s) for s in charts.SEVERITY_ORDER}
    c2.plotly_chart(charts.severity_bars(counts, "Alerts by severity"), width="stretch")
    table = pd.DataFrame(
        [
            {
                "ID": a["id"],
                "Time": a["created_at"][:16].replace("T", " "),
                "Severity": sev_label(a["severity"]),
                "Trigger": a["trigger"],
                "Title": a["title"],
                "Asset": a.get("asset") or "",
                "Channels": ", ".join(a["channels"]),
                "Ack": "yes" if a["acknowledged"] else "no",
            }
            for a in alerts
        ]
    )
    st.dataframe(table, hide_index=True, width="stretch", height=420)
    if can("alert:ack"):
        pending = [a for a in alerts if not a["acknowledged"]]
        if pending:
            ids = st.multiselect("Acknowledge alerts", [a["id"] for a in pending])
            if ids and st.button("Acknowledge selected", type="primary"):
                for alert_id in ids:
                    run_action("Acknowledging...", client().ack_alert, alert_id)
                st.rerun()


# =============================================================================
# Shell
# =============================================================================


def main() -> None:
    if "token" not in st.session_state:
        login_page()
        return
    me = st.session_state["me"]
    with st.sidebar:
        st.markdown("<div class='cs-brand'>CYBERSHIELD</div>", unsafe_allow_html=True)
        st.markdown(f"**{me['username']}** · `{me['role']}`")
        page = st.radio("Navigation", PAGES, label_visibility="collapsed")
        st.divider()
        if st.button("Refresh data", width="stretch"):
            refresh()
            st.rerun()
        if can("admin:manage"):
            with st.expander("Demo dataset"):
                st.caption("Fictional, flagged data replayed through the real pipelines.")
                if st.button("Load demo data", width="stretch"):
                    run_action("Seeding...", client().seed_demo)
                    st.rerun()
                if st.button("Purge demo data", width="stretch"):
                    run_action("Purging...", client().purge_demo)
                    st.rerun()
        if st.button("Sign out", width="stretch"):
            with contextlib.suppress(APIError):
                client().logout()
            st.session_state.clear()
            refresh()
            st.rerun()
        st.caption("Authorised defensive use only.")
    {
        "Overview": page_overview,
        "Assets": page_assets,
        "Vulnerabilities": page_vulnerabilities,
        "Compliance": page_compliance,
        "Traffic Monitoring": page_traffic,
        "Reports": page_reports,
        "Alerts": page_alerts,
    }[page]()


main()
