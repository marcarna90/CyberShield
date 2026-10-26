# Examples

Everything in this folder was produced by the real pipelines replaying the **demo scenario** (fictional assets in
`10.10.0.0/24`, a deliberately weak Debian host, synthetic traffic using RFC 5737 addresses and `.example`
domains). Regenerate with `python scripts/generate_examples.py`.

## Files

| File | Produced by | Content |
|---|---|---|
| `executive_report.pdf` / `.html` / `.json` | reporting engine | 7-page management report |
| `technical_report.pdf` / `.html` / `.json` | reporting engine | every finding + host checks, asset inventory, traffic tables |
| `vulnerability_report.pdf` / `.html` / `.json` | reporting engine | CVE/exposure findings + asset inventory |
| `compliance_report.pdf` / `.html` / `.json` | reporting engine | framework scores, controls, gap analysis, risk matrix |
| `host_audit.json` | `system_auditor` | 25 checks with status, evidence, recommendation, references |
| `vulnerability_scan.json` | `network_scanner` + `vulnerability_analyzer` | scan summary, asset risk, recommendations |
| `vulnerability_findings.json` | `vulnerability_analyzer` | open CVE/exposure findings |
| `traffic_analysis.json` | `traffic_monitor` | protocol mix, talkers, DNS/HTTP/TLS stats, trends, anomalies |
| `compliance_evaluation.json` | `compliance_checker` | complete evaluation incl. per-control evidence |
| `alerts.json` | `alert_manager` | latest alerts and channels |
| `dashboard_overview.json` | `GET /dashboard/overview` | KPIs feeding the dashboard |
| `sample_traffic.pcap` | `synthetic.py` | 763-packet capture with C2 beacons, DGA, DNS tunnelling, port scan, legacy TLS |

## PDF report structure

Every report type shares one structure (sections are omitted when not relevant to the type):

```text
Page header: CYBERSHIELD ENTERPRISE SECURITY PLATFORM ................................ CONFIDENTIAL
1. Cover        title, organisation, generation time, author, scope
                KPI cards: risk score | posture | open findings | critical | high | assets | compliance | network health
2. Summary      narrative: counts, risk level, compliance statement, priority-1 gaps, network health
3. Severity matrix
                category x severity table (critical / high / medium / low / informational) with totals
                Risk matrix: 5x5 likelihood x impact heat map (executive, technical, compliance)
4. Compliance   (executive: P1 gaps only - compliance report: all gaps)
                framework table: score, passed, partial, failed, not assessed
                gap analysis per framework: priority, control, status, recommendation
5. Findings     one card per finding, most severe first:
                [SEVERITY] title
                identifier | CVSS | confidence - asset:port | category | source
                description - evidence - recommendation - references
6. Recommendations    de-duplicated, ordered by severity
7. Remediation priorities
                P1 Immediate (critical, 24-72 h) - P2 Urgent (high, 7 d) - P3 Planned (medium, 30 d) - P4 Routine (low, 90 d)
8. Annex tables (technical / vulnerability)
                asset inventory - host audit checks - traffic protocol mix - top talkers
Page footer: report title - organisation ..................................................... Page N
```

## JSON samples

Host audit check (`host_audit.json` → `checks[]`):

```json
{
  "check_id": "SSH-001",
  "title": "SSH root login is disabled",
  "category": "ssh",
  "status": "fail",
  "severity": "high",
  "evidence": "PermitRootLogin yes",
  "recommendation": "Set `PermitRootLogin no` in /etc/ssh/sshd_config and administer via named accounts + sudo.",
  "references": ["CIS Debian/Ubuntu Benchmark 5.1", "ISO 27001 A.8.5"]
}
```

Vulnerability finding (`vulnerability_findings.json`):

```json
{
  "finding_id": "CVE-2021-42013",
  "title": "Apache HTTP Server 2.4.49 affected by CVE-2021-42013",
  "severity": "critical",
  "category": "vulnerability",
  "source": "vulnerability_analyzer",
  "asset": "10.10.0.10",
  "description": "Incomplete fix for CVE-2021-41773: path traversal and remote code execution in Apache HTTP Server 2.4.49 and 2.4.50. A public exploit is available.",
  "evidence": "80/tcp banner 'Apache httpd 2.4.49 (Unix) OpenSSL/1.0.1f' matches affected range (versions 2.4.49, 2.4.50).",
  "recommendation": "Upgrade Apache HTTP Server to 2.4.51 or later.",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
  "cve": "CVE-2021-42013",
  "cvss": 9.8,
  "port": 80,
  "confidence": "high"
}
```

Traffic anomaly (`traffic_analysis.json` → `anomalies[]`):

```json
{
  "finding_id": "TRF-IOC-IP",
  "title": "Communication with known malicious IP 203.0.113.66",
  "severity": "critical",
  "category": "traffic",
  "source": "traffic_monitor",
  "asset": "10.10.0.13",
  "evidence": "10 packets / 1420 bytes exchanged with 203.0.113.66 (IOC 203.0.113.66, source cybershield-sample: Sample botnet command-and-control server)",
  "recommendation": "Isolate the host, block the indicator at the perimeter, and start incident response (collect volatile evidence before remediation)."
}
```

Dashboard overview (`dashboard_overview.json`, abridged):

```json
{
  "risk_score": 99.7,
  "posture_score": 0.3,
  "assets": 8,
  "open_findings": 57,
  "severity_counts": {"critical": 13, "high": 17, "medium": 16, "low": 11, "informational": 0},
  "compliance": {"CIS": 15.4, "NIST_CSF": 11.5, "ISO27001": 0.0},
  "traffic": {"health_score": 0.0, "packets": 43216, "source": "demo:sensor-eth0"}
}
```

> The demo environment is intentionally insecure, which is why its scores are so low. A hardened host scores
> 100/100 on the host audit (see `tests/conftest.py::HARDENED_FILES`).
