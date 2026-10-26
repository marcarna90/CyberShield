# CyberShield Enterprise Security Platform

![Python](https://img.shields.io/badge/python-3.12-blue) ![FastAPI](https://img.shields.io/badge/API-FastAPI-009688)
![Tests](https://img.shields.io/badge/tests-300%2B%20passing-brightgreen) ![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Open-source **defensive** security automation for SOC and DevSecOps teams: host configuration auditing, authorised
network discovery with CVE correlation, passive traffic analysis, threat-intelligence matching, compliance scoring
(CIS v8, NIST CSF 2.0, ISO/IEC 27001:2022), alerting and executive/technical reporting, behind a hardened API and
a Streamlit dashboard.

```bash
git clone https://github.com/marcarna90/CyberShield.git && cd CyberShield
docker compose up -d
docker compose exec api cat /run/cybershield-secrets/admin_password   # then open http://localhost:8501
```

Uninstall: `./scripts/uninstall.sh` ([details](docs/INSTALLATION.md#6-uninstall)).

![Dashboard overview](docs/screenshots/01_overview.png)

> **Authorised use only.** CyberShield refuses to scan outside `CYBERSHIELD_ALLOWED_TARGETS` (private ranges by
> default), never intercepts or modifies traffic, and records every action in a tamper-evident audit trail.

---

## Features

| Module | What it does |
|---|---|
| **Host Security Auditor** | 25 read-only checks: firewall (ufw/firewalld/nftables/iptables), UID 0 & empty-password accounts, system shells, sessions, risky listeners, password ageing/hashing/complexity, sudo (NOPASSWD, use_pty, logfile), 8 SSH hardening checks, critical file permissions, ASLR, IP forwarding, auto-updates, auditd. JSON + PDF output, CI gate (`--fail-on`). |
| **Network Scanner** | Nmap wrapper with fixed safe profiles (`discovery`, `quick`, `standard`, `full`), allow-list scope guard, host cap, option-injection protection. |
| **Vulnerability Analyzer** | Service/CPE identification, tolerant version matching, offline CVE knowledge base + **NVD JSON 2.0 import**, exposure rules (Telnet, FTP, Docker API, Redis, databases, RDP, VNC, SMB...), 5-level severity, patching / hardening / best-practice recommendations, back-port aware confidence. |
| **Network Traffic Analyzer** | Passive capture (sensor or PCAP upload): protocol categorisation, statistics, top talkers, DNS / HTTP / TLS (SNI, version) metadata, trends, **11 detectors**: IOC IP/domain, port scan, large outbound transfer, traffic spike, DGA, DNS tunnelling, NXDOMAIN storms, legacy TLS, cleartext HTTP, backdoor ports. Network health score. No payloads, no MITM, no credential capture. |
| **Threat Intelligence** | IOC database (IP, CIDR, domain with parent matching), validated HTTPS feed refresh, reputation lookups. |
| **Compliance Checker** | 33 mapped controls across CIS Controls v8, NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A; weighted scoring, gap analysis with P1-P3 priorities, 5×5 risk matrix, executive summary. |
| **Reporting Engine** | Executive, technical, vulnerability and compliance reports in **PDF, HTML and JSON** with summary, findings, severity matrix, recommendations and remediation priorities; SHA-256 per file. |
| **Alert System** | Critical / high / medium / low alerts to **log, e-mail (STARTTLS) and dashboard**; triggers for unsafe configuration, vulnerabilities, traffic spikes/anomalies, threat-intel matches and compliance failures; de-duplication with cooldown. |
| **Dashboard** | Overview, Assets, Vulnerabilities, Compliance, Traffic Monitoring, Reports, Alerts: risk gauge, pie/donut, trends, severity distribution, compliance scores, risk matrix. |
| **Platform security** | JWT + Argon2id, RBAC (admin / analyst / auditor / viewer), rate limiting, lockout, strict validation, security headers, secrets via files, hash-chained audit trail, hardened containers. Mapped to OWASP ASVS & Top 10. |

## Quick start

### Docker (recommended)

```bash
docker compose up -d                                   # api + dashboard + PostgreSQL (+ secret generation)
docker compose exec api cat /run/cybershield-secrets/admin_password
docker compose --profile sensor up -d sensor           # optional passive network sensor
```

* Dashboard: <http://localhost:8501> · API docs: <http://localhost:8000/docs>
* Load the demo dataset from the dashboard sidebar to explore every screen.
* Settings: `cp .env.example .env` (all optional).

### Native (Kali / Parrot / Ubuntu / Debian)

```bash
./scripts/install.sh && source .venv/bin/activate
sudo .venv/bin/cybershield audit host --pdf host-audit.pdf --json host-audit.json
cybershield scan network 192.168.1.0/24 --profile standard --i-am-authorized
sudo .venv/bin/cybershield traffic capture --iface eth0 --duration 120
cybershield report generate --type executive --format pdf html json
./scripts/start_native.sh                              # API :8000 + dashboard :8501
```

Full walkthrough: **[Step-by-step execution](docs/QUICKSTART.md)**.

## Documentation

| Guide | |
|---|---|
| [Installation](docs/INSTALLATION.md) | Docker & native install, configuration, upgrade, backup, troubleshooting, uninstall |
| [Kali Linux deployment](docs/DEPLOYMENT_KALI.md) · [Parrot OS deployment](docs/DEPLOYMENT_PARROT.md) | distribution-specific steps |
| [Step-by-step execution](docs/QUICKSTART.md) | from `git clone` to an executive PDF in 10 steps |
| [User guide](docs/USER_GUIDE.md) | roles, dashboard tour, workflows, scores, CLI reference |
| [API documentation](docs/API.md) · [OpenAPI spec](docs/openapi.json) | endpoints, permissions, examples |
| [Architecture](docs/ARCHITECTURE.md) | components, flows, data model, deployment topology |
| [Developer guide](docs/DEVELOPER_GUIDE.md) | extending checks, controls, detectors, endpoints; testing; CI |
| [Security model](docs/SECURITY.md) | OWASP ASVS / Top 10 mapping, threat model, production checklist |
| [Examples](docs/examples/README.md) | real PDF/HTML/JSON reports, module JSON outputs, sample PCAP, PDF structure |

## Architecture

![Architecture](docs/images/architecture.png)

## Repository layout

```text
CyberShield/
├── app/
│   ├── api/                 FastAPI routers (15), schemas, auth/RBAC dependencies
│   ├── core/                config, security, RBAC, scope guard, rate limit, middleware, audit trail, logging
│   ├── database/            SQLAlchemy models, session, repository, bootstrap
│   ├── modules/
│   │   ├── system_auditor/          host checks + scoring
│   │   ├── network_scanner/         Nmap wrapper + scope enforcement
│   │   ├── vulnerability_analyzer/  CVE DB, NVD import, version matching, exposure rules
│   │   ├── traffic_monitor/         passive parsing, analytics, detectors, capture, synthetic data
│   │   ├── threat_intelligence/     IOC database and feeds
│   │   ├── compliance_checker/      controls.yaml (CIS / NIST / ISO) + scoring
│   │   ├── alert_manager/           routing, de-duplication, log/e-mail/dashboard channels
│   │   └── reporting_engine/        report builders, PDF (ReportLab), HTML (Jinja2), JSON
│   ├── services/            orchestration, sensor loop, demo dataset, secret generation
│   ├── dashboard/           Streamlit app, API client, Plotly charts
│   ├── cli.py               `cybershield` command
│   └── main.py              ASGI app factory
├── tests/                   300+ pytest tests (unit, integration, API, CLI, dashboard)
├── docker/                  Dockerfile (multi-stage, non-root) + entrypoint
├── docs/                    guides, OpenAPI, examples, screenshots, architecture diagram
├── scripts/                 install, uninstall, start, scheduled audit, backup, example generation
├── reports/  logs/          runtime output (git-ignored)
├── .github/workflows/main.yml   lint → tests → security → build → docker smoke test
├── docker-compose.yml       init · db · api · dashboard · sensor (profile)
├── requirements.txt         pinned runtime dependencies
├── pyproject.toml           packaging, ruff, pytest, coverage (≥ 90 %), bandit
└── LICENSE                  MIT + acceptable-use notice
```

## Quality gates

| Gate | Result at release |
|---|---|
| Tests | 300+ passed (positive, negative, edge cases, mocks, real Nmap integration) |
| Coverage | ~99 % of `app/` (gate: 90 %) |
| Lint | ruff (incl. security rules) clean, shellcheck clean |
| SAST | bandit: no findings |
| Dependencies | pip-audit: no known vulnerabilities |
| Deployment | `docker compose up -d` → all services healthy; login, host audit, Nmap scan, PCAP analysis, sensor, reports and audit-trail verification exercised end-to-end |

## Contributing & security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Use only on systems and networks you own or are explicitly authorised to assess.
