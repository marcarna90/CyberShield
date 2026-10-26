# Developer Guide

## 1. Environment

```bash
./scripts/install.sh --dev        # .venv with runtime + pytest, ruff, bandit, pip-audit
source .venv/bin/activate
make test                         # 300+ tests, coverage gate 90 % (currently ~99 %)
make lint security                # ruff + shellcheck, bandit + pip-audit
make run                          # API :8000 + dashboard :8501 with SQLite in ./data
```

Python 3.12 is required (PEP 695 generics, `StrEnum`). Formatting/linting: `ruff format` + `ruff check`
(line length 120, security rules `S` enabled).

## 2. Repository layout

```text
app/
├── api/            FastAPI routers (one file per resource), schemas, deps (auth/RBAC)
├── core/           config, security, rbac, scope, rate_limit, middleware, audit, logging, models, netutils
├── database/       SQLAlchemy models, session, repository, init_db
├── modules/        the eight security engines (no FastAPI imports)
├── services/       orchestration shared by API, CLI, sensor, demo
├── dashboard/      Streamlit app, API client, Plotly chart builders
├── cli.py          `cybershield` command
└── main.py         ASGI application factory
tests/              pytest suite (fixtures in conftest.py)
docker/             Dockerfile + entrypoint
scripts/            install / start / audit / backup / examples
docs/               guides, OpenAPI spec, examples, screenshots, diagrams
```

## 3. Conventions

* **Modules never import `app.api` or `app.database`.** They receive data and return pydantic models.
  Persistence, alerting and compliance re-evaluation happen in `app/services/operations.py`.
* **Every state-changing endpoint** depends on `require(Perm.X)` and calls `record_event(...)`.
* **Validation** lives in schemas (`extra="forbid"`, patterns, bounds). Never pass user input to a shell, a file
  path or Nmap arguments.
* **Findings** must include evidence and an actionable recommendation; use `Finding(...)` from `app.core.models`.
* **Time** is always `utcnow()` (timezone-aware).
* Secrets are read via settings properties (`*_value`) that support `*_FILE`.

## 4. Extending CyberShield

### 4.1 Add a host check

```python
# app/modules/system_auditor/checks.py
@check(
    "SYS-010",                                   # stable ID (used by compliance mapping)
    "Core dumps are restricted",
    "kernel",
    Severity.LOW,
    "Set `fs.suid_dumpable = 0` and `* hard core 0` in /etc/security/limits.conf.",
    ("CIS Debian/Ubuntu Benchmark 1.5.4",),
)
def check_core_dumps(ctx: AuditContext) -> Outcome:
    value = ctx.read("proc/sys/fs/suid_dumpable")
    if value is None:
        return CheckStatus.UNKNOWN, "fs.suid_dumpable not available under the audit root"
    return (CheckStatus.PASS, "fs.suid_dumpable = 0") if value.strip() == "0" else (
        CheckStatus.FAIL, f"fs.suid_dumpable = {value.strip()}")
```

Registration is automatic (decorator). Add a test with `write_tree()` fixtures and, if relevant, map the ID to
controls in `compliance_checker/data/controls.yaml`.

### 4.2 Map a compliance control

```yaml
- id: "A.8.7"
  framework: ISO27001
  title: "Protection against malware"
  checks: [NET-011, UPD-001]           # host check IDs and/or derived signals
  weight: 2
  recommendation: "Deploy endpoint protection and DNS filtering."
```

Derived signals (e.g. `VULN-001`, `NET-010`) are computed in `derive_signals()`.

### 4.3 Add CVE knowledge

* Bulk: `cybershield cve import <NVD API 2.0 JSON>`.
* Curated: add a record to `vulnerability_analyzer/data/cve_sample.json` and, if Nmap names the product
  differently, a line in `PRODUCT_MAP` / `VENDOR_ALIASES`.

### 4.4 Add an exposure rule

Append an `ExposureRule` to `EXPOSURE_RULES` in `vulnerability_analyzer/analyzer.py` (ports, service names,
severity, recommendation) and a parametrised case in `tests/test_scanning_and_vulns.py`.

### 4.5 Add a traffic detector

Extend `TrafficAnalyzer`: update counters in `ingest()` (bounded!) and emit findings from
`detect_anomalies()` with a `TRF-*` ID. Use `synthetic.py` to generate test traffic.

### 4.6 Add an alert channel

Implement `name` and `send(alert) -> bool` (see `channels.py`) and register a `ChannelRoute` in
`operations.build_alert_manager()`.

### 4.7 Add an API endpoint

```python
router = APIRouter(prefix="/things", tags=["things"])

@router.post("", status_code=201)
def create(request: Request, body: ThingIn, user: Annotated[User, Depends(require(Perm.X))], db: DbDep):
    ...
    record_event(db, actor=user.username, action="thing.create", ip=client_ip(request))
```

Register the router in `app/api/router.py`, add a permission in `core/rbac.py`, and tests for 401/403/422/2xx.

## 5. Testing

| File | Scope |
|---|---|
| `test_core.py` | config, security primitives, RBAC, scope guard, rate limiter, logging redaction, audit chain |
| `test_system_auditor.py` | parsers, all checks (weak/hardened fixtures), live mode with mocked commands |
| `test_scanning_and_vulns.py` | Nmap parsing, fake + real Nmap (integration), versions, CVE DB, NVD import, analyzer |
| `test_traffic_and_intel.py` | TLS/HTTP/DNS parsing, all detectors, PCAP round-trip, capture mocks, IOC feeds |
| `test_compliance_alerts_reports.py` | scoring, signals, risk matrix, alert routing/e-mail, all report formats, XSS escaping |
| `test_api.py` | every endpoint, RBAC matrix, lockout, rate limits, uploads, error masking |
| `test_cli_and_services.py` | every CLI command, sensor, demo, secrets, repository lifecycle |
| `test_dashboard.py` | chart builders, API client, Streamlit `AppTest` smoke test |

Useful fixtures (`tests/conftest.py`): `settings` (isolated temp dirs + SQLite), `client` (TestClient),
`admin_headers`, `make_user(role)`, `weak_root` / `hardened_root` (fake filesystems), `fake_nmap`.

```bash
pytest -k traffic -q                 # subset
pytest -m "not integration"          # skip tests needing the nmap binary
pytest --cov=app --cov-report=html   # reports/coverage/index.html
```

## 6. CI/CD

`.github/workflows/main.yml`: **lint** (ruff, shellcheck, compose validation) → **test** (pytest + coverage
artifact) and **security** (bandit, pip-audit, secret patterns) → **build** (sdist/wheel) and **docker**
(build image, start the real stack, smoke-test login/audit/scan/demo/reports/audit-trail, publish to GHCR on
`v*` tags).

## 7. Regenerating documentation assets

```bash
python scripts/generate_examples.py          # docs/examples (reports, JSON, sample PCAP)
curl -s localhost:8000/openapi.json > docs/openapi.json
```

## 8. Release checklist

1. `make lint test security` green.
2. Bump `__version__` (`app/__init__.py`), `pyproject.toml`, image tag in `docker-compose.yml`.
3. Regenerate examples and OpenAPI.
4. Tag `vX.Y.Z` → CI publishes `ghcr.io/<owner>/cybershield:X.Y.Z`.
