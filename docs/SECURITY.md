# Security Model

CyberShield is a security tool, so its own security is a feature. This page maps the implementation to
**OWASP ASVS 4.0.3** and the **OWASP Top 10 (2021)**, lists the threat model and gives a production checklist.

## 1. Acceptable use

* Scanning is restricted to `CYBERSHIELD_ALLOWED_TARGETS` (private ranges by default), capped by
  `CYBERSHIELD_MAX_SCAN_HOSTS`, and requires an explicit `authorization_confirmed: true` / `--i-am-authorized`.
* Refused scans are recorded in the audit trail with outcome `denied`.
* The traffic monitor is passive: no injection, no ARP spoofing, no MITM, no TLS interception, no payload or
  credential storage (HTTP query strings and headers other than `Host` are discarded at parse time).
* Host checks are read-only; commands are a fixed list executed without a shell.

## 2. OWASP ASVS mapping (Level 2 focus)

| ASVS | Requirement | Implementation |
|---|---|---|
| V1.4 | Centralised access control | `require(Perm)` dependency on every protected route; role → permission table in `core/rbac.py` |
| V2.1.1 / 2.1.7 | Password length, breached/common passwords | ≥ 12 chars, complexity, username check, common-password list (`password_policy_violations`) |
| V2.2.1 | Anti-automation | per-IP login rate limit (10/min) + account lockout (5 failures → 15 min) |
| V2.4.1 | Password storage | Argon2id (`argon2-cffi`), transparent re-hash on login |
| V2.5.x | Credential recovery / initial secrets | admin password generated with `secrets`, stored `0400`/`0600`, never logged |
| V3.5.3 | Stateless token integrity | JWT HS256 pinned algorithm (no `none`), `exp`/`nbf`/`iat`/`iss`/`aud` validated |
| V3.3.1 | Logout invalidates session | `jti` revocation list; password/role change also invalidates |
| V4.1.3 | Least privilege | four roles; viewer read-only, analyst operational, auditor audit trail, admin management |
| V4.2.1 | IDOR protection | numeric IDs only reachable through authorised routes; report files resolved by DB record, never by path |
| V5.1.3 | Input validation | pydantic schemas with `extra=forbid`, regex/length/range constraints, enum profiles |
| V5.2.x | Sanitisation | targets validated as IP/CIDR/RFC 1123 hostname; shell metacharacters and `-` prefixes rejected |
| V5.3.3 | Output encoding (XSS) | Jinja2 `autoescape=True`; ReportLab text XML-escaped; tested with `<script>` payloads |
| V5.3.8 | OS command injection | `subprocess.run([...], shell=False)` with absolute executables; Nmap arguments are constants |
| V6.2.1 | Approved cryptography | Argon2id, SHA-256, HMAC-SHA256 (JWT), TLS-verified SMTP/feeds |
| V6.4.1 | Secret management | `*_FILE` variables, Docker secrets volume, no secrets in images, `.env` ignored by git |
| V7.1.1 | No sensitive data in logs | JSON log formatter redacts password/token/secret/cookie keys and bearer tokens |
| V7.2.x | Security events logged | login success/failure/lockout, every create/update/scan/report/download |
| V7.3.4 | Log integrity | hash-chained `audit_events` + `GET /audit-trail/verify` |
| V7.4.1 | Generic errors | global exception handler returns a request ID, never a stack trace |
| V8.3.x | Sensitive data protection | `Cache-Control: no-store` on API responses; reports carry a classification banner |
| V12.1.1 | Upload limits | Content-Length gate + streamed size cap + magic-byte check, temp files deleted |
| V12.3.1 | Path traversal | report filenames regex-validated and resolved inside the reports directory |
| V13.2.x | REST security | methods restricted via CORS allow-list, JSON only, strict schemas |
| V14.2.x | Dependencies | pinned versions, `pip-audit` in CI, Dependabot-ready |
| V14.4.x | HTTP security headers | CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP, HSTS on HTTPS |

## 3. OWASP Top 10 (2021)

| Risk | Mitigation |
|---|---|
| A01 Broken Access Control | deny-by-default RBAC, last-admin protection, role change revokes tokens, 401/403 test matrix |
| A02 Cryptographic Failures | Argon2id, strong random secrets, TLS-verified outbound connections |
| A03 Injection | ORM-only SQL, no shell, validated targets, escaped HTML/PDF output |
| A04 Insecure Design | scope guard, fixed scan profiles, passive monitoring, threat model below |
| A05 Security Misconfiguration | hardened containers, docs toggle, localhost binding, safe defaults |
| A06 Vulnerable Components | pinned requirements, pip-audit + bandit in CI, slim base image |
| A07 Identification & Authentication Failures | lockout, rate limit, generic errors, token revocation |
| A08 Software & Data Integrity | hash-chained audit trail, SHA-256 per report, HTTPS-only feeds with line validation |
| A09 Logging & Monitoring Failures | structured JSON logs, audit/alert streams, alerting channels |
| A10 SSRF | no user-supplied URLs fetched; feed URLs come from configuration and must be HTTPS |

## 4. Threat model (summary)

| Asset | Threat | Control |
|---|---|---|
| Scan capability | Abuse to attack third parties | allow-list, host cap, profiles, confirmation flag, audit trail |
| Findings / reports | Disclosure of weaknesses | RBAC, localhost binding, classification banner, no-store |
| Credentials | Brute force, theft from logs | rate limit, lockout, Argon2id, log redaction |
| Audit trail | Tampering to hide actions | hash chain, verification endpoint/CLI |
| Host | Container escape / privilege abuse | non-root, read-only FS, no capabilities, read-only host mounts |
| Sensor | Over-collection of personal data | metadata only, no payloads, query strings stripped |
| Supply chain | Malicious dependency/feed | pinned deps, pip-audit, feed size cap + strict parsing |

## 5. Production checklist

- [ ] TLS reverse proxy in front of 8000/8501; keep the published ports on `127.0.0.1`.
- [ ] Change the generated admin password; create named accounts per person.
- [ ] Limit `CYBERSHIELD_ALLOWED_TARGETS` to the authorised scope.
- [ ] Set `CYBERSHIELD_ENABLE_DOCS=false` if the API is reachable by untrusted users.
- [ ] Configure SMTP alerts and real threat feeds.
- [ ] Back up the database **and** the secrets volume; encrypt the archive.
- [ ] Forward `logs/*.log` (JSON) to your SIEM; verify the audit trail periodically.
- [ ] Import the NVD database and keep the image patched (`docker compose build --pull`).

## 6. Reporting a vulnerability in CyberShield

Please open a private security advisory on the repository (GitHub → Security → Report a vulnerability) rather than
a public issue. Include reproduction steps and the affected version. We aim to acknowledge within 72 hours.
