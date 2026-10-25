# Contributing

Thanks for helping improve CyberShield.

1. Read the [Developer Guide](docs/DEVELOPER_GUIDE.md) and the [Security Model](docs/SECURITY.md).
2. `./scripts/install.sh --dev && source .venv/bin/activate`
3. Create a branch, write tests first, then the code.
4. `make lint test security` must pass (coverage gate 90 %).
5. Open a pull request describing the change and its security impact.

Ground rules:

* **Defensive scope only.** Contributions that add exploitation, evasion, credential harvesting, traffic
  interception/injection or scanning outside the authorised scope will not be accepted.
* Every new endpoint needs an RBAC permission, input validation and an audit-trail event.
* Every new finding needs evidence, an actionable recommendation and, where possible, references.
* Never commit secrets, real customer data or real IOC lists with personal data; use RFC 5737 / `.example` data.
