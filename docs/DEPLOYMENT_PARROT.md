# Deployment Guide - Parrot OS

Tested target: Parrot OS 6.x (Security and Home editions), amd64. Parrot is Debian-based, so the Debian packages and
the `apt` workflow apply.

> **Authorised use only.** Set `CYBERSHIELD_ALLOWED_TARGETS` to the networks you are allowed to assess.

## 1. Prepare the system

```bash
sudo parrot-upgrade            # or: sudo apt update && sudo apt full-upgrade -y
sudo apt install -y git curl jq
```

**AnonSurf / Tor:** if AnonSurf is active, stop it (`sudo anonsurf stop`) before running scans or the sensor, so that
scan results and traffic statistics reflect the real network path rather than the Tor tunnel.

## 2. Option A - Docker deployment (recommended)

### 2.1 Docker Engine + Compose v2

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" && newgrp docker
docker compose version || docker-compose version    # must be v2.x
```

If the repository only provides Compose v1, install the v2 plugin:

```bash
mkdir -p ~/.docker/cli-plugins
curl -fsSL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 \
  -o ~/.docker/cli-plugins/docker-compose && chmod +x ~/.docker/cli-plugins/docker-compose
```

### 2.2 Deploy

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
docker compose up -d
docker compose ps
docker compose exec api cat /run/cybershield-secrets/admin_password
```

> Type the whole `git clone ...` line: pasting the URL alone gives `/bin/sh: https://...: not found`.
> No GitHub account is needed (public repository).

Dashboard: <http://localhost:8501> · API documentation: <http://localhost:8000/docs>.

**Parrot specifics**

* Parrot enables **AppArmor**. The CyberShield containers run with Docker's default AppArmor profile; no custom
  profile is required. The sensor only needs `NET_RAW`/`NET_ADMIN`.
* Parrot's firewall is permissive by default; the CyberShield host audit (`FW-001`) will flag it. Enable `ufw`
  (`sudo apt install ufw && sudo ufw default deny incoming && sudo ufw enable`) after allowing what you need.
* Passive sensor:

  ```bash
  echo "CYBERSHIELD_SENSOR_INTERFACE=eth0" >> .env
  docker compose --profile sensor up -d sensor
  ```

## 3. Option B - Native deployment

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
./scripts/install.sh
source .venv/bin/activate
cat data/initial_admin_password
./scripts/start_native.sh
```

Operator workflow:

```bash
sudo .venv/bin/cybershield audit host --pdf ~/parrot-host-audit.pdf --json ~/parrot-host-audit.json
cybershield scan network 10.0.2.0/24 --profile quick --i-am-authorized
cybershield traffic pcap ~/captures/session.pcapng            # analyse an existing Wireshark capture
cybershield report generate --type technical --format pdf html json
```

## 4. Systemd service (native, optional)

```ini
# /etc/systemd/system/cybershield-api.service
[Unit]
Description=CyberShield API
After=network-online.target

[Service]
User=cybershield
WorkingDirectory=/opt/CyberShield
ExecStart=/opt/CyberShield/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/CyberShield/data /opt/CyberShield/reports /opt/CyberShield/logs

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --home /opt/CyberShield --shell /usr/sbin/nologin cybershield
sudo chown -R cybershield: /opt/CyberShield/{data,reports,logs}
sudo systemctl daemon-reload && sudo systemctl enable --now cybershield-api
```

Create a matching `cybershield-dashboard.service` with
`ExecStart=/opt/CyberShield/.venv/bin/streamlit run app/dashboard/streamlit_app.py --server.address 127.0.0.1`.

## 5. Hardening checklist

- [ ] Ports bound to localhost, TLS reverse proxy for remote access.
- [ ] Generated admin password changed; named accounts per analyst (least privilege).
- [ ] Scope limited with `CYBERSHIELD_ALLOWED_TARGETS`.
- [ ] Threat feeds configured (`CYBERSHIELD_THREAT_FEEDS`) and refreshed (`cybershield intel refresh`).
- [ ] Backups scheduled (`./scripts/backup.sh`), audit trail verified.

## 6. Uninstall

```bash
cd /opt/CyberShield                       # or wherever you cloned it
./scripts/uninstall.sh --dry-run          # preview
sudo ./scripts/uninstall.sh               # sudo: data/ is owned by the cybershield service user
sudo userdel cybershield                  # only if you created the service user (section 4)
cd .. && sudo rm -rf CyberShield          # optional: delete the source code
```

Options and details: [Installation guide → Uninstall](INSTALLATION.md#6-uninstall).
