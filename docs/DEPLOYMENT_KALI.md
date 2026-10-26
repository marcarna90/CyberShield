# Deployment Guide - Kali Linux

Tested target: Kali Linux rolling (2025.x / 2026.x), amd64, bare metal or VM.

> **Authorised use only.** Configure `CYBERSHIELD_ALLOWED_TARGETS` to the networks you are permitted to assess.
> Every scan request (including refused ones) is written to the tamper-evident audit trail.

## 1. Prepare the system

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y git curl jq
```

## 2. Option A - Docker deployment (recommended)

### 2.1 Install Docker Engine and Compose v2

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"     # log out / in (or: newgrp docker)
docker --version
docker compose version || docker-compose version   # must report v2.x
```

If only Compose v1 is available, install the v2 plugin for your user:

```bash
mkdir -p ~/.docker/cli-plugins
curl -fsSL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 \
  -o ~/.docker/cli-plugins/docker-compose
chmod +x ~/.docker/cli-plugins/docker-compose
docker compose version
```

### 2.2 Deploy

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
docker compose up -d
docker compose ps                                              # all services "healthy"
docker compose exec api cat /run/cybershield-secrets/admin_password
```

> The repository is private: authenticate once before cloning, e.g. `sudo apt install -y gh && gh auth login`
> (then `gh repo clone marcarna90/CyberShield`), or paste a personal access token when `git` asks for a password.
> Details: [Installation guide](INSTALLATION.md#2-docker-compose-recommended).

Open <http://localhost:8501> and sign in as `admin`.

**Kali specifics**

* Kali's own PostgreSQL (used by Metasploit) listens on 5432. CyberShield's database is only published on
  `127.0.0.1:55432`, so both coexist.
* In a VM, use **bridged** networking if you want to scan or monitor the physical LAN; NAT only shows the VM's traffic.
* Passive sensor on your Wi-Fi or Ethernet interface:

  ```bash
  echo "CYBERSHIELD_SENSOR_INTERFACE=wlan0" >> .env    # or eth0
  docker compose --profile sensor up -d sensor
  docker compose logs -f sensor
  ```

### 2.3 Full-visibility host audit of the Kali host

```bash
docker compose run --rm --user 0:0 -e CYBERSHIELD_LOGS_DIR=/tmp api cli audit host
```

Results land in the dashboard (Vulnerabilities → source `system_auditor`) and drive the compliance scores.

## 3. Option B - Native deployment

Kali ships Python 3.12+ and nmap, which makes a native install quick:

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
./scripts/install.sh
source .venv/bin/activate
cat data/initial_admin_password
./scripts/start_native.sh
```

Typical operator workflow:

```bash
# 1. Harden-check this machine (root for shadow/sudoers/firewall)
sudo .venv/bin/cybershield audit host --pdf ~/kali-host-audit.pdf --fail-on critical

# 2. Inventory + CVE correlation of an authorised lab subnet
cybershield scan network 192.168.56.0/24 --profile standard --i-am-authorized

# 3. Passive traffic capture for 5 minutes
sudo .venv/bin/cybershield traffic capture --iface eth0 --duration 300

# 4. Compliance + reports
cybershield compliance evaluate
cybershield report generate --type executive --format pdf html
ls reports/
```

## 4. Schedule recurring audits

```bash
sudo crontab -e
# daily host audit at 06:00, weekly scan on Monday 07:00
0 6 * * *  /home/kali/CyberShield/scripts/run_audit.sh >> /var/log/cybershield-audit.log 2>&1
0 7 * * 1  cd /home/kali/CyberShield && .venv/bin/cybershield scan network 192.168.56.0/24 --i-am-authorized
```

## 5. Hardening checklist for Kali deployments

- [ ] Keep `CYBERSHIELD_API_BIND` / `CYBERSHIELD_DASHBOARD_BIND` on `127.0.0.1` unless behind a TLS reverse proxy.
- [ ] Change the generated admin password and create named `analyst` / `auditor` / `viewer` accounts.
- [ ] Restrict `CYBERSHIELD_ALLOWED_TARGETS` to the engagement scope.
- [ ] Configure SMTP for critical alerts.
- [ ] Run `./scripts/backup.sh` before upgrades; store the secrets archive encrypted.
- [ ] Review `GET /api/v1/audit-trail/verify` regularly (must return `"valid": true`).

## 6. Uninstall

```bash
cd ~/CyberShield
./scripts/uninstall.sh --dry-run     # preview
./scripts/uninstall.sh               # Docker and/or native, asks for confirmation (--keep-data to keep results)
cd .. && rm -rf CyberShield          # optional: delete the source code
```

Options and details: [Installation guide → Uninstall](INSTALLATION.md#6-uninstall).
