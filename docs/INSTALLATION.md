# Installation Guide

CyberShield runs in two ways:

| Mode | Best for | Database | What you get |
|---|---|---|---|
| **Docker Compose** (recommended) | servers, SOC workstations, quick evaluation | PostgreSQL 16 | API + dashboard + DB, secrets generated automatically, optional sensor |
| **Native** (Python venv) | Kali / Parrot laptops, host audits as root, CI jobs | SQLite (or PostgreSQL) | CLI + API + dashboard on the host |

Distribution-specific walkthroughs: [Kali Linux](DEPLOYMENT_KALI.md) · [Parrot OS](DEPLOYMENT_PARROT.md).

---

## 1. Requirements

| | Minimum | Recommended |
|---|---|---|
| CPU / RAM | 2 vCPU / 2 GB | 4 vCPU / 4 GB |
| Disk | 3 GB (image + database) | 10 GB |
| OS | Kali Linux (rolling), Parrot OS 6+, Ubuntu 24.04+, Debian 12+ | same, 64-bit |
| Docker mode | Docker Engine 24+ with **Compose v2** (`docker compose version` ≥ 2.20) | latest stable |
| Native mode | Python **3.12+**, `nmap`, `libpcap` | + `sudo` for complete host audits |

> Compose v1 (`docker-compose` 1.x, written in Python) is end-of-life and does not support this file.
> Both `docker compose ...` (plugin) and the standalone `docker-compose` **v2** binary work.

---

## 2. Docker Compose (recommended)

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
docker compose up -d            # or: docker-compose up -d (v2)
```

> The repository is public: no GitHub account or token is needed. Type the whole command, `git clone` included
> (install Git first if necessary: `sudo apt install -y git`).
>
> Without Git: download <https://github.com/marcarna90/CyberShield/archive/refs/heads/main.zip>, then
> `unzip main.zip && cd CyberShield-main`.

The first start builds the image locally (2-5 minutes), then:

1. `init` generates the JWT signing key, the PostgreSQL password and a strong admin password into the
   `cybershield-secrets` volume (only on the first run; never overwritten).
2. `db` (PostgreSQL 16) starts and becomes healthy.
3. `api` creates the schema and the `admin` account, then serves on **127.0.0.1:8000**.
4. `dashboard` serves on **127.0.0.1:8501**.

Check that everything is healthy:

```bash
docker compose ps
```

Read the generated administrator password and sign in at <http://localhost:8501>:

```bash
docker compose exec api cat /run/cybershield-secrets/admin_password
```

Change it immediately (dashboard → API or `POST /api/v1/auth/change-password`), then optionally load the demo
dataset from the sidebar (**Demo dataset → Load demo data**) to explore every screen.

### Optional: passive network sensor

```bash
docker compose --profile sensor up -d sensor
```

The sensor joins the **host network** with only `NET_RAW`/`NET_ADMIN` capabilities and sniffs read-only.
Choose the interface with `CYBERSHIELD_SENSOR_INTERFACE=eth0` in `.env`.

### Configuration

Every setting has a safe default. To change one, copy the template and edit it:

```bash
cp .env.example .env
nano .env
docker compose up -d   # re-creates only what changed
```

Most useful settings:

| Variable | Default | Purpose |
|---|---|---|
| `CYBERSHIELD_ALLOWED_TARGETS` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8` | **Authorised scan scope.** Anything outside is refused and audited. |
| `CYBERSHIELD_ORGANIZATION` | `My Organization` | Name printed on reports |
| `CYBERSHIELD_API_BIND` / `_DASHBOARD_BIND` | `127.0.0.1` | Interface the ports are published on |
| `CYBERSHIELD_API_PORT` / `_DASHBOARD_PORT` | `8000` / `8501` | Published ports |
| `CYBERSHIELD_SMTP_HOST`, `..._ALERT_EMAIL_TO` | empty | Enables e-mail alerts |
| `CYBERSHIELD_THREAT_FEEDS` | empty | HTTPS IOC feeds (one indicator per line) |
| `CYBERSHIELD_SEED_DEMO` | `false` | Load the demo dataset at first start |

The complete list with comments is in [`.env.example`](../.env.example).

### Exposing the platform on the network

Ports are bound to `127.0.0.1` on purpose. To reach CyberShield from other machines, put a TLS reverse proxy
(nginx, Caddy, Traefik) in front of ports 8000/8501, or set `CYBERSHIELD_*_BIND=0.0.0.0` **only** on a trusted,
firewalled management network. Add the public dashboard URL to `CYBERSHIELD_CORS_ORIGINS`.

### Complete host audit from Docker

The API container sees the host's `/etc` read-only but runs unprivileged, so `/etc/shadow`, `/etc/sudoers` and the
firewall state are reported as `unknown`. For a complete audit either run the CLI natively with `sudo` (section 3),
or run a one-off privileged audit (still read-only, no capabilities):

```bash
docker compose run --rm --user 0:0 -e CYBERSHIELD_LOGS_DIR=/tmp api cli audit host
```

### Upgrade, backup, stop

```bash
git pull && docker compose up -d --build     # upgrade (data and secrets are kept)
./scripts/backup.sh                          # PostgreSQL dump + reports + secrets into ./backups
docker compose down                          # stop (keeps volumes)
```

To remove the platform, see [6. Uninstall](#6-uninstall).

---

## 3. Native installation

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
./scripts/install.sh          # add --dev for pytest/ruff/bandit/pip-audit
source .venv/bin/activate
```

The installer installs `python3`, `python3-venv`, `nmap` and `libpcap` with `apt`, creates `.venv`, installs the
pinned dependencies, registers the `cybershield` command and initialises a local SQLite database in `./data`.
The generated admin password is written to `data/initial_admin_password` (mode `0600`).

Start the API and dashboard:

```bash
./scripts/start_native.sh      # API on 127.0.0.1:8000, dashboard on 127.0.0.1:8501
```

Use PostgreSQL instead of SQLite:

```bash
export CYBERSHIELD_DATABASE_URL='postgresql+psycopg://cybershield:<password>@127.0.0.1:5432/cybershield'
cybershield init-db
```

Run audits/captures with full visibility (root is needed to read `/etc/shadow`, `sudoers`, the firewall and raw
sockets):

```bash
sudo .venv/bin/cybershield audit host --pdf host-audit.pdf --json host-audit.json
sudo .venv/bin/cybershield traffic capture --iface eth0 --duration 120
```

---

## 4. Verification

```bash
curl -s http://127.0.0.1:8000/api/v1/health          # {"status":"ok","version":"1.0.0"}
curl -s http://127.0.0.1:8000/api/v1/health/ready    # {"status":"ready"}
cybershield verify-audit-trail                        # native: hash chain must be valid
```

Developers can run the full test suite (`make test`, 300+ tests, coverage gate 90%).

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `address already in use` on 8000/8501 | Another service uses the port: set `CYBERSHIELD_API_PORT` / `CYBERSHIELD_DASHBOARD_PORT` in `.env`. |
| `api` unhealthy, log says `password authentication failed` | The DB volume was created with other secrets (e.g. secrets volume deleted). Run `docker compose down -v` to reset both, or restore `cybershield-secrets` from backup. |
| `Unsupported config option` / `Additional properties are not allowed` | You are using Compose v1. Install Compose v2 (see the Kali/Parrot guides). |
| Host audit shows many `unknown` | Expected inside the container for root-only files: use the privileged one-off command above or a native `sudo` audit. |
| Scan refused: "outside the authorised scope" | Add the network to `CYBERSHIELD_ALLOWED_TARGETS` (only if you are authorised). |
| Sensor captures nothing | Set `CYBERSHIELD_SENSOR_INTERFACE`; on VMs use bridged networking; check `docker compose logs sensor`. |
| Dashboard says "API unreachable" | `docker compose logs api`; the dashboard waits for the API healthcheck. |
| Corporate proxy during `docker compose build` | Configure `~/.docker/config.json` → `proxies` so the build can reach PyPI and Debian mirrors. |
| `/bin/sh: https://github.com/...: not found` | Only the URL was pasted. The command is `git clone https://github.com/marcarna90/CyberShield.git`. |
| `git: not found` / `git: command not found` | Install Git: `sudo apt install -y git`. |
| `git clone`: `Repository not found` or asks for a password | Typo in the URL: it must be exactly `https://github.com/marcarna90/CyberShield.git`. |
| `app/`, `docker/` or `docs/` missing after cloning | The repository was filled with GitHub's web "Upload files", which drops folders. Push from a local clone with `git add -A && git commit && git push` instead. |
| `permission denied` on `scripts/*.sh` | The execute bit was lost (zip from Windows, web upload): `chmod +x scripts/*.sh docker/entrypoint.sh`. |

---

## 6. Uninstall

`scripts/uninstall.sh` detects what is installed (Docker deployment, native install, systemd units) and removes it
after showing a summary and asking you to type `yes`.

```bash
cd CyberShield
./scripts/uninstall.sh --dry-run            # show what would be removed, change nothing
./scripts/uninstall.sh                      # remove everything that was found (asks for confirmation)
make uninstall                              # same thing
```

| Option | Effect |
|---|---|
| `--docker` / `--native` / `--all` | limit to one mode (default: auto-detect) |
| `--keep-data` | remove containers / virtualenv but keep the database, reports, logs and secrets |
| `--backup` | run `./scripts/backup.sh` before removing a running Docker deployment |
| `--yes`, `-y` | no confirmation prompt (scripts, CI) |
| `--dry-run` | print the actions only |

What is removed:

| Mode | Removed |
|---|---|
| Docker | containers `init`, `db`, `api`, `dashboard`, `sensor`; the compose network; image `cybershield:1.0.0`; volumes `cybershield_*` (PostgreSQL data, reports, logs, generated secrets) unless `--keep-data` |
| Native | `.venv`, `build/`, `dist/`, `*.egg-info`, test caches, `/etc/systemd/system/cybershield-*.service` (via `sudo`); `data/` (SQLite DB, admin password) and the contents of `reports/` and `logs/` unless `--keep-data` |

Never removed: the source code, `./backups` (contains secrets: store or delete it securely) and the shared system
packages (`docker`, `nmap`, `python3`, `libpcap`). Crontab lines that call CyberShield are listed so you can delete
them with `crontab -e`.

Notes:

- If Docker requires root on your machine, run `sudo ./scripts/uninstall.sh --docker`.
- If you created the `cybershield` system user for the systemd service (Parrot guide), remove it with
  `sudo userdel cybershield`.
- Finally, delete the source folder: `cd .. && rm -rf CyberShield`.

Manual equivalent:

```bash
docker compose --profile sensor down --volumes --remove-orphans && docker image rm cybershield:1.0.0   # Docker
rm -rf .venv data build dist *.egg-info && find reports logs -mindepth 1 ! -name .gitkeep -delete       # native
```
