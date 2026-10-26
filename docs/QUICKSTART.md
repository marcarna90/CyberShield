# Step-by-step execution

A 15-minute walkthrough from `git clone` to an executive PDF report. Every command was run end-to-end against the
Docker stack during release testing.

## Step 1 - Start the platform

```bash
git clone https://github.com/marcarna90/CyberShield.git
cd CyberShield
docker compose up -d
docker compose ps        # init: exited (0) - db, api, dashboard: healthy
```

## Step 2 - Get the admin password and an API token

```bash
PW="$(docker compose exec -T api cat /run/cybershield-secrets/admin_password)"
TOKEN="$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/token \
  --data-urlencode username=admin --data-urlencode "password=$PW" | jq -r .access_token)"
AUTH="Authorization: Bearer $TOKEN"
```

Open <http://localhost:8501> and sign in with the same credentials.

## Step 3 - (optional) Load the demo dataset

Fictional assets, a weak host configuration and synthetic traffic replayed through the real pipelines
(14 days of history). Every record is flagged and can be purged.

```bash
curl -s -X POST -H "$AUTH" http://127.0.0.1:8000/api/v1/admin/demo-data | jq
# {"assets": 8, "open_findings": 57, "alerts": 40}
```

## Step 4 - Audit the host

```bash
curl -s -X POST -H "$AUTH" http://127.0.0.1:8000/api/v1/audits/host | jq '{hostname, score, summary}'
```

For root-only checks (shadow, sudoers, firewall):
`docker compose run --rm --user 0:0 -e CYBERSHIELD_LOGS_DIR=/tmp api cli audit host`.

## Step 5 - Scan an authorised network

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' http://127.0.0.1:8000/api/v1/scans \
  -d '{"targets":["192.168.1.0/24"],"profile":"standard","authorization_confirmed":true}' | jq
# 202 Accepted -> {"id": 3, "status": "queued", ...}

curl -s -H "$AUTH" http://127.0.0.1:8000/api/v1/scans/3 | jq '{status, summary: .summary.severity_counts}'
```

Targets outside `CYBERSHIELD_ALLOWED_TARGETS` return `422` and are recorded in the audit trail as `denied`.

## Step 6 - Analyse traffic

Upload a capture (Wireshark/tcpdump `.pcap` or `.pcapng`) or start the sensor:

```bash
curl -s -X POST -H "$AUTH" -F "file=@docs/examples/sample_traffic.pcap" \
  http://127.0.0.1:8000/api/v1/traffic/pcap | jq '{health_score, packets, anomalies: [.summary.anomalies[].finding_id]}'

docker compose --profile sensor up -d sensor      # continuous passive monitoring
```

## Step 7 - Review findings, compliance and alerts

```bash
curl -s -H "$AUTH" "http://127.0.0.1:8000/api/v1/findings?severity=critical" | jq '.items[] | {finding_id, asset, title}'
curl -s -X POST -H "$AUTH" http://127.0.0.1:8000/api/v1/compliance/evaluate | jq '{overall_score, frameworks: [.frameworks[] | {framework, score}]}'
curl -s -H "$AUTH" "http://127.0.0.1:8000/api/v1/alerts?acknowledged=false" | jq '.total'
```

Triage a finding (analyst role or above):

```bash
curl -s -X PATCH -H "$AUTH" -H 'Content-Type: application/json' http://127.0.0.1:8000/api/v1/findings/1 \
  -d '{"status":"accepted_risk","comment":"Isolated lab host, compensating control FW-12"}'
```

## Step 8 - Generate and download reports

```bash
curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' http://127.0.0.1:8000/api/v1/reports \
  -d '{"report_type":"executive","formats":["pdf","html","json"]}' | jq '.[] | {id, filename, sha256}'

curl -s -H "$AUTH" -o executive.pdf http://127.0.0.1:8000/api/v1/reports/1/download
sha256sum executive.pdf     # matches the X-Content-SHA256 header / the sha256 above
```

## Step 9 - Verify the audit trail

```bash
curl -s -H "$AUTH" http://127.0.0.1:8000/api/v1/audit-trail/verify   # {"valid": true, "checked": N, ...}
```

## Step 10 - Clean up the demo data (keep your real results)

```bash
curl -s -X DELETE -H "$AUTH" http://127.0.0.1:8000/api/v1/admin/demo-data | jq
```
