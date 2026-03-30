# harbor-slack

A small Go service that receives [Harbor](https://goharbor.io/) webhook notifications and sends formatted Slack messages for:

- Vulnerability scans that find vulnerabilities above a configurable severity threshold
- Failed vulnerability scans
- Failed SBOM scans

SBOM scan completions are silently ignored.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SLACK_WEBHOOK_URL` | yes | — | Slack [incoming webhook](https://api.slack.com/messaging/webhooks) URL |
| `HARBOR_BASE_URL` | yes | — | Public Harbor URL (used to build "View in Harbor" links) |
| `HARBOR_API_URL` | no | `HARBOR_BASE_URL` | Harbor API URL (e.g. in-cluster service URL) |
| `HARBOR_USERNAME` | yes | — | Harbor API username (for resolving project IDs and artifact tags) |
| `HARBOR_PASSWORD` | yes | — | Harbor API password |
| `MIN_SEVERITY` | no | `Low` | Minimum severity to notify on: `None`, `Low`, `Medium`, `High`, `Critical` |
| `PORT` | no | `8080` | Server listen port |

## Run with Docker

```bash
docker build -t harbor-slack .

docker run -d \
  -e SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx" \
  -e HARBOR_BASE_URL="https://harbor.example.com" \
  -e HARBOR_USERNAME="admin" \
  -e HARBOR_PASSWORD="..." \
  -e MIN_SEVERITY="High" \
  -p 9980:8080 \
  harbor-slack
```

## Run locally

```bash
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx" \
HARBOR_BASE_URL="https://harbor.example.com" \
HARBOR_USERNAME="admin" \
HARBOR_PASSWORD="..." \
MIN_SEVERITY="Low" \
go run .
```

## Harbor setup

In your Harbor project, go to **Webhooks** and add a new endpoint:

- **Endpoint URL:** `http://<host>:9980/webhook`
- **Event types:** `Scanning completed`, `Scanning failed`

## Testing

Run unit tests:

```bash
go test -v ./...
```

### Manual testing with curl

Start the server locally, then send test payloads. Replace `SLACK_WEBHOOK_URL` with a real webhook to see the Slack messages.

**1. Vulnerability scan with critical findings (sends Slack message):**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9980/webhook \
  -H "Content-Type: application/json" \
  -d '{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1774657690,
  "operator": "admin",
  "event_data": {
    "resources": [{
      "digest": "sha256:4afa52abb0f4866fe603c893fe5abec9197853c40f9bd452f87fb1ce5c5260c0",
      "resource_url": "oaicr.io/integrations/google-drive-integration@sha256:4afa52abb0f4866fe603c893fe5abec9197853c40f9bd452f87fb1ce5c5260c0",
      "scan_overview": {
        "application/vnd.security.vulnerability.report; version=1.1": {
          "report_id": "5425ccf1-8a26-4435-9246-b9c075b0d8fc",
          "scan_status": "Success",
          "severity": "Critical",
          "duration": 18,
          "summary": {"total": 7, "fixable": 7, "summary": {"Critical": 1, "High": 5, "Medium": 1}},
          "start_time": "2026-03-28T00:27:52Z",
          "end_time": "2026-03-28T00:28:10Z",
          "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "v0.69.3"},
          "complete_percent": 100
        }
      }
    }],
    "repository": {"name": "google-drive-integration", "namespace": "integrations", "repo_full_name": "integrations/google-drive-integration", "repo_type": "private"},
    "scan": {"scan_type": "vulnerability"}
  }
}'
```

**2. Clean image with no vulnerabilities (no Slack message):**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9980/webhook \
  -H "Content-Type: application/json" \
  -d '{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [{
      "digest": "sha256:abc123",
      "tag": "latest",
      "resource_url": "harbor.example.com/myproject/clean@sha256:abc123",
      "scan_overview": {
        "application/vnd.security.vulnerability.report; version=1.1": {
          "report_id": "test-2",
          "scan_status": "Success",
          "severity": "None",
          "duration": 3,
          "summary": {"total": 0, "fixable": 0, "summary": {}},
          "start_time": "2023-04-03T06:12:47Z",
          "end_time": "2023-04-03T06:12:50Z",
          "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "v0.37.2"},
          "complete_percent": 100
        }
      }
    }],
    "repository": {"name": "clean", "namespace": "myproject", "repo_full_name": "myproject/clean", "repo_type": "private"},
    "scan": {"scan_type": "vulnerability"}
  }
}'
```

**3. Vulnerability scan failed (sends Slack message):**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9980/webhook \
  -H "Content-Type: application/json" \
  -d '{
  "type": "SCANNING_FAILED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [{
      "digest": "sha256:deadbeef",
      "tag": "v2.0.0",
      "resource_url": "harbor.example.com/myproject/broken@sha256:deadbeef",
      "scan_overview": {}
    }],
    "repository": {"name": "broken", "namespace": "myproject", "repo_full_name": "myproject/broken", "repo_type": "private"},
    "scan": {"scan_type": "vulnerability"}
  }
}'
```

**4. SBOM scan failed (sends Slack message):**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9980/webhook \
  -H "Content-Type: application/json" \
  -d '{
  "type": "SCANNING_FAILED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [{
      "digest": "sha256:deadbeef",
      "tag": "v2.0.0",
      "resource_url": "harbor.example.com/myproject/broken@sha256:deadbeef",
      "scan_overview": {}
    }],
    "repository": {"name": "broken", "namespace": "myproject", "repo_full_name": "myproject/broken", "repo_type": "private"},
    "scan": {"scan_type": "sbom"}
  }
}'
```

**5. SBOM scan completed (no Slack message):**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9980/webhook \
  -H "Content-Type: application/json" \
  -d '{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [{
      "digest": "sha256:abc123",
      "tag": "v1.0.0",
      "resource_url": "harbor.example.com/myproject/myapp@sha256:abc123",
      "scan_overview": {}
    }],
    "repository": {"name": "myapp", "namespace": "myproject", "repo_full_name": "myproject/myapp", "repo_type": "private"},
    "scan": {"scan_type": "sbom"}
  }
}'
```

**6. Non-scan event (ignored, no Slack message):**

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:9980/webhook \
  -H "Content-Type: application/json" \
  -d '{"type": "PUSH_ARTIFACT", "event_data": {}}'
```

All commands return `200`. Cases 1, 3, and 4 send a Slack message; cases 2, 5, and 6 are silent.
