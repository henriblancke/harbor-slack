# Harbor Slack Vulnerability Notifier

## Overview

A small standalone Go service that receives webhook notifications from Harbor container registry, filters for images with vulnerabilities above a configurable severity threshold, and sends a formatted Slack message with vulnerability details and a link to the Harbor UI.

## Architecture

Single Go HTTP server with one endpoint: `POST /webhook`. No framework — just `net/http`. No external dependencies — only Go standard library.

**Flow:** Receive Harbor webhook → parse JSON → check severity threshold → if met, POST Slack Block Kit message → return 200 OK either way.

No database. No state. No queues.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SLACK_WEBHOOK_URL` | yes | — | Slack incoming webhook URL |
| `HARBOR_BASE_URL` | yes | — | Harbor instance URL for UI links |
| `MIN_SEVERITY` | no | `Low` | Minimum severity to notify on |
| `PORT` | no | `8080` | Server listen port |

## Severity Ranking

```
Critical: 4, High: 3, Medium: 2, Low: 1, None: 0
```

Compare the scan's overall severity against `MIN_SEVERITY`. Discard silently if below threshold.

## Slack Message

Block Kit message with:
- Header emoji/color based on highest severity (red=Critical, orange=High, yellow=Medium, blue=Low)
- Image name with tag (fallback to short digest if tag missing)
- Unicode bar chart showing vulnerability count per severity level
- Total count with fixable count
- Scanner name and version
- "View in Harbor" link constructed from: `{HARBOR_BASE_URL}/harbor/projects/{namespace}/repositories/{name}/artifacts/{digest}`

## Harbor UI Link Construction

Built from payload fields:
- `repository.namespace` → project name
- `repository.name` → repository name
- `resources[].digest` → artifact identifier

Pattern: `{HARBOR_BASE_URL}/harbor/projects/{namespace}/repositories/{name}/artifacts/{digest}`

## Project Structure

```
harbor-slack/
├── main.go              # entrypoint, HTTP server, config loading
├── webhook.go           # Harbor payload parsing & filtering
├── slack.go             # Slack message building & sending
├── webhook_test.go      # tests with example Harbor payloads
├── Dockerfile           # multi-stage build
├── go.mod
└── README.md
```

## Key Decisions

- No external dependencies — standard library only
- No interfaces or abstractions — three files, direct code
- Multi-stage Docker build: golang:1.22-alpine → scratch/alpine (~10MB image)
- One Slack message per webhook (no batching)
- Tag fallback to short digest due to known Harbor bug with empty tags
