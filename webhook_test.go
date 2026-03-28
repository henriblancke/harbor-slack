package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const payloadWithVulnerabilities = `{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:954b378c375d852eb3c63ab88978f640b4348b01c1b3456a024a81536dafbbf4",
        "tag": "v1.2.3",
        "resource_url": "harbor.example.com/myproject/myapp@sha256:954b378c375d852eb3c63ab88978f640b4348b01c1b3456a024a81536dafbbf4",
        "scan_overview": {
          "application/vnd.security.vulnerability.report; version=1.1": {
            "report_id": "af0546c1-67dc-4e9d-927e-372900ead0df",
            "scan_status": "Success",
            "severity": "Critical",
            "duration": 8,
            "summary": {
              "total": 13,
              "fixable": 5,
              "summary": {
                "Critical": 3,
                "High": 7,
                "Medium": 1,
                "Low": 2
              }
            },
            "start_time": "2023-04-03T06:12:47Z",
            "end_time": "2023-04-03T06:12:55Z",
            "scanner": {
              "name": "Trivy",
              "vendor": "Aqua Security",
              "version": "v0.37.2"
            },
            "complete_percent": 100
          }
        }
      }
    ],
    "repository": {
      "name": "myapp",
      "namespace": "myproject",
      "repo_full_name": "myproject/myapp",
      "repo_type": "private"
    }
  }
}`

const payloadClean = `{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:abc123",
        "tag": "latest",
        "resource_url": "harbor.example.com/myproject/clean@sha256:abc123",
        "scan_overview": {
          "application/vnd.security.vulnerability.report; version=1.1": {
            "report_id": "clean-report",
            "scan_status": "Success",
            "severity": "None",
            "duration": 3,
            "summary": {
              "total": 0,
              "fixable": 0,
              "summary": {}
            },
            "start_time": "2023-04-03T06:12:47Z",
            "end_time": "2023-04-03T06:12:50Z",
            "scanner": {
              "name": "Trivy",
              "vendor": "Aqua Security",
              "version": "v0.37.2"
            },
            "complete_percent": 100
          }
        }
      }
    ],
    "repository": {
      "name": "clean",
      "namespace": "myproject",
      "repo_full_name": "myproject/clean",
      "repo_type": "private"
    }
  }
}`

const payloadNoTag = `{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:954b378c375d852eb3c63ab88978f640b4348b01c1b3456a024a81536dafbbf4",
        "tag": "",
        "resource_url": "harbor.example.com/myproject/myapp@sha256:954b378c375d852eb3c63ab88978f640b4348b01c1b3456a024a81536dafbbf4",
        "scan_overview": {
          "application/vnd.security.vulnerability.report; version=1.1": {
            "report_id": "no-tag-report",
            "scan_status": "Success",
            "severity": "High",
            "duration": 5,
            "summary": {
              "total": 4,
              "fixable": 2,
              "summary": {
                "High": 3,
                "Medium": 1
              }
            },
            "start_time": "2023-04-03T06:12:47Z",
            "end_time": "2023-04-03T06:12:52Z",
            "scanner": {
              "name": "Trivy",
              "vendor": "Aqua Security",
              "version": "v0.37.2"
            },
            "complete_percent": 100
          }
        }
      }
    ],
    "repository": {
      "name": "myapp",
      "namespace": "myproject",
      "repo_full_name": "myproject/myapp",
      "repo_type": "private"
    }
  }
}`

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		severity    string
		minSeverity string
		want        bool
	}{
		{"Critical", "Low", true},
		{"High", "High", true},
		{"Medium", "High", false},
		{"Low", "Low", true},
		{"None", "Low", false},
		{"Critical", "Critical", true},
		{"High", "Critical", false},
	}

	for _, tt := range tests {
		got := meetsThreshold(tt.severity, tt.minSeverity)
		if got != tt.want {
			t.Errorf("meetsThreshold(%q, %q) = %v, want %v", tt.severity, tt.minSeverity, got, tt.want)
		}
	}
}

func TestImageRef(t *testing.T) {
	repo := Repository{RepoFullName: "myproject/myapp"}

	// With tag
	res := Resource{Tag: "v1.2.3", Digest: "sha256:abc123"}
	got := imageRef(repo, res)
	if got != "myproject/myapp:v1.2.3" {
		t.Errorf("imageRef with tag = %q, want %q", got, "myproject/myapp:v1.2.3")
	}

	// Without tag — falls back to short digest
	res = Resource{Tag: "", Digest: "sha256:954b378c375d852eb3c63ab88978f640b4348b01c1b3456a024a81536dafbbf4"}
	got = imageRef(repo, res)
	if got != "myproject/myapp:sha256:954b378c375d" {
		t.Errorf("imageRef without tag = %q, want %q", got, "myproject/myapp:sha256:954b378c375d")
	}
}

func TestHarborLink(t *testing.T) {
	repo := Repository{Name: "myapp", Namespace: "myproject"}
	got := harborLink("https://harbor.example.com", repo, "sha256:abc123")
	want := "https://harbor.example.com/harbor/projects/myproject/repositories/myapp/artifacts/sha256:abc123"
	if got != want {
		t.Errorf("harborLink = %q, want %q", got, want)
	}

	// Trailing slash in base URL
	got = harborLink("https://harbor.example.com/", repo, "sha256:abc123")
	if got != want {
		t.Errorf("harborLink with trailing slash = %q, want %q", got, want)
	}
}

func TestBuildSlackMessage(t *testing.T) {
	report := &ScanReport{
		Severity: "Critical",
		Summary: Summary{
			Total:   13,
			Fixable: 5,
			Summary: map[string]int{
				"Critical": 3,
				"High":     7,
				"Medium":   1,
				"Low":      2,
			},
		},
		Scanner: Scanner{Name: "Trivy", Version: "v0.37.2"},
	}

	msg := buildSlackMessage("myproject/myapp:v1.2.3", "https://harbor.example.com/link", report)

	// Verify it's valid JSON
	_, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("buildSlackMessage produced invalid JSON: %v", err)
	}

	blocks, ok := msg["blocks"].([]map[string]any)
	if !ok {
		t.Fatal("expected blocks array")
	}

	// Should have header, image ref, breakdown, totals, divider, actions
	if len(blocks) != 6 {
		t.Errorf("expected 6 blocks, got %d", len(blocks))
	}
}

func TestWebhookHandler_Vulnerabilities(t *testing.T) {
	// Track Slack messages sent
	var slackPayload map[string]any
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &slackPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := Config{
		SlackWebhookURL: slackServer.URL,
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Low",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payloadWithVulnerabilities))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackPayload == nil {
		t.Fatal("expected Slack message to be sent")
	}
}

func TestWebhookHandler_CleanImage(t *testing.T) {
	slackCalled := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := Config{
		SlackWebhookURL: slackServer.URL,
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Low",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payloadClean))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackCalled {
		t.Error("expected no Slack message for clean image")
	}
}

func TestWebhookHandler_BelowThreshold(t *testing.T) {
	slackCalled := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := Config{
		SlackWebhookURL: slackServer.URL,
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Critical",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	// This payload has severity "High" which is below "Critical" threshold
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payloadNoTag))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackCalled {
		t.Error("expected no Slack message when below severity threshold")
	}
}

func TestWebhookHandler_ScanFailed(t *testing.T) {
	payload := `{
  "type": "SCANNING_FAILED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:abc123def456",
        "tag": "v2.0.0",
        "resource_url": "harbor.example.com/myproject/broken@sha256:abc123def456",
        "scan_overview": {}
      }
    ],
    "repository": {
      "name": "broken",
      "namespace": "myproject",
      "repo_full_name": "myproject/broken",
      "repo_type": "private"
    }
  }
}`

	var slackPayload map[string]any
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &slackPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := Config{
		SlackWebhookURL: slackServer.URL,
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Low",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackPayload == nil {
		t.Fatal("expected Slack message to be sent for failed scan")
	}

	blocks, ok := slackPayload["blocks"].([]any)
	if !ok {
		t.Fatal("expected blocks array")
	}
	// Failed message: header, section, divider, actions
	if len(blocks) != 4 {
		t.Errorf("expected 4 blocks for failed scan message, got %d", len(blocks))
	}
}

func TestBuildSlackFailedMessage(t *testing.T) {
	msg := buildSlackFailedMessage("myproject/broken:v2.0.0", "https://harbor.example.com/link", "Vulnerability Scan")

	_, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("buildSlackFailedMessage produced invalid JSON: %v", err)
	}

	blocks, ok := msg["blocks"].([]map[string]any)
	if !ok {
		t.Fatal("expected blocks array")
	}
	if len(blocks) != 4 {
		t.Errorf("expected 4 blocks, got %d", len(blocks))
	}
}

func TestWebhookHandler_SbomCompleted_Ignored(t *testing.T) {
	payload := `{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:abc123def456",
        "tag": "v1.0.0",
        "resource_url": "harbor.example.com/myproject/myapp@sha256:abc123def456",
        "scan_overview": {}
      }
    ],
    "repository": {
      "name": "myapp",
      "namespace": "myproject",
      "repo_full_name": "myproject/myapp",
      "repo_type": "private"
    },
    "scan": {"scan_type": "sbom"}
  }
}`

	slackCalled := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := Config{
		SlackWebhookURL: slackServer.URL,
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Low",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackCalled {
		t.Error("expected no Slack message for SBOM scan completed")
	}
}

func TestWebhookHandler_SbomFailed(t *testing.T) {
	payload := `{
  "type": "SCANNING_FAILED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "sha256:abc123def456",
        "tag": "v1.0.0",
        "resource_url": "harbor.example.com/myproject/myapp@sha256:abc123def456",
        "scan_overview": {}
      }
    ],
    "repository": {
      "name": "myapp",
      "namespace": "myproject",
      "repo_full_name": "myproject/myapp",
      "repo_type": "private"
    },
    "scan": {"scan_type": "sbom"}
  }
}`

	var slackPayload map[string]any
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &slackPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	cfg := Config{
		SlackWebhookURL: slackServer.URL,
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Low",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackPayload == nil {
		t.Fatal("expected Slack message for failed SBOM scan")
	}
}

func TestWebhookHandler_NonScanEvent(t *testing.T) {
	payload := `{"type": "PUSH_ARTIFACT", "event_data": {}}`

	cfg := Config{
		SlackWebhookURL: "http://unused",
		HarborBaseURL:   "https://harbor.example.com",
		MinSeverity:     "Low",
		Port:            "8080",
	}

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
