package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// newMockHarborAPI returns a test server that responds to Harbor API project and artifact calls.
// Single-arch artifacts get tags directly. Use newMockHarborAPIMultiArch for multi-arch scenarios.
func newMockHarborAPI() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v2.0/projects/") && strings.Contains(r.URL.Path, "/repositories/") {
			json.NewEncoder(w).Encode(map[string]any{
				"digest": "sha256:abc123",
				"tags":   []map[string]string{{"name": "v1.2.3"}, {"name": "latest"}},
			})
			return
		}
		if strings.Contains(r.URL.Path, "/api/v2.0/projects/") {
			json.NewEncoder(w).Encode(map[string]any{"project_id": 8, "name": "myproject"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// newMockHarborAPIMultiArch returns a test server that simulates multi-arch images.
// Child digests have no tags; the parent manifest list has tags and references.
func newMockHarborAPIMultiArch(childDigestAmd64, childDigestArm64 string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		query := r.URL.RawQuery

		// Project lookup
		if strings.Contains(path, "/api/v2.0/projects/") && !strings.Contains(path, "/repositories/") {
			json.NewEncoder(w).Encode(map[string]any{"project_id": 8, "name": "myproject"})
			return
		}

		// List artifacts (parent search) — returns only tagged artifacts due to q=tags=*
		if strings.Contains(path, "/repositories/") && strings.Contains(path, "/artifacts") &&
			!strings.Contains(path, "sha256") && strings.Contains(query, "tags") {
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"digest": "sha256:parentaaa",
					"tags":   []map[string]string{{"name": "v1.2.3"}},
					"references": []map[string]string{
						{"child_digest": childDigestAmd64},
						{"child_digest": childDigestArm64},
					},
				},
			})
			return
		}

		// Single artifact lookup — child has no tags
		if strings.Contains(path, "/artifacts/") {
			json.NewEncoder(w).Encode(map[string]any{
				"digest": strings.TrimPrefix(path[strings.LastIndex(path, "/artifacts/")+11:], ""),
				"tags":   nil,
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

func testConfig(slackURL, harborURL string) Config {
	return Config{
		SlackWebhookURL: slackURL,
		HarborBaseURL:   harborURL,
		HarborUsername:  "admin",
		HarborPassword:  "test",
		MinSeverity:     "Low",
		Port:            "8080",
		Harbor:          NewHarborClient(harborURL, "admin", "test"),
		Dedup:           newDedupCache(10 * time.Minute),
	}
}

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

	res := Resource{Digest: "sha256:954b378c375d852eb3c63ab88978f640b4348b01c1b3456a024a81536dafbbf4"}
	got := imageRef(repo, res)
	want := "myproject/myapp@sha256:954b378c375d"
	if got != want {
		t.Errorf("imageRef = %q, want %q", got, want)
	}
}

func TestFormatTags(t *testing.T) {
	got := formatTags([]string{"v1.2.3", "latest"})
	want := "`v1.2.3`  `latest`"
	if got != want {
		t.Errorf("formatTags = %q, want %q", got, want)
	}

	got = formatTags(nil)
	if got != "_no tags_" {
		t.Errorf("formatTags(nil) = %q, want %q", got, "_no tags_")
	}
}

func TestHarborLink(t *testing.T) {
	repo := Repository{Name: "myapp", Namespace: "myproject"}
	got := harborLink("https://harbor.example.com", 8, repo, "sha256:abc123")
	want := "https://harbor.example.com/harbor/projects/8/repositories/myapp/artifacts-tab/artifacts/sha256:abc123?sbomDigest="
	if got != want {
		t.Errorf("harborLink = %q, want %q", got, want)
	}

	// Trailing slash in base URL
	got = harborLink("https://harbor.example.com/", 8, repo, "sha256:abc123")
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

	msg := buildSlackMessage("myproject/myapp@sha256:abc123", "https://harbor.example.com/link", "", []string{"v1.2.3"}, report)

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)
	cfg.MinSeverity = "Critical"

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

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
	msg := buildSlackFailedMessage("myproject/broken@sha256:abc123", "https://harbor.example.com/link", "", []string{"v2.0.0"}, "Vulnerability Scan")

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

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

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig("http://unused", harborAPI.URL)

	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func multiArchPayload(digest string) string {
	return `{
  "type": "SCANNING_COMPLETED",
  "occur_at": 1680502375,
  "operator": "auto",
  "event_data": {
    "resources": [
      {
        "digest": "` + digest + `",
        "tag": "",
        "resource_url": "harbor.example.com/myproject/myapp@` + digest + `",
        "scan_overview": {
          "application/vnd.security.vulnerability.report; version=1.1": {
            "report_id": "multi-arch-report",
            "scan_status": "Success",
            "severity": "Critical",
            "duration": 5,
            "summary": {
              "total": 9,
              "fixable": 9,
              "summary": {
                "Critical": 1,
                "High": 5,
                "Medium": 1,
                "Low": 2
              }
            },
            "start_time": "2023-04-03T06:12:47Z",
            "end_time": "2023-04-03T06:12:52Z",
            "scanner": {
              "name": "Trivy",
              "vendor": "Aqua Security",
              "version": "v0.69.3"
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
}

func TestWebhookHandler_MultiArch_SmallestDigestSends(t *testing.T) {
	digestAmd64 := "sha256:1111111111111111" // lexicographically smaller
	digestArm64 := "sha256:9999999999999999" // lexicographically larger

	slackCalled := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	harborAPI := newMockHarborAPIMultiArch(digestAmd64, digestArm64)
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

	// Webhook for the smallest digest — should send
	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(multiArchPayload(digestAmd64)))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if !slackCalled {
		t.Error("expected Slack message for smallest digest in multi-arch image")
	}
}

func TestWebhookHandler_MultiArch_LargerDigestSkipped(t *testing.T) {
	digestAmd64 := "sha256:1111111111111111" // lexicographically smaller
	digestArm64 := "sha256:9999999999999999" // lexicographically larger

	slackCalled := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	harborAPI := newMockHarborAPIMultiArch(digestAmd64, digestArm64)
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

	// Webhook for the larger digest — should skip
	handler := handleWebhook(cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(multiArchPayload(digestArm64)))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if slackCalled {
		t.Error("expected no Slack message for non-smallest digest in multi-arch image")
	}
}

func TestIsSmallestDigest(t *testing.T) {
	refs := []HarborReference{
		{ChildDigest: "sha256:bbb"},
		{ChildDigest: "sha256:aaa"},
		{ChildDigest: "sha256:ccc"},
	}

	if !isSmallestDigest("sha256:aaa", refs) {
		t.Error("sha256:aaa should be the smallest")
	}
	if isSmallestDigest("sha256:bbb", refs) {
		t.Error("sha256:bbb should not be the smallest")
	}
	if isSmallestDigest("sha256:ccc", refs) {
		t.Error("sha256:ccc should not be the smallest")
	}

	// Single child — always the winner
	single := []HarborReference{{ChildDigest: "sha256:only"}}
	if !isSmallestDigest("sha256:only", single) {
		t.Error("single child should always be the smallest")
	}
}

func TestWebhookHandler_SameDigestDedup(t *testing.T) {
	slackCount := 0
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	harborAPI := newMockHarborAPI()
	defer harborAPI.Close()

	cfg := testConfig(slackServer.URL, harborAPI.URL)

	handler := handleWebhook(cfg)

	// Send the same webhook 3 times (simulating Harbor retries)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payloadWithVulnerabilities))
		w := httptest.NewRecorder()
		handler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, w.Code)
		}
	}

	if slackCount != 1 {
		t.Errorf("expected 1 Slack message, got %d", slackCount)
	}
}
