package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Severity ranking for comparison
var severityRank = map[string]int{
	"None":     0,
	"Low":      1,
	"Medium":   2,
	"High":     3,
	"Critical": 4,
}

// Harbor webhook payload types

type HarborWebhook struct {
	Type      string    `json:"type"`
	EventData EventData `json:"event_data"`
}

type EventData struct {
	Resources  []Resource `json:"resources"`
	Repository Repository `json:"repository"`
	Scan       Scan       `json:"scan"`
}

type Scan struct {
	ScanType string `json:"scan_type"`
}

type Resource struct {
	Digest      string                            `json:"digest"`
	Tag         string                            `json:"tag"`
	ResourceURL string                            `json:"resource_url"`
	ScanOverview map[string]json.RawMessage       `json:"scan_overview"`
}

type ScanReport struct {
	ReportID        string  `json:"report_id"`
	ScanStatus      string  `json:"scan_status"`
	Severity        string  `json:"severity"`
	Duration        int     `json:"duration"`
	Summary         Summary `json:"summary"`
	StartTime       string  `json:"start_time"`
	EndTime         string  `json:"end_time"`
	Scanner         Scanner `json:"scanner"`
	CompletePercent int     `json:"complete_percent"`
}

type Summary struct {
	Total   int            `json:"total"`
	Fixable int            `json:"fixable"`
	Summary map[string]int `json:"summary"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Repository struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace"`
	RepoFullName string `json:"repo_full_name"`
	RepoType     string `json:"repo_type"`
}

// parseScanReport extracts the first scan report from the scan_overview map.
// The key is a MIME type like "application/vnd.security.vulnerability.report; version=1.1".
func parseScanReport(overview map[string]json.RawMessage) (*ScanReport, error) {
	for _, raw := range overview {
		var report ScanReport
		if err := json.Unmarshal(raw, &report); err != nil {
			return nil, fmt.Errorf("unmarshal scan report: %w", err)
		}
		return &report, nil
	}
	return nil, fmt.Errorf("no scan report found in scan_overview")
}

// meetsThreshold returns true if the scan severity meets or exceeds the minimum.
func meetsThreshold(severity, minSeverity string) bool {
	return severityRank[severity] >= severityRank[minSeverity]
}

// imageRef returns a human-readable image reference, falling back to short digest if tag is empty.
func imageRef(repo Repository, resource Resource) string {
	tag := resource.Tag
	if tag == "" {
		// Fall back to short digest
		digest := resource.Digest
		if strings.HasPrefix(digest, "sha256:") && len(digest) > 19 {
			tag = digest[:19] // "sha256:" + 12 chars
		} else {
			tag = digest
		}
	}
	return fmt.Sprintf("%s:%s", repo.RepoFullName, tag)
}

// harborLink builds a URL to the artifact in the Harbor UI.
func harborLink(baseURL string, repo Repository, digest string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	return fmt.Sprintf("%s/harbor/projects/%s/repositories/%s/artifacts/%s",
		baseURL, repo.Namespace, repo.Name, digest)
}

func handleScanCompleted(cfg Config, webhook HarborWebhook) {
	for _, resource := range webhook.EventData.Resources {
		report, err := parseScanReport(resource.ScanOverview)
		if err != nil {
			fmt.Printf("error parsing scan report: %v\n", err)
			continue
		}

		if report.ScanStatus != "Success" {
			continue
		}

		if !meetsThreshold(report.Severity, cfg.MinSeverity) {
			continue
		}

		if report.Summary.Total == 0 {
			continue
		}

		ref := imageRef(webhook.EventData.Repository, resource)
		link := harborLink(cfg.HarborBaseURL, webhook.EventData.Repository, resource.Digest)

		msg := buildSlackMessage(ref, link, report)
		if err := sendSlackMessage(cfg.SlackWebhookURL, msg); err != nil {
			fmt.Printf("error sending slack message: %v\n", err)
		}
	}
}

func handleScanFailed(cfg Config, webhook HarborWebhook, scanType string) {
	label := "Vulnerability Scan"
	if scanType == "sbom" {
		label = "SBOM Scan"
	}

	for _, resource := range webhook.EventData.Resources {
		ref := imageRef(webhook.EventData.Repository, resource)
		link := harborLink(cfg.HarborBaseURL, webhook.EventData.Repository, resource.Digest)

		msg := buildSlackFailedMessage(ref, link, label)
		if err := sendSlackMessage(cfg.SlackWebhookURL, msg); err != nil {
			fmt.Printf("error sending slack message: %v\n", err)
		}
	}
}

// handleWebhook processes an incoming Harbor webhook request.
func handleWebhook(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var webhook HarborWebhook
		if err := json.Unmarshal(body, &webhook); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		scanType := webhook.EventData.Scan.ScanType

		switch webhook.Type {
		case "SCANNING_COMPLETED":
			if scanType != "sbom" {
				handleScanCompleted(cfg, webhook)
			}
		case "SCANNING_FAILED":
			handleScanFailed(cfg, webhook, scanType)
		}

		w.WriteHeader(http.StatusOK)
	}
}
