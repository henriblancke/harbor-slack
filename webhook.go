package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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
// NOTE: Harbor currently sends a single entry; if multiple keys exist, one is returned arbitrarily.
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

// imageRef returns a human-readable image reference using the short digest.
func imageRef(repo Repository, resource Resource) string {
	digest := resource.Digest
	if strings.HasPrefix(digest, "sha256:") && len(digest) > 19 {
		digest = digest[:19] // "sha256:" + 12 chars
	}
	return fmt.Sprintf("%s@%s", repo.RepoFullName, digest)
}

// formatTags returns a display string for tags.
func formatTags(tags []string) string {
	if len(tags) == 0 {
		return "_no tags_"
	}
	formatted := make([]string, len(tags))
	for i, t := range tags {
		formatted[i] = "`" + t + "`"
	}
	return strings.Join(formatted, "  ")
}

// harborLink builds a URL to the artifact in the Harbor UI using the numeric project ID.
func harborLink(baseURL string, projectID int, repo Repository, digest string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	return fmt.Sprintf("%s/harbor/projects/%d/repositories/%s/artifacts-tab/artifacts/%s?sbomDigest=",
		baseURL, projectID, url.PathEscape(repo.Name), url.PathEscape(digest))
}

// lookupArtifact resolves the project ID, tags, and parent digest from the Harbor API.
// On failure it falls back to zero values so messages still send.
func lookupArtifact(cfg Config, repo Repository, digest string) (int, *ArtifactInfo) {
	projectID, err := cfg.Harbor.GetProjectID(repo.Namespace)
	if err != nil {
		slog.Warn("harbor API get project", "error", err)
	}
	info, err := cfg.Harbor.GetArtifactInfo(repo.Namespace, repo.Name, digest)
	if err != nil {
		slog.Warn("harbor API get artifact info", "error", err)
		info = &ArtifactInfo{}
	}
	return projectID, info
}

func handleScanCompleted(cfg Config, webhook HarborWebhook) {
	for _, resource := range webhook.EventData.Resources {
		report, err := parseScanReport(resource.ScanOverview)
		if err != nil {
			slog.Error("parsing scan report", "error", err)
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

		projectID, info := lookupArtifact(cfg, webhook.EventData.Repository, resource.Digest)

		if !info.ShouldNotify {
			slog.Info("skipping non-winner multi-arch digest",
				"digest", resource.Digest,
				"repo", webhook.EventData.Repository.RepoFullName)
			continue
		}

		// Dedup key: use parent digest when available so all children of the
		// same manifest list share one key; fall back to the digest itself.
		dedupKey := webhook.EventData.Repository.RepoFullName + "@" + resource.Digest
		if info.ParentDigest != "" {
			dedupKey = webhook.EventData.Repository.RepoFullName + "@" + info.ParentDigest
		}
		if cfg.Dedup.seen(dedupKey) {
			slog.Info("skipping already-notified digest",
				"digest", resource.Digest,
				"repo", webhook.EventData.Repository.RepoFullName)
			continue
		}

		ref := imageRef(webhook.EventData.Repository, resource)
		link := harborLink(cfg.HarborBaseURL, projectID, webhook.EventData.Repository, resource.Digest)
		parentLink := ""
		if info.ParentDigest != "" {
			parentLink = harborLink(cfg.HarborBaseURL, projectID, webhook.EventData.Repository, info.ParentDigest)
		}

		msg := buildSlackMessage(ref, link, parentLink, info.Tags, report)
		if err := sendSlackMessage(cfg.SlackWebhookURL, msg); err != nil {
			slog.Error("sending slack message", "error", err)
		}
	}
}

func handleScanFailed(cfg Config, webhook HarborWebhook, scanType string) {
	label := "Vulnerability Scan"
	if scanType == "sbom" {
		label = "SBOM Scan"
	}

	for _, resource := range webhook.EventData.Resources {
		projectID, info := lookupArtifact(cfg, webhook.EventData.Repository, resource.Digest)
		ref := imageRef(webhook.EventData.Repository, resource)
		link := harborLink(cfg.HarborBaseURL, projectID, webhook.EventData.Repository, resource.Digest)
		parentLink := ""
		if info.ParentDigest != "" {
			parentLink = harborLink(cfg.HarborBaseURL, projectID, webhook.EventData.Repository, info.ParentDigest)
		}

		msg := buildSlackFailedMessage(ref, link, parentLink, info.Tags, label)
		if err := sendSlackMessage(cfg.SlackWebhookURL, msg); err != nil {
			slog.Error("sending slack message", "error", err)
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

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB
		defer r.Body.Close()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

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
