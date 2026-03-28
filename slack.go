package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

var severityEmoji = map[string]string{
	"Critical": "\U0001f534", // red circle
	"High":     "\U0001f7e0", // orange circle
	"Medium":   "\U0001f7e1", // yellow circle
	"Low":      "\U0001f535", // blue circle
}

var severityOrder = []string{"Critical", "High", "Medium", "Low"}

// buildBar creates a unicode bar of proportional length.
func buildBar(count, maxCount int) string {
	if maxCount == 0 || count == 0 {
		return ""
	}
	maxWidth := 12
	width := (count * maxWidth) / maxCount
	if width == 0 && count > 0 {
		width = 1
	}
	return strings.Repeat("\u2588", width)
}

// buildSlackMessage constructs a Slack Block Kit message for a vulnerability report.
func buildSlackMessage(imageRef, harborLink string, report *ScanReport) map[string]any {
	emoji := severityEmoji[report.Severity]
	if emoji == "" {
		emoji = "\u2139\ufe0f" // info
	}

	// Find max count for proportional bars
	maxCount := 0
	for _, sev := range severityOrder {
		if c, ok := report.Summary.Summary[sev]; ok && c > maxCount {
			maxCount = c
		}
	}

	// Build severity breakdown lines
	var lines []string
	for _, sev := range severityOrder {
		count, ok := report.Summary.Summary[sev]
		if !ok || count == 0 {
			continue
		}
		bar := buildBar(count, maxCount)
		sevEmoji := severityEmoji[sev]
		lines = append(lines, fmt.Sprintf("%s  *%-8s*  %s  %d", sevEmoji, sev, bar, count))
	}

	breakdown := strings.Join(lines, "\n")

	totalLine := fmt.Sprintf("*Total:* %d vulnerabilities (%d fixable)",
		report.Summary.Total, report.Summary.Fixable)

	scannerLine := fmt.Sprintf("_Scanner: %s %s_", report.Scanner.Name, report.Scanner.Version)

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s  %s Vulnerabilities Found", emoji, report.Severity),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s*", imageRef),
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": breakdown,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s\n%s", totalLine, scannerLine),
			},
		},
		{
			"type": "divider",
		},
		{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type": "button",
					"text": map[string]any{
						"type":  "plain_text",
						"text":  "View in Harbor",
						"emoji": true,
					},
					"url": harborLink,
				},
			},
		},
	}

	return map[string]any{"blocks": blocks}
}

// buildSlackFailedMessage constructs a Slack Block Kit message for a failed scan.
func buildSlackFailedMessage(imageRef, harborLink, label string) map[string]any {
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("\u26a0\ufe0f  %s Failed", label),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s*\n\n%s did not complete successfully. Check Harbor for details.", imageRef, label),
			},
		},
		{
			"type": "divider",
		},
		{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type": "button",
					"text": map[string]any{
						"type":  "plain_text",
						"text":  "View in Harbor",
						"emoji": true,
					},
					"url": harborLink,
				},
			},
		},
	}

	return map[string]any{"blocks": blocks}
}

// sendSlackMessage posts a message to a Slack webhook URL.
func sendSlackMessage(webhookURL string, message map[string]any) error {
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal slack message: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post to slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}
