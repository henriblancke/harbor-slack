package main

import (
	"fmt"
	"net/http"
	"os"
)

type Config struct {
	SlackWebhookURL string
	HarborBaseURL   string
	MinSeverity     string
	Port            string
}

func loadConfig() (Config, error) {
	cfg := Config{
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		HarborBaseURL:   os.Getenv("HARBOR_BASE_URL"),
		MinSeverity:     os.Getenv("MIN_SEVERITY"),
		Port:            os.Getenv("PORT"),
	}

	if cfg.SlackWebhookURL == "" {
		return cfg, fmt.Errorf("SLACK_WEBHOOK_URL is required")
	}
	if cfg.HarborBaseURL == "" {
		return cfg, fmt.Errorf("HARBOR_BASE_URL is required")
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "Low"
	}
	if _, ok := severityRank[cfg.MinSeverity]; !ok {
		return cfg, fmt.Errorf("invalid MIN_SEVERITY: %s (must be None, Low, Medium, High, or Critical)", cfg.MinSeverity)
	}
	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	return cfg, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	http.HandleFunc("/webhook", handleWebhook(cfg))

	fmt.Printf("harbor-slack listening on :%s (min severity: %s)\n", cfg.Port, cfg.MinSeverity)
	if err := http.ListenAndServe(":"+cfg.Port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
