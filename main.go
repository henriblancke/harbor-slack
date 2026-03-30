package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Config struct {
	SlackWebhookURL string
	HarborBaseURL   string
	HarborAPIURL    string
	HarborUsername  string
	HarborPassword  string
	MinSeverity     string
	Port            string
	Harbor          *HarborClient
}

func loadConfig() (Config, error) {
	cfg := Config{
		SlackWebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		HarborBaseURL:   os.Getenv("HARBOR_BASE_URL"),
		HarborAPIURL:    os.Getenv("HARBOR_API_URL"),
		HarborUsername:  os.Getenv("HARBOR_USERNAME"),
		HarborPassword:  os.Getenv("HARBOR_PASSWORD"),
		MinSeverity:     os.Getenv("MIN_SEVERITY"),
		Port:            os.Getenv("PORT"),
	}

	if cfg.SlackWebhookURL == "" {
		return cfg, fmt.Errorf("SLACK_WEBHOOK_URL is required")
	}
	if cfg.HarborBaseURL == "" {
		return cfg, fmt.Errorf("HARBOR_BASE_URL is required")
	}
	if cfg.HarborAPIURL == "" {
		cfg.HarborAPIURL = cfg.HarborBaseURL
	}
	if cfg.HarborUsername == "" {
		return cfg, fmt.Errorf("HARBOR_USERNAME is required")
	}
	if cfg.HarborPassword == "" {
		return cfg, fmt.Errorf("HARBOR_PASSWORD is required")
	}
	cfg.Harbor = NewHarborClient(cfg.HarborAPIURL, cfg.HarborUsername, cfg.HarborPassword)
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
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", handleWebhook(cfg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		<-sigCh
		slog.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	slog.Info("harbor-slack listening", "port", cfg.Port, "min_severity", cfg.MinSeverity)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
