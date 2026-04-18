package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/ailite"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/health"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"go.uber.org/zap"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "aegis-ai-lite",
		Short: "AegisNAS AI Lite – Advisory recommendations",
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the AI lite analysis daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("validate config: %w", err)
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return err
		}
		defer logging.Sync()
		logger := logging.L()

		if !cfg.AILite.Enabled {
			logger.Info("AI Lite is disabled in config; exiting")
			return nil
		}

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		analyzer, err := ailite.NewAnalyzer(cfg, logger)
		if err != nil {
			return fmt.Errorf("create analyzer: %w", err)
		}

		// Background tasks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go analyzer.RunAuthFailureAnalyzer(ctx, 2*time.Minute)
		go analyzer.RunSessionAnomalyDetector(ctx, 5*time.Minute)
		go analyzer.RunConfigLinter(ctx, 10*time.Minute)

		// Remote webhook sender (optional)
		if cfg.AILite.RemoteWebhook != "" {
			go analyzer.RunRemoteWebhookSender(ctx, 30*time.Second)
		}

		// API server
		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(10 * time.Second))

		r.Get("/api/v1/ai/recommendations", analyzer.HandleListRecommendations)
		r.Post("/api/v1/ai/recommendations/{id}/acknowledge", analyzer.HandleAcknowledge)
		r.Post("/api/v1/ai/run-analysis", analyzer.HandleRunAnalysisNow)

		health.RegisterRoutes(r)

		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Health.Port+4),
			Handler: r,
		}

		go func() {
			logger.Info("AI lite API listening", zap.Int("port", cfg.Health.Port+4))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("server failed", zap.Error(err))
			}
		}()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Info("shutting down AI lite")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return httpServer.Shutdown(shutdownCtx)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
