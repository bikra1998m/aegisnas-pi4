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
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/health"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	session "github.com/yourorg/aegisnas-pi4/internal/sessions"
	"go.uber.org/zap"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "aegis-session",
		Short: "AegisNAS Session Management Service",
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
	Short: "Run the session management daemon",
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

		// Initialize database
		if err := db.InitConfigured(cmd.Context(), cfg); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		// Create session manager
		mgr, err := session.NewManager(cfg, logger)
		if err != nil {
			return fmt.Errorf("create session manager: %w", err)
		}

		// Start background tasks
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go mgr.StartCleanupTask(ctx, 1*time.Minute)
		go mgr.StartTimeoutEnforcer(ctx, 30*time.Second)
		go radius.StartAccountingIngestSpoolReplayer(ctx, cfg)
		if cfg.Radius.InterimUpdateSeconds > 0 {
			go mgr.StartInterimAccountingTask(ctx, time.Duration(cfg.Radius.InterimUpdateSeconds)*time.Second)
		}
		if cfg.Radius.DynamicAuth.Enabled {
			dynamicAuth := session.NewDynamicAuthServer(cfg, logger, mgr)
			go func() {
				logger.Info("dynamic authorization listener starting", zap.Int("port", cfg.Radius.DynamicAuth.Port))
				if err := dynamicAuth.ListenAndServe(ctx); err != nil {
					logger.Fatal("dynamic authorization listener failed", zap.Error(err))
				}
			}()
		}

		// Setup HTTP API
		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(10 * time.Second))

		// Session API routes
		r.Route("/api/v1/sessions", func(r chi.Router) {
			r.Get("/", mgr.HandleListSessions)
			r.Get("/active", mgr.HandleListActiveSessions)
			r.Get("/{sessionID}", mgr.HandleGetSession)
			r.Delete("/{sessionID}", mgr.HandleTerminateSession)
			r.Get("/user/{username}", mgr.HandleListUserSessions)
		})

		// Health endpoint
		health.RegisterRoutes(r)

		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Health.Port+7),
			Handler: r,
		}

		go func() {
			logger.Info("session API listening", zap.Int("port", cfg.Health.Port+7))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("server failed", zap.Error(err))
			}
		}()

		// Wait for interrupt
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Info("shutting down session service")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("server shutdown error", zap.Error(err))
		}
		cancel() // stop background tasks
		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
