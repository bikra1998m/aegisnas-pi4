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
	portalserver "github.com/yourorg/aegisnas-pi4/internal/portal/server"
	"go.uber.org/zap"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "aegis-portal",
		Short: "AegisNAS Captive Portal Service",
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
	Short: "Run the captive portal web server",
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

		// Create portal server
		srv, err := portalserver.New(cfg, logger)
		if err != nil {
			return fmt.Errorf("create portal server: %w", err)
		}
		staticHandler, err := portalserver.StaticHandler()
		if err != nil {
			return fmt.Errorf("create portal static handler: %w", err)
		}

		// Setup HTTP router
		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.RealIP)
		r.Use(middleware.Timeout(30 * time.Second))

		// Static assets
		r.Handle("/static/*", http.StripPrefix("/static/", staticHandler))

		// Portal routes
		r.Get("/", srv.HandleLoginPage)
		r.Post("/login", srv.HandleLogin)
		r.Get("/success", srv.HandleSuccess)
		r.Get("/status", srv.HandleStatus)
		r.Get("/logout", srv.HandleLogout)
		r.Post("/logout", srv.HandleLogout)
		r.Get("/voucher", srv.HandleVoucherPage)
		r.Post("/voucher", srv.HandleVoucherLogin)
		r.Get("/register", srv.HandleRegistrationPage)
		r.Post("/register", srv.HandleRegistrationSubmit)
		r.Get("/register/pending", srv.HandleRegistrationPending)
		r.Get("/register/approve", srv.HandleRegistrationApprovalPage)
		r.Post("/register/approve", srv.HandleRegistrationApprovalDecision)
		r.Get("/register/complete", srv.HandleRegistrationComplete)
		r.Get("/onboarding", srv.HandleOnboardingPage)
		r.Post("/onboarding", srv.HandleOnboardingRegister)
		r.Get("/onboarding/download/*", srv.HandleOnboardingDownload)
		r.Get("/onboarding/profile/*", srv.HandleOnboardingProfileDownload)

		// Health endpoint
		health.RegisterRoutes(r)

		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Portal.Port),
			Handler: r,
		}

		// Start server in goroutine
		go func() {
			logger.Info("portal server listening", zap.Int("port", cfg.Portal.Port))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("server failed", zap.Error(err))
			}
		}()

		// Wait for interrupt signal
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Info("shutting down portal server")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("server shutdown error", zap.Error(err))
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
