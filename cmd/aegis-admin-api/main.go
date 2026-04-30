package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/adminapi"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/health"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"go.uber.org/zap"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "aegis-admin-api",
		Short: "AegisNAS Admin REST API",
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
	Short: "Run the admin API server",
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

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(30 * time.Second))
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   adminAllowedOrigins(),
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			AllowCredentials: false,
		}))

		// Public health endpoint
		health.RegisterRoutes(r)

		// API routes (protected)
		r.Route("/api/v1", func(r chi.Router) {
			r.Use(adminapi.AuthMiddleware)
			r.Get("/auth/validate", adminapi.HandleValidateToken)
			r.Get("/system/settings", adminapi.HandleGetSystemSettings)
			r.Get("/system/status", adminapi.HandleGetSystemStatus)
			r.Put("/system/settings", adminapi.HandleUpdateSystemSettings)
			r.Post("/system/settings/evaluate", adminapi.HandleEvaluateSystemSettings)
			r.Get("/system/settings/export", adminapi.HandleExportSystemSettings)
			r.Post("/system/settings/import", adminapi.HandleImportSystemSettings)
			r.Get("/system/hostapd-preview", adminapi.HandlePreviewHostapdConfig)
			r.Post("/system/hostapd-config", adminapi.HandleWriteHostapdConfig)
			r.Post("/system/hostapd-publish", adminapi.HandlePublishHostapdConfig)
			r.Post("/system/radius-apply", adminapi.HandleApplyRadiusConfig)

			// VLANs
			r.Get("/vlans", adminapi.HandleListVLANs)
			r.Post("/vlans", adminapi.HandleCreateVLAN)
			r.Put("/vlans/{id}", adminapi.HandleUpdateVLAN)
			r.Delete("/vlans/{id}", adminapi.HandleDeleteVLAN)

			// Users
			r.Get("/users", adminapi.HandleListUsers)
			r.Post("/users", adminapi.HandleCreateUser)
			r.Put("/users/{id}", adminapi.HandleUpdateUser)
			r.Delete("/users/{id}", adminapi.HandleDeleteUser)

			// Vouchers
			r.Get("/vouchers", adminapi.HandleListVouchers)
			r.Post("/vouchers", adminapi.HandleCreateVoucher)
			r.Put("/vouchers/{id}", adminapi.HandleUpdateVoucher)
			r.Delete("/vouchers/{id}", adminapi.HandleDeleteVoucher)

			// Roles
			r.Get("/roles", adminapi.HandleListRoles)
			r.Post("/roles", adminapi.HandleCreateRole)
			r.Put("/roles/{id}", adminapi.HandleUpdateRole)
			r.Delete("/roles/{id}", adminapi.HandleDeleteRole)

			// Policies
			r.Get("/policies", adminapi.HandleListPolicies)
			r.Post("/policies", adminapi.HandleCreatePolicy)
			r.Put("/policies/{id}", adminapi.HandleUpdatePolicy)
			r.Delete("/policies/{id}", adminapi.HandleDeletePolicy)

			// Identity Sources
			r.Get("/identity-sources", adminapi.HandleListIdentitySources)
			r.Post("/identity-sources", adminapi.HandleCreateIdentitySource)
			r.Put("/identity-sources/{id}", adminapi.HandleUpdateIdentitySource)
			r.Delete("/identity-sources/{id}", adminapi.HandleDeleteIdentitySource)

			// Portal Profiles
			r.Get("/portal-profiles", adminapi.HandleListPortalProfiles)
			r.Post("/portal-profiles", adminapi.HandleCreatePortalProfile)
			r.Put("/portal-profiles/{id}", adminapi.HandleUpdatePortalProfile)
			r.Delete("/portal-profiles/{id}", adminapi.HandleDeletePortalProfile)

			// Bandwidth Profiles
			r.Get("/bandwidth-profiles", adminapi.HandleListBandwidthProfiles)
			r.Post("/bandwidth-profiles", adminapi.HandleCreateBandwidthProfile)
			r.Put("/bandwidth-profiles/{id}", adminapi.HandleUpdateBandwidthProfile)
			r.Delete("/bandwidth-profiles/{id}", adminapi.HandleDeleteBandwidthProfile)

			// RADIUS Clients
			r.Get("/radius-clients", adminapi.HandleListRadiusClients)
			r.Post("/radius-clients", adminapi.HandleCreateRadiusClient)
			r.Put("/radius-clients/{id}", adminapi.HandleUpdateRadiusClient)
			r.Delete("/radius-clients/{id}", adminapi.HandleDeleteRadiusClient)

			// Sessions
			r.Get("/sessions", adminapi.HandleListSessions)
			r.Delete("/sessions/{id}", adminapi.HandleTerminateSession)

			// Alerts
			r.Get("/alerts", adminapi.HandleListAlerts)
			r.Post("/alerts/{id}/acknowledge", adminapi.HandleAcknowledgeAlert)

			// Config Revisions
			r.Get("/config-revisions", adminapi.HandleListConfigRevisions)
			r.Post("/config/rollback/{revision}", adminapi.HandleRollback)

			// Backups
			r.Get("/backups/config", adminapi.HandleExportConfig)
			r.Post("/backups/config", adminapi.HandleImportConfig)

			// AI recommendations
			r.Get("/ai-recommendations", adminapi.HandleListAIRecommendations)
			r.Post("/ai-recommendations/run", adminapi.HandleRunAIAnalysis)
			r.Post("/ai-recommendations/{id}/acknowledge", adminapi.HandleAcknowledgeAIRecommendation)

			// Staging and Apply
			r.Get("/staged-changes", adminapi.HandleListStagedChanges)
			r.Post("/apply", adminapi.HandleApplyChanges)
			r.Post("/validate", adminapi.HandleValidateStagedChanges)
		})

		mountAdminUI(r, logger)

		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.AdminPort),
			Handler: r,
		}

		go func() {
			logger.Info("admin API listening", zap.Int("port", cfg.AdminPort))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("server failed", zap.Error(err))
			}
		}()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Info("shutting down admin API")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func adminAllowedOrigins() []string {
	raw := os.Getenv("AEGIS_ADMIN_ALLOWED_ORIGINS")
	if raw == "" {
		return []string{
			"https://aegis.local",
			"http://localhost:5173",
			"http://127.0.0.1:5173",
		}
	}
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		if origin := strings.TrimSpace(part); origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

func mountAdminUI(r chi.Router, logger *zap.Logger) {
	uiDir := resolveAdminUIDir()
	if uiDir == "" {
		logger.Info("admin UI bundle not found; API-only mode enabled")
		return
	}

	indexPath := filepath.Join(uiDir, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		logger.Warn("admin UI bundle missing index.html", zap.String("dir", uiDir), zap.Error(err))
		return
	}

	logger.Info("serving admin UI", zap.String("dir", uiDir))
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			http.NotFound(w, req)
			return
		}

		cleanPath := path.Clean("/" + strings.TrimPrefix(req.URL.Path, "/"))
		switch {
		case cleanPath == "/health":
			http.NotFound(w, req)
			return
		case strings.HasPrefix(cleanPath, "/api/"):
			http.NotFound(w, req)
			return
		}

		relativePath := strings.TrimPrefix(cleanPath, "/")
		if relativePath == "" {
			http.ServeFile(w, req, indexPath)
			return
		}

		candidate := filepath.Join(uiDir, filepath.FromSlash(relativePath))
		if fileExists(candidate) {
			http.ServeFile(w, req, candidate)
			return
		}

		http.ServeFile(w, req, indexPath)
	})
}

func resolveAdminUIDir() string {
	candidates := []string{}
	if configured := strings.TrimSpace(os.Getenv("AEGIS_ADMIN_UI_DIR")); configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates,
		"/opt/aegisnas/admin-ui",
		filepath.Join("web", "admin-ui", "dist"),
		filepath.Join(".", "web", "admin-ui", "dist"),
	)

	for _, candidate := range candidates {
		if fileExists(filepath.Join(candidate, "index.html")) {
			return candidate
		}
	}
	return ""
}

func fileExists(target string) bool {
	info, err := os.Stat(target)
	return err == nil && !info.IsDir()
}
