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

		if err := db.InitConfigured(cmd.Context(), cfg); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()
		if err := adminapi.StartNetworkRecoveryMonitor(cfg, logger); err != nil {
			return fmt.Errorf("resume network recovery monitor: %w", err)
		}
		if err := adminapi.StartDiagnosticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start diagnostics export scheduler: %w", err)
		}
		if err := adminapi.StartAuditExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start audit export scheduler: %w", err)
		}
		if err := adminapi.StartSessionExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start session export scheduler: %w", err)
		}
		if err := adminapi.StartSessionAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start session analytics export scheduler: %w", err)
		}
		if err := adminapi.StartVoucherAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start voucher analytics export scheduler: %w", err)
		}
		if err := adminapi.StartVoucherAgingAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start voucher aging analytics export scheduler: %w", err)
		}
		if err := adminapi.StartVoucherRedemptionAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start voucher redemption analytics export scheduler: %w", err)
		}
		if err := adminapi.StartVoucherExpiryAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start voucher expiry analytics export scheduler: %w", err)
		}
		if err := adminapi.StartGuestLifecycleExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest lifecycle export scheduler: %w", err)
		}
		if err := adminapi.StartGuestInviteAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest invite analytics export scheduler: %w", err)
		}
		if err := adminapi.StartGuestConversionAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest conversion analytics export scheduler: %w", err)
		}
		if err := adminapi.StartGuestRejectionAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest rejection analytics export scheduler: %w", err)
		}
		if err := adminapi.StartGuestDeliveryAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest delivery analytics export scheduler: %w", err)
		}
		if err := adminapi.StartGuestDeliveryFailuresExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest delivery failures export scheduler: %w", err)
		}
		if err := adminapi.StartGuestSponsorAnalyticsExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start guest sponsor analytics export scheduler: %w", err)
		}
		if err := adminapi.StartIntegrationExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start integration export scheduler: %w", err)
		}
		if err := adminapi.StartHAExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start ha export scheduler: %w", err)
		}
		if err := adminapi.StartNetworkExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start network export scheduler: %w", err)
		}
		if err := adminapi.StartUpstreamAAAExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start upstream aaa export scheduler: %w", err)
		}
		if err := adminapi.StartUpgradeReadinessExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start upgrade readiness export scheduler: %w", err)
		}
		if err := adminapi.StartSupportBundleExportScheduler(cfg, logger); err != nil {
			return fmt.Errorf("start support bundle export scheduler: %w", err)
		}

		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(30 * time.Second))
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   adminAllowedOrigins(),
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-AegisNAS-Enrollment-Token"},
			AllowCredentials: false,
		}))

		// Public health endpoint
		health.RegisterRoutes(r)

		registerAdminRoutes(r, cfg)

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

func registerAdminRoutes(r chi.Router, cfg *config.Config) {
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/openapi.json", adminapi.HandleGetOpenAPI)
		r.Get("/auth/options", adminapi.HandleAdminAuthOptions)
		r.Get("/auth/sso/start", adminapi.HandleAdminSSOStart)
		r.Get("/auth/sso/metadata", adminapi.HandleAdminSSOMetadata)
		r.Post("/nas/enroll", adminapi.HandleEnrollNASClient)

		r.Group(func(r chi.Router) {
			r.Use(adminapi.AuthMiddleware)
			r.Use(adminapi.AuthorizationMiddleware)
			r.Get("/auth/validate", adminapi.HandleValidateToken)
			r.Post("/auth/logout", adminapi.HandleLogout)
			r.Get("/system/settings", adminapi.HandleGetSystemSettings)
			r.Get("/system/status", adminapi.HandleGetSystemStatus)
			r.Get("/system/production-readiness", adminapi.HandleGetProductionReadiness)
			r.Get("/system/controller-adapters", adminapi.HandleGetControllerAdapters)
			r.Get("/system/controller-sync/preview", adminapi.HandlePreviewControllerSync)
			r.Post("/system/controller-sync", adminapi.HandleRunControllerSync)
			r.Get("/system/vendor-compatibility", adminapi.HandleGetVendorCompatibility)
			r.Get("/system/dictionary-release-profiles", adminapi.HandleGetDictionaryReleaseProfiles)
			r.Get("/system/compatibility-evidence", adminapi.HandleGetCompatibilityEvidence)
			r.Get("/system/vsa-codec", adminapi.HandleGetVSACodec)
			r.Get("/system/opaque-passthrough", adminapi.HandleGetOpaquePassThrough)
			r.Get("/system/radius-hardening", adminapi.HandleGetRadiusHardening)
			r.Get("/system/radsec-credentials", adminapi.HandleGetRadSecCredentials)
			r.Get("/system/nas-clients", adminapi.HandleGetNASClients)
			r.Get("/system/nas-clients/enrollments", adminapi.HandleListNASClientEnrollments)
			r.Post("/system/nas-clients/enrollments", adminapi.HandleCreateNASClientEnrollment)
			r.Post("/system/nas-clients/enrollments/{id}/approve", adminapi.HandleApproveNASClientEnrollment)
			r.Post("/system/nas-clients/enrollments/{id}/reject", adminapi.HandleRejectNASClientEnrollment)
			r.Post("/system/nas-clients/enrollments/{id}/revoke", adminapi.HandleRevokeNASClientEnrollment)
			r.Get("/system/nas-clients/templates", adminapi.HandleListNASClientCapabilityTemplates)
			r.Post("/system/nas-clients/templates", adminapi.HandleUpsertNASClientCapabilityTemplate)
			r.Put("/system/nas-clients/templates/{name}", adminapi.HandleUpsertNASClientCapabilityTemplate)
			r.Delete("/system/nas-clients/templates/{name}", adminapi.HandleDeleteNASClientCapabilityTemplate)
			r.Get("/system/proxy-routes", adminapi.HandleGetProxyRoutes)
			r.Get("/system/transport-policy", adminapi.HandleGetTransportPolicy)
			r.Get("/system/proxy-policy", adminapi.HandleGetProxyPolicy)
			r.Get("/system/accounting-spool", adminapi.HandleGetAccountingSpool)
			r.Post("/system/accounting-spool/replay", adminapi.HandleReplayAccountingSpool)
			r.Get("/system/secret-providers", adminapi.HandleGetSecretProviders)
			r.Get("/system/database", adminapi.HandleGetDatabaseStatus)
			r.Get("/system/attribute-registry", adminapi.HandleGetAttributeRegistry)
			r.Get("/system/vendor-identity", adminapi.HandleGetVendorIdentity)
			r.Post("/system/vendor-identity/migrations/preview", adminapi.HandlePreviewVendorIdentityMigration)
			r.Post("/system/vendor-identity/migrations/apply", adminapi.HandleApplyVendorIdentityMigration)
			r.Post("/system/vendor-identity/migrations/{id}/rollback", adminapi.HandleRollbackVendorIdentityMigration)
			r.Get("/system/vendor-observability", adminapi.HandleGetVendorObservability)
			r.Get("/system/vendor-observability/export", adminapi.HandleExportVendorObservability)
			r.Post("/system/vendor-reply-preview", adminapi.HandlePreviewVendorReply)
			r.Get("/system/dhcp-leases", adminapi.HandleListDHCPLeases)
			r.Get("/system/dhcp-lease-history", adminapi.HandleListDHCPLeaseHistory)
			r.Get("/system/dhcp-lease-history/export", adminapi.HandleExportDHCPLeaseHistory)
			r.Get("/system/session-history", adminapi.HandleListSessionHistory)
			r.Get("/system/session-history/export", adminapi.HandleExportSessionHistory)
			r.Get("/system/session-analytics", adminapi.HandleGetSessionAnalytics)
			r.Get("/system/session-analytics/export", adminapi.HandleExportSessionAnalytics)
			r.Get("/system/voucher-analytics", adminapi.HandleGetVoucherAnalytics)
			r.Get("/system/voucher-analytics/export", adminapi.HandleExportVoucherAnalytics)
			r.Get("/system/voucher-aging-analytics", adminapi.HandleGetVoucherAgingAnalytics)
			r.Get("/system/voucher-aging-analytics/export", adminapi.HandleExportVoucherAgingAnalytics)
			r.Get("/system/voucher-redemption-analytics", adminapi.HandleGetVoucherRedemptionAnalytics)
			r.Get("/system/voucher-redemption-analytics/export", adminapi.HandleExportVoucherRedemptionAnalytics)
			r.Get("/system/voucher-expiry-analytics", adminapi.HandleGetVoucherExpiryAnalytics)
			r.Get("/system/voucher-expiry-analytics/export", adminapi.HandleExportVoucherExpiryAnalytics)
			r.Get("/system/voucher-analytics-exports", adminapi.HandleListVoucherAnalyticsExports)
			r.Get("/system/voucher-analytics-exports/download", adminapi.HandleDownloadVoucherAnalyticsExport)
			r.Get("/system/voucher-aging-analytics-exports", adminapi.HandleListVoucherAgingAnalyticsExports)
			r.Get("/system/voucher-aging-analytics-exports/download", adminapi.HandleDownloadVoucherAgingAnalyticsExport)
			r.Get("/system/voucher-redemption-analytics-exports", adminapi.HandleListVoucherRedemptionAnalyticsExports)
			r.Get("/system/voucher-redemption-analytics-exports/download", adminapi.HandleDownloadVoucherRedemptionAnalyticsExport)
			r.Get("/system/voucher-expiry-analytics-exports", adminapi.HandleListVoucherExpiryAnalyticsExports)
			r.Get("/system/voucher-expiry-analytics-exports/download", adminapi.HandleDownloadVoucherExpiryAnalyticsExport)
			r.Get("/system/guest-lifecycle", adminapi.HandleGetGuestLifecycle)
			r.Get("/system/guest-lifecycle/export", adminapi.HandleExportGuestLifecycle)
			r.Get("/system/guest-invite-analytics", adminapi.HandleGetGuestInviteAnalytics)
			r.Get("/system/guest-invite-analytics/export", adminapi.HandleExportGuestInviteAnalytics)
			r.Get("/system/guest-invite-analytics-exports", adminapi.HandleListGuestInviteAnalyticsExports)
			r.Get("/system/guest-invite-analytics-exports/download", adminapi.HandleDownloadGuestInviteAnalyticsExport)
			r.Get("/system/guest-conversion-analytics", adminapi.HandleGetGuestConversionAnalytics)
			r.Get("/system/guest-conversion-analytics/export", adminapi.HandleExportGuestConversionAnalytics)
			r.Get("/system/guest-conversion-analytics-exports", adminapi.HandleListGuestConversionAnalyticsExports)
			r.Get("/system/guest-conversion-analytics-exports/download", adminapi.HandleDownloadGuestConversionAnalyticsExport)
			r.Get("/system/guest-delivery-analytics", adminapi.HandleGetGuestDeliveryAnalytics)
			r.Get("/system/guest-delivery-analytics/export", adminapi.HandleExportGuestDeliveryAnalytics)
			r.Get("/system/guest-rejection-analytics", adminapi.HandleGetGuestRejectionAnalytics)
			r.Get("/system/guest-rejection-analytics/export", adminapi.HandleExportGuestRejectionAnalytics)
			r.Get("/system/guest-rejection-analytics-exports", adminapi.HandleListGuestRejectionAnalyticsExports)
			r.Get("/system/guest-rejection-analytics-exports/download", adminapi.HandleDownloadGuestRejectionAnalyticsExport)
			r.Get("/system/guest-delivery-failures", adminapi.HandleGetGuestDeliveryFailures)
			r.Get("/system/guest-delivery-failures/export", adminapi.HandleExportGuestDeliveryFailures)
			r.Get("/system/guest-sponsor-analytics", adminapi.HandleGetGuestSponsorAnalytics)
			r.Get("/system/guest-sponsor-analytics/export", adminapi.HandleExportGuestSponsorAnalytics)
			r.Get("/system/guest-delivery-analytics-exports", adminapi.HandleListGuestDeliveryAnalyticsExports)
			r.Get("/system/guest-delivery-analytics-exports/download", adminapi.HandleDownloadGuestDeliveryAnalyticsExport)
			r.Get("/system/guest-delivery-failures-exports", adminapi.HandleListGuestDeliveryFailuresExports)
			r.Get("/system/guest-delivery-failures-exports/download", adminapi.HandleDownloadGuestDeliveryFailuresExport)
			r.Get("/system/guest-sponsor-analytics-exports", adminapi.HandleListGuestSponsorAnalyticsExports)
			r.Get("/system/guest-sponsor-analytics-exports/download", adminapi.HandleDownloadGuestSponsorAnalyticsExport)
			r.Get("/system/guest-lifecycle-exports", adminapi.HandleListGuestLifecycleExports)
			r.Get("/system/guest-lifecycle-exports/download", adminapi.HandleDownloadGuestLifecycleExport)
			r.Get("/system/session-analytics-exports", adminapi.HandleListSessionAnalyticsExports)
			r.Get("/system/session-analytics-exports/download", adminapi.HandleDownloadSessionAnalyticsExport)
			r.Get("/system/session-exports", adminapi.HandleListSessionExports)
			r.Get("/system/session-exports/download", adminapi.HandleDownloadSessionExport)
			r.Get("/system/upstream-aaa-history", adminapi.HandleListUpstreamAAAHistory)
			r.Get("/system/upstream-aaa-history/export", adminapi.HandleExportUpstreamAAAHistory)
			r.Get("/system/upstream-aaa-exports", adminapi.HandleListUpstreamAAAExports)
			r.Get("/system/upstream-aaa-exports/download", adminapi.HandleDownloadUpstreamAAAExport)
			r.Get("/system/audit-history", adminapi.HandleListAuditHistory)
			r.Get("/system/audit-history/export", adminapi.HandleExportAuditHistory)
			r.Get("/system/audit-exports", adminapi.HandleListAuditExports)
			r.Get("/system/audit-exports/download", adminapi.HandleDownloadAuditExport)
			r.Get("/system/integration-history", adminapi.HandleListIntegrationHistory)
			r.Get("/system/integration-history/export", adminapi.HandleExportIntegrationHistory)
			r.Get("/system/integration-exports", adminapi.HandleListIntegrationExports)
			r.Get("/system/integration-exports/download", adminapi.HandleDownloadIntegrationExport)
			r.Get("/system/network-preview", adminapi.HandlePreviewNetworkServices)
			r.Get("/system/network-backups", adminapi.HandleListNetworkSnapshots)
			r.Get("/system/network-apply-history", adminapi.HandleListNetworkApplyHistory)
			r.Get("/system/network-apply-history/export", adminapi.HandleExportNetworkApplyHistory)
			r.Get("/system/network-observability", adminapi.HandleGetNetworkObservability)
			r.Get("/system/network-exports", adminapi.HandleListNetworkExports)
			r.Get("/system/network-exports/download", adminapi.HandleDownloadNetworkExport)
			r.Get("/system/diagnostics-report", adminapi.HandleGetDiagnosticsReport)
			r.Get("/system/diagnostics-report/export", adminapi.HandleExportDiagnosticsReport)
			r.Get("/system/diagnostics-exports", adminapi.HandleListDiagnosticsExports)
			r.Get("/system/diagnostics-exports/download", adminapi.HandleDownloadDiagnosticsExport)
			r.Get("/system/support-bundle/summary", adminapi.HandleGetSupportBundleSummary)
			r.Get("/system/support-bundle", adminapi.HandleDownloadSupportBundle)
			r.Get("/system/support-bundle-exports", adminapi.HandleListSupportBundleExports)
			r.Get("/system/support-bundle-exports/download", adminapi.HandleDownloadSupportBundleExport)
			r.Get("/system/upgrade-readiness", adminapi.HandleGetUpgradeReadiness)
			r.Get("/system/upgrade-readiness-exports", adminapi.HandleListUpgradeReadinessExports)
			r.Get("/system/upgrade-readiness-exports/download", adminapi.HandleDownloadUpgradeReadinessExport)
			r.Get("/system/upgrade-rollback-package", adminapi.HandleDownloadUpgradeRollbackPackage)
			r.Post("/system/upgrade-rollback-package/inspect", adminapi.HandleInspectUpgradeRollbackPackage)
			r.Post("/system/upgrade-rollback-package/restore", adminapi.HandleRestoreUpgradeRollbackPackage)
			r.Get("/system/ha/history", adminapi.HandleListHAHistory)
			r.Get("/system/ha/history/export", adminapi.HandleExportHAHistory)
			r.Get("/system/ha/exports", adminapi.HandleListHAExports)
			r.Get("/system/ha/exports/download", adminapi.HandleDownloadHAExport)
			r.Get("/system/ha/replication-package", adminapi.HandleDownloadHAReplicationPackage)
			r.Get("/system/ha/replication-shared", adminapi.HandleGetSharedHAReplicationStatus)
			r.Get("/system/ha/replication-staged", adminapi.HandleListHAReplicationPackages)
			r.Put("/system/settings", adminapi.HandleUpdateSystemSettings)
			r.Post("/system/settings/evaluate", adminapi.HandleEvaluateSystemSettings)
			r.Get("/system/settings/export", adminapi.HandleExportSystemSettings)
			r.Post("/system/settings/import", adminapi.HandleImportSystemSettings)
			r.Post("/system/network-apply", adminapi.HandleApplyNetworkServices)
			r.Post("/system/network-recovery/confirm", adminapi.HandleConfirmNetworkRecovery)
			r.Post("/system/network-rollback", adminapi.HandleRollbackNetworkServices)
			r.Post("/system/ha/replication-package", adminapi.HandleImportHAReplicationPackage)
			r.Post("/system/ha/replication-stage-shared", adminapi.HandleStageLatestSharedHAReplicationPackage)
			r.Post("/system/ha/replication-activate", adminapi.HandleActivateHAReplicationPackage)
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

			// Devices
			r.Get("/devices", adminapi.HandleListDevices)
			r.Post("/devices/profile-observations", adminapi.HandleObserveDeviceProfile)
			r.Get("/devices/certificates", adminapi.HandleListDeviceCertificates)
			r.Get("/devices/certificates/crl", adminapi.HandleDownloadDeviceCRL)
			r.Get("/devices/certificates/{id}/status", adminapi.HandleGetDeviceCertificateStatus)
			r.Post("/devices/certificates/{id}/revoke", adminapi.HandleRevokeDeviceCertificate)
			r.Post("/devices/certificates/{id}/renew", adminapi.HandleRenewDeviceCertificate)
			r.Get("/devices/{id}/certificate", adminapi.HandleDownloadDeviceCertificate)

			// Admin principals
			r.Get("/admin-principals", adminapi.HandleListAdminPrincipals)
			r.Put("/admin-principals/{id}", adminapi.HandleUpdateAdminPrincipal)

			// Guest registrations
			r.Get("/guest-registrations", adminapi.HandleListGuestRegistrations)
			r.Post("/guest-registrations/{id}/approve", adminapi.HandleApproveGuestRegistration)
			r.Post("/guest-registrations/{id}/reject", adminapi.HandleRejectGuestRegistration)

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

			// Vendor-neutral ACL policies
			r.Get("/acl-policies", adminapi.HandleListACLPolicies)
			r.Post("/acl-policies", adminapi.HandleCreateACLPolicy)
			r.Put("/acl-policies/{id}", adminapi.HandleUpdateACLPolicy)
			r.Delete("/acl-policies/{id}", adminapi.HandleDeleteACLPolicy)

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
	})

	if callbackPath := adminapi.AdminSSOCallbackPath(cfg); callbackPath != "" {
		r.Get(callbackPath, adminapi.HandleAdminSSOCallback)
		r.Post(callbackPath, adminapi.HandleAdminSSOCallback)
	}
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
