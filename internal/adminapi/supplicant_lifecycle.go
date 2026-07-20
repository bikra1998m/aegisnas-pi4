package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"github.com/yourorg/aegisnas-pi4/internal/supplicantprofile"
)

type supplicantLifecycleResponse struct {
	supplicantprofile.Report
	Events   []db.SupplicantLifecycleEvent  `json:"events,omitempty"`
	Profiles []db.SupplicantProfileDelivery `json:"profiles,omitempty"`
}

type supplicantLifecycleEvaluationRequest struct {
	Protocol                   string            `json:"protocol"`
	Platform                   string            `json:"platform"`
	Username                   string            `json:"username"`
	DeviceID                   string            `json:"device_id"`
	Tenant                     string            `json:"tenant"`
	EAPMethod                  string            `json:"eap_method"`
	InnerMethod                string            `json:"inner_method"`
	IdentitySource             string            `json:"identity_source"`
	PasswordExpired            bool              `json:"password_expired"`
	DaysUntilExpiry            int               `json:"days_until_expiry"`
	PasswordChangeRequested    bool              `json:"password_change_requested"`
	OldPasswordVerified        bool              `json:"old_password_verified"`
	NewPasswordMeetsPolicy     bool              `json:"new_password_meets_policy"`
	MFAComplete                bool              `json:"mfa_complete"`
	TLSProtected               bool              `json:"tls_protected"`
	PasswordVerifierCompatible bool              `json:"password_verifier_compatible"`
	ProfileRequested           bool              `json:"profile_requested"`
	ProfileSigned              bool              `json:"profile_signed"`
	SigningKeyAvailable        bool              `json:"signing_key_available"`
	TrustAnchorPinned          bool              `json:"trust_anchor_pinned"`
	ServerNameMatched          bool              `json:"server_name_matched"`
	DeliveryTokenValid         bool              `json:"delivery_token_valid"`
	DeviceManaged              bool              `json:"device_managed"`
	CertificateLifecycleReady  bool              `json:"certificate_lifecycle_ready"`
	LatencyMS                  int               `json:"latency_ms"`
	Audit                      bool              `json:"audit"`
	Details                    map[string]string `json:"details"`
}

type supplicantProfileRenderRequest struct {
	Platform            string            `json:"platform"`
	Username            string            `json:"username"`
	DeviceID            string            `json:"device_id"`
	Tenant              string            `json:"tenant"`
	EAPMethod           string            `json:"eap_method"`
	InnerMethod         string            `json:"inner_method"`
	IdentitySource      string            `json:"identity_source"`
	IncludePasswordURL  bool              `json:"include_password_url"`
	CertificateTemplate string            `json:"certificate_template"`
	Delivery            string            `json:"delivery"`
	TLSProtected        bool              `json:"tls_protected"`
	DeliveryTokenValid  bool              `json:"delivery_token_valid"`
	DeviceManaged       bool              `json:"device_managed"`
	Audit               bool              `json:"audit"`
	Details             map[string]string `json:"details"`
}

func HandleGetSupplicantLifecycle(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	events, err := db.ListSupplicantLifecycleEvents(db.SupplicantLifecycleEventFilter{
		Decision:  r.URL.Query().Get("decision"),
		Platform:  r.URL.Query().Get("platform"),
		EAPMethod: r.URL.Query().Get("eap_method"),
		Limit:     limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	profiles, err := db.ListSupplicantProfileDeliveries(db.SupplicantProfileDeliveryFilter{
		Status:   r.URL.Query().Get("status"),
		Platform: r.URL.Query().Get("platform"),
		Limit:    limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeSupplicantLifecycle(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := supplicantprofile.BuildReport(cfg, supplicantRuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, supplicantLifecycleResponse{Report: report, Events: events, Profiles: profiles})
}

func HandleEvaluateSupplicantLifecycle(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req supplicantLifecycleEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := supplicantprofile.Evaluate(cfg, supplicantprofile.EvaluationRequest{
		Protocol:                   req.Protocol,
		Platform:                   req.Platform,
		Username:                   req.Username,
		DeviceID:                   req.DeviceID,
		Tenant:                     req.Tenant,
		EAPMethod:                  req.EAPMethod,
		InnerMethod:                req.InnerMethod,
		IdentitySource:             req.IdentitySource,
		PasswordExpired:            req.PasswordExpired,
		DaysUntilExpiry:            req.DaysUntilExpiry,
		PasswordChangeRequested:    req.PasswordChangeRequested,
		OldPasswordVerified:        req.OldPasswordVerified,
		NewPasswordMeetsPolicy:     req.NewPasswordMeetsPolicy,
		MFAComplete:                req.MFAComplete,
		TLSProtected:               req.TLSProtected,
		PasswordVerifierCompatible: req.PasswordVerifierCompatible,
		ProfileRequested:           req.ProfileRequested,
		ProfileSigned:              req.ProfileSigned,
		SigningKeyAvailable:        req.SigningKeyAvailable,
		TrustAnchorPinned:          req.TrustAnchorPinned,
		ServerNameMatched:          req.ServerNameMatched,
		DeliveryTokenValid:         req.DeliveryTokenValid,
		DeviceManaged:              req.DeviceManaged,
		CertificateLifecycleReady:  req.CertificateLifecycleReady,
		Details:                    req.Details,
	})
	audited := req.Audit && cfg.Onboarding.SupplicantLifecycle.AuditEnabled
	if audited {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		_ = db.RecordSupplicantLifecycleEvent(supplicantLifecycleEventFromDecision(decision, latency), cfg.Onboarding.SupplicantLifecycle.EventRetentionLimit, cfg.Onboarding.SupplicantLifecycle.ProfileRetentionLimit)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  audited,
	})
}

func HandleRenderSupplicantProfile(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req supplicantProfileRenderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	signingSecret, signingAvailable, err := resolveSupplicantSigningKey(r.Context(), cfg)
	if err != nil && cfg.Onboarding.SupplicantLifecycle.RequireSignedProfiles && cfg.Onboarding.SupplicantLifecycle.Mode == "enforce" && cfg.Onboarding.SupplicantLifecycle.FailClosed {
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
		return
	}
	pkg, err := supplicantprofile.BuildProfilePackage(cfg, supplicantprofile.ProfileRequest{
		Platform:            req.Platform,
		Username:            req.Username,
		DeviceID:            req.DeviceID,
		Tenant:              req.Tenant,
		EAPMethod:           req.EAPMethod,
		InnerMethod:         req.InnerMethod,
		IncludePasswordURL:  req.IncludePasswordURL,
		CertificateTemplate: req.CertificateTemplate,
		Delivery:            defaultString(req.Delivery, "api"),
		Details:             req.Details,
	}, signingSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	decision := supplicantprofile.Evaluate(cfg, supplicantprofile.EvaluationRequest{
		Protocol:                   defaultString(req.Delivery, "api"),
		Platform:                   pkg.Manifest.Platform,
		Username:                   req.Username,
		DeviceID:                   req.DeviceID,
		Tenant:                     req.Tenant,
		EAPMethod:                  pkg.Manifest.EAPMethod,
		InnerMethod:                pkg.Manifest.InnerMethod,
		IdentitySource:             req.IdentitySource,
		TLSProtected:               req.TLSProtected,
		PasswordVerifierCompatible: true,
		ProfileRequested:           true,
		ProfileSigned:              pkg.Signature != "",
		SigningKeyAvailable:        signingAvailable,
		TrustAnchorPinned:          len(pkg.Manifest.TrustAnchorPins) > 0,
		ServerNameMatched:          len(pkg.Manifest.ServerNames) > 0,
		DeliveryTokenValid:         req.DeliveryTokenValid,
		DeviceManaged:              req.DeviceManaged,
		CertificateLifecycleReady:  cfg.Onboarding.CertificateLifecycle.Enabled,
		Details:                    supplicantProfileDetails(pkg, req.Details),
	})
	audited := req.Audit && cfg.Onboarding.SupplicantLifecycle.AuditEnabled
	if audited {
		event := supplicantLifecycleEventFromDecision(decision, 0)
		_ = db.RecordSupplicantLifecycleEvent(event, cfg.Onboarding.SupplicantLifecycle.EventRetentionLimit, cfg.Onboarding.SupplicantLifecycle.ProfileRetentionLimit)
		if decision.Decision == "accepted" {
			_ = db.UpsertSupplicantProfileDelivery(supplicantProfileDeliveryFromPackage(pkg, decision), cfg.Onboarding.SupplicantLifecycle.ProfileRetentionLimit)
		}
	}
	if decision.Decision != "accepted" && cfg.Onboarding.SupplicantLifecycle.Mode == "enforce" && cfg.Onboarding.SupplicantLifecycle.FailClosed {
		http.Error(w, decision.Reason, http.StatusPreconditionFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":  pkg,
		"decision": decision,
		"audited":  audited,
	})
}

func supplicantRuntimeSummaryFromDB(summary db.SupplicantLifecycleSummary) supplicantprofile.RuntimeSummary {
	return supplicantprofile.RuntimeSummary{
		TotalEvents:            summary.TotalEvents,
		Accepted:               summary.Accepted,
		Rejected:               summary.Rejected,
		MonitorAllowed:         summary.MonitorAllowed,
		PasswordChangeRequired: summary.PasswordChangeRequired,
		PasswordChanged:        summary.PasswordChanged,
		ProfilesDelivered:      summary.ProfilesDelivered,
		UnsignedProfileBlocked: summary.UnsignedProfileBlocked,
		TrustPinFailures:       summary.TrustPinFailures,
		VerifierFailures:       summary.VerifierFailures,
		TLSFailures:            summary.TLSFailures,
		ActiveProfiles:         summary.ActiveProfiles,
		ExpiredProfiles:        summary.ExpiredProfiles,
		ByDecision:             summary.ByDecision,
		ByPlatform:             summary.ByPlatform,
		ByEAPMethod:            summary.ByEAPMethod,
		LastEventAt:            summary.LastEventAt,
		LastRejectedReason:     summary.LastRejectedReason,
		LastProfileDeliveredAt: summary.LastProfileDeliveredAt,
	}
}

func supplicantLifecycleEventFromDecision(decision supplicantprofile.Decision, latency int) db.SupplicantLifecycleEvent {
	return db.SupplicantLifecycleEvent{
		ObservedAt:                time.Now().UTC(),
		Protocol:                  decision.Protocol,
		Platform:                  decision.Platform,
		Decision:                  decision.Decision,
		Action:                    decision.Action,
		Reason:                    decision.Reason,
		UsernameHash:              decision.UsernameHash,
		DeviceIDHash:              decision.DeviceIDHash,
		Tenant:                    decision.Tenant,
		EAPMethod:                 decision.EAPMethod,
		InnerMethod:               decision.InnerMethod,
		IdentitySource:            decision.IdentitySource,
		PasswordExpired:           decision.PasswordExpired,
		DaysUntilExpiry:           decision.DaysUntilExpiry,
		PasswordChangeRequested:   decision.PasswordChangeRequested,
		PasswordChangeRequired:    decision.PasswordChangeRequired,
		PasswordChanged:           decision.PasswordChanged,
		OldPasswordVerified:       decision.OldPasswordVerified,
		NewPasswordMeetsPolicy:    decision.NewPasswordMeetsPolicy,
		MFAComplete:               decision.MFAComplete,
		TLSProtected:              decision.TLSProtected,
		VerifierCompatible:        decision.PasswordVerifierCompatible,
		ProfileRequested:          decision.ProfileRequested,
		ProfileSigned:             decision.ProfileSigned,
		SigningKeyAvailable:       decision.SigningKeyAvailable,
		TrustAnchorPinned:         decision.TrustAnchorPinned,
		ServerNameMatched:         decision.ServerNameMatched,
		DeliveryTokenValid:        decision.DeliveryTokenValid,
		DeviceManaged:             decision.DeviceManaged,
		CertificateLifecycleReady: decision.CertificateLifecycleReady,
		PolicyMode:                decision.PolicyMode,
		LatencyMS:                 latency,
		Details:                   decision.Details,
	}
}

func supplicantProfileDeliveryFromPackage(pkg supplicantprofile.ProfilePackage, decision supplicantprofile.Decision) db.SupplicantProfileDelivery {
	expiresAt, _ := time.Parse(time.RFC3339, pkg.Manifest.ExpiresAt)
	return db.SupplicantProfileDelivery{
		DeliveryKey:          db.SupplicantLifecycleDeliveryKey(decision.UsernameHash, decision.DeviceIDHash, pkg.Manifest.Platform, pkg.Manifest.SSID),
		UpdatedAt:            time.Now().UTC(),
		Status:               "active",
		Platform:             pkg.Manifest.Platform,
		UsernameHash:         decision.UsernameHash,
		DeviceIDHash:         decision.DeviceIDHash,
		Tenant:               decision.Tenant,
		SSID:                 pkg.Manifest.SSID,
		EAPMethod:            pkg.Manifest.EAPMethod,
		InnerMethod:          pkg.Manifest.InnerMethod,
		ProfileHash:          pkg.ContentSHA256,
		SignatureFingerprint: pkg.SigningKeyFingerprint,
		ContentType:          pkg.ContentType,
		FileExtension:        pkg.FileExtension,
		ExpiresAt:            expiresAt,
		PolicyMode:           decision.PolicyMode,
		Details:              supplicantProfileDetails(pkg, map[string]string{"release_checklist": "nas-0028-release-certification-checklist.md"}),
	}
}

func supplicantProfileDetails(pkg supplicantprofile.ProfilePackage, extra map[string]string) map[string]string {
	details := map[string]string{
		"profile_id":              pkg.ProfileID,
		"ssid":                    pkg.Manifest.SSID,
		"content_type":            pkg.ContentType,
		"file_extension":          pkg.FileExtension,
		"content_sha256":          pkg.ContentSHA256,
		"signature_algorithm":     pkg.SignatureAlgorithm,
		"signing_key_fingerprint": pkg.SigningKeyFingerprint,
	}
	for key, value := range extra {
		key = strings.TrimSpace(key)
		if key != "" {
			details[key] = strings.TrimSpace(value)
		}
	}
	return details
}

func resolveSupplicantSigningKey(ctx context.Context, cfg *config.Config) (string, bool, error) {
	ref := strings.TrimSpace(cfg.Onboarding.SupplicantLifecycle.ProfileSigningKeyRef)
	if ref == "" {
		return "", false, nil
	}
	value, err := secrets.NewResolver(secrets.OptionsFromConfig(cfg)).Resolve(ctx, ref)
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
