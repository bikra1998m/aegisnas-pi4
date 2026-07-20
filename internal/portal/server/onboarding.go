package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
	"github.com/yourorg/aegisnas-pi4/internal/portal"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
	"github.com/yourorg/aegisnas-pi4/internal/supplicantprofile"
	"go.uber.org/zap"
)

func (s *Server) HandleOnboardingPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Onboarding.PortalEnabled {
		http.Redirect(w, r, "/success?client_mac="+url.QueryEscape(r.URL.Query().Get("client_mac")), http.StatusFound)
		return
	}
	mac := strings.TrimSpace(r.URL.Query().Get("client_mac"))
	client, ok := s.stateMachine.GetClient(mac)
	if !ok || client.State != portal.StateAuthenticated {
		http.Redirect(w, r, "/?client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}
	s.observeClient(r, mac, client.IP, client.Username, client.SessionID)
	data := map[string]any{
		"Branding":                   s.cfg.Portal.Branding,
		"ClientMAC":                  mac,
		"Username":                   client.Username,
		"CertificateEnrollment":      s.cfg.Onboarding.CertificateEnrollmentEnabled,
		"EAPTLSEnabled":              s.cfg.Onboarding.EAPTLSEnabled,
		"SupplicantLifecycleEnabled": s.cfg.Onboarding.SupplicantLifecycle.Enabled,
		"Error":                      r.URL.Query().Get("error"),
		"Success":                    r.URL.Query().Get("success"),
	}
	s.render(w, "onboarding.html", data)
}

func (s *Server) HandleOnboardingRegister(w http.ResponseWriter, r *http.Request) {
	mac := strings.TrimSpace(r.FormValue("client_mac"))
	client, ok := s.stateMachine.GetClient(mac)
	if !ok || client.State != portal.StateAuthenticated {
		http.Redirect(w, r, "/?client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}
	result, err := s.onboarding.RegisterDevice(r.Context(), onboarding.RegisterRequest{
		MAC:          mac,
		Username:     client.Username,
		SessionID:    client.SessionID,
		LastIP:       client.IP,
		FriendlyName: strings.TrimSpace(r.FormValue("friendly_name")),
		Ownership:    strings.TrimSpace(r.FormValue("ownership")),
		Platform:     strings.TrimSpace(r.FormValue("platform")),
		UserAgent:    r.UserAgent(),
		Source:       "portal-onboarding",
	})
	if err != nil {
		s.logger.Warn("device onboarding failed", zap.String("mac", mac), zap.String("username", client.Username), zap.Error(err))
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	if result.Certificate != nil {
		http.Redirect(w, r, fmt.Sprintf("/onboarding/download/%s?client_mac=%s", url.PathEscape(result.Certificate.ID), url.QueryEscape(mac)), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&success=registered", http.StatusFound)
}

func (s *Server) HandleOnboardingDownload(w http.ResponseWriter, r *http.Request) {
	mac := strings.TrimSpace(r.URL.Query().Get("client_mac"))
	client, ok := s.stateMachine.GetClient(mac)
	if !ok || client.State != portal.StateAuthenticated {
		http.Redirect(w, r, "/?client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}
	certID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/onboarding/download/"))
	item, certPEM, keyPEM, caPEM, err := s.onboarding.LoadCertificateBundle(certID)
	if err != nil {
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	device, err := s.onboarding.GetDeviceByMAC(item.DeviceMAC)
	if err != nil || !strings.EqualFold(strings.ToLower(strings.TrimSpace(device.MAC)), strings.ToLower(strings.TrimSpace(mac))) {
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&error=certificate_not_authorized", http.StatusFound)
		return
	}
	filename := strings.ReplaceAll(client.Username+"-"+item.DeviceMAC, ":", "-") + ".pem"
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = fmt.Fprintf(w, "%s\n%s\n%s", certPEM, keyPEM, caPEM)
}

func (s *Server) HandleOnboardingProfileDownload(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Onboarding.SupplicantLifecycle.Enabled {
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(r.URL.Query().Get("client_mac"))+"&error=supplicant_lifecycle_disabled", http.StatusFound)
		return
	}
	mac := strings.TrimSpace(r.URL.Query().Get("client_mac"))
	client, ok := s.stateMachine.GetClient(mac)
	if !ok || client.State != portal.StateAuthenticated {
		http.Redirect(w, r, "/?client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}
	platform := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/onboarding/profile/"))
	signingSecret, signingAvailable, err := s.resolveSupplicantProfileSigningKey(r)
	if err != nil && s.cfg.Onboarding.SupplicantLifecycle.RequireSignedProfiles && s.cfg.Onboarding.SupplicantLifecycle.Mode == "enforce" && s.cfg.Onboarding.SupplicantLifecycle.FailClosed {
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	pkg, err := supplicantprofile.BuildProfilePackage(s.cfg, supplicantprofile.ProfileRequest{
		Platform:           platform,
		Username:           client.Username,
		DeviceID:           mac,
		EAPMethod:          s.cfg.Onboarding.SupplicantLifecycle.DefaultEAPMethod,
		InnerMethod:        s.cfg.Onboarding.SupplicantLifecycle.DefaultInnerMethod,
		IncludePasswordURL: true,
		Delivery:           "portal",
		Details:            map[string]string{"client_ip": client.IP, "session_id": client.SessionID},
	}, signingSecret)
	if err != nil {
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	tlsProtected := supplicantPortalTLS(r)
	decision := supplicantprofile.Evaluate(s.cfg, supplicantprofile.EvaluationRequest{
		Protocol:                   "portal",
		Platform:                   pkg.Manifest.Platform,
		Username:                   client.Username,
		DeviceID:                   mac,
		EAPMethod:                  pkg.Manifest.EAPMethod,
		InnerMethod:                pkg.Manifest.InnerMethod,
		IdentitySource:             "portal",
		TLSProtected:               tlsProtected,
		PasswordVerifierCompatible: true,
		ProfileRequested:           true,
		ProfileSigned:              pkg.Signature != "",
		SigningKeyAvailable:        signingAvailable,
		TrustAnchorPinned:          len(pkg.Manifest.TrustAnchorPins) > 0,
		ServerNameMatched:          len(pkg.Manifest.ServerNames) > 0,
		DeliveryTokenValid:         true,
		DeviceManaged:              true,
		CertificateLifecycleReady:  s.cfg.Onboarding.CertificateLifecycle.Enabled,
		Details: map[string]string{
			"profile_id":              pkg.ProfileID,
			"ssid":                    pkg.Manifest.SSID,
			"content_sha256":          pkg.ContentSHA256,
			"signature_algorithm":     pkg.SignatureAlgorithm,
			"signing_key_fingerprint": pkg.SigningKeyFingerprint,
		},
	})
	if s.cfg.Onboarding.SupplicantLifecycle.AuditEnabled {
		event := db.SupplicantLifecycleEvent{
			ObservedAt:                time.Now().UTC(),
			Protocol:                  decision.Protocol,
			Platform:                  decision.Platform,
			Decision:                  decision.Decision,
			Action:                    decision.Action,
			Reason:                    decision.Reason,
			UsernameHash:              decision.UsernameHash,
			DeviceIDHash:              decision.DeviceIDHash,
			EAPMethod:                 decision.EAPMethod,
			InnerMethod:               decision.InnerMethod,
			IdentitySource:            decision.IdentitySource,
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
			Details:                   decision.Details,
		}
		_ = db.RecordSupplicantLifecycleEvent(event, s.cfg.Onboarding.SupplicantLifecycle.EventRetentionLimit, s.cfg.Onboarding.SupplicantLifecycle.ProfileRetentionLimit)
	}
	if decision.Decision != "accepted" && s.cfg.Onboarding.SupplicantLifecycle.Mode == "enforce" && s.cfg.Onboarding.SupplicantLifecycle.FailClosed {
		http.Redirect(w, r, "/onboarding?client_mac="+url.QueryEscape(mac)+"&error="+url.QueryEscape(decision.Reason), http.StatusFound)
		return
	}
	filename := strings.ReplaceAll(client.Username+"-"+mac+"-"+pkg.Manifest.Platform, ":", "-") + ".aegisnas-profile.json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_ = json.NewEncoder(w).Encode(pkg)
}

func (s *Server) resolveSupplicantProfileSigningKey(r *http.Request) (string, bool, error) {
	ref := strings.TrimSpace(s.cfg.Onboarding.SupplicantLifecycle.ProfileSigningKeyRef)
	if ref == "" {
		return "", false, nil
	}
	value, err := secrets.NewResolver(secrets.OptionsFromConfig(s.cfg)).Resolve(r.Context(), ref)
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func supplicantPortalTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}
