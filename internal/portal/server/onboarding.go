package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
	"github.com/yourorg/aegisnas-pi4/internal/portal"
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
