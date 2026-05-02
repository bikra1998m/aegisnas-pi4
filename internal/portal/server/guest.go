package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/portal/guestworkflow"
	"github.com/yourorg/aegisnas-pi4/internal/portal/auth"
	"go.uber.org/zap"
)

// HandleRegistrationPage serves the self-registration form.
func (s *Server) HandleRegistrationPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Portal.GuestWorkflows.SelfRegistrationEnabled {
		http.Redirect(w, r, "/?error=registration_disabled&client_mac="+url.QueryEscape(r.URL.Query().Get("client_mac")), http.StatusFound)
		return
	}
	mac := strings.TrimSpace(r.URL.Query().Get("client_mac"))
	data := map[string]any{
		"Branding":                s.cfg.Portal.Branding,
		"ClientMAC":               mac,
		"Error":                   r.URL.Query().Get("error"),
		"SponsorApprovalRequired": s.cfg.Portal.GuestWorkflows.SponsorApprovalEnabled,
		"ApprovalDelivery":        strings.ToLower(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.ApprovalDelivery)),
		"InviteDelivery":          strings.ToLower(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.InviteDelivery)),
	}
	s.render(w, "register.html", data)
}

// HandleRegistrationSubmit creates a self-registration request.
func (s *Server) HandleRegistrationSubmit(w http.ResponseWriter, r *http.Request) {
	clientIP := clientIPOnly(r.RemoteAddr)
	mac := strings.TrimSpace(r.FormValue("client_mac"))
	record, err := s.guestFlows.Submit(r.Context(), guestworkflowRequestFromHTTP(r, clientIP, mac))
	if err != nil {
		s.logger.Warn("guest registration submit failed", zap.String("mac", mac), zap.Error(err))
		http.Redirect(w, r, "/register?error="+url.QueryEscape(err.Error())+"&client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}

	if strings.EqualFold(record.Status, "approved") || strings.EqualFold(record.Status, "completed") {
		http.Redirect(w, r, "/register/complete?id="+url.QueryEscape(record.ID)+"&token="+url.QueryEscape(record.GuestToken)+"&client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/register/pending?id="+url.QueryEscape(record.ID)+"&token="+url.QueryEscape(record.GuestToken)+"&client_mac="+url.QueryEscape(mac), http.StatusFound)
}

// HandleRegistrationPending shows the pending/approved/rejected status for a guest workflow request.
func (s *Server) HandleRegistrationPending(w http.ResponseWriter, r *http.Request) {
	record, err := s.guestFlows.GetForGuest(strings.TrimSpace(r.URL.Query().Get("id")), strings.TrimSpace(r.URL.Query().Get("token")))
	if err != nil {
		http.Redirect(w, r, "/?error=registration_not_found&client_mac="+url.QueryEscape(r.URL.Query().Get("client_mac")), http.StatusFound)
		return
	}
	data := map[string]any{
		"Branding":                s.cfg.Portal.Branding,
		"ClientMAC":               r.URL.Query().Get("client_mac"),
		"Record":                  record,
		"GuestToken":              r.URL.Query().Get("token"),
		"SponsorApprovalRequired": s.cfg.Portal.GuestWorkflows.SponsorApprovalEnabled,
	}
	s.render(w, "pending.html", data)
}

// HandleRegistrationApprovalPage renders the sponsor approval decision screen.
func (s *Server) HandleRegistrationApprovalPage(w http.ResponseWriter, r *http.Request) {
	record, err := s.guestFlows.LookupForApproval(strings.TrimSpace(r.URL.Query().Get("token")))
	if err != nil {
		http.Error(w, "Approval request not found.", http.StatusNotFound)
		return
	}
	data := map[string]any{
		"Branding":      s.cfg.Portal.Branding,
		"Record":        record,
		"ApprovalToken": r.URL.Query().Get("token"),
		"Error":         r.URL.Query().Get("error"),
		"Outcome":       r.URL.Query().Get("outcome"),
	}
	s.render(w, "approve.html", data)
}

// HandleRegistrationApprovalDecision applies the sponsor's approve/reject action.
func (s *Server) HandleRegistrationApprovalDecision(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.FormValue("token"))
	decision := strings.TrimSpace(r.FormValue("decision"))
	reason := strings.TrimSpace(r.FormValue("reason"))

	switch decision {
	case "approve":
		if _, err := s.guestFlows.ApproveByToken(r.Context(), token, "sponsor"); err != nil {
			http.Redirect(w, r, "/register/approve?token="+url.QueryEscape(token)+"&error="+url.QueryEscape(err.Error()), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/register/approve?token="+url.QueryEscape(token)+"&outcome=approved", http.StatusFound)
	case "reject":
		if _, err := s.guestFlows.RejectByToken(r.Context(), token, "sponsor", reason); err != nil {
			http.Redirect(w, r, "/register/approve?token="+url.QueryEscape(token)+"&error="+url.QueryEscape(err.Error()), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/register/approve?token="+url.QueryEscape(token)+"&outcome=rejected", http.StatusFound)
	default:
		http.Redirect(w, r, "/register/approve?token="+url.QueryEscape(token)+"&error=invalid_decision", http.StatusFound)
	}
}

// HandleRegistrationComplete finalizes an approved guest request on the current client.
func (s *Server) HandleRegistrationComplete(w http.ResponseWriter, r *http.Request) {
	mac := strings.TrimSpace(r.URL.Query().Get("client_mac"))
	clientIP := clientIPOnly(r.RemoteAddr)
	authResult, record, err := s.guestFlows.Complete(strings.TrimSpace(r.URL.Query().Get("id")), strings.TrimSpace(r.URL.Query().Get("token")))
	if err != nil {
		s.logger.Warn("guest registration completion failed", zap.String("mac", mac), zap.Error(err))
		http.Redirect(w, r, "/register/pending?id="+url.QueryEscape(r.URL.Query().Get("id"))+"&token="+url.QueryEscape(r.URL.Query().Get("token"))+"&client_mac="+url.QueryEscape(mac), http.StatusFound)
		return
	}
	if err := s.establishAuthenticatedSession(clientIP, mac, &auth.Result{
		Accepted:       true,
		Username:       authResult.Username,
		Role:           authResult.Role,
		IdentitySource: "guest-workflow",
		AuthMethod:     "guest-self-registration",
	}); err != nil {
		s.logger.Error("failed to establish guest workflow session", zap.String("registration_id", record.ID), zap.Error(err))
		http.Redirect(w, r, "/register/pending?id="+url.QueryEscape(record.ID)+"&token="+url.QueryEscape(r.URL.Query().Get("token"))+"&client_mac="+url.QueryEscape(mac)+"&error=session_error", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/success?client_mac="+url.QueryEscape(mac), http.StatusFound)
}

func guestworkflowRequestFromHTTP(r *http.Request, clientIP, mac string) guestworkflow.RegistrationRequest {
	return guestworkflow.RegistrationRequest{
		FullName:      strings.TrimSpace(r.FormValue("full_name")),
		Email:         strings.TrimSpace(r.FormValue("email")),
		Phone:         strings.TrimSpace(r.FormValue("phone")),
		Company:       strings.TrimSpace(r.FormValue("company")),
		Purpose:       strings.TrimSpace(r.FormValue("purpose")),
		SponsorName:   strings.TrimSpace(r.FormValue("sponsor_name")),
		SponsorEmail:  strings.TrimSpace(r.FormValue("sponsor_email")),
		SponsorPhone:  strings.TrimSpace(r.FormValue("sponsor_phone")),
		ClientMAC:     mac,
		ClientIP:      clientIP,
		PortalBaseURL: portalBaseURL(r),
	}
}

func portalBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}
