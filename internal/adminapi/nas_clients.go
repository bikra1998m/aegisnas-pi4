package adminapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

type nasClientTransitionRequest struct {
	Reason string `json:"reason"`
}

func HandleEnrollNASClient(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	policy := config.EffectiveRadiusDynamicClientsConfig(cfg.Radius.DynamicClients)
	if !policy.Enabled {
		http.Error(w, "dynamic NAS enrollment is disabled", http.StatusNotFound)
		return
	}
	if err := verifyNASEnrollmentToken(r.Context(), cfg, r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var req db.NASClientEnrollmentRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	remoteIP := remoteIPFromHTTPRequest(r)
	if req.SourceIP == "" {
		req.SourceIP = remoteIP
	} else if remoteIP != "" && req.SourceIP != remoteIP && !isLoopbackRemote(remoteIP) {
		http.Error(w, "source_ip must match the enrollment request source", http.StatusBadRequest)
		return
	}
	if err := validateNASSecretRef(req.SecretRef); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ExpiresAt = time.Now().UTC().Add(time.Duration(policy.EnrollmentTTLSeconds) * time.Second)
	req.DiscoverySource = "bootstrap"
	req.Actor = "bootstrap:" + remoteIP
	enrollment, err := db.CreateOrRefreshNASClientEnrollment(req, policy.MaxPending)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	status := http.StatusAccepted
	message := "NAS enrollment is pending administrator approval."
	if !policy.ApprovalRequired {
		approved, err := db.ApproveNASClientEnrollment(enrollment.EnrollmentID, db.NASClientApprovalRequest{
			SecretRef:               req.SecretRef,
			RadSecCertificateCN:     req.RadSecCertificateCN,
			RadSecCertificateIssuer: req.RadSecCertificateIssuer,
			RadSecRadiusV11:         req.RadSecRadiusV11,
			ApprovedBy:              "bootstrap:auto",
		})
		if err == nil {
			enrollment = approved
			status = http.StatusCreated
			message = "NAS enrollment was approved automatically by bootstrap policy."
		} else {
			message = "NAS enrollment is pending administrator approval because automatic approval could not validate credentials: " + err.Error()
		}
	}
	writeJSON(w, status, map[string]any{
		"status":     enrollment.Status,
		"message":    message,
		"enrollment": enrollment,
	})
}

func HandleGetNASClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, radius.BuildDynamicNASClientReport(config.Get()))
}

func HandleListNASClientEnrollments(w http.ResponseWriter, r *http.Request) {
	limit := parseNASPositiveInt(r.URL.Query().Get("limit"), 200)
	enrollments, err := db.ListNASClientEnrollments(r.URL.Query().Get("status"), limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, enrollments)
}

func HandleCreateNASClientEnrollment(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	policy := config.EffectiveRadiusDynamicClientsConfig(config.RadiusDynamicClientsConfig{})
	if cfg != nil {
		policy = config.EffectiveRadiusDynamicClientsConfig(cfg.Radius.DynamicClients)
	}
	var req db.NASClientEnrollmentRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().UTC().Add(time.Duration(policy.EnrollmentTTLSeconds) * time.Second)
	}
	if err := validateNASSecretRef(req.SecretRef); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Actor = userFromRequest(r)
	if req.DiscoverySource == "" {
		req.DiscoverySource = "admin"
	}
	enrollment, err := db.CreateOrRefreshNASClientEnrollment(req, policy.MaxPending)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "nas_client_enrollment_create", fmt.Sprintf("enrollment_id=%s source_ip=%s", enrollment.EnrollmentID, enrollment.SourceIP), "success")
	writeJSON(w, http.StatusCreated, enrollment)
}

func HandleApproveNASClientEnrollment(w http.ResponseWriter, r *http.Request) {
	var req db.NASClientApprovalRequest
	if err := decodeBody(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := validateNASSecretRef(req.SecretRef); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.ApprovedBy = userFromRequest(r)
	enrollment, err := db.ApproveNASClientEnrollment(chi.URLParam(r, "id"), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "nas_client_enrollment_approve", fmt.Sprintf("enrollment_id=%s radius_client_id=%d", enrollment.EnrollmentID, enrollment.RadiusClientID), "success")
	writeJSON(w, http.StatusOK, enrollment)
}

func HandleRejectNASClientEnrollment(w http.ResponseWriter, r *http.Request) {
	var req nasClientTransitionRequest
	_ = decodeBody(r, &req)
	enrollment, err := db.RejectNASClientEnrollment(chi.URLParam(r, "id"), userFromRequest(r), req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "nas_client_enrollment_reject", fmt.Sprintf("enrollment_id=%s", enrollment.EnrollmentID), "success")
	writeJSON(w, http.StatusOK, enrollment)
}

func HandleRevokeNASClientEnrollment(w http.ResponseWriter, r *http.Request) {
	var req nasClientTransitionRequest
	_ = decodeBody(r, &req)
	enrollment, err := db.RevokeNASClientEnrollment(chi.URLParam(r, "id"), userFromRequest(r), req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "nas_client_enrollment_revoke", fmt.Sprintf("enrollment_id=%s radius_client_id=%d", enrollment.EnrollmentID, enrollment.RadiusClientID), "success")
	writeJSON(w, http.StatusOK, enrollment)
}

func HandleListNASClientCapabilityTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := db.ListNASClientCapabilityTemplates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, templates)
}

func HandleUpsertNASClientCapabilityTemplate(w http.ResponseWriter, r *http.Request) {
	var template db.NASClientCapabilityTemplate
	if err := decodeBody(r, &template); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if name := strings.TrimSpace(chi.URLParam(r, "name")); name != "" {
		template.Name = name
	}
	saved, err := db.UpsertNASClientCapabilityTemplate(template)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "nas_client_template_upsert", "template="+saved.Name, "success")
	writeJSON(w, http.StatusOK, saved)
}

func HandleDeleteNASClientCapabilityTemplate(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := db.DeleteNASClientCapabilityTemplate(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "nas_client_template_delete", "template="+name, "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func verifyNASEnrollmentToken(ctx context.Context, cfg *config.Config, r *http.Request) error {
	ref := strings.TrimSpace(cfg.Radius.DynamicClients.EnrollmentTokenRef)
	if ref == "" {
		return fmt.Errorf("enrollment token is not configured")
	}
	provided := strings.TrimSpace(r.Header.Get("X-AegisNAS-Enrollment-Token"))
	if provided == "" {
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			provided = strings.TrimSpace(auth[len("bearer "):])
		}
	}
	if provided == "" {
		return fmt.Errorf("enrollment token is required")
	}
	resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
	expected, err := secrets.ResolveConfiguredSecret(ctx, resolver, "radius.dynamic_clients.enrollment_token_ref", "", ref)
	if err != nil {
		return fmt.Errorf("enrollment token cannot be resolved")
	}
	providedSHA := sha256.Sum256([]byte(provided))
	expectedSHA := sha256.Sum256([]byte(strings.TrimSpace(expected)))
	if subtle.ConstantTimeCompare(providedSHA[:], expectedSHA[:]) != 1 {
		return fmt.Errorf("enrollment token is invalid")
	}
	return nil
}

func remoteIPFromHTTPRequest(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func isLoopbackRemote(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.IsLoopback()
}

func parseNASPositiveInt(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func validateNASSecretRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if _, err := secrets.ParseRef(ref); err != nil {
		return fmt.Errorf("secret_ref is invalid: %w", err)
	}
	return nil
}
