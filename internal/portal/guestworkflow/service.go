package guestworkflow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	StatusPending   = "pending"
	StatusApproved  = "approved"
	StatusRejected  = "rejected"
	StatusCompleted = "completed"

	runtimeComponent = "guest_workflows"
)

type Registration struct {
	ID                     string `json:"id"`
	Status                 string `json:"status"`
	Tenant                 string `json:"tenant"`
	FullName               string `json:"full_name"`
	Email                  string `json:"email"`
	Phone                  string `json:"phone"`
	Company                string `json:"company"`
	Purpose                string `json:"purpose"`
	SponsorName            string `json:"sponsor_name"`
	SponsorEmail           string `json:"sponsor_email"`
	SponsorPhone           string `json:"sponsor_phone"`
	ClientMAC              string `json:"client_mac"`
	ClientIP               string `json:"client_ip"`
	PortalBaseURL          string `json:"portal_base_url"`
	Username               string `json:"username"`
	Role                   string `json:"role"`
	ApprovedBy             string `json:"approved_by"`
	RejectionReason        string `json:"rejection_reason"`
	ApprovalDeliveryStatus string `json:"approval_delivery_status"`
	ApprovalDeliveryError  string `json:"approval_delivery_error"`
	InviteDeliveryStatus   string `json:"invite_delivery_status"`
	InviteDeliveryError    string `json:"invite_delivery_error"`
	CreatedAt              string `json:"created_at"`
	UpdatedAt              string `json:"updated_at"`
	ApprovedAt             string `json:"approved_at"`
	RejectedAt             string `json:"rejected_at"`
	CompletedAt            string `json:"completed_at"`
	ExpiresAt              string `json:"expires_at"`

	GuestToken    string `json:"-"`
	ApprovalToken string `json:"-"`
}

type RegistrationRequest struct {
	FullName      string
	Email         string
	Phone         string
	Company       string
	Purpose       string
	SponsorName   string
	SponsorEmail  string
	SponsorPhone  string
	ClientMAC     string
	ClientIP      string
	PortalBaseURL string
}

type RegistrationCompletion struct {
	Record     *Registration
	AuthResult *GuestAuthResult
}

type GuestAuthResult struct {
	Username string
	Role     string
}

type DeliverySender interface {
	SendEmail(ctx context.Context, from, to, subject, body string) error
	SendSMS(ctx context.Context, provider, endpoint, to, message string) error
}

type Service struct {
	cfg    *config.Config
	logger *zap.Logger
	sender DeliverySender
}

func New(cfg *config.Config, logger *zap.Logger, sender DeliverySender) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}
	if sender == nil {
		sender = &DefaultDeliverySender{
			client: &http.Client{Timeout: 10 * time.Second},
		}
	}
	return &Service{
		cfg:    cfg,
		logger: logger,
		sender: sender,
	}
}

type DefaultDeliverySender struct {
	client *http.Client
}

func (s *DefaultDeliverySender) SendEmail(_ context.Context, from, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", config.Get().Portal.GuestWorkflows.SMTPServer, config.Get().Portal.GuestWorkflows.SMTPPort)
	message := strings.Join([]string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")
	return smtp.SendMail(addr, nil, from, []string{to}, []byte(message))
}

func (s *DefaultDeliverySender) SendSMS(ctx context.Context, provider, endpoint, to, message string) error {
	payload := strings.NewReader(fmt.Sprintf(`{"provider":%q,"to":%q,"message":%q}`, provider, to, message))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sms delivery returned %s", resp.Status)
	}
	return nil
}

func (s *Service) Submit(ctx context.Context, req RegistrationRequest) (*Registration, error) {
	if s.cfg == nil {
		return nil, errors.New("configuration is required")
	}
	if !s.cfg.Portal.GuestWorkflows.SelfRegistrationEnabled {
		return nil, errors.New("guest self-registration is disabled")
	}
	if err := s.validateRequest(req); err != nil {
		return nil, err
	}

	guestToken, guestTokenHash, err := generateToken()
	if err != nil {
		return nil, err
	}
	approvalToken := ""
	approvalTokenHash := ""
	if s.cfg.Portal.GuestWorkflows.SponsorApprovalEnabled {
		approvalToken, approvalTokenHash, err = generateToken()
		if err != nil {
			return nil, err
		}
	}

	now := time.Now().UTC()
	record := &Registration{
		ID:                     uuid.NewString(),
		Status:                 StatusPending,
		Tenant:                 deriveTenant(req.SponsorEmail, req.Email),
		FullName:               strings.TrimSpace(req.FullName),
		Email:                  strings.TrimSpace(req.Email),
		Phone:                  strings.TrimSpace(req.Phone),
		Company:                strings.TrimSpace(req.Company),
		Purpose:                strings.TrimSpace(req.Purpose),
		SponsorName:            strings.TrimSpace(req.SponsorName),
		SponsorEmail:           strings.TrimSpace(req.SponsorEmail),
		SponsorPhone:           strings.TrimSpace(req.SponsorPhone),
		ClientMAC:              strings.TrimSpace(req.ClientMAC),
		ClientIP:               strings.TrimSpace(req.ClientIP),
		PortalBaseURL:          strings.TrimSpace(req.PortalBaseURL),
		Role:                   guestRole(s.cfg),
		ApprovalDeliveryStatus: "not_required",
		InviteDeliveryStatus:   "not_requested",
		CreatedAt:              now.Format(time.RFC3339),
		UpdatedAt:              now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
		GuestToken:             guestToken,
		ApprovalToken:          approvalToken,
	}
	if s.cfg.Portal.GuestWorkflows.SponsorApprovalEnabled {
		record.ApprovalDeliveryStatus = "pending"
	}
	if strings.TrimSpace(s.cfg.Portal.GuestWorkflows.InviteDelivery) != "" && !strings.EqualFold(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.InviteDelivery), "none") {
		record.InviteDeliveryStatus = "queued"
	}

	if _, err := db.DB.Exec(`INSERT INTO guest_registrations (
		id, status, tenant, full_name, email, phone, company, purpose,
		sponsor_name, sponsor_email, sponsor_phone,
		client_mac, client_ip, portal_base_url, username, role,
		approval_token_hash, guest_token_hash,
		approval_delivery_status, approval_delivery_error,
		invite_delivery_status, invite_delivery_error,
		created_at, updated_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, record.Status, nullable(record.Tenant), nullable(record.FullName), nullable(record.Email), nullable(record.Phone), nullable(record.Company), nullable(record.Purpose),
		nullable(record.SponsorName), nullable(record.SponsorEmail), nullable(record.SponsorPhone),
		nullable(record.ClientMAC), nullable(record.ClientIP), nullable(record.PortalBaseURL), nil, record.Role,
		nullable(approvalTokenHash), guestTokenHash,
		record.ApprovalDeliveryStatus, nil,
		record.InviteDeliveryStatus, nil,
		record.CreatedAt, record.UpdatedAt, record.ExpiresAt); err != nil {
		return nil, err
	}
	s.audit("guest", "guest_registration_submitted", record.ID, "submitted", req.ClientIP)

	if s.cfg.Portal.GuestWorkflows.SponsorApprovalEnabled {
		if err := s.sendApprovalNotification(ctx, record, approvalToken); err != nil {
			s.recordDeliveryFailure(record.ID, "approval", err)
			s.logger.Warn("failed to deliver sponsor approval", zap.String("registration_id", record.ID), zap.Error(err))
		}
		record, err = s.GetForGuest(record.ID, guestToken)
		if err != nil {
			return nil, err
		}
		record.GuestToken = guestToken
		return record, nil
	}

	approved, err := s.ApproveByID(ctx, record.ID, "self-registration")
	if err != nil {
		return nil, err
	}
	approved.GuestToken = guestToken
	return approved, nil
}

func (s *Service) GetForGuest(id, rawGuestToken string) (*Registration, error) {
	record, err := s.loadByID(id)
	if err != nil {
		return nil, err
	}
	if err := matchToken(rawGuestToken, recordTokenHashByID(id, "guest_token_hash")); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *Service) GetByID(id string) (*Registration, error) {
	return s.loadByID(strings.TrimSpace(id))
}

func (s *Service) LookupForApproval(rawToken string) (*Registration, error) {
	hash := hashToken(rawToken)
	return s.loadByColumn("approval_token_hash", hash)
}

func (s *Service) Complete(id, rawGuestToken string) (*GuestAuthResult, *Registration, error) {
	record, err := s.loadByID(id)
	if err != nil {
		return nil, nil, err
	}
	if err := matchToken(rawGuestToken, recordTokenHashByID(id, "guest_token_hash")); err != nil {
		return nil, nil, err
	}
	if strings.EqualFold(record.Status, StatusRejected) {
		return nil, record, errors.New("registration was rejected")
	}
	if strings.EqualFold(record.Status, StatusPending) {
		return nil, record, errors.New("registration is still pending approval")
	}
	if strings.TrimSpace(record.Username) == "" {
		return nil, record, errors.New("approved registration is missing local credentials")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	nextStatus := StatusCompleted
	if strings.EqualFold(record.Status, StatusCompleted) {
		nextStatus = StatusCompleted
	}
	if _, err := db.DB.Exec(`UPDATE guest_registrations
		SET status = ?, completed_at = COALESCE(completed_at, ?), updated_at = ?
		WHERE id = ?`, nextStatus, now, now, id); err != nil {
		return nil, nil, err
	}
	s.audit(record.Username, "guest_registration_completed", id, "completed", record.ClientIP)
	record.Status = nextStatus
	record.CompletedAt = now
	record.UpdatedAt = now
	return &GuestAuthResult{
		Username: record.Username,
		Role:     record.Role,
	}, record, nil
}

func (s *Service) ApproveByID(ctx context.Context, id, approver string) (*Registration, error) {
	return s.decide(ctx, id, approver, true, "")
}

func (s *Service) ApproveByToken(ctx context.Context, rawToken, approver string) (*Registration, error) {
	record, err := s.LookupForApproval(rawToken)
	if err != nil {
		return nil, err
	}
	return s.ApproveByID(ctx, record.ID, approver)
}

func (s *Service) RejectByID(ctx context.Context, id, approver, reason string) (*Registration, error) {
	return s.decide(ctx, id, approver, false, reason)
}

func (s *Service) RejectByToken(ctx context.Context, rawToken, approver, reason string) (*Registration, error) {
	record, err := s.LookupForApproval(rawToken)
	if err != nil {
		return nil, err
	}
	return s.RejectByID(ctx, record.ID, approver, reason)
}

func (s *Service) List(status string, limit int, tenantScopes ...string) ([]Registration, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT id, status, COALESCE(tenant, ''), COALESCE(full_name, ''), COALESCE(email, ''), COALESCE(phone, ''),
		COALESCE(company, ''), COALESCE(purpose, ''), COALESCE(sponsor_name, ''),
		COALESCE(sponsor_email, ''), COALESCE(sponsor_phone, ''), COALESCE(client_mac, ''),
		COALESCE(client_ip, ''), COALESCE(portal_base_url, ''), COALESCE(username, ''),
		COALESCE(role, ''), COALESCE(approved_by, ''), COALESCE(rejection_reason, ''),
		COALESCE(approval_delivery_status, ''), COALESCE(approval_delivery_error, ''),
		COALESCE(invite_delivery_status, ''), COALESCE(invite_delivery_error, ''),
		COALESCE(created_at, ''), COALESCE(updated_at, ''), COALESCE(approved_at, ''),
		COALESCE(rejected_at, ''), COALESCE(completed_at, ''), COALESCE(expires_at, '')
		FROM guest_registrations`
	args := []any{}
	clauses := []string{}
	if trimmed := strings.TrimSpace(status); trimmed != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, trimmed)
	}
	if scopes := normalizeTenants(tenantScopes); len(scopes) > 0 {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(scopes)), ",")
		clauses = append(clauses, fmt.Sprintf("COALESCE(tenant, '') IN (%s)", placeholders))
		for _, scope := range scopes {
			args = append(args, scope)
		}
	}
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []Registration
	for rows.Next() {
		record, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *record)
	}
	return records, rows.Err()
}

func (s *Service) decide(ctx context.Context, id, approver string, approve bool, reason string) (*Registration, error) {
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	record, err := loadByIDTx(tx, id)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(record.Status, StatusRejected) && approve {
		return nil, errors.New("registration has already been rejected")
	}
	if strings.EqualFold(record.Status, StatusApproved) || strings.EqualFold(record.Status, StatusCompleted) {
		if approve {
			return record, tx.Commit()
		}
		return nil, errors.New("registration has already been approved")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if !approve {
		if _, err := tx.Exec(`UPDATE guest_registrations
			SET status = ?, rejected_at = ?, updated_at = ?, approved_by = ?, rejection_reason = ?
			WHERE id = ?`, StatusRejected, now, now, strings.TrimSpace(approver), nullable(strings.TrimSpace(reason)), id); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		s.audit(strings.TrimSpace(approver), "guest_registration_rejected", id, "rejected", record.ClientIP)
		record.Status = StatusRejected
		record.RejectedAt = now
		record.UpdatedAt = now
		record.ApprovedBy = strings.TrimSpace(approver)
		record.RejectionReason = strings.TrimSpace(reason)
		return record, nil
	}

	username := strings.TrimSpace(record.Username)
	password := ""
	if username == "" {
		username, err = uniqueGuestUsernameTx(tx, record)
		if err != nil {
			return nil, err
		}
		password, err = generatePassword(14)
		if err != nil {
			return nil, err
		}
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO local_users (username, password_hash, role, full_name, email, tenant)
			VALUES (?, ?, ?, ?, ?, ?)`, username, string(passwordHash), record.Role, nullable(record.FullName), nullable(record.Email), nullable(record.Tenant)); err != nil {
			return nil, err
		}
	}

	if _, err := tx.Exec(`UPDATE guest_registrations
		SET status = ?, approved_at = ?, updated_at = ?, approved_by = ?, rejection_reason = NULL, username = ?
		WHERE id = ?`, StatusApproved, now, now, strings.TrimSpace(approver), username, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	record.Status = StatusApproved
	record.ApprovedAt = now
	record.UpdatedAt = now
	record.ApprovedBy = strings.TrimSpace(approver)
	record.Username = username
	s.audit(strings.TrimSpace(approver), "guest_registration_approved", id, "approved", record.ClientIP)

	if err := s.sendInviteNotification(ctx, record, password); err != nil {
		s.recordDeliveryFailure(record.ID, "invite", err)
		s.logger.Warn("failed to deliver guest invite", zap.String("registration_id", record.ID), zap.Error(err))
	} else if strings.TrimSpace(password) != "" {
		_ = s.updateDeliveryStatus(record.ID, "invite", "sent", "")
		record.InviteDeliveryStatus = "sent"
		record.InviteDeliveryError = ""
	} else if record.InviteDeliveryStatus == "" {
		record.InviteDeliveryStatus = "not_requested"
	}

	return record, nil
}

func (s *Service) validateRequest(req RegistrationRequest) error {
	if strings.TrimSpace(req.FullName) == "" {
		return errors.New("full name is required")
	}
	if strings.TrimSpace(req.ClientMAC) == "" {
		return errors.New("client MAC is required")
	}
	if strings.TrimSpace(req.PortalBaseURL) == "" {
		return errors.New("portal base URL is required")
	}
	if _, err := url.ParseRequestURI(req.PortalBaseURL); err != nil {
		return fmt.Errorf("invalid portal base URL: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.InviteDelivery)) {
	case "email":
		if strings.TrimSpace(req.Email) == "" {
			return errors.New("guest email is required for email invite delivery")
		}
	case "sms":
		if strings.TrimSpace(req.Phone) == "" {
			return errors.New("guest phone is required for SMS invite delivery")
		}
	}
	if s.cfg.Portal.GuestWorkflows.SponsorApprovalEnabled {
		switch strings.ToLower(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.ApprovalDelivery)) {
		case "email":
			if strings.TrimSpace(req.SponsorEmail) == "" {
				return errors.New("sponsor email is required for sponsor approval")
			}
		case "sms":
			if strings.TrimSpace(req.SponsorPhone) == "" {
				return errors.New("sponsor phone is required for sponsor approval")
			}
		}
	}
	return nil
}

func (s *Service) sendApprovalNotification(ctx context.Context, record *Registration, approvalToken string) error {
	baseURL := strings.TrimRight(record.PortalBaseURL, "/")
	link := fmt.Sprintf("%s/register/approve?token=%s", baseURL, url.QueryEscape(approvalToken))
	body := fmt.Sprintf("%s requested guest network access.\n\nGuest: %s\nPurpose: %s\nApprove or reject here:\n%s\n", record.FullName, record.FullName, blankAs(record.Purpose, "not provided"), link)

	var err error
	switch strings.ToLower(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.ApprovalDelivery)) {
	case "email":
		target := strings.TrimSpace(record.SponsorEmail)
		err = s.sender.SendEmail(ctx, s.cfg.Portal.GuestWorkflows.EmailFrom, target, s.cfg.Portal.Branding+" guest approval", body)
	case "sms":
		target := strings.TrimSpace(record.SponsorPhone)
		err = s.sender.SendSMS(ctx, s.cfg.Portal.GuestWorkflows.SMSProvider, s.cfg.Portal.GuestWorkflows.SMSEndpoint, target, compactSMS(body))
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if updateErr := s.updateDeliveryStatus(record.ID, "approval", "sent", ""); updateErr != nil {
		s.logger.Warn("failed to persist approval delivery status", zap.String("registration_id", record.ID), zap.Error(updateErr))
	}
	return nil
}

func (s *Service) sendInviteNotification(ctx context.Context, record *Registration, password string) error {
	inviteMode := strings.ToLower(strings.TrimSpace(s.cfg.Portal.GuestWorkflows.InviteDelivery))
	if inviteMode == "" || inviteMode == "none" || strings.TrimSpace(password) == "" {
		return nil
	}

	loginURL := strings.TrimRight(record.PortalBaseURL, "/") + "/?client_mac=" + url.QueryEscape(record.ClientMAC)
	body := fmt.Sprintf("Your guest access has been approved.\n\nUsername: %s\nPassword: %s\nLogin portal: %s\n", record.Username, password, loginURL)

	var err error
	switch inviteMode {
	case "email":
		err = s.sender.SendEmail(ctx, s.cfg.Portal.GuestWorkflows.EmailFrom, record.Email, s.cfg.Portal.Branding+" guest access", body)
	case "sms":
		err = s.sender.SendSMS(ctx, s.cfg.Portal.GuestWorkflows.SMSProvider, s.cfg.Portal.GuestWorkflows.SMSEndpoint, record.Phone, compactSMS(body))
	}
	return err
}

func (s *Service) updateDeliveryStatus(id, deliveryType, status, message string) error {
	columnStatus := "invite_delivery_status"
	columnError := "invite_delivery_error"
	if deliveryType == "approval" {
		columnStatus = "approval_delivery_status"
		columnError = "approval_delivery_error"
	}
	_, err := db.DB.Exec(fmt.Sprintf(`UPDATE guest_registrations SET %s = ?, %s = ?, updated_at = ? WHERE id = ?`, columnStatus, columnError),
		status, nullable(strings.TrimSpace(message)), time.Now().UTC().Format(time.RFC3339), id)
	return err
}

func (s *Service) recordDeliveryFailure(id, deliveryType string, err error) {
	if err == nil {
		return
	}
	_ = s.updateDeliveryStatus(id, deliveryType, "failed", err.Error())
	_ = db.UpsertRuntimeStatus(runtimeComponent, "degraded", fmt.Sprintf("Guest workflow %s delivery failed: %v", deliveryType, err), map[string]any{
		"registration_id": id,
		"delivery_type":   deliveryType,
	})
	_, _ = db.DB.Exec(`INSERT INTO alerts (severity, source, message, details) VALUES (?, ?, ?, ?)`,
		"warning", "guest-workflow", "Guest workflow delivery failed", fmt.Sprintf("%s delivery failed for %s: %v", deliveryType, id, err))
}

func (s *Service) audit(user, action, details, result, ipAddress string) {
	_, _ = db.DB.Exec(`INSERT INTO audit_logs (user, action, details, result, ip_address)
		VALUES (?, ?, ?, ?, ?)`, blankAs(user, "guest"), action, details, result, nullable(strings.TrimSpace(ipAddress)))
}

func (s *Service) loadByID(id string) (*Registration, error) {
	return s.loadByColumn("id", id)
}

func (s *Service) loadByColumn(column, value string) (*Registration, error) {
	row := db.DB.QueryRow(fmt.Sprintf(`SELECT id, status, COALESCE(tenant, ''), COALESCE(full_name, ''), COALESCE(email, ''), COALESCE(phone, ''),
		COALESCE(company, ''), COALESCE(purpose, ''), COALESCE(sponsor_name, ''),
		COALESCE(sponsor_email, ''), COALESCE(sponsor_phone, ''), COALESCE(client_mac, ''),
		COALESCE(client_ip, ''), COALESCE(portal_base_url, ''), COALESCE(username, ''),
		COALESCE(role, ''), COALESCE(approved_by, ''), COALESCE(rejection_reason, ''),
		COALESCE(approval_delivery_status, ''), COALESCE(approval_delivery_error, ''),
		COALESCE(invite_delivery_status, ''), COALESCE(invite_delivery_error, ''),
		COALESCE(created_at, ''), COALESCE(updated_at, ''), COALESCE(approved_at, ''),
		COALESCE(rejected_at, ''), COALESCE(completed_at, ''), COALESCE(expires_at, '')
		FROM guest_registrations WHERE %s = ?`, column), value)
	return scanRegistration(row)
}

func loadByIDTx(tx *sql.Tx, id string) (*Registration, error) {
	row := tx.QueryRow(`SELECT id, status, COALESCE(tenant, ''), COALESCE(full_name, ''), COALESCE(email, ''), COALESCE(phone, ''),
		COALESCE(company, ''), COALESCE(purpose, ''), COALESCE(sponsor_name, ''),
		COALESCE(sponsor_email, ''), COALESCE(sponsor_phone, ''), COALESCE(client_mac, ''),
		COALESCE(client_ip, ''), COALESCE(portal_base_url, ''), COALESCE(username, ''),
		COALESCE(role, ''), COALESCE(approved_by, ''), COALESCE(rejection_reason, ''),
		COALESCE(approval_delivery_status, ''), COALESCE(approval_delivery_error, ''),
		COALESCE(invite_delivery_status, ''), COALESCE(invite_delivery_error, ''),
		COALESCE(created_at, ''), COALESCE(updated_at, ''), COALESCE(approved_at, ''),
		COALESCE(rejected_at, ''), COALESCE(completed_at, ''), COALESCE(expires_at, '')
		FROM guest_registrations WHERE id = ?`, id)
	return scanRegistration(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRegistration(row scanner) (*Registration, error) {
	record := &Registration{}
	if err := row.Scan(
		&record.ID, &record.Status, &record.Tenant, &record.FullName, &record.Email, &record.Phone,
		&record.Company, &record.Purpose, &record.SponsorName,
		&record.SponsorEmail, &record.SponsorPhone, &record.ClientMAC,
		&record.ClientIP, &record.PortalBaseURL, &record.Username,
		&record.Role, &record.ApprovedBy, &record.RejectionReason,
		&record.ApprovalDeliveryStatus, &record.ApprovalDeliveryError,
		&record.InviteDeliveryStatus, &record.InviteDeliveryError,
		&record.CreatedAt, &record.UpdatedAt, &record.ApprovedAt,
		&record.RejectedAt, &record.CompletedAt, &record.ExpiresAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("guest registration not found")
		}
		return nil, err
	}
	return record, nil
}

func recordTokenHashByID(id, column string) string {
	var value sql.NullString
	if err := db.DB.QueryRow(fmt.Sprintf(`SELECT %s FROM guest_registrations WHERE id = ?`, column), id).Scan(&value); err != nil {
		return ""
	}
	return strings.TrimSpace(value.String)
}

func matchToken(rawToken, expectedHash string) error {
	if strings.TrimSpace(rawToken) == "" || strings.TrimSpace(expectedHash) == "" {
		return errors.New("invalid token")
	}
	if hashToken(rawToken) != strings.TrimSpace(expectedHash) {
		return errors.New("invalid token")
	}
	return nil
}

func uniqueGuestUsernameTx(tx *sql.Tx, record *Registration) (string, error) {
	base := "guest_" + strings.ReplaceAll(record.ID[:8], "-", "")
	username := base
	for i := 1; i < 1000; i++ {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM local_users WHERE username = ?`, username).Scan(&count); err != nil {
			return "", err
		}
		if count == 0 {
			return username, nil
		}
		username = fmt.Sprintf("%s_%d", base, i)
	}
	return "", errors.New("could not allocate unique guest username")
}

func generateToken() (string, string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := hex.EncodeToString(buf)
	return raw, hashToken(raw), nil
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func generatePassword(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	if length < 8 {
		length = 8
	}
	buf := make([]byte, length)
	randBytes := make([]byte, length)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(randBytes[i])%len(alphabet)]
	}
	return string(buf), nil
}

func guestRole(cfg *config.Config) string {
	if cfg == nil {
		return "guest-basic"
	}
	if role := strings.TrimSpace(cfg.Policy.DefaultRole); role != "" && !strings.EqualFold(role, "admin") {
		return role
	}
	return "guest-basic"
}

func deriveTenant(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(strings.ToLower(value))
		if trimmed == "" {
			continue
		}
		parts := strings.Split(trimmed, "@")
		if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func normalizeTenants(scopes []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if scope == "" || scope == "*" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func blankAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func compactSMS(value string) string {
	lines := strings.Fields(value)
	return strings.Join(lines, " ")
}
