package guestworkflow

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type deliveryMessage struct {
	mode    string
	target  string
	subject string
	body    string
}

type stubSender struct {
	messages []deliveryMessage
}

func (s *stubSender) SendEmail(_ context.Context, _ string, to, subject, body string) error {
	s.messages = append(s.messages, deliveryMessage{mode: "email", target: to, subject: subject, body: body})
	return nil
}

func (s *stubSender) SendSMS(_ context.Context, _, _, to, message string) error {
	s.messages = append(s.messages, deliveryMessage{mode: "sms", target: to, body: message})
	return nil
}

func TestSubmitApproveAndCompleteWithoutSponsor(t *testing.T) {
	setupGuestWorkflowDB(t)

	cfg := &config.Config{
		Portal: config.PortalConfig{
			Enabled:       true,
			LocalFallback: true,
			Branding:      "AegisNAS Guest",
			GuestWorkflows: config.PortalGuestWorkflowConfig{
				SelfRegistrationEnabled: true,
				InviteDelivery:          "none",
			},
		},
		Policy: config.PolicyConfig{DefaultRole: "guest-basic"},
	}
	sender := &stubSender{}
	service := New(cfg, nil, sender)

	record, err := service.Submit(context.Background(), RegistrationRequest{
		FullName:      "Guest User",
		Email:         "guest@example.com",
		ClientMAC:     "aa:bb:cc:dd:ee:ff",
		ClientIP:      "192.168.50.23",
		PortalBaseURL: "http://192.168.50.1:8081",
	})
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, StatusApproved, record.Status)
	assert.NotEmpty(t, record.Username)
	assert.Empty(t, sender.messages)

	var count int
	err = db.DB.QueryRow(`SELECT COUNT(*) FROM local_users WHERE username = ?`, record.Username).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	authResult, completed, err := service.Complete(record.ID, record.GuestToken)
	require.NoError(t, err)
	assert.Equal(t, record.Username, authResult.Username)
	assert.Equal(t, "guest-basic", authResult.Role)
	assert.Equal(t, StatusCompleted, completed.Status)
}

func TestSponsorApprovalFlow(t *testing.T) {
	setupGuestWorkflowDB(t)

	cfg := &config.Config{
		Portal: config.PortalConfig{
			Enabled:       true,
			LocalFallback: true,
			Branding:      "AegisNAS Guest",
			GuestWorkflows: config.PortalGuestWorkflowConfig{
				SelfRegistrationEnabled: true,
				SponsorApprovalEnabled:  true,
				ApprovalDelivery:        "email",
				InviteDelivery:          "email",
				EmailFrom:               "portal@example.com",
				SMTPServer:              "smtp.example.com",
				SMTPPort:                25,
			},
		},
		Policy: config.PolicyConfig{DefaultRole: "guest-basic"},
	}
	sender := &stubSender{}
	service := New(cfg, nil, sender)

	record, err := service.Submit(context.Background(), RegistrationRequest{
		FullName:      "Guest User",
		Email:         "guest@example.com",
		SponsorName:   "Team Lead",
		SponsorEmail:  "lead@example.com",
		Purpose:       "Short meeting access",
		ClientMAC:     "aa:bb:cc:11:22:33",
		ClientIP:      "192.168.50.40",
		PortalBaseURL: "http://192.168.50.1:8081",
	})
	require.NoError(t, err)
	assert.Equal(t, StatusPending, record.Status)
	require.Len(t, sender.messages, 1)
	assert.Equal(t, "lead@example.com", sender.messages[0].target)

	approvalToken := extractApprovalToken(t, sender.messages[0].body)
	approved, err := service.ApproveByToken(context.Background(), approvalToken, "sponsor")
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, approved.Status)
	assert.NotEmpty(t, approved.Username)

	require.Len(t, sender.messages, 2)
	assert.Equal(t, "guest@example.com", sender.messages[1].target)
	assert.Contains(t, sender.messages[1].body, approved.Username)
	assert.Contains(t, sender.messages[1].body, "Password:")

	authResult, completed, err := service.Complete(record.ID, record.GuestToken)
	require.NoError(t, err)
	assert.Equal(t, approved.Username, authResult.Username)
	assert.Equal(t, StatusCompleted, completed.Status)
}

func setupGuestWorkflowDB(t *testing.T) {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "guest-workflow-*.db")
	require.NoError(t, err)
	path := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(path)
	})

	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	require.NoError(t, db.Seed())
}

func extractApprovalToken(t *testing.T, body string) string {
	t.Helper()
	index := strings.Index(body, "/register/approve?token=")
	require.NotEqual(t, -1, index)
	raw := body[index:]
	end := strings.Index(raw, "\n")
	if end >= 0 {
		raw = raw[:end]
	}
	link := strings.TrimSpace(raw)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	return parsed.Query().Get("token")
}
