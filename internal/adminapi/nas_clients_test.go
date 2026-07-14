package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleEnrollNASClientRequiresTokenAndCreatesPendingEnrollment(t *testing.T) {
	cfg := prepareDynamicNASTestConfig(t)
	_ = cfg
	body := bytes.NewBufferString(`{"shortname":"branch-ap","vendor":"Cisco","model":"C9130","capabilities":{"radius":{"authentication":true},"policy":{"vlan":true}}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nas/enroll", body)
	req.RemoteAddr = "192.0.2.60:50000"
	req.Header.Set("X-AegisNAS-Enrollment-Token", "enrollment-token")
	rec := httptest.NewRecorder()

	HandleEnrollNASClient(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, db.NASClientStatusPending, payload["status"])

	enrollments, err := db.ListNASClientEnrollments(db.NASClientStatusPending, 10)
	require.NoError(t, err)
	require.Len(t, enrollments, 1)
	assert.Equal(t, "192.0.2.60", enrollments[0].SourceIP)
	assert.Equal(t, "branch-ap", enrollments[0].ShortName)
}

func TestHandleApproveNASClientEnrollmentCreatesRadiusClient(t *testing.T) {
	prepareDynamicNASTestConfig(t)
	enrollment, err := db.CreateOrRefreshNASClientEnrollment(db.NASClientEnrollmentRequest{
		SourceIP:     "192.0.2.61",
		ShortName:    "branch-ap-61",
		Vendor:       "Cisco",
		TemplateName: "default",
		Capabilities: map[string]any{"radius": map[string]any{"authentication": true}},
	}, 10)
	require.NoError(t, err)

	body := bytes.NewBufferString(`{"secret_ref":"env:AEGIS_BRANCH_AP_SECRET"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/nas-clients/enrollments/"+enrollment.EnrollmentID+"/approve", body)
	req = withURLParam(req, "id", enrollment.EnrollmentID)
	rec := httptest.NewRecorder()

	HandleApproveNASClientEnrollment(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), `"secret":"`)
	var approved db.NASClientEnrollment
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &approved))
	assert.Equal(t, db.NASClientStatusApproved, approved.Status)
	assert.NotZero(t, approved.RadiusClientID)
}

func TestHandleGetNASClientsReturnsLifecycleReport(t *testing.T) {
	prepareDynamicNASTestConfig(t)
	rec := httptest.NewRecorder()

	HandleGetNASClients(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/nas-clients", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"schema_version"`)
	assert.Contains(t, rec.Body.String(), `"templates"`)
}

func prepareDynamicNASTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AEGIS_NAS_ENROLLMENT_TOKEN", "enrollment-token")
	cfg := &config.Config{
		Mode:     "two-nic",
		WAN:      config.InterfaceConfig{Name: "eth0"},
		LAN:      config.InterfaceConfig{Name: "eth1"},
		Database: config.DatabaseConfig{Path: memorySQLitePath(t)},
		Radius: config.RadiusConfig{
			AuthPort:              1812,
			AcctPort:              1813,
			RequestTimeoutSeconds: 5,
			DynamicClients: config.RadiusDynamicClientsConfig{
				Enabled:               true,
				DiscoveryEnabled:      true,
				ApprovalRequired:      true,
				EnrollmentTokenRef:    "env:AEGIS_NAS_ENROLLMENT_TOKEN",
				EnrollmentTTLSeconds:  3600,
				MaxPending:            10,
				DiscoveryAllowedCIDRs: []string{"192.0.2.0/24"},
				DefaultNASType:        "other",
				DefaultTransport:      "udp",
				DefaultTemplate:       "default",
			},
		},
	}
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, config.WriteFile(configPath, cfg))
	_, err := config.Load(configPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(cfg.Database.Path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
	})
	return cfg
}

func memorySQLitePath(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(t.Name())
	return fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", name, time.Now().UTC().UnixNano())
}

func withURLParam(r *http.Request, key, value string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}
