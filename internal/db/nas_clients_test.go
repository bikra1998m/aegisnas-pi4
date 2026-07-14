package db

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNASClientEnrollmentApprovalLifecycle(t *testing.T) {
	path := tempDBPath(t, "nas-client-lifecycle-*.db")
	require.NoError(t, Init(path))
	require.NoError(t, Migrate())
	t.Cleanup(func() { _ = Close() })

	enrollment, err := CreateOrRefreshNASClientEnrollment(NASClientEnrollmentRequest{
		SourceIP:        "192.0.2.44",
		ShortName:       "branch-ap-44",
		NASType:         "cisco",
		Vendor:          "Cisco",
		Model:           "C9130",
		FirmwareVersion: "17.12.1",
		SerialNumber:    "FTX1234",
		Capabilities: map[string]any{
			"radius": map[string]any{"authentication": true, "accounting": true},
			"policy": map[string]any{"role": true, "vlan": true},
		},
		TemplateName:    "default",
		DiscoverySource: "bootstrap",
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
		Actor:           "bootstrap",
	}, 10)
	require.NoError(t, err)
	assert.Equal(t, NASClientStatusPending, enrollment.Status)
	assert.NotEmpty(t, enrollment.EvidenceSHA256)

	approved, err := ApproveNASClientEnrollment(enrollment.EnrollmentID, NASClientApprovalRequest{
		SecretRef:  "env:AEGIS_BRANCH_AP_SECRET",
		ApprovedBy: "ops@example.test",
	})
	require.NoError(t, err)
	assert.Equal(t, NASClientStatusApproved, approved.Status)
	assert.NotZero(t, approved.RadiusClientID)

	var clientCount int
	require.NoError(t, DB.QueryRow(`SELECT COUNT(*) FROM radius_clients WHERE shortname = 'branch-ap-44' AND enabled = 1 AND dynamic_source = 'enrollment' AND lifecycle_status = 'approved' AND secret_ref = 'env:AEGIS_BRANCH_AP_SECRET'`).Scan(&clientCount))
	assert.Equal(t, 1, clientCount)

	summary, err := GetNASClientSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.ApprovedCount)
	assert.Equal(t, 1, summary.DynamicClients)

	revoked, err := RevokeNASClientEnrollment(enrollment.EnrollmentID, "ops@example.test", "lab cleanup")
	require.NoError(t, err)
	assert.Equal(t, NASClientStatusRevoked, revoked.Status)
	require.NoError(t, DB.QueryRow(`SELECT COUNT(*) FROM radius_clients WHERE id = ? AND enabled = 0 AND lifecycle_status = 'revoked'`, approved.RadiusClientID).Scan(&clientCount))
	assert.Equal(t, 1, clientCount)
}

func TestNASClientCapabilityTemplateBlocksMissingCapabilities(t *testing.T) {
	path := tempDBPath(t, "nas-client-template-*.db")
	require.NoError(t, Init(path))
	require.NoError(t, Migrate())
	t.Cleanup(func() { _ = Close() })

	_, err := UpsertNASClientCapabilityTemplate(NASClientCapabilityTemplate{
		Name:                 "enterprise-switch",
		Description:          "Campus switch gate",
		NASType:              "cisco",
		RequiredCapabilities: []string{"radius.authentication", "policy.vlan", "coa.disconnect"},
		AllowedVendors:       []string{"cisco"},
		DefaultCapabilities:  map[string]any{"radius": map[string]any{"accounting": true}},
		Enabled:              true,
	})
	require.NoError(t, err)

	enrollment, err := CreateOrRefreshNASClientEnrollment(NASClientEnrollmentRequest{
		SourceIP:  "192.0.2.45",
		ShortName: "switch-45",
		NASType:   "cisco",
		Vendor:    "Cisco",
		Capabilities: map[string]any{
			"radius": map[string]any{"authentication": true},
			"policy": map[string]any{"vlan": true},
		},
		TemplateName: "enterprise-switch",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}, 10)
	require.NoError(t, err)

	_, err = ApproveNASClientEnrollment(enrollment.EnrollmentID, NASClientApprovalRequest{
		SecretRef:  "env:AEGIS_SWITCH_SECRET",
		ApprovedBy: "ops@example.test",
	})
	assert.ErrorContains(t, err, "coa.disconnect")
}

func TestNASClientEnrollmentExpiry(t *testing.T) {
	path := tempDBPath(t, "nas-client-expiry-*.db")
	require.NoError(t, Init(path))
	require.NoError(t, Migrate())
	t.Cleanup(func() { _ = Close() })

	enrollment, err := CreateOrRefreshNASClientEnrollment(NASClientEnrollmentRequest{
		SourceIP:  "192.0.2.46",
		ShortName: "expired-ap",
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
	}, 10)
	require.NoError(t, err)
	require.Equal(t, NASClientStatusPending, enrollment.Status)

	require.NoError(t, ExpireNASClientEnrollments(time.Now().UTC()))
	enrollment, err = GetNASClientEnrollment(enrollment.EnrollmentID)
	require.NoError(t, err)
	assert.Equal(t, NASClientStatusExpired, enrollment.Status)
}

func tempDBPath(t *testing.T, pattern string) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", " ", "-", "*", "").Replace(pattern + "-" + t.Name())
	return fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", name, time.Now().UTC().UnixNano())
}
