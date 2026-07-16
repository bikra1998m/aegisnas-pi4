package mab

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestEvaluateApprovedEndpoint(t *testing.T) {
	cfg := prepareMABTestDB(t, "enforce", "deny")
	_, err := db.UpsertMABEndpoint(db.MABEndpoint{
		MAC:        "aa-bb-cc-dd-ee-ff",
		Status:     "approved",
		Role:       "printer",
		VLAN:       30,
		Tenant:     "tenant-a",
		Source:     "test",
		Posture:    "trusted",
		LastSeenAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}, time.Now().UTC())
	require.NoError(t, err)

	result := Evaluate(cfg, AccessRequest{
		Username:         "aabb.ccdd.eeff",
		CallingStationID: "AA-BB-CC-DD-EE-FF",
		NASPortType:      "Ethernet",
		NASIdentifier:    "switch-1",
	}, true)

	assert.True(t, result.Candidate)
	assert.True(t, result.Accepted)
	assert.Equal(t, "accepted", result.Decision)
	assert.Equal(t, "approved", result.State)
	assert.Equal(t, "printer", result.Role)
	assert.Equal(t, 30, result.VLAN)

	summary, err := db.GetMABEventSummary()
	require.NoError(t, err)
	assert.Equal(t, 1, summary.AcceptedCount)
}

func TestEvaluateUnknownEndpointPolicies(t *testing.T) {
	cfg := prepareMABTestDB(t, "enforce", "deny")
	denied := Evaluate(cfg, AccessRequest{CallingStationID: "00:11:22:33:44:55", NASPortType: "Wireless-802.11"}, false)
	assert.False(t, denied.Accepted)
	assert.Equal(t, "rejected", denied.Decision)

	cfg.MAB.UnknownEndpointPolicy = "guest"
	guest := Evaluate(cfg, AccessRequest{CallingStationID: "00:11:22:33:44:55", NASPortType: "Wireless-802.11"}, false)
	assert.True(t, guest.Accepted)
	assert.Equal(t, "accepted", guest.Decision)
	assert.Equal(t, "guest", guest.Role)

	cfg.MAB.UnknownEndpointPolicy = "fail_open"
	failOpen := Evaluate(cfg, AccessRequest{CallingStationID: "00:11:22:33:44:55"}, false)
	assert.True(t, failOpen.Accepted)
	assert.Equal(t, "fail_open", failOpen.Decision)
}

func TestEvaluateMonitorAllowsRejectedCandidate(t *testing.T) {
	cfg := prepareMABTestDB(t, "monitor", "deny")
	result := Evaluate(cfg, AccessRequest{CallingStationID: "00:11:22:33:44:55"}, false)
	assert.True(t, result.Accepted)
	assert.Equal(t, "monitor_allowed", result.Decision)
	assert.Contains(t, result.Warnings, "monitor mode allowed a request that enforce mode would deny")
}

func TestEvaluateHighRiskProfileQuarantinesUnknownEndpoint(t *testing.T) {
	cfg := prepareMABTestDB(t, "enforce", "deny")
	_, err := db.DB.Exec(`INSERT INTO device_inventory
		(mac, tenant, platform, device_type, hostname, source, risk_score, risk_reasons_json, compliance_status, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"00:11:22:33:44:55", "tenant-b", "linux", "camera", "cam-1", "dhcp-lease", 80, `["high risk"]`, "non_compliant", time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	result := Evaluate(cfg, AccessRequest{CallingStationID: "00-11-22-33-44-55"}, false)
	assert.True(t, result.Accepted)
	assert.Equal(t, "quarantined", result.Decision)
	assert.Equal(t, "profile_quarantine", result.State)
	assert.Equal(t, "quarantine", result.Role)
	assert.Equal(t, "tenant-b", result.Tenant)
	assert.NotNil(t, result.Profile)
}

func TestMACVariants(t *testing.T) {
	variants := MACVariants("aa:bb:cc:dd:ee:ff", []string{"colon", "plain", "cisco-dot"})
	assert.Contains(t, variants, "aa:bb:cc:dd:ee:ff")
	assert.Contains(t, variants, "AA:BB:CC:DD:EE:FF")
	assert.Contains(t, variants, "aabbccddeeff")
	assert.Contains(t, variants, "aabb.ccdd.eeff")
}

func prepareMABTestDB(t *testing.T, mode, unknownPolicy string) *config.Config {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "mab-engine-*.db")
	require.NoError(t, err)
	dbPath := tmpfile.Name()
	require.NoError(t, tmpfile.Close())
	require.NoError(t, db.Init(dbPath))
	t.Cleanup(func() {
		db.Close()
		_ = os.Remove(dbPath)
	})
	require.NoError(t, db.Migrate())
	return &config.Config{
		MAB: config.MABConfig{
			Enabled:                   true,
			Mode:                      mode,
			FailClosed:                true,
			UnknownEndpointPolicy:     unknownPolicy,
			DefaultRole:               "employee",
			GuestRole:                 "guest",
			QuarantineRole:            "quarantine",
			AllowedNASPortTypes:       []string{"ethernet", "wireless-802.11", "wireless80211"},
			MACFormats:                []string{"colon", "hyphen", "plain", "cisco-dot"},
			PasswordPolicy:            "accept_known_mac",
			ProfilingLinkEnabled:      true,
			EndpointInventoryFallback: true,
			RevalidateIntervalSeconds: 300,
			CacheTTLSeconds:           300,
			AuditEnabled:              true,
			RetentionLimit:            6000,
		},
	}
}
