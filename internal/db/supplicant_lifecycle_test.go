package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupplicantLifecycleEventAndProfilePersistence(t *testing.T) {
	dbPath := tempSupplicantLifecycleDB(t)
	defer func() {
		Close()
		_ = os.Remove(dbPath)
	}()

	event := SupplicantLifecycleEvent{
		ObservedAt:                time.Now().UTC(),
		Protocol:                  "api",
		Platform:                  "windows",
		Decision:                  "accepted",
		Action:                    "profile_delivery_allowed",
		Reason:                    "profile delivered",
		UsernameHash:              "alice@example.com",
		DeviceIDHash:              "AA:BB:CC:DD:EE:FF",
		EAPMethod:                 "tls",
		ProfileRequested:          true,
		ProfileSigned:             true,
		SigningKeyAvailable:       true,
		TrustAnchorPinned:         true,
		ServerNameMatched:         true,
		DeliveryTokenValid:        true,
		CertificateLifecycleReady: true,
		PolicyMode:                "enforce",
		Details:                   map[string]string{"ssid": "AegisNAS-Enterprise"},
	}
	require.NoError(t, RecordSupplicantLifecycleEvent(event, 10, 10))
	require.NoError(t, UpsertSupplicantProfileDelivery(SupplicantProfileDelivery{
		UpdatedAt:            time.Now().UTC(),
		Status:               "active",
		Platform:             "windows",
		UsernameHash:         "alice@example.com",
		DeviceIDHash:         "AA:BB:CC:DD:EE:FF",
		SSID:                 "AegisNAS-Enterprise",
		EAPMethod:            "tls",
		ProfileHash:          "hash",
		SignatureFingerprint: "fingerprint",
		ExpiresAt:            time.Now().Add(24 * time.Hour),
		PolicyMode:           "enforce",
	}, 10))

	events, err := ListSupplicantLifecycleEvents(SupplicantLifecycleEventFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.NotContains(t, events[0].UsernameHash, "alice")

	profiles, err := ListSupplicantProfileDeliveries(SupplicantProfileDeliveryFilter{Limit: 10})
	require.NoError(t, err)
	require.NotEmpty(t, profiles)
	assert.Equal(t, "active", profiles[0].Status)

	summary, err := SummarizeSupplicantLifecycle(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 1, summary.ProfilesDelivered)
	assert.GreaterOrEqual(t, summary.ActiveProfiles, 1)
}

func TestSupplicantLifecycleRetention(t *testing.T) {
	dbPath := tempSupplicantLifecycleDB(t)
	defer func() {
		Close()
		_ = os.Remove(dbPath)
	}()
	for i := 0; i < 5; i++ {
		require.NoError(t, RecordSupplicantLifecycleEvent(SupplicantLifecycleEvent{
			ObservedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Protocol:   "api",
			Platform:   "linux",
			Decision:   "rejected",
			Action:     "deny",
			Reason:     "tls failure",
		}, 2, 2))
	}
	events, err := ListSupplicantLifecycleEvents(SupplicantLifecycleEventFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 2)
}

func tempSupplicantLifecycleDB(t *testing.T) string {
	t.Helper()
	file, err := os.CreateTemp("", "supplicant-lifecycle-*.db")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	require.NoError(t, Init(path))
	require.NoError(t, Migrate())
	return path
}
