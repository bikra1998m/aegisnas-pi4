package db

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateLifecycleEventAndInventoryPersistence(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cert-lifecycle-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	notAfter := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339)
	err = RecordCertificateLifecycleEvent(CertificateLifecycleEvent{
		ObservedAt:        time.Now().UTC(),
		Protocol:          "est",
		Decision:          "accepted",
		Reason:            "ok",
		Template:          "device-eap-tls",
		Issuer:            "aegisnas-local",
		IssuerState:       "active",
		DeviceIDHash:      HashEAPIdentity("device-1"),
		SubjectHash:       CertificateLifecycleSubjectHash("CN=device-1"),
		SANHash:           CertificateLifecycleSANHash("device-1"),
		SerialHash:        HashEAPIdentity("01"),
		RenewalDue:        true,
		InventoryStatus:   "renewal_due",
		KeyType:           "rsa",
		KeyBits:           2048,
		ValidityDays:      90,
		ProofOfPossession: true,
		CSRPresent:        true,
		CSRValid:          true,
		CSRSignatureValid: true,
		DeviceBound:       true,
		RevocationChecked: true,
		CRLReachable:      true,
		PolicyMode:        "enforce",
		Details:           map[string]string{"certificate_not_after": notAfter},
	}, 10, 10)
	require.NoError(t, err)

	events, err := ListCertificateLifecycleEvents(CertificateLifecycleEventFilter{Protocol: "est", Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "accepted", events[0].Decision)
	assert.Equal(t, "rsa", events[0].KeyType)
	assert.NotEmpty(t, events[0].DeviceIDHash)

	inventory, err := ListCertificateLifecycleInventory(CertificateLifecycleInventoryFilter{Status: "renewal_due", Limit: 10})
	require.NoError(t, err)
	require.Len(t, inventory, 1)
	assert.Equal(t, "renewal_due", inventory[0].Status)
	assert.NotNil(t, inventory[0].NotAfter)

	summary, err := SummarizeCertificateLifecycle(10)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.TotalEvents)
	assert.Equal(t, 1, summary.Accepted)
	assert.Equal(t, 1, summary.RenewalDue)
	assert.Equal(t, 1, summary.RenewalDueInventory)
}

func TestCertificateLifecycleRetention(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "cert-lifecycle-retention-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	require.NoError(t, Init(tmpfile.Name()))
	defer Close()
	require.NoError(t, Migrate())

	for i := 0; i < 3; i++ {
		err = RecordCertificateLifecycleEvent(CertificateLifecycleEvent{
			ObservedAt:      time.Now().UTC().Add(time.Duration(i) * time.Second),
			Protocol:        "scep",
			Decision:        "rejected",
			Reason:          "CSR is required for certificate lifecycle evaluation",
			Template:        "device-eap-tls",
			Issuer:          "aegisnas-local",
			IssuerState:     "active",
			InventoryStatus: "pending",
			PolicyMode:      "enforce",
		}, 2, 10)
		require.NoError(t, err)
	}

	events, err := ListCertificateLifecycleEvents(CertificateLifecycleEventFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 2)
	summary, err := SummarizeCertificateLifecycle(10)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.TotalEvents)
	assert.Equal(t, 2, summary.MissingCSR)
}
