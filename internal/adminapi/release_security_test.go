package adminapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReleaseSecurityReceiptIntegrityAndMissingEvidence(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "aegis-admin-api")
	now := time.Now().UTC()
	require.Equal(t, "not_admitted", buildReleaseSecurityReport(dir, executable, now).Status)
	data := []byte("unit fixture, not a signed executable")
	require.NoError(t, os.WriteFile(executable, data, 0600))
	hash := sha256.Sum256(data)
	receipt := releaseAdmission{
		SchemaVersion: 1, FeatureID: "NAS-0116", Status: "admitted", VerifiedAt: now,
		ArtifactSHA256: strings.Repeat("a", 64), SignatureVerifiedAtAdmission: true,
		PayloadSHA256: map[string]string{"bin/aegis-admin-api": hex.EncodeToString(hash[:])},
		Manifest:      releaseManifest{SchemaVersion: 1, SourceCommit: strings.Repeat("b", 40), Repository: "owner/repo", Platform: "linux-amd64", ReleaseSequence: 12},
	}
	write := func() {
		encoded, err := json.Marshal(receipt)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "admission.json"), encoded, 0600))
	}
	write()
	report := buildReleaseSecurityReport(dir, executable, now)
	require.Equal(t, "admission_recorded", report.Status)
	require.True(t, report.CurrentBinaryMatchesReceipt)
	require.False(t, report.SignatureReverified)
	require.NoError(t, os.WriteFile(executable, []byte("altered"), 0600))
	require.Equal(t, "integrity_mismatch", buildReleaseSecurityReport(dir, executable, now).Status)
	receipt.VerifiedAt = now.Add(time.Hour)
	write()
	require.Equal(t, "invalid_receipt", buildReleaseSecurityReport(dir, executable, now).Status)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "admission.json"), []byte(`{} garbage`), 0600))
	require.Equal(t, "invalid_receipt", buildReleaseSecurityReport(dir, executable, now).Status)
}

func TestReleaseSecurityAPIReadOnlyAuthorizationOpenAPIAndSupportBundle(t *testing.T) {
	t.Setenv("AEGIS_RELEASE_DIR", t.TempDir())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/release-security", nil)
	recorder := httptest.NewRecorder()
	HandleGetReleaseSecurity(recorder, request)
	require.Equal(t, 200, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"status":"not_admitted"`)
	for _, role := range []string{adminRoleReadOnly, adminRoleGuestAdmin, adminRoleOpsAdmin} {
		require.True(t, authorizeRequest(AdminIdentity{Role: role}, http.MethodGet, request.URL.Path))
		require.False(t, authorizeRequest(AdminIdentity{Role: role}, http.MethodPost, request.URL.Path))
	}
	spec := buildOpenAPISpec(request, nil)
	require.Contains(t, spec["paths"], request.URL.Path)
	found := false
	for _, capture := range supportBundleAPICaptures() {
		if capture.requestPath == request.URL.Path {
			found = true
			require.Equal(t, "api/release-security.json", capture.archivePath)
		}
	}
	require.True(t, found)
}
