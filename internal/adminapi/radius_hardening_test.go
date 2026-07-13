package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestHandleGetRadiusHardening(t *testing.T) {
	cfgFile, err := os.CreateTemp("", "radius-hardening-config-*.yaml")
	require.NoError(t, err)
	cfgPath := cfgFile.Name()
	require.NoError(t, cfgFile.Close())
	t.Cleanup(func() { _ = os.Remove(cfgPath) })

	require.NoError(t, os.WriteFile(cfgPath, []byte(`
mode: two-nic
wan:
  name: eth0
lan:
  name: eth1
database:
  path: /tmp/aegis.db
radius:
  secret: secret
  auth_port: 1812
  acct_port: 1813
  request_timeout_seconds: 5
  clients:
    - ip: 192.0.2.10
      shortname: lab-ap
      secret: secret
`), 0644))
	_, err = config.Load(cfgPath)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	HandleGetRadiusHardening(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/system/radius-hardening", nil))
	require.Equal(t, http.StatusOK, recorder.Code)

	var payload struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Policy        struct {
			Enabled                     bool   `json:"enabled"`
			RequireMessageAuthenticator string `json:"require_message_authenticator"`
			RequireKnownSource          bool   `json:"require_known_source"`
		} `json:"policy"`
		SourceTrust struct {
			TrustedSources []string `json:"trusted_sources"`
		} `json:"source_trust"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	assert.Equal(t, 1, payload.SchemaVersion)
	assert.Equal(t, "ready", payload.Status)
	assert.True(t, payload.Policy.Enabled)
	assert.True(t, payload.Policy.RequireKnownSource)
	assert.Equal(t, "auto", payload.Policy.RequireMessageAuthenticator)
	assert.Contains(t, payload.SourceTrust.TrustedSources, "192.0.2.10/32")
	assert.NotContains(t, recorder.Body.String(), "secret")
}
