package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestACLCompilerAPICompileDecompileHistoryAndReadiness(t *testing.T) {
	prepareACLCompilerAPITestRuntime(t)

	compileBody := `{
		"policy_name":"guest-internet",
		"inbound_acl":"guest-in",
		"outbound_acl":"guest-out",
		"pack_keys":["cisco","mikrotik","paloalto"],
		"rules":[
			{"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443","log":true},
			{"action":"deny","direction":"out","protocol":"udp","source":"any","destination":"10.0.0.0/24","destination_port":"53"}
		]
	}`
	compileRec := httptest.NewRecorder()
	HandleCompileACL(compileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/acl-compilers/compile", bytes.NewBufferString(compileBody)))
	require.Equal(t, http.StatusOK, compileRec.Code, compileRec.Body.String())

	var compilePayload struct {
		Run struct {
			Status  string `json:"status"`
			Summary struct {
				CompiledCount         int `json:"compiled_count"`
				ProfileReferenceCount int `json:"profile_reference_count"`
				BlockedCount          int `json:"blocked_count"`
			} `json:"summary"`
			Results []struct {
				PackKey             string `json:"pack_key"`
				Status              string `json:"status"`
				CertificationState  string `json:"certification_state"`
				ArtifactFingerprint string `json:"artifact_fingerprint"`
				Attributes          []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"attributes"`
			} `json:"results"`
		} `json:"run"`
	}
	require.NoError(t, json.Unmarshal(compileRec.Body.Bytes(), &compilePayload))
	assert.Equal(t, "degraded", compilePayload.Run.Status)
	assert.Equal(t, 1, compilePayload.Run.Summary.CompiledCount)
	assert.Equal(t, 1, compilePayload.Run.Summary.ProfileReferenceCount)
	assert.Equal(t, 1, compilePayload.Run.Summary.BlockedCount)

	results := map[string]struct {
		Status              string
		CertificationState  string
		ArtifactFingerprint string
		Attributes          []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
	}{}
	for _, result := range compilePayload.Run.Results {
		results[result.PackKey] = struct {
			Status              string
			CertificationState  string
			ArtifactFingerprint string
			Attributes          []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}
		}{
			Status:              result.Status,
			CertificationState:  result.CertificationState,
			ArtifactFingerprint: result.ArtifactFingerprint,
			Attributes:          result.Attributes,
		}
	}
	require.Equal(t, "compiled", results["cisco"].Status)
	assert.Equal(t, "software-certified", results["cisco"].CertificationState)
	assert.NotEmpty(t, results["cisco"].ArtifactFingerprint)
	assert.Equal(t, "profile_reference", results["mikrotik"].Status)
	assert.Equal(t, "profile-reference", results["mikrotik"].CertificationState)
	assert.Equal(t, "blocked", results["paloalto"].Status)

	decompileRec := httptest.NewRecorder()
	HandleDecompileACL(decompileRec, httptest.NewRequest(http.MethodPost, "/api/v1/system/acl-compilers/decompile", bytes.NewBufferString(`{
		"pack_key":"cisco",
		"policy_name":"guest-internet",
		"attributes":[
			{"name":"Cisco-AVPair","value":"ip:inacl#1=permit tcp any any eq 443 log","quoted":true},
			{"name":"Cisco-AVPair","value":"ip:outacl#1=deny udp any 10.0.0.0/24 eq 53","quoted":true}
		]
	}`)))
	require.Equal(t, http.StatusOK, decompileRec.Code, decompileRec.Body.String())
	assert.Contains(t, decompileRec.Body.String(), `"status":"compiled"`)
	assert.Contains(t, decompileRec.Body.String(), `"artifact_fingerprint":"sha256:`)

	historyRec := httptest.NewRecorder()
	HandleListACLCompilerHistory(historyRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/acl-compilers/history", nil))
	require.Equal(t, http.StatusOK, historyRec.Code, historyRec.Body.String())
	assert.Contains(t, historyRec.Body.String(), `"total_events":4`)
	assert.Contains(t, historyRec.Body.String(), `"compile_events":3`)
	assert.Contains(t, historyRec.Body.String(), `"decompile_events":1`)
	assert.Contains(t, historyRec.Body.String(), `"pack_key":"paloalto"`)

	catalogRec := httptest.NewRecorder()
	HandleGetACLCompilers(catalogRec, httptest.NewRequest(http.MethodGet, "/api/v1/system/acl-compilers", nil))
	require.Equal(t, http.StatusOK, catalogRec.Code, catalogRec.Body.String())
	assert.Contains(t, catalogRec.Body.String(), `"compiler_version":"nas-0049.1"`)
	assert.Contains(t, catalogRec.Body.String(), `"software_certified":7`)
	assert.Contains(t, catalogRec.Body.String(), `"recent_events"`)

	readiness := buildProductionReadinessReport(config.Get())
	assert.Equal(t, "degraded", productionReadinessCheckStatus(readiness.Checks, "acl_compilers"))
}

func prepareACLCompilerAPITestRuntime(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	content := `
mode: two-nic
deployment:
  profile: enterprise
  form: virtual
  hardware:
    memory_mb: 8192
    cpu_cores: 4
    storage_gb: 64
wan:
  name: ens33
  dhcp: true
lan:
  name: ens37
  address: 192.168.50.1/24
database:
  path: ":memory:"
radius:
  secret: radius-shared-secret
  dynamic_auth:
    enabled: true
    port: 3799
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
	})
}
