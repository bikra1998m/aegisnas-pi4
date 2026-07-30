package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestSubscriberServiceChainAPIActivationAndRollback(t *testing.T) {
	preparePolicyEngineAPITestConfig(t)
	_, err := db.DB.Exec(`DELETE FROM policy_rules`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO policy_rules (
		name, description, priority, enabled, match_conditions, action, service_chain_json
	) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"subscriber-data-chain", "authorize data and qos services", 100, true,
		`{"field":"authenticated","op":"eq","value":true}`,
		"allow",
		`[
			{"key":"data","name":"Internet Data","type":"data","sequence":10,"accounting_class":"internet"},
			{"key":"qos","name":"Gold QoS","type":"qos","sequence":20,"depends_on":["data"],"optional":true}
		]`)
	require.NoError(t, err)

	body := []byte(`{
		"session_id": "sess-api-1",
		"request": {
			"username": "alice@example.com",
			"calling_station_id": "aa:bb:cc:dd:ee:ff",
			"authenticated": true,
			"tenant": "corp"
		}
	}`)
	previewReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/subscriber-service-chains/preview", bytes.NewReader(body))
	previewRec := httptest.NewRecorder()
	HandlePreviewSubscriberServiceChain(previewRec, previewReq)
	require.Equal(t, http.StatusOK, previewRec.Code)
	var preview subscriberServiceChainPreview
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &preview))
	assert.Equal(t, "ready", preview.Status)
	assert.Equal(t, 2, preview.Validation.ServiceCount)
	assert.NotEmpty(t, preview.ChainID)

	activateReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/subscriber-service-chains/activate", bytes.NewReader(body))
	activateRec := httptest.NewRecorder()
	HandleActivateSubscriberServiceChain(activateRec, activateReq)
	require.Equal(t, http.StatusOK, activateRec.Code)
	var activation struct {
		Status string `json:"status"`
		Chain  struct {
			ChainID        string `json:"chain_id"`
			Status         string `json:"status"`
			ServiceCount   int    `json:"service_count"`
			ActivatedCount int    `json:"activated_count"`
		} `json:"chain"`
	}
	require.NoError(t, json.Unmarshal(activateRec.Body.Bytes(), &activation))
	assert.Equal(t, "activated", activation.Status)
	assert.Equal(t, db.SubscriberServiceChainStatusActive, activation.Chain.Status)
	assert.Equal(t, 2, activation.Chain.ServiceCount)
	assert.Equal(t, 2, activation.Chain.ActivatedCount)

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/subscriber-service-chains", nil)
	reportRec := httptest.NewRecorder()
	HandleGetSubscriberServiceChains(reportRec, reportReq)
	require.Equal(t, http.StatusOK, reportRec.Code)
	var report subscriberServiceChainsReport
	require.NoError(t, json.Unmarshal(reportRec.Body.Bytes(), &report))
	assert.Equal(t, "passed", report.Status)
	assert.Equal(t, 1, report.Summary.ActiveChains)
	assert.Len(t, report.Recent, 1)

	rollbackReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/subscriber-service-chains/"+activation.Chain.ChainID+"/rollback", bytes.NewBufferString(`{"reason":"test"}`))
	rollbackReq = withChiURLParam(rollbackReq, "chainID", activation.Chain.ChainID)
	rollbackRec := httptest.NewRecorder()
	HandleRollbackSubscriberServiceChain(rollbackRec, rollbackReq)
	require.Equal(t, http.StatusOK, rollbackRec.Code)
	assert.Contains(t, rollbackRec.Body.String(), db.SubscriberServiceChainStatusRolledBack)
}

func TestSubscriberServiceChainAuthorization(t *testing.T) {
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "GET", "/api/v1/system/subscriber-service-chains"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleReadOnly}, "POST", "/api/v1/system/subscriber-service-chains/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/subscriber-service-chains/preview"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/subscriber-service-chains/activate"))
	assert.False(t, authorizeRequest(AdminIdentity{Role: adminRoleOpsAdmin}, "POST", "/api/v1/system/subscriber-service-chains/ssc-1/rollback"))
	assert.True(t, authorizeRequest(AdminIdentity{Role: adminRoleSuperAdmin}, "POST", "/api/v1/system/subscriber-service-chains/ssc-1/rollback"))
}
