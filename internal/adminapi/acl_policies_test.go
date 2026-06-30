package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func prepareACLPolicyTestDB(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	tmpfile, err := os.CreateTemp("", "acl-policies-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	require.NoError(t, db.Init(tmpfile.Name()))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
		_ = os.Remove(tmpfile.Name())
	})
}

func TestACLPolicyStagingApplyListAndPreview(t *testing.T) {
	prepareACLPolicyTestDB(t)

	body := `{
		"name":"guest-internet",
		"description":"Permit web access and block DNS to the private resolver",
		"enabled":true,
		"inbound_acl":"guest-in",
		"outbound_acl":"guest-out",
		"rules":[
			{"action":"PERMIT","direction":"IN","protocol":"TCP","source":"any","destination":"any","destination_port":"443"},
			{"action":"deny","direction":"out","protocol":"udp","source":"any","destination":"10.0.0.0/24","destination_port":"53"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acl-policies", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	HandleCreateACLPolicy(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	tx, err := db.DB.Begin()
	require.NoError(t, err)
	changes, err := pendingChanges(tx)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, "acl_policy", changes[0].ResourceType)
	require.NoError(t, applyChange(tx, changes[0]))
	require.NoError(t, tx.Commit())

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/acl-policies", nil)
	listRec := httptest.NewRecorder()
	HandleListACLPolicies(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)
	var policies []struct {
		Name        string `json:"name"`
		InboundACL  string `json:"inbound_acl"`
		OutboundACL string `json:"outbound_acl"`
		Rules       []struct {
			Action    string `json:"action"`
			Direction string `json:"direction"`
		} `json:"rules"`
	}
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &policies))
	require.Len(t, policies, 1)
	assert.Equal(t, "guest-in", policies[0].InboundACL)
	assert.Equal(t, "guest-out", policies[0].OutboundACL)
	require.Len(t, policies[0].Rules, 2)
	assert.Equal(t, "permit", policies[0].Rules[0].Action)
	assert.Equal(t, "in", policies[0].Rules[0].Direction)

	previewReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-reply-preview", bytes.NewBufferString(`{
		"nas_type":"cisco",
		"compatibility_packs":["standard","cisco","aegisnas"],
		"acl_policy_name":"guest-internet"
	}`))
	previewRec := httptest.NewRecorder()
	HandlePreviewVendorReply(previewRec, previewReq)
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	var preview struct {
		ACLPolicyLoaded    bool   `json:"acl_policy_loaded"`
		NormalizedACLRules []any  `json:"normalized_acl_rules"`
		FreeRADIUS         string `json:"freeradius"`
	}
	require.NoError(t, json.Unmarshal(previewRec.Body.Bytes(), &preview))
	assert.True(t, preview.ACLPolicyLoaded)
	assert.Len(t, preview.NormalizedACLRules, 2)
	assert.Contains(t, preview.FreeRADIUS, `Cisco-In-ACL = "guest-in"`)
	assert.Contains(t, preview.FreeRADIUS, `Cisco-AVPair = "ip:inacl#1=permit tcp any any eq 443"`)
	assert.Contains(t, preview.FreeRADIUS, `AegisNAS-ACL-Name = "guest-internet"`)
}

func TestACLPolicyStagingRejectsInvalidRule(t *testing.T) {
	prepareACLPolicyTestDB(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/acl-policies", bytes.NewBufferString(`{
		"name":"unsafe","rules":[{"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any\""}]
	}`))
	rec := httptest.NewRecorder()
	HandleCreateACLPolicy(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "acl_rules[0] is invalid")
	var staged int
	require.NoError(t, db.DB.QueryRow(`SELECT COUNT(*) FROM config_staging`).Scan(&staged))
	assert.Zero(t, staged)
}

func TestDecodeSnapshotAcceptsPreACLPolicyRevision(t *testing.T) {
	tables := make(map[string][]map[string]any)
	for _, table := range configurableTables {
		if table != "acl_policies" {
			tables[table] = []map[string]any{}
		}
	}
	data, err := json.Marshal(configSnapshot{Tables: tables})
	require.NoError(t, err)

	snapshot, err := decodeSnapshot(data)
	require.NoError(t, err)
	assert.Empty(t, snapshot.Tables["acl_policies"])
}

func TestACLPolicyBindingsValidateAndProtectReferences(t *testing.T) {
	prepareACLPolicyTestDB(t)

	result, err := db.DB.Exec(`INSERT INTO acl_policies (name, rules_json, enabled) VALUES ('corp-access', '[]', 1)`)
	require.NoError(t, err)
	aclID, err := result.LastInsertId()
	require.NoError(t, err)

	tx, err := db.DB.Begin()
	require.NoError(t, err)
	roleData, err := json.Marshal(map[string]any{
		"name": "corp", "description": "", "acl_policy_name": "corp-access", "priority": 10,
	})
	require.NoError(t, err)
	require.NoError(t, applyChange(tx, stagedChange{ResourceType: "role", Operation: "create", Data: string(roleData)}))
	require.NoError(t, tx.Commit())

	var boundACL string
	require.NoError(t, db.DB.QueryRow(`SELECT acl_policy_name FROM roles WHERE name = 'corp'`).Scan(&boundACL))
	assert.Equal(t, "corp-access", boundACL)

	tx, err = db.DB.Begin()
	require.NoError(t, err)
	disabledData, err := json.Marshal(map[string]any{
		"name": "corp-access", "description": "", "enabled": false, "rules": []any{},
	})
	require.NoError(t, err)
	err = applyChange(tx, stagedChange{ResourceType: "acl_policy", ResourceID: fmt.Sprint(aclID), Operation: "update", Data: string(disabledData)})
	assert.ErrorContains(t, err, "cannot be renamed or disabled")
	require.NoError(t, tx.Rollback())

	tx, err = db.DB.Begin()
	require.NoError(t, err)
	err = applyChange(tx, stagedChange{ResourceType: "acl_policy", ResourceID: fmt.Sprint(aclID), Operation: "delete", Data: `{}`})
	assert.ErrorContains(t, err, "still assigned")
	require.NoError(t, tx.Rollback())

	tx, err = db.DB.Begin()
	require.NoError(t, err)
	missingData, err := json.Marshal(map[string]any{
		"name": "broken", "description": "", "acl_policy_name": "missing", "priority": 1,
	})
	require.NoError(t, err)
	err = applyChange(tx, stagedChange{ResourceType: "role", Operation: "create", Data: string(missingData)})
	assert.ErrorContains(t, err, "does not exist or is disabled")
	require.NoError(t, tx.Rollback())
}
