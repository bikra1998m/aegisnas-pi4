package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func prepareACLPolicyTestDB(t *testing.T) {
	t.Helper()
	previousDB := db.DB
	require.NoError(t, db.Init(":memory:"))
	db.DB.SetMaxOpenConns(1)
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
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

func TestACLPolicyASTStagingReportNormalizeAndPreview(t *testing.T) {
	prepareACLPolicyTestDB(t)

	body := `{
		"name":"corp-apps",
		"description":"Rich ACL AST with object and service groups",
		"enabled":true,
		"inbound_acl":"corp-in",
		"acl_ast":{
			"schema_version":1,
			"object_groups":[{"name":"corp-nets","values":["10.0.0.0/8","2001:db8::/32"]}],
			"service_groups":[{"name":"web","protocols":["tcp"],"ports":["443"]}],
			"rules":[{
				"id":"allow-managed-web",
				"sequence":10,
				"action":"permit",
				"direction":"in",
				"match":{
					"protocols":["tcp"],
					"source":{"object_groups":["corp-nets"],"port_groups":["web"]},
					"destination":{"any":true},
					"applications":["web-browsing"],
					"url_categories":["business"],
					"states":["established"]
				},
				"log":true
			}]
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/acl-policies", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	HandleCreateACLPolicy(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())

	tx, err := db.DB.Begin()
	require.NoError(t, err)
	changes, err := pendingChanges(tx)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.NoError(t, applyChange(tx, changes[0]))
	require.NoError(t, tx.Commit())

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/acl-policies", nil)
	listRec := httptest.NewRecorder()
	HandleListACLPolicies(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	var policies []struct {
		Name           string `json:"name"`
		ASTFingerprint string `json:"ast_fingerprint"`
		Rules          []any  `json:"rules"`
		ACLAST         struct {
			ObjectGroups []any `json:"object_groups"`
			Rules        []any `json:"rules"`
		} `json:"acl_ast"`
		Diagnostics []struct {
			Code string `json:"code"`
		} `json:"ast_diagnostics"`
		RoundTrip struct {
			Lossless bool `json:"lossless"`
		} `json:"acl_round_trip"`
	}
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &policies))
	require.Len(t, policies, 1)
	assert.Equal(t, "corp-apps", policies[0].Name)
	assert.NotEmpty(t, policies[0].ASTFingerprint)
	assert.Len(t, policies[0].ACLAST.ObjectGroups, 1)
	assert.GreaterOrEqual(t, len(policies[0].Rules), 2)
	assert.False(t, policies[0].RoundTrip.Lossless)
	assert.NotEmpty(t, policies[0].Diagnostics)

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/acl-ast", nil)
	reportRec := httptest.NewRecorder()
	HandleGetACLASTReport(reportRec, reportReq)
	require.Equal(t, http.StatusOK, reportRec.Code, reportRec.Body.String())
	assert.Contains(t, reportRec.Body.String(), `"status":"degraded"`)
	assert.Contains(t, reportRec.Body.String(), `"non_lossless_policies":1`)

	normalizeReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/acl-ast/normalize", bytes.NewBufferString(body))
	normalizeRec := httptest.NewRecorder()
	HandleNormalizeACLAST(normalizeRec, normalizeReq)
	require.Equal(t, http.StatusOK, normalizeRec.Code, normalizeRec.Body.String())
	assert.Contains(t, normalizeRec.Body.String(), `"acl_fingerprint":"sha256:`)
	assert.Contains(t, normalizeRec.Body.String(), `"field_not_rendered"`)

	previewReq := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-reply-preview", bytes.NewBufferString(`{
		"nas_type":"aruba",
		"compatibility_packs":["standard","aruba"],
		"acl_policy_name":"corp-apps"
	}`))
	previewRec := httptest.NewRecorder()
	HandlePreviewVendorReply(previewRec, previewReq)
	require.Equal(t, http.StatusOK, previewRec.Code, previewRec.Body.String())
	assert.Contains(t, previewRec.Body.String(), `"acl_policy_loaded":true`)
	assert.Contains(t, previewRec.Body.String(), `"acl_fingerprint":"sha256:`)
	assert.Contains(t, previewRec.Body.String(), `"acl_diagnostics"`)
	assert.Contains(t, previewRec.Body.String(), `Aruba-NAS-Filter-Rule`)
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
