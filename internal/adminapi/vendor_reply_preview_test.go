package adminapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlePreviewVendorReplyForKnownNASProfile(t *testing.T) {
	body := `{
		"nas_type": "aruba",
		"compatibility_packs": ["standard", "mikrotik", "wispr", "aegisnas"],
		"role": "guest",
		"vlan": 20,
		"download_kbps": 50000,
		"upload_kbps": 20000,
		"acl_policy_name": "guest-internet",
		"acl_rules": [
			{"action": "permit", "direction": "in", "protocol": "tcp", "source": "any", "destination": "any", "destination_port": "443"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-reply-preview", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	HandlePreviewVendorReply(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		NASType         string   `json:"nas_type"`
		KnownPack       bool     `json:"known_pack"`
		UsesGlobalPacks bool     `json:"uses_global_packs"`
		EffectivePacks  []string `json:"effective_packs"`
		Attributes      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"attributes"`
		NormalizedACLRules []struct {
			Action          string `json:"action"`
			Direction       string `json:"direction"`
			Protocol        string `json:"protocol"`
			DestinationPort string `json:"destination_port"`
		} `json:"normalized_acl_rules"`
		ACLExports []struct {
			PackKey    string `json:"pack_key"`
			ExportMode string `json:"export_mode"`
			Attributes []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"attributes"`
		} `json:"acl_exports"`
		FreeRADIUS string `json:"freeradius"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	assert.Equal(t, "aruba", payload.NASType)
	assert.True(t, payload.KnownPack)
	assert.False(t, payload.UsesGlobalPacks)
	assert.Equal(t, []string{"standard", "aruba", "aegisnas", "wispr"}, payload.EffectivePacks)
	assert.Contains(t, payload.FreeRADIUS, "Aruba-User-Role = \"guest\"")
	assert.Contains(t, payload.FreeRADIUS, "Aruba-NAS-Filter-Rule = \"permit in tcp from any to any 443\"")
	assert.Contains(t, payload.FreeRADIUS, "AegisNAS-ACL-Rule = \"permit in tcp from any to any 443\"")
	assert.NotContains(t, payload.FreeRADIUS, "Mikrotik-Rate-Limit")
	assertPreviewAttribute(t, payload.Attributes, "Aruba-User-Role", "guest")
	assertPreviewAttribute(t, payload.Attributes, "Aruba-User-Vlan", "20")
	assertPreviewAttribute(t, payload.Attributes, "AegisNAS-Role", "guest")
	assertPreviewAttribute(t, payload.Attributes, "Aruba-NAS-Filter-Rule", "permit in tcp from any to any 443")
	require.Len(t, payload.NormalizedACLRules, 1)
	assert.Equal(t, "permit", payload.NormalizedACLRules[0].Action)
	assert.Equal(t, "443", payload.NormalizedACLRules[0].DestinationPort)
	assertACLExportAttribute(t, payload.ACLExports, "standard", "NAS-Filter-Rule", "permit in tcp from any to any 443")
	assertACLExportAttribute(t, payload.ACLExports, "aruba", "Aruba-NAS-Filter-Rule", "permit in tcp from any to any 443")
	assertACLExportAttribute(t, payload.ACLExports, "aegisnas", "AegisNAS-ACL-Rule", "permit in tcp from any to any 443")
}

func TestHandlePreviewVendorReplyForCustomNASProfileUsesGlobalPacks(t *testing.T) {
	body := `{
		"nas_type": "custom-ap",
		"compatibility_packs": ["standard", "mikrotik", "wispr"],
		"role": "guest",
		"download_kbps": 50000,
		"upload_kbps": 20000
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-reply-preview", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()

	HandlePreviewVendorReply(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		NASType         string   `json:"nas_type"`
		KnownPack       bool     `json:"known_pack"`
		UsesGlobalPacks bool     `json:"uses_global_packs"`
		EffectivePacks  []string `json:"effective_packs"`
		FreeRADIUS      string   `json:"freeradius"`
		Warnings        []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	assert.Equal(t, "custom-ap", payload.NASType)
	assert.False(t, payload.KnownPack)
	assert.True(t, payload.UsesGlobalPacks)
	assert.Equal(t, []string{"standard", "mikrotik", "wispr"}, payload.EffectivePacks)
	assert.Contains(t, payload.FreeRADIUS, "Mikrotik-Rate-Limit = \"50000k/20000k\"")
	assert.Contains(t, payload.Warnings, "unknown NAS type uses global compatibility packs")
}

func TestHandlePreviewVendorReplyRejectsInvalidRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-reply-preview", bytes.NewBufferString(`{"vlan": -1}`))
	rec := httptest.NewRecorder()

	HandlePreviewVendorReply(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "vlan cannot be negative")
}

func TestHandlePreviewVendorReplyRejectsInvalidACLRule(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/vendor-reply-preview", bytes.NewBufferString(`{
		"acl_rules": [{"action": "permit", "direction": "in", "protocol": "tcp", "source": "any", "destination": "any\""}]
	}`))
	rec := httptest.NewRecorder()

	HandlePreviewVendorReply(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "acl_rules[0] is invalid")
}

func assertPreviewAttribute(t *testing.T, attrs []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}, name, value string) {
	t.Helper()
	for _, attr := range attrs {
		if attr.Name == name && attr.Value == value {
			return
		}
	}
	t.Fatalf("attribute %s=%s not found in %#v", name, value, attrs)
}

func assertACLExportAttribute(t *testing.T, exports []struct {
	PackKey    string `json:"pack_key"`
	ExportMode string `json:"export_mode"`
	Attributes []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"attributes"`
}, packKey, name, value string) {
	t.Helper()
	for _, export := range exports {
		if export.PackKey != packKey {
			continue
		}
		for _, attr := range export.Attributes {
			if attr.Name == name && attr.Value == value {
				return
			}
		}
		t.Fatalf("attribute %s=%s not found in ACL export %#v", name, value, export)
	}
	t.Fatalf("ACL export %s not found in %#v", packKey, exports)
}
