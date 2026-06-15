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
		Attributes      []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"attributes"`
		FreeRADIUS string `json:"freeradius"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	assert.Equal(t, "aruba", payload.NASType)
	assert.True(t, payload.KnownPack)
	assert.False(t, payload.UsesGlobalPacks)
	assert.Equal(t, []string{"standard", "aruba", "aegisnas", "wispr"}, payload.EffectivePacks)
	assert.Contains(t, payload.FreeRADIUS, "Aruba-User-Role = \"guest\"")
	assert.NotContains(t, payload.FreeRADIUS, "Mikrotik-Rate-Limit")
	assertPreviewAttribute(t, payload.Attributes, "Aruba-User-Role", "guest")
	assertPreviewAttribute(t, payload.Attributes, "Aruba-User-Vlan", "20")
	assertPreviewAttribute(t, payload.Attributes, "AegisNAS-Role", "guest")
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
