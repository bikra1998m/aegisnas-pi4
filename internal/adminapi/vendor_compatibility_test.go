package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleGetVendorCompatibility(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-compatibility", nil)
	rec := httptest.NewRecorder()

	HandleGetVendorCompatibility(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))

	summary, ok := payload["summary"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "AegisNAS", summary["product_vendor_name"])
	assert.EqualValues(t, 55555, summary["product_vendor_id"])
	assert.EqualValues(t, 11, summary["product_attribute_count"])
	assert.Greater(t, int(summary["pack_count"].(float64)), 5)

	semantics, ok := payload["semantics"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, semantics)

	packs, ok := payload["packs"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, packs)

	activePacks, ok := payload["active_packs"].([]any)
	require.True(t, ok)
	assert.Contains(t, activePacks, "standard")
}

func TestHandleGetVendorCompatibilityIncludesClientProfiles(t *testing.T) {
	previousDB := db.DB
	tmpfile, err := os.CreateTemp("", "vendor-compatibility-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
		_ = os.Remove(tmpfile.Name())
	})

	require.NoError(t, db.Init(tmpfile.Name()))
	require.NoError(t, db.Migrate())
	_, err = db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled)
		VALUES ('aruba-ap', '10.20.0.2', 'secret', 'aruba', 1),
		       ('custom-ap', '10.20.0.3', 'secret', 'custom-ap', 1)`)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/vendor-compatibility", nil)
	rec := httptest.NewRecorder()
	HandleGetVendorCompatibility(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var payload struct {
		ClientProfiles []struct {
			ShortName       string   `json:"shortname"`
			NASType         string   `json:"nas_type"`
			KnownPack       bool     `json:"known_pack"`
			UsesGlobalPacks bool     `json:"uses_global_packs"`
			EffectivePacks  []string `json:"effective_packs"`
			Warning         string   `json:"warning"`
		} `json:"client_profiles"`
		ProfileSummary struct {
			TotalClients              int            `json:"total_clients"`
			EnabledClients            int            `json:"enabled_clients"`
			ProfileCounts             map[string]int `json:"profile_counts"`
			UnknownProfiles           []string       `json:"unknown_profiles"`
			GlobalFallbackClientCount int            `json:"global_fallback_client_count"`
			KnownVendorProfileClients int            `json:"known_vendor_profile_clients"`
		} `json:"profile_summary"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Len(t, payload.ClientProfiles, 2)

	profilesByName := map[string]struct {
		NASType         string
		KnownPack       bool
		UsesGlobalPacks bool
		EffectivePacks  []string
		Warning         string
	}{}
	for _, profile := range payload.ClientProfiles {
		profilesByName[profile.ShortName] = struct {
			NASType         string
			KnownPack       bool
			UsesGlobalPacks bool
			EffectivePacks  []string
			Warning         string
		}{
			NASType:         profile.NASType,
			KnownPack:       profile.KnownPack,
			UsesGlobalPacks: profile.UsesGlobalPacks,
			EffectivePacks:  profile.EffectivePacks,
			Warning:         profile.Warning,
		}
	}

	aruba := profilesByName["aruba-ap"]
	assert.Equal(t, "aruba", aruba.NASType)
	assert.True(t, aruba.KnownPack)
	assert.False(t, aruba.UsesGlobalPacks)
	assert.Contains(t, aruba.EffectivePacks, "aruba")

	custom := profilesByName["custom-ap"]
	assert.Equal(t, "custom-ap", custom.NASType)
	assert.False(t, custom.KnownPack)
	assert.True(t, custom.UsesGlobalPacks)
	assert.Contains(t, custom.Warning, "global compatibility packs")

	assert.Equal(t, 2, payload.ProfileSummary.TotalClients)
	assert.Equal(t, 2, payload.ProfileSummary.EnabledClients)
	assert.Equal(t, 1, payload.ProfileSummary.ProfileCounts["aruba"])
	assert.Equal(t, 1, payload.ProfileSummary.ProfileCounts["custom-ap"])
	assert.Contains(t, payload.ProfileSummary.UnknownProfiles, "custom-ap")
	assert.Equal(t, 1, payload.ProfileSummary.GlobalFallbackClientCount)
	assert.Equal(t, 1, payload.ProfileSummary.KnownVendorProfileClients)
}
