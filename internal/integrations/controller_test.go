package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"go.uber.org/zap"
)

func TestPushControllerStatePostsExpectedPayload(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN"
	t.Setenv(tokenEnv, "controller-secret")

	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "generic", r.Header.Get("X-AegisNAS-Controller-Platform"))
		assert.Equal(t, "push-config", r.Header.Get("X-AegisNAS-Sync-Mode"))
		assert.Equal(t, "generic-rest", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"summary":"Generic controller accepted sync.","warnings":["staged-only"]}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Mode = "two-nic"
	cfg.Deployment.Profile = "enterprise"
	cfg.Deployment.Form = "virtual"
	cfg.Portal.Enabled = true
	cfg.Portal.Port = 8081
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "generic-rest", result.Adapter)
	assert.Equal(t, "bearer", result.AuthScheme)
	assert.Equal(t, http.StatusText(http.StatusAccepted), strings.TrimPrefix(result.ResponseStatus, "202 "))
	assert.Equal(t, "Generic controller accepted sync.", result.ResponseSummary)
	assert.Equal(t, 1, result.WarningCount)
	assert.Equal(t, "branch-lab", payload["controller"].(map[string]any)["site"])
	assert.Equal(t, "192.168.50.1", payload["portal"].(map[string]any)["listen_ip"])
	assert.NotEmpty(t, result.DesiredStateHash)
	assert.Len(t, result.DesiredStateHash, 64)
	assert.Equal(t, result.DesiredStateHash, payload["desired_state_hash"])
	capabilities := payload["adapter_capabilities"].(map[string]any)
	assert.Equal(t, "generic", capabilities["platform"])
	assert.Equal(t, "generic-rest", capabilities["adapter"])
	assert.Equal(t, true, capabilities["drift_detection"])
}

func TestControllerAdapterCatalogDescribesNativeAdapters(t *testing.T) {
	catalog := ControllerAdapterCatalog()
	require.Len(t, catalog, 8)

	byPlatform := map[string]ControllerAdapterDescriptor{}
	for _, adapter := range catalog {
		byPlatform[adapter.Platform] = adapter
	}

	generic := byPlatform["generic"]
	assert.Equal(t, "Generic REST Controller", generic.Label)
	assert.False(t, generic.RequiresSite)
	assert.Equal(t, "{endpoint}", generic.EndpointTemplate)
	assert.Equal(t, "contract", generic.OperationalState)
	assert.True(t, generic.DriftDetection)
	assert.False(t, generic.NativePolicyPush)

	cisco := byPlatform["cisco"]
	assert.Equal(t, "cisco-ise-ers", cisco.Adapter)
	assert.Equal(t, "basic", cisco.AuthScheme)
	assert.True(t, cisco.RequiresSite)
	assert.True(t, cisco.NativePolicyPush)
	assert.True(t, cisco.DynamicACL)
	assert.True(t, cisco.DownloadableACL)
	assert.True(t, cisco.UserRoles)
	assert.False(t, cisco.CoA)
	assert.False(t, cisco.GuestPortal)
	assert.False(t, cisco.WirelessProfiles)
	assert.Contains(t, cisco.SupportedSyncModes, "push-config")
	assert.Contains(t, cisco.EndpointTemplate, "/ers/config/downloadableacl")
	assert.Equal(t, "native-adapter", cisco.OperationalState)

	aruba := byPlatform["aruba"]
	assert.Equal(t, "aruba-central-classic", aruba.Adapter)
	assert.Equal(t, "bearer", aruba.AuthScheme)
	assert.True(t, aruba.NativePolicyPush)
	assert.True(t, aruba.WirelessProfiles)
	assert.False(t, aruba.RadiusProfiles)
	assert.False(t, aruba.GuestPortal)
	assert.False(t, aruba.DynamicACL)
	assert.False(t, aruba.CoA)
	assert.NotContains(t, aruba.SupportedSyncModes, "coa-only")
	assert.Contains(t, aruba.EndpointTemplate, "/configuration/v2/wlan/")
	assert.Equal(t, "native-adapter", aruba.OperationalState)

	mist := byPlatform["juniper-mist"]
	assert.Equal(t, "token", mist.AuthScheme)
	assert.True(t, mist.CloudInventory)
	assert.Equal(t, "contract", mist.OperationalState)

	mikrotik := byPlatform["mikrotik"]
	assert.Equal(t, "header-token", mikrotik.AuthScheme)
	assert.True(t, mikrotik.AddressLists)
}

func TestArubaCentralNativeWLANReconciliation(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_ARUBA_TOKEN"
	t.Setenv(tokenEnv, "central-secret")

	state := map[string]map[string]any{
		"Corp": {
			"name": "Corp", "essid": "Corp", "type": "employee", "opmode": "wpa2-aes",
			"vlan": "10", "hide_ssid": false, "auth_server1": "old-radius",
			"accounting_server1": "old-radius", "radius_accounting": true,
			"radius_accounting_mode": "user-authentication", "download_role": true,
		},
	}
	writes := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer central-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		prefix := "/configuration/v2/wlan/branch-lab/"
		require.True(t, strings.HasPrefix(r.URL.Path, prefix), r.URL.Path)
		name := strings.TrimPrefix(r.URL.Path, prefix)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			wlan, ok := state[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"WLAN not found"}`))
				return
			}
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"wlan": wlan}))
		case http.MethodPost, http.MethodPut:
			var payload map[string]map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			state[name] = payload["wlan"]
			writes[name] = r.Method
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"message":"success"}`))
		default:
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "aruba"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.RadiusProfile = "aegisnas-radius"
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 20},
		{Name: "Staff", AuthMode: "wpa3-enterprise", VLAN: 30, Hidden: true},
		{Name: "Guest", AuthMode: "captive-portal", VLAN: 40},
	}

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "aruba-central-classic", pullResult.Adapter)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 2, pullResult.DriftCount)
	assert.Zero(t, pullResult.AppliedCount)
	assert.Equal(t, 1, pullResult.WarningCount)
	assert.Empty(t, writes)

	pushResult, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, 2, pushResult.AppliedCount)
	assert.False(t, pushResult.DriftDetected)
	assert.Equal(t, "healthy", pushResult.ControllerHealth)
	assert.Equal(t, http.MethodPut, writes["Corp"])
	assert.Equal(t, http.MethodPost, writes["Staff"])
	assert.Equal(t, "20", state["Corp"]["vlan"])
	assert.Equal(t, "aegisnas-radius", state["Corp"]["auth_server1"])
	assert.Equal(t, "wpa3-aes-ccm-128", state["Staff"]["opmode"])
	assert.Equal(t, true, state["Staff"]["hide_ssid"])
	assert.Equal(t, true, pushResult.ResponseDetails["native_api"])
}

func TestArubaCentralRetriesRateLimitedRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"wlan":{"name":"Corp"}}`))
	}))
	defer server.Close()

	client := &arubaCentralClient{baseURL: server.URL, token: "token", http: server.Client()}
	body, status, err := client.doJSON(context.Background(), http.MethodGet, "/wlan", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(body), "Corp")
	assert.Equal(t, 2, requests)
}

func TestPushControllerStateUsesJuniperMistAdapter(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_MIST"
	t.Setenv(tokenEnv, "controller-secret")

	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/sites/branch-lab/aegisnas/sync", r.URL.Path)
		assert.Equal(t, "Token controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "juniper-mist", r.Header.Get("X-AegisNAS-Controller-Platform"))
		assert.Equal(t, "juniper-mist", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"summary":"Mist site staged.","site_id":"branch-lab"}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Portal.Enabled = true
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Portal.Port = 8081
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Wireless.SSIDs = []config.SSIDConfig{{Name: "Guest", AuthMode: "wpa2-enterprise", VLAN: 20, PortalProfile: "guest"}}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "juniper-mist"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "juniper-mist", result.Adapter)
	assert.Equal(t, "token", result.AuthScheme)
	assert.Equal(t, "branch-lab", payload["site_id"])
	assert.Equal(t, float64(1812), payload["radius_config"].(map[string]any)["auth_port"])
	wlans := payload["wlan_overrides"].([]any)
	require.Len(t, wlans, 1)
	assert.Equal(t, "Guest", wlans[0].(map[string]any)["name"])
	assert.Equal(t, "branch-lab", result.ResponseDetails["response_scope"])
}

func TestPushControllerStateUsesUniFiAdapter(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_UNIFI"
	t.Setenv(tokenEnv, "controller-secret")

	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/proxy/network/api/s/default/aegisnas/sync", r.URL.Path)
		assert.Equal(t, "Bearer controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "unifi", r.Header.Get("X-AegisNAS-Controller-Platform"))
		assert.Equal(t, "unifi-network", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"summary":"UniFi site staged.","site":"default"}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Portal.Enabled = true
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Portal.Port = 8081
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Wireless.SSIDs = []config.SSIDConfig{{Name: "Guest", AuthMode: "wpa2-enterprise", VLAN: 20, PortalProfile: "guest"}}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "unifi"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "default"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "unifi-network", result.Adapter)
	assert.Equal(t, "bearer", result.AuthScheme)
	assert.Equal(t, "unifi-network", payload["adapter"])
	assert.Equal(t, "default", payload["site"])
	assert.NotEmpty(t, payload["desired_state_hash"])
	capabilities := payload["adapter_capabilities"].(map[string]any)
	assert.Equal(t, "unifi", capabilities["platform"])
	assert.Equal(t, true, capabilities["site_profiles"])
	assert.Equal(t, "default", result.ResponseDetails["response_scope"])
}

func TestPushControllerStateUsesCiscoAdapter(t *testing.T) {
	const usernameEnv = "AEGIS_TEST_CISCO_USERNAME"
	const passwordEnv = "AEGIS_TEST_CISCO_PASSWORD"
	t.Setenv(usernameEnv, "ers-admin")
	t.Setenv(passwordEnv, "controller-secret")

	previousDB := db.DB
	tmpfile, err := os.CreateTemp("", "controller-cisco-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())
	require.NoError(t, db.Init(tmpfile.Name()))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
		_ = os.Remove(tmpfile.Name())
	})
	_, err = db.DB.Exec(`INSERT INTO acl_policies (name, description, rules_json, enabled) VALUES
		('guest-internet', 'Guest web access', '[{"action":"permit","direction":"in","protocol":"tcp","source":"any","destination":"any","destination_port":"443"}]', 1)`)
	require.NoError(t, err)
	_, err = db.DB.Exec(`INSERT INTO roles (name, description, vlan, acl_policy_name) VALUES ('guest', 'Guest role', 30, 'guest-internet')`)
	require.NoError(t, err)

	writes := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "ers-admin", username)
		assert.Equal(t, "controller-secret", password)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.Header.Get("X-CSRF-TOKEN") == "Fetch" {
			w.Header().Set("X-CSRF-TOKEN", "csrf-123")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == ciscoISEDACLCollection:
			assert.Contains(t, r.URL.Query().Get("filter"), "aegisnas-branch-lab-guest-internet")
			_, _ = w.Write([]byte(`{"SearchResult":{"total":1,"resources":[{"id":"dacl-1","name":"aegisnas-branch-lab-guest-internet"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == ciscoISEDACLCollection+"/dacl-1":
			_, _ = w.Write([]byte(`{"DownloadableAcl":{"name":"aegisnas-branch-lab-guest-internet","description":"old","dacl":"deny ip any any","daclType":"IPV4"}}`))
		case r.Method == http.MethodPut && r.URL.Path == ciscoISEDACLCollection+"/dacl-1":
			assert.Equal(t, "csrf-123", r.Header.Get("X-CSRF-TOKEN"))
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			writes["dacl"] = payload
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == ciscoISEAuthzCollection:
			_, _ = w.Write([]byte(`{"SearchResult":{"total":0,"resources":[]}}`))
		case r.Method == http.MethodPost && r.URL.Path == ciscoISEAuthzCollection:
			assert.Equal(t, "csrf-123", r.Header.Get("X-CSRF-TOKEN"))
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			writes["profile"] = payload
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "cisco"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APIUsernameEnv = usernameEnv
	cfg.Integrations.Controller.APIPasswordEnv = passwordEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, pullResult)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 2, pullResult.DriftCount)
	assert.Zero(t, pullResult.AppliedCount)
	assert.Empty(t, writes)

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "cisco-ise-ers", result.Adapter)
	assert.Equal(t, "basic", result.AuthScheme)
	assert.Equal(t, 2, result.AppliedCount)
	assert.False(t, result.DriftDetected)
	assert.Equal(t, "permit tcp any any eq 443", writes["dacl"]["DownloadableAcl"].(map[string]any)["dacl"])
	profile := writes["profile"]["AuthorizationProfile"].(map[string]any)
	assert.Equal(t, "aegisnas-branch-lab-guest-internet", profile["daclName"])
	assert.Equal(t, "30", profile["vlan"].(map[string]any)["nameID"])
}

func TestPushControllerStateCapturesControllerDriftAndHealth(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_DRIFT"
	t.Setenv(tokenEnv, "controller-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{
			"summary":"Controller accepted sync with drift.",
			"drift":{"count":2,"items":["ssid:Guest","acl:guest"],"summary":"two objects changed"},
			"applied_count":3,
			"failed_count":1,
			"controller_health":"degraded",
			"compatibility_score":82,
			"observed_state_hash":"observed-123"
		}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Portal.ListenIP = "192.168.50.1"
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.DriftDetected)
	assert.Equal(t, 2, result.DriftCount)
	assert.Equal(t, 3, result.AppliedCount)
	assert.Equal(t, 1, result.FailedCount)
	assert.Equal(t, "degraded", result.ControllerHealth)
	assert.Equal(t, 82, result.CompatibilityScore)
	assert.Equal(t, "observed-123", result.ObservedStateHash)
	assert.Equal(t, "two objects changed", result.ResponseDetails["drift_summary"])
	assert.Equal(t, "degraded", controllerResultRuntimeStatus(result))
}

func TestControllerPullPreviewAndExecutionDetectHashDrift(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_PULL_TOKEN"
	t.Setenv(tokenEnv, "pull-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/", r.URL.Path)
		assert.Equal(t, "pull-config", r.Header.Get("X-AegisNAS-Sync-Mode"))
		assert.Equal(t, "pull", r.Header.Get("X-AegisNAS-Controller-Operation"))
		assert.Equal(t, "generic-rest", r.Header.Get("X-AegisNAS-Controller-Adapter"))
		assert.Equal(t, "Bearer pull-secret", r.Header.Get("Authorization"))
		assert.NotEmpty(t, r.Header.Get("X-AegisNAS-Desired-State-Hash"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"summary":"Controller state loaded.","observed_state_hash":"outdated-state","controller_health":"healthy"}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "monitor"
	cfg.Integrations.Controller.Site = "branch-lab"

	preview, err := BuildControllerSyncPreview(cfg, "pull")
	require.NoError(t, err)
	assert.Equal(t, "pull", preview.Operation)
	assert.Equal(t, http.MethodGet, preview.Method)
	assert.Equal(t, server.URL, preview.TargetURL)
	assert.NotEmpty(t, preview.DesiredStateHash)
	assert.NotEmpty(t, preview.Payload)

	result, err := ExecuteControllerOperation(context.Background(), cfg, "pull")
	require.NoError(t, err)
	assert.Equal(t, "pull", result.Operation)
	assert.Equal(t, "generic-rest", result.Adapter)
	assert.Equal(t, "healthy", result.ControllerHealth)
	assert.Equal(t, "outdated-state", result.ObservedStateHash)
	assert.NotEmpty(t, result.DesiredStateHash)
	assert.True(t, result.DriftDetected)
	assert.Equal(t, 1, result.DriftCount)
}

func TestSyncControllerStateUsesPullForMonitorMode(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_MONITOR_TOKEN"
	t.Setenv(tokenEnv, "monitor-secret")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "pull", r.Header.Get("X-AegisNAS-Controller-Operation"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "monitor"

	_, err := syncControllerState(context.Background(), cfg)
	require.NoError(t, err)
}

func TestPushControllerStateRequiresToken(t *testing.T) {
	cfg := &config.Config{}
	cfg.Integrations.Controller.Endpoint = "https://example.invalid"
	cfg.Integrations.Controller.APITokenEnv = "AEGIS_MISSING_TOKEN"
	_, err := pushControllerState(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AEGIS_MISSING_TOKEN")
}

func TestStartControllerAutomationTracksRuntimeCounters(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_RUNTIME"
	t.Setenv(tokenEnv, "controller-secret")

	tmpfile, err := os.CreateTemp("", "controller-runtime-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	defer db.Close()
	require.NoError(t, db.Migrate())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "generic"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartControllerAutomation(ctx, cfg, zap.NewNop())
	}()

	require.Eventually(t, func() bool {
		status, err := db.GetRuntimeStatus(ControllerComponent())
		if err != nil || status == nil || status.Status != "ok" {
			return false
		}
		return int64ControllerDetail(status.Details, "sync_count") >= 1 &&
			int64ControllerDetail(status.Details, "success_count") >= 1 &&
			int64ControllerDetail(status.Details, "failure_count") == 0
	}, 2*time.Second, 50*time.Millisecond)

	history, err := db.ListIntegrationHistory(ControllerComponent(), 10)
	require.NoError(t, err)
	require.NotEmpty(t, history)
	assert.Equal(t, ControllerComponent(), history[0].Component)
	assert.Equal(t, "ok", history[0].Status)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("controller automation did not stop after context cancellation")
	}
}
