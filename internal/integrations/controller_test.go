package integrations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
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
	require.Len(t, catalog, 9)

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
	assert.True(t, mist.NativePolicyPush)
	assert.True(t, mist.WirelessProfiles)
	assert.False(t, mist.CloudInventory)
	assert.False(t, mist.CoA)
	assert.NotContains(t, mist.SupportedSyncModes, "coa-only")
	assert.Equal(t, "native-adapter", mist.OperationalState)

	mikrotik := byPlatform["mikrotik"]
	assert.Equal(t, "basic", mikrotik.AuthScheme)
	assert.Equal(t, "mikrotik-routeros", mikrotik.Adapter)
	assert.True(t, mikrotik.NativePolicyPush)
	assert.True(t, mikrotik.RadiusProfiles)
	assert.True(t, mikrotik.WirelessProfiles)
	assert.False(t, mikrotik.AddressLists)
	assert.False(t, mikrotik.DynamicACL)
	assert.NotContains(t, mikrotik.SupportedSyncModes, "coa-only")
	assert.Contains(t, mikrotik.EndpointTemplate, "/rest/interface/wifi/")
	assert.Equal(t, "native-adapter", mikrotik.OperationalState)

	ruckus := byPlatform["ruckus"]
	assert.Equal(t, "session", ruckus.AuthScheme)
	assert.True(t, ruckus.NativePolicyPush)
	assert.True(t, ruckus.WirelessProfiles)
	assert.False(t, ruckus.ZonePolicy)
	assert.False(t, ruckus.CoA)
	assert.NotContains(t, ruckus.SupportedSyncModes, "coa-only")
	assert.Contains(t, ruckus.EndpointTemplate, "/v13_1/rkszones/")
	assert.Equal(t, "native-adapter", ruckus.OperationalState)

	fortinet := byPlatform["fortinet"]
	assert.Equal(t, "bearer", fortinet.AuthScheme)
	assert.True(t, fortinet.NativePolicyPush)
	assert.True(t, fortinet.WirelessProfiles)
	assert.False(t, fortinet.PolicyProfiles)
	assert.False(t, fortinet.CoA)
	assert.NotContains(t, fortinet.SupportedSyncModes, "coa-only")
	assert.Contains(t, fortinet.EndpointTemplate, "/wireless-controller/vap/")
	assert.Equal(t, "native-adapter", fortinet.OperationalState)

	unifi := byPlatform["unifi"]
	assert.Equal(t, "api-key", unifi.AuthScheme)
	assert.True(t, unifi.NativePolicyPush)
	assert.True(t, unifi.WirelessProfiles)
	assert.False(t, unifi.RadiusProfiles)
	assert.False(t, unifi.GuestPortal)
	assert.False(t, unifi.SiteProfiles)
	assert.False(t, unifi.CoA)
	assert.NotContains(t, unifi.SupportedSyncModes, "coa-only")
	assert.Contains(t, unifi.EndpointTemplate, "/v1/sites/{siteId}/wifi/broadcasts")
	assert.Equal(t, "native-adapter", unifi.OperationalState)

	meraki := byPlatform["meraki"]
	assert.Equal(t, "cisco-meraki-dashboard", meraki.Adapter)
	assert.Equal(t, "api-key", meraki.AuthScheme)
	assert.True(t, meraki.NativePolicyPush)
	assert.True(t, meraki.WirelessProfiles)
	assert.False(t, meraki.RadiusProfiles)
	assert.False(t, meraki.GuestPortal)
	assert.False(t, meraki.CoA)
	assert.NotContains(t, meraki.SupportedSyncModes, "coa-only")
	assert.Contains(t, meraki.EndpointTemplate, "/networks/{networkId}/wireless/ssids/{number}")
	assert.Equal(t, "native-adapter", meraki.OperationalState)
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

func TestJuniperMistNativeWLANReconciliation(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_MIST"
	const secretEnv = "AEGIS_TEST_MIST_RADIUS_SECRET"
	t.Setenv(tokenEnv, "controller-secret")
	t.Setenv(secretEnv, "radius-secret")

	state := map[string]map[string]any{
		"Corp": {
			"id": "wlan-1", "ssid": "Corp", "enabled": true, "hide_ssid": false,
			"auth":         map[string]any{"type": "eap", "pairwise": []any{"wpa2-ccmp"}},
			"auth_servers": []any{map[string]any{"host": "192.0.2.10", "port": float64(1812), "secret": "radius-secret"}},
			"acct_servers": []any{map[string]any{"host": "192.0.2.10", "port": float64(1813), "secret": "radius-secret"}},
			"isolation":    false, "max_num_clients": float64(0), "vlan_enabled": true, "vlan_id": float64(10),
			"coa_servers": []any{map[string]any{"ip": "192.0.2.10", "port": float64(3799), "secret": "radius-secret", "enabled": true}},
		},
	}
	writes := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Token controller-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json, application/vnd.api+json", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		collection := "/api/v1/sites/site-123/wlans"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == collection:
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
			items := make([]map[string]any, 0, len(state))
			for _, wlan := range state {
				items = append(items, wlan)
			}
			require.NoError(t, json.NewEncoder(w).Encode(items))
		case r.Method == http.MethodPut && r.URL.Path == collection+"/wlan-1":
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			payload["id"] = "wlan-1"
			state["Corp"] = payload
			writes["Corp"] = r.Method
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			payload["id"] = "wlan-2"
			state["Staff"] = payload
			writes["Staff"] = r.Method
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Radius.DynamicAuth.Port = 3799
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 20},
		{Name: "Staff", AuthMode: "wpa3-enterprise", VLAN: 30, DynamicVLAN: true, Hidden: true, ClientIsolation: true, MaxClients: 120},
		{Name: "Guest", AuthMode: "captive-portal", VLAN: 40},
	}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "juniper-mist"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.RadiusServer = "192.0.2.10"
	cfg.Integrations.Controller.RadiusSecretEnv = secretEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "site-123"

	preview, err := BuildControllerSyncPreview(cfg, "push")
	require.NoError(t, err)
	previewJSON, err := json.Marshal(preview)
	require.NoError(t, err)
	assert.Contains(t, string(previewJSON), "redacted")
	assert.NotContains(t, string(previewJSON), "radius-secret")

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 2, pullResult.DriftCount)
	assert.Equal(t, 1, pullResult.WarningCount)
	assert.Empty(t, writes)

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "juniper-mist", result.Adapter)
	assert.Equal(t, "token", result.AuthScheme)
	assert.Equal(t, 2, result.AppliedCount)
	assert.False(t, result.DriftDetected)
	assert.Equal(t, http.MethodPut, writes["Corp"])
	assert.Equal(t, http.MethodPost, writes["Staff"])
	assert.Equal(t, float64(20), state["Corp"]["vlan_id"])
	staffAuth := state["Staff"]["auth"].(map[string]any)
	assert.Equal(t, "wpa3", staffAuth["pairwise"].([]any)[0])
	assert.Equal(t, true, state["Staff"]["isolation"])
	assert.Equal(t, float64(120), state["Staff"]["max_num_clients"])
	assert.Equal(t, "radius-secret", state["Staff"]["auth_servers"].([]any)[0].(map[string]any)["secret"])
}

func TestJuniperMistClientRedactsSecretsFromErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"token":"api-secret","radius":"radius-secret"}`))
	}))
	defer server.Close()

	client := &mistClient{baseURL: server.URL, token: "api-secret", secret: "radius-secret", http: server.Client()}
	_, _, err := client.doJSON(context.Background(), http.MethodPost, "/wlans", map[string]any{"secret": "radius-secret"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "api-secret")
	assert.NotContains(t, err.Error(), "radius-secret")
	assert.Contains(t, err.Error(), "[redacted]")
}

func TestMistCredentialsDoNotRequireRadiusSecretWithoutEnterpriseWLANs(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_MIST_HEALTH_TOKEN"
	t.Setenv(tokenEnv, "api-secret")
	cfg := &config.Config{}
	cfg.Integrations.Controller.APITokenEnv = tokenEnv

	token, secret, err := mistCredentials(cfg)
	require.NoError(t, err)
	assert.Equal(t, "api-secret", token)
	assert.Empty(t, secret)
}

func TestRuckusSmartZoneNativeWLANReconciliation(t *testing.T) {
	const usernameEnv = "AEGIS_TEST_RUCKUS_USERNAME"
	const passwordEnv = "AEGIS_TEST_RUCKUS_PASSWORD"
	t.Setenv(usernameEnv, "api-admin")
	t.Setenv(passwordEnv, "controller-secret")

	state := map[string]map[string]any{
		"Corp": {
			"id": "wlan-1", "name": "Corp", "ssid": "Corp", "description": "Managed by AegisNAS",
			"accessTunnelType":     "APLBO",
			"encryption":           map[string]any{"method": "WPA2", "algorithm": "AES", "mfp": "disabled"},
			"authServiceOrProfile": map[string]any{"throughController": false, "name": "aegis-radius"},
			"advancedOptions": map[string]any{
				"hideSsidEnabled": false, "clientIsolationEnabled": false,
				"clientIsolationUnicastEnabled": false, "clientIsolationMulticastEnabled": false,
			},
			"vlan": map[string]any{"accessVlan": float64(10), "aaaVlanOverride": false},
		},
	}
	writes := map[string]string{}
	logins := 0
	logouts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "/wsg/api/public/v13_1"
		collection := base + "/rkszones/zone-123/wlans"
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == base+"/session" {
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			assert.Equal(t, "api-admin", payload["username"])
			assert.Equal(t, "controller-secret", payload["password"])
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "session-123", Path: "/"})
			logins++
			_, _ = w.Write([]byte(`{"controllerVersion":"7.1.1"}`))
			return
		}
		cookie, err := r.Cookie("JSESSIONID")
		require.NoError(t, err)
		assert.Equal(t, "session-123", cookie.Value)
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == base+"/session":
			logouts++
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == collection:
			assert.Equal(t, "0", r.URL.Query().Get("index"))
			assert.Equal(t, "1000", r.URL.Query().Get("listSize"))
			items := make([]map[string]any, 0, len(state))
			for _, wlan := range state {
				items = append(items, map[string]any{"id": wlan["id"], "name": wlan["name"], "ssid": wlan["ssid"]})
			}
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"totalCount": len(items), "hasMore": false, "firstIndex": 0, "list": items}))
		case r.Method == http.MethodGet && r.URL.Path == collection+"/wlan-1":
			require.NoError(t, json.NewEncoder(w).Encode(state["Corp"]))
		case r.Method == http.MethodPatch && r.URL.Path == collection+"/wlan-1":
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			payload["id"] = "wlan-1"
			state["Corp"] = payload
			writes["Corp"] = r.Method
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == collection+"/standard8021X":
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			payload["id"] = "wlan-2"
			state["Staff"] = payload
			writes["Staff"] = r.Method
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"wlan-2"}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 20},
		{Name: "Staff", AuthMode: "wpa3-enterprise", VLAN: 30, DynamicVLAN: true, Hidden: true, ClientIsolation: true, MaxClients: 64},
		{Name: "Guest", AuthMode: "captive-portal"},
	}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "ruckus"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APIUsernameEnv = usernameEnv
	cfg.Integrations.Controller.APIPasswordEnv = passwordEnv
	cfg.Integrations.Controller.RadiusProfile = "aegis-radius"
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "zone-123"

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 2, pullResult.DriftCount)
	assert.Equal(t, 1, pullResult.WarningCount)
	assert.Empty(t, writes)

	pushResult, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "ruckus-smartzone", pushResult.Adapter)
	assert.Equal(t, "session", pushResult.AuthScheme)
	assert.Equal(t, 2, pushResult.AppliedCount)
	assert.False(t, pushResult.DriftDetected)
	assert.Equal(t, http.MethodPatch, writes["Corp"])
	assert.Equal(t, http.MethodPost, writes["Staff"])
	assert.Equal(t, float64(20), state["Corp"]["vlan"].(map[string]any)["accessVlan"])
	assert.Equal(t, "WPA3", state["Staff"]["encryption"].(map[string]any)["method"])
	assert.Equal(t, true, state["Staff"]["advancedOptions"].(map[string]any)["hideSsidEnabled"])
	assert.Equal(t, 2, logins)
	assert.Equal(t, 2, logouts)
}

func TestFortiGateNativeVAPReconciliation(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_FORTIGATE_TOKEN"
	t.Setenv(tokenEnv, "fortigate-secret")

	state := map[string]map[string]any{
		"Corp": {
			"name": "Corp", "ssid": "Corp", "security": "wpa2-only-enterprise",
			"auth": "radius", "radius-server": "aegis-radius", "broadcast-ssid": "enable",
			"dynamic-vlan": "disable", "intra-vap-privacy": "disable", "max-clients": float64(0), "vlanid": float64(10),
		},
	}
	writes := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer fortigate-secret", r.Header.Get("Authorization"))
		assert.Equal(t, "root", r.URL.Query().Get("vdom"))
		collection := fortiGateVAPCollection
		w.Header().Set("Content-Type", "application/json")
		name := strings.TrimPrefix(r.URL.Path, collection+"/")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == collection+"/Corp":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"status": "success", "results": state["Corp"]}))
		case r.Method == http.MethodGet && r.URL.Path == collection+"/Staff":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"error","message":"not found"}`))
		case r.Method == http.MethodPut && r.URL.Path == collection+"/Corp":
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			state["Corp"] = payload
			writes["Corp"] = r.Method
			_, _ = w.Write([]byte(`{"status":"success","http_status":200}`))
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			state[payload["name"].(string)] = payload
			writes[payload["name"].(string)] = r.Method
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"success","http_status":201}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+name, http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 20},
		{Name: "Staff", AuthMode: "wpa3-enterprise", VLAN: 30, DynamicVLAN: true, Hidden: true, ClientIsolation: true, MaxClients: 80},
		{Name: "Guest", AuthMode: "captive-portal"},
	}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "fortinet"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.RadiusProfile = "aegis-radius"
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "root"

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 2, pullResult.DriftCount)
	assert.Equal(t, 1, pullResult.WarningCount)
	assert.Empty(t, writes)

	pushResult, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "fortinet-fortigate", pushResult.Adapter)
	assert.Equal(t, "bearer", pushResult.AuthScheme)
	assert.Equal(t, 2, pushResult.AppliedCount)
	assert.False(t, pushResult.DriftDetected)
	assert.Equal(t, http.MethodPut, writes["Corp"])
	assert.Equal(t, http.MethodPost, writes["Staff"])
	assert.Equal(t, float64(20), state["Corp"]["vlanid"])
	assert.Equal(t, "wpa3-only-enterprise", state["Staff"]["security"])
	assert.Equal(t, "enable", state["Staff"]["dynamic-vlan"])
	assert.Equal(t, "disable", state["Staff"]["broadcast-ssid"])
}

func TestMikroTikNativeWiFiReconciliation(t *testing.T) {
	const usernameEnv = "AEGIS_TEST_MIKROTIK_USERNAME"
	const passwordEnv = "AEGIS_TEST_MIKROTIK_PASSWORD"
	const radiusSecretEnv = "AEGIS_TEST_MIKROTIK_RADIUS_SECRET"
	t.Setenv(usernameEnv, "aegis-api")
	t.Setenv(passwordEnv, "router-password")
	t.Setenv(radiusSecretEnv, "radius-secret")

	base := mikroTikManagedName("branch-lab", "Corp")
	securityName := base + "-sec"
	datapathName := base + "-dp"
	configurationName := base + "-cfg"
	state := map[string][]map[string]any{
		mikroTikRadiusCollection: {{
			".id": "*1", "address": "192.0.2.10", "service": "wireless",
			"authentication-port": "1812", "accounting-port": "1813", "comment": "aegisnas:branch-lab:radius",
		}},
		mikroTikSecurityCollection: {{
			".id": "*2", "name": securityName, "authentication-types": "wpa2-eap",
			"eap-accounting": "yes", "management-protection": "allowed", "comment": "aegisnas:branch-lab:Corp",
		}},
		mikroTikDatapathCollection:      {},
		mikroTikConfigurationCollection: {},
	}
	writes := map[string]string{}
	nextID := 10
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "aegis-api", username)
		assert.Equal(t, "router-password", password)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			records, exists := state[r.URL.Path]
			require.True(t, exists, r.URL.Path)
			require.NoError(t, json.NewEncoder(w).Encode(records))
			return
		}
		if r.Method == http.MethodPut {
			records, exists := state[r.URL.Path]
			require.True(t, exists, r.URL.Path)
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			payload[".id"] = "*" + strconv.Itoa(nextID)
			nextID++
			state[r.URL.Path] = append(records, payload)
			writes[firstNonEmptyString(payload["name"], payload["comment"])] = r.Method
			w.WriteHeader(http.StatusCreated)
			require.NoError(t, json.NewEncoder(w).Encode(payload))
			return
		}
		if r.Method == http.MethodPatch {
			for collection, records := range state {
				prefix := collection + "/"
				if !strings.HasPrefix(r.URL.Path, prefix) {
					continue
				}
				id := strings.TrimPrefix(r.URL.Path, prefix)
				for index, record := range records {
					if firstNonEmptyString(record[".id"]) != id {
						continue
					}
					var payload map[string]any
					require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
					payload[".id"] = id
					state[collection][index] = payload
					writes[firstNonEmptyString(payload["name"], payload["comment"])] = r.Method
					require.NoError(t, json.NewEncoder(w).Encode(payload))
					return
				}
			}
		}
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Wireless.SSIDs = []config.SSIDConfig{{
		Name: "Corp", AuthMode: "wpa3-enterprise", VLAN: 20, Hidden: true, ClientIsolation: true, MaxClients: 80,
	}}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "mikrotik"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APIUsernameEnv = usernameEnv
	cfg.Integrations.Controller.APIPasswordEnv = passwordEnv
	cfg.Integrations.Controller.RadiusServer = "192.0.2.10"
	cfg.Integrations.Controller.RadiusSecretEnv = radiusSecretEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = "branch-lab"

	preview, err := BuildControllerSyncPreview(cfg, "push")
	require.NoError(t, err)
	encodedPreview, err := json.Marshal(preview.Payload)
	require.NoError(t, err)
	assert.Contains(t, string(encodedPreview), "redacted")
	assert.NotContains(t, string(encodedPreview), "radius-secret")
	assert.Equal(t, "basic", preview.AuthScheme)
	assert.Equal(t, server.URL+mikroTikConfigurationCollection, preview.TargetURL)

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 3, pullResult.DriftCount)
	assert.Equal(t, 1, pullResult.WarningCount)
	assert.Empty(t, writes)

	pushResult, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "mikrotik-routeros", pushResult.Adapter)
	assert.Equal(t, "basic", pushResult.AuthScheme)
	assert.Equal(t, 3, pushResult.AppliedCount)
	assert.False(t, pushResult.DriftDetected)
	assert.Equal(t, http.MethodPatch, writes[securityName])
	assert.Equal(t, http.MethodPut, writes[datapathName])
	assert.Equal(t, http.MethodPut, writes[configurationName])
	assert.Equal(t, "wpa3-eap", state[mikroTikSecurityCollection][0]["authentication-types"])
	assert.Equal(t, "required", state[mikroTikSecurityCollection][0]["management-protection"])
	assert.Equal(t, "20", state[mikroTikDatapathCollection][0]["vlan-id"])
	assert.Equal(t, "yes", state[mikroTikDatapathCollection][0]["client-isolation"])
	assert.Equal(t, "yes", state[mikroTikConfigurationCollection][0]["hide-ssid"])
	assert.Equal(t, "80", state[mikroTikConfigurationCollection][0]["max-clients"])
}

func TestUniFiNativeWiFiReconciliation(t *testing.T) {
	const tokenEnv = "AEGIS_TEST_CONTROLLER_TOKEN_UNIFI"
	t.Setenv(tokenEnv, "unifi-api-key")

	site := "00000000-0000-0000-0000-000000000001"
	collection := unifiWiFiCollectionPath(site)
	state := map[string]map[string]any{
		"Corp": {
			"id": "wifi-1", "metadata": map[string]any{"origin": "USER_DEFINED"},
			"type": "STANDARD", "name": "Corp", "enabled": true,
			"network": map[string]any{"type": "SPECIFIC", "networkId": "network-10"},
			"securityConfiguration": map[string]any{
				"type": "WPA2_ENTERPRISE", "radiusConfiguration": map[string]any{
					"profileId": "radius-1", "nasId": map[string]any{"type": "DERIVED", "source": "DEVICE_MAC_ADDRESS"},
				}, "coaEnabled": true, "pmfMode": "OPTIONAL", "fastRoamingEnabled": true,
			},
			"multicastToUnicastConversionEnabled": false, "clientIsolationEnabled": false,
			"hideName": false, "uapsdEnabled": true, "bandSteeringEnabled": true,
		},
	}
	writes := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "unifi-api-key", r.Header.Get("X-API-Key"))
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		page := func(data []map[string]any) {
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"offset": 0, "limit": 100, "count": len(data), "totalCount": len(data), "data": data,
			}))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == unifiRadiusCollectionPath(site):
			page([]map[string]any{{"id": "radius-1", "name": "aegis-radius", "metadata": map[string]any{"origin": "USER_DEFINED"}}})
		case r.Method == http.MethodGet && r.URL.Path == unifiNetworkCollectionPath(site):
			page([]map[string]any{
				{"id": "network-20", "name": "Corp VLAN", "vlanId": 20},
				{"id": "network-30", "name": "Staff VLAN", "vlanId": 30},
			})
		case r.Method == http.MethodGet && r.URL.Path == collection:
			overviews := make([]map[string]any, 0, len(state))
			for _, detail := range state {
				overviews = append(overviews, map[string]any{"id": detail["id"], "name": detail["name"]})
			}
			page(overviews)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, collection+"/"):
			id := strings.TrimPrefix(r.URL.Path, collection+"/")
			for _, detail := range state {
				if detail["id"] == id {
					require.NoError(t, json.NewEncoder(w).Encode(detail))
					return
				}
			}
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, collection+"/"):
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			assert.NotContains(t, payload, "id")
			assert.NotContains(t, payload, "metadata")
			name := firstNonEmptyString(payload["name"])
			writes[name] = r.Method
			payload["id"] = strings.TrimPrefix(r.URL.Path, collection+"/")
			payload["metadata"] = map[string]any{"origin": "USER_DEFINED"}
			state[name] = payload
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case r.Method == http.MethodPost && r.URL.Path == collection:
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			name := firstNonEmptyString(payload["name"])
			writes[name] = r.Method
			payload["id"] = "wifi-2"
			payload["metadata"] = map[string]any{"origin": "USER_DEFINED"}
			state[name] = payload
			w.WriteHeader(http.StatusCreated)
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 20},
		{Name: "Staff", AuthMode: "wpa3-enterprise", VLAN: 30, Hidden: true, ClientIsolation: true},
	}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "unifi"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = tokenEnv
	cfg.Integrations.Controller.RadiusProfile = "aegis-radius"
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = site

	preview, err := BuildControllerSyncPreview(cfg, "pull")
	require.NoError(t, err)
	assert.Equal(t, "api-key", preview.AuthScheme)
	assert.Equal(t, server.URL+collection, preview.TargetURL)
	encodedPreview, err := json.Marshal(preview.Payload)
	require.NoError(t, err)
	assert.Contains(t, string(encodedPreview), "aegis-radius")
	assert.NotContains(t, string(encodedPreview), "unifi-api-key")

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 2, pullResult.DriftCount)
	assert.Empty(t, writes)

	result, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "unifi-network", result.Adapter)
	assert.Equal(t, "api-key", result.AuthScheme)
	assert.Equal(t, 2, result.AppliedCount)
	assert.False(t, result.DriftDetected)
	assert.Equal(t, http.MethodPut, writes["Corp"])
	assert.Equal(t, http.MethodPost, writes["Staff"])
	assert.Equal(t, true, state["Corp"]["bandSteeringEnabled"])
	corpSecurity := state["Corp"]["securityConfiguration"].(map[string]any)
	assert.Equal(t, true, corpSecurity["fastRoamingEnabled"])
	assert.Equal(t, "radius-1", corpSecurity["radiusConfiguration"].(map[string]any)["profileId"])
	staffSecurity := state["Staff"]["securityConfiguration"].(map[string]any)
	assert.Equal(t, "WPA3_ENTERPRISE", staffSecurity["type"])
	assert.Equal(t, "DEFAULT", staffSecurity["securityMode"])
	assert.Equal(t, "DEVICE_MAC_ADDRESS", staffSecurity["radiusConfiguration"].(map[string]any)["nasId"].(map[string]any)["source"])
	assert.Equal(t, "network-30", state["Staff"]["network"].(map[string]any)["networkId"])
}

func TestMerakiNativeSSIDReconciliation(t *testing.T) {
	const apiKeyEnv = "AEGIS_TEST_MERAKI_API_KEY"
	const radiusSecretEnv = "AEGIS_TEST_MERAKI_RADIUS_SECRET"
	t.Setenv(apiKeyEnv, "meraki-api-key")
	t.Setenv(radiusSecretEnv, "radius-secret")

	networkID := "N_123456789"
	cfg := &config.Config{}
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Radius.DynamicAuth.Enabled = true
	cfg.Wireless.SSIDs = []config.SSIDConfig{
		{Name: "Corp", AuthMode: "wpa2-enterprise", VLAN: 20, DynamicVLAN: true},
		{Name: "Staff", AuthMode: "wpa3-enterprise", VLAN: 30, Hidden: true, ClientIsolation: true},
	}
	cfg.Integrations.Controller.Enabled = true
	cfg.Integrations.Controller.Platform = "meraki"
	cfg.Integrations.Controller.APITokenEnv = apiKeyEnv
	cfg.Integrations.Controller.RadiusServer = "192.0.2.10"
	cfg.Integrations.Controller.RadiusSecretEnv = radiusSecretEnv
	cfg.Integrations.Controller.SyncMode = "push-config"
	cfg.Integrations.Controller.Site = networkID

	resources, _, err := loadMerakiSSIDResources(cfg, "radius-secret")
	require.NoError(t, err)
	state := map[int]map[string]any{}
	for number, resource := range resources {
		state[number] = merakiComparablePayload(resource.Payload)
		state[number]["number"] = number
	}
	state[0]["authMode"] = "open"
	state[0]["enabled"] = false

	writes := map[int]map[string]any{}
	collection := merakiSSIDCollectionPath(networkID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "meraki-api-key", r.Header.Get("X-Cisco-Meraki-API-Key"))
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == collection:
			items := make([]map[string]any, 0, len(state))
			for number := 0; number < len(state); number++ {
				items = append(items, state[number])
			}
			require.NoError(t, json.NewEncoder(w).Encode(items))
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, collection+"/"):
			number, parseErr := strconv.Atoi(strings.TrimPrefix(r.URL.Path, collection+"/"))
			require.NoError(t, parseErr)
			var payload map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			authServers := payload["radiusServers"].([]any)
			assert.Equal(t, "radius-secret", authServers[0].(map[string]any)["secret"])
			writes[number] = payload
			state[number] = merakiComparablePayload(payload)
			state[number]["number"] = number
			require.NoError(t, json.NewEncoder(w).Encode(state[number]))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()
	cfg.Integrations.Controller.Endpoint = server.URL

	preview, err := BuildControllerSyncPreview(cfg, "pull")
	require.NoError(t, err)
	assert.Equal(t, "cisco-meraki-dashboard", preview.Adapter)
	assert.Equal(t, "api-key", preview.AuthScheme)
	assert.Equal(t, server.URL+collection, preview.TargetURL)
	encodedPreview, err := json.Marshal(preview.Payload)
	require.NoError(t, err)
	assert.Contains(t, string(encodedPreview), "redacted")
	assert.NotContains(t, string(encodedPreview), "radius-secret")
	assert.NotContains(t, string(encodedPreview), "meraki-api-key")

	pullResult, err := pullControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.True(t, pullResult.DriftDetected)
	assert.Equal(t, 1, pullResult.DriftCount)
	assert.Empty(t, writes)

	pushResult, err := pushControllerState(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "cisco-meraki-dashboard", pushResult.Adapter)
	assert.Equal(t, 2, pushResult.AppliedCount)
	assert.False(t, pushResult.DriftDetected)
	assert.Len(t, writes, 2)
	assert.Equal(t, "8021x-radius", writes[0]["authMode"])
	assert.Equal(t, true, writes[0]["radiusOverride"])
	assert.Equal(t, true, writes[0]["radiusCoaEnabled"])
	assert.Equal(t, "WPA3 only", writes[1]["wpaEncryptionMode"])
	assert.Equal(t, true, writes[1]["lanIsolationEnabled"])
	assert.Equal(t, false, writes[1]["visible"])
	assert.Equal(t, 1, pushResult.ResponseDetails["write_only_secret_refresh_count"])
}

func TestMerakiPushRefusesToAllocateMissingSSIDSlot(t *testing.T) {
	const apiKeyEnv = "AEGIS_TEST_MERAKI_MISSING_API_KEY"
	const radiusSecretEnv = "AEGIS_TEST_MERAKI_MISSING_RADIUS_SECRET"
	t.Setenv(apiKeyEnv, "meraki-api-key")
	t.Setenv(radiusSecretEnv, "radius-secret")

	writeAttempted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		writeAttempted = true
		http.Error(w, "unexpected write", http.StatusBadRequest)
	}))
	defer server.Close()

	cfg := &config.Config{}
	cfg.Radius.AuthPort = 1812
	cfg.Radius.AcctPort = 1813
	cfg.Wireless.SSIDs = []config.SSIDConfig{{Name: "Corp", AuthMode: "wpa2-enterprise"}}
	cfg.Integrations.Controller.Platform = "meraki"
	cfg.Integrations.Controller.Endpoint = server.URL
	cfg.Integrations.Controller.APITokenEnv = apiKeyEnv
	cfg.Integrations.Controller.RadiusServer = "192.0.2.10"
	cfg.Integrations.Controller.RadiusSecretEnv = radiusSecretEnv
	cfg.Integrations.Controller.Site = "N_missing"

	result, err := pushControllerState(context.Background(), cfg)
	require.Error(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.FailedCount)
	assert.True(t, result.DriftDetected)
	assert.Contains(t, result.ResponseDetails["drift_items"], "ssid:Corp:missing")
	assert.False(t, writeAttempted)
}

func TestMerakiClientRedactsCredentialsFromAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rejected meraki-api-key and radius-secret", http.StatusBadRequest)
	}))
	defer server.Close()

	client := &merakiClient{
		baseURL: server.URL, apiKey: "meraki-api-key", radiusSecret: "radius-secret",
		http: server.Client(),
	}
	_, _, err := client.doJSON(context.Background(), http.MethodPut, "/networks/N_1/wireless/ssids/0", map[string]any{"name": "Corp"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "meraki-api-key")
	assert.NotContains(t, err.Error(), "radius-secret")
	assert.Contains(t, err.Error(), "[redacted]")
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
