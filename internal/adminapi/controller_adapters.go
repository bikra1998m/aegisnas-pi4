package adminapi

import (
	"net/http"
	"os"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/integrations"
)

type controllerAdaptersResponse struct {
	Adapters   []integrations.ControllerAdapterDescriptor `json:"adapters"`
	Configured controllerAdapterConfiguredState           `json:"configured"`
	Runtime    *db.RuntimeStatus                          `json:"runtime,omitempty"`
}

type controllerAdapterConfiguredState struct {
	Enabled                 bool                                     `json:"enabled"`
	Platform                string                                   `json:"platform"`
	Normalized              string                                   `json:"normalized_platform"`
	Adapter                 string                                   `json:"adapter"`
	SyncMode                string                                   `json:"sync_mode"`
	Endpoint                string                                   `json:"endpoint,omitempty"`
	Site                    string                                   `json:"site,omitempty"`
	SiteRequired            bool                                     `json:"site_required"`
	SiteConfigured          bool                                     `json:"site_configured"`
	EndpointSet             bool                                     `json:"endpoint_set"`
	TokenEnv                string                                   `json:"token_env,omitempty"`
	TokenEnvSet             bool                                     `json:"token_env_set"`
	TokenPresent            bool                                     `json:"token_present"`
	UsernameEnv             string                                   `json:"username_env,omitempty"`
	UsernamePresent         bool                                     `json:"username_present"`
	PasswordEnv             string                                   `json:"password_env,omitempty"`
	PasswordPresent         bool                                     `json:"password_present"`
	RadiusProfile           string                                   `json:"radius_profile,omitempty"`
	RadiusProfileRequired   bool                                     `json:"radius_profile_required"`
	RadiusProfileConfigured bool                                     `json:"radius_profile_configured"`
	RadiusServer            string                                   `json:"radius_server,omitempty"`
	RadiusSecretEnv         string                                   `json:"radius_secret_env,omitempty"`
	RadiusSecretPresent     bool                                     `json:"radius_secret_present"`
	RadiusServerRequired    bool                                     `json:"radius_server_required"`
	RadiusServerConfigured  bool                                     `json:"radius_server_configured"`
	Ready                   bool                                     `json:"ready"`
	ReadinessWarnings       []string                                 `json:"readiness_warnings,omitempty"`
	Selected                integrations.ControllerAdapterDescriptor `json:"selected"`
}

func HandleGetControllerAdapters(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	configured := buildControllerAdapterConfiguredState(cfg)
	runtime, _ := db.GetRuntimeStatus(integrations.ControllerComponent())
	writeJSON(w, http.StatusOK, controllerAdaptersResponse{
		Adapters:   integrations.ControllerAdapterCatalog(),
		Configured: configured,
		Runtime:    runtime,
	})
}

func buildControllerAdapterConfiguredState(cfg *config.Config) controllerAdapterConfiguredState {
	controller := config.ControllerConfig{}
	if cfg != nil {
		controller = cfg.Integrations.Controller
	}
	platform := normalizeControllerPlatformForAdmin(controller.Platform)
	if platform == "" {
		platform = "generic"
	}
	tokenEnv := strings.TrimSpace(controller.APITokenEnv)
	usernameEnv := strings.TrimSpace(controller.APIUsernameEnv)
	passwordEnv := strings.TrimSpace(controller.APIPasswordEnv)
	descriptor := integrations.ControllerAdapterDescriptorForPlatform(platform)
	state := controllerAdapterConfiguredState{
		Enabled:         controller.Enabled,
		Platform:        strings.TrimSpace(controller.Platform),
		Normalized:      platform,
		Adapter:         descriptor.Adapter,
		SyncMode:        strings.TrimSpace(controller.SyncMode),
		Endpoint:        strings.TrimSpace(controller.Endpoint),
		Site:            strings.TrimSpace(controller.Site),
		TokenEnv:        tokenEnv,
		UsernameEnv:     usernameEnv,
		PasswordEnv:     passwordEnv,
		RadiusProfile:   strings.TrimSpace(controller.RadiusProfile),
		RadiusServer:    strings.TrimSpace(controller.RadiusServer),
		RadiusSecretEnv: strings.TrimSpace(controller.RadiusSecretEnv),
		SiteRequired:    descriptor.RequiresSite,
		EndpointSet:     strings.TrimSpace(controller.Endpoint) != "",
		TokenEnvSet:     tokenEnv != "",
		TokenPresent:    tokenEnv != "" && strings.TrimSpace(os.Getenv(tokenEnv)) != "",
		UsernamePresent: usernameEnv != "" && strings.TrimSpace(os.Getenv(usernameEnv)) != "",
		PasswordPresent: passwordEnv != "" && strings.TrimSpace(os.Getenv(passwordEnv)) != "",
		Selected:        descriptor,
	}
	state.RadiusSecretPresent = state.RadiusSecretEnv != "" && os.Getenv(state.RadiusSecretEnv) != ""
	state.RadiusProfileRequired = (platform == "aruba" || platform == "ruckus" || platform == "fortinet" || platform == "unifi") && controllerConfigHasEnterpriseSSIDs(cfg)
	state.RadiusProfileConfigured = !state.RadiusProfileRequired || state.RadiusProfile != ""
	state.RadiusServerRequired = (platform == "juniper-mist" || platform == "mikrotik" || platform == "meraki") && controllerConfigHasEnterpriseSSIDs(cfg)
	state.RadiusServerConfigured = !state.RadiusServerRequired || (state.RadiusServer != "" && state.RadiusSecretEnv != "" && state.RadiusSecretPresent)
	state.SiteConfigured = !state.SiteRequired || state.Site != ""
	if state.SyncMode == "" {
		state.SyncMode = "monitor"
	}
	if state.Platform == "" {
		state.Platform = platform
	}
	if state.Enabled {
		if !state.EndpointSet {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "controller endpoint is not configured")
		}
		if platform == "cisco" || platform == "ruckus" || platform == "mikrotik" {
			if usernameEnv == "" || passwordEnv == "" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, descriptor.Label+" requires API username and password environment variables")
			} else if !state.UsernamePresent || !state.PasswordPresent {
				state.ReadinessWarnings = append(state.ReadinessWarnings, descriptor.Label+" API credential environment variables are configured but not both present")
			}
		} else if !state.TokenEnvSet {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "controller API token environment variable is not configured")
		} else if !state.TokenPresent {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "controller API token environment variable is configured but not present in the process environment")
		}
		if !state.SiteConfigured {
			state.ReadinessWarnings = append(state.ReadinessWarnings, "selected controller platform requires a site, zone, or network identifier")
		}
		if !state.RadiusProfileConfigured {
			if platform == "ruckus" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "Ruckus SmartZone enterprise WLAN sync requires an existing authentication service name")
			} else if platform == "fortinet" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "FortiGate enterprise VAP sync requires an existing RADIUS profile name")
			} else if platform == "unifi" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "UniFi enterprise WiFi sync requires an existing RADIUS profile name")
			} else {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "Aruba Central enterprise WLAN sync requires an existing controller RADIUS profile")
			}
		}
		if !state.RadiusServerConfigured {
			if platform == "mikrotik" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "MikroTik enterprise WiFi sync requires a RADIUS server and a present shared-secret environment variable")
			} else if platform == "meraki" {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "Cisco Meraki enterprise SSID sync requires a RADIUS server and a present shared-secret environment variable")
			} else {
				state.ReadinessWarnings = append(state.ReadinessWarnings, "Juniper Mist enterprise WLAN sync requires a RADIUS server and a present shared-secret environment variable")
			}
		}
	}
	credentialsReady := state.TokenEnvSet && state.TokenPresent
	if platform == "cisco" || platform == "ruckus" || platform == "mikrotik" {
		credentialsReady = state.UsernamePresent && state.PasswordPresent
	}
	state.Ready = state.EndpointSet && credentialsReady && state.SiteConfigured && state.RadiusProfileConfigured && state.RadiusServerConfigured
	if !state.Enabled {
		state.Ready = false
	}
	return state
}

func controllerConfigHasEnterpriseSSIDs(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, ssid := range cfg.Wireless.SSIDs {
		switch strings.ToLower(strings.TrimSpace(ssid.AuthMode)) {
		case "wpa2-enterprise", "wpa3-enterprise":
			return true
		}
	}
	return false
}

func normalizeControllerPlatformForAdmin(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "ubnt", "ubiquiti":
		return "unifi"
	default:
		return strings.ToLower(strings.TrimSpace(platform))
	}
}
