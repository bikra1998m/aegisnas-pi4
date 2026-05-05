package ha

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestProbeStatusDisabled(t *testing.T) {
	status, message, details := ProbeStatus(&config.Config{}, nil)

	assert.Equal(t, "disabled", status)
	assert.Contains(t, message, "disabled")
	assert.Equal(t, "", details["peer_api_url"])
}

func TestProbeStatusHealthyPeer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                  true,
			Role:                     "active",
			PeerAPIURL:               server.URL,
			VirtualIP:                "192.0.2.10",
			HeartbeatIntervalSeconds: 5,
			FailoverTimeoutSeconds:   20,
		},
	}

	status, message, details := ProbeStatus(cfg, server.Client())

	assert.Equal(t, "ok", status)
	assert.Contains(t, message, "healthy")
	assert.Equal(t, true, details["peer_reachable"])
	assert.Equal(t, http.StatusOK, details["peer_status_code"])
}

func TestProbeStatusUnhealthyPeer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                  true,
			Role:                     "standby",
			PeerAPIURL:               server.URL,
			VirtualIP:                "192.0.2.11",
			HeartbeatIntervalSeconds: 5,
			FailoverTimeoutSeconds:   20,
		},
	}

	status, message, details := ProbeStatus(cfg, server.Client())

	assert.Equal(t, "degraded", status)
	assert.Contains(t, message, "503")
	assert.Equal(t, false, details["peer_reachable"])
}
