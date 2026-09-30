package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"go.uber.org/zap"
)

func TestHandleCaptivePortalAPIReturnsRFC8910Payload(t *testing.T) {
	srv, err := New(&config.Config{
		Portal: config.PortalConfig{
			Enabled:  true,
			Port:     8081,
			ListenIP: "192.168.50.1",
			CWA: config.PortalCWAConfig{
				Enabled:           true,
				RFC8910APIEnabled: true,
				HTTPSRequired:     true,
				PortalBaseURL:     "https://portal.example.test",
				CaptiveAPIPath:    "/captive-portal/api",
				VenueInfoURL:      "https://portal.example.test/venue",
			},
		},
	}, zap.NewNop())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/captive-portal/api?client_mac=02:11:22:33:44:55", nil)
	srv.HandleCaptivePortalAPI(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/captive+json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, true, payload["captive"])
	assert.Equal(t, "https://portal.example.test/venue", payload["venue-info-url"])
	assert.Contains(t, payload["user-portal-url"], "client_mac=02%3A11%3A22%3A33%3A44%3A55")
}
