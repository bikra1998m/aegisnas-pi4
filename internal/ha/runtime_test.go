package ha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func signWitnessBody(t *testing.T, key string, payload any) ([]byte, string) {
	t.Helper()
	body, err := json.Marshal(payload)
	assert.NoError(t, err)
	mac := hmac.New(sha256.New, []byte(key))
	_, err = mac.Write(body)
	assert.NoError(t, err)
	return body, hex.EncodeToString(mac.Sum(nil))
}

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

func TestProbeWitnessDecisionSendsBearerToken(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_TOKEN", "super-secret-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer super-secret-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
			ObservedAt:     "2026-05-08T12:00:00Z",
			WitnessNode:    "witness-1",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.0.2.11",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               server.URL,
			WitnessTokenEnv:             "AEGIS_HA_WITNESS_TOKEN",
		},
	}

	decision, err := probeWitnessDecision(cfg, server.Client())
	assert.NoError(t, err)
	assert.True(t, decision.AllowPromotion)
	assert.Equal(t, "witness-1", decision.WitnessNode)
}

func TestProbeWitnessDecisionFailsWhenTokenEnvMissing(t *testing.T) {
	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.0.2.11",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               "https://witness.example.test/ha",
			WitnessTokenEnv:             "AEGIS_HA_WITNESS_TOKEN",
		},
	}

	_, err := probeWitnessDecision(cfg, nil)
	assert.ErrorContains(t, err, `ha witness bearer token env "AEGIS_HA_WITNESS_TOKEN" is configured but not loaded`)
}

func TestProbeWitnessDecisionVerifiesSignature(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_SIGNING_KEY", "witness-signing-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, signature := signWitnessBody(t, "witness-signing-secret", witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
			ObservedAt:     "2026-05-08T12:00:00Z",
			WitnessNode:    "witness-1",
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-AegisNAS-Witness-Signature", "sha256="+signature)
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.0.2.11",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               server.URL,
			WitnessSigningKeyEnv:        "AEGIS_HA_WITNESS_SIGNING_KEY",
		},
	}

	decision, err := probeWitnessDecision(cfg, server.Client())
	assert.NoError(t, err)
	assert.True(t, decision.AllowPromotion)
}

func TestProbeWitnessDecisionFailsWhenSignatureMissing(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_SIGNING_KEY", "witness-signing-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
		})
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.0.2.11",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               server.URL,
			WitnessSigningKeyEnv:        "AEGIS_HA_WITNESS_SIGNING_KEY",
		},
	}

	_, err := probeWitnessDecision(cfg, server.Client())
	assert.ErrorIs(t, err, errWitnessSignatureMissing)
}

func TestProbeWitnessDecisionFailsWhenSignatureEnvMissing(t *testing.T) {
	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.0.2.11",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               "https://witness.example.test/ha",
			WitnessSigningKeyEnv:        "AEGIS_HA_WITNESS_SIGNING_KEY",
		},
	}

	_, err := probeWitnessDecision(cfg, nil)
	assert.ErrorContains(t, err, `ha witness signing key env "AEGIS_HA_WITNESS_SIGNING_KEY" is configured but not loaded`)
}

func TestProbeWitnessDecisionVerifiesReplayChallenge(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_SIGNING_KEY", "witness-signing-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.Header.Get("X-AegisNAS-Witness-Challenge")
		assert.NotEmpty(t, challenge)
		body, signature := signWitnessBody(t, "witness-signing-secret", witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
			ObservedAt:     "2026-05-12T10:00:00Z",
			WitnessNode:    "witness-1",
			Challenge:      challenge,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-AegisNAS-Witness-Signature", "sha256="+signature)
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                        true,
			Role:                           "standby",
			PeerAPIURL:                     "https://active.example.test:8083",
			VirtualIP:                      "192.0.2.11",
			HeartbeatIntervalSeconds:       5,
			FailoverTimeoutSeconds:         20,
			SplitBrainProtectionEnabled:    true,
			WitnessAPIURL:                  server.URL,
			WitnessSigningKeyEnv:           "AEGIS_HA_WITNESS_SIGNING_KEY",
			WitnessReplayProtectionEnabled: true,
		},
	}

	decision, err := probeWitnessDecision(cfg, server.Client())
	assert.NoError(t, err)
	assert.True(t, decision.AllowPromotion)
}

func TestProbeWitnessDecisionFailsWhenReplayChallengeMissing(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_SIGNING_KEY", "witness-signing-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, signature := signWitnessBody(t, "witness-signing-secret", witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
			ObservedAt:     "2026-05-12T10:00:00Z",
			WitnessNode:    "witness-1",
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-AegisNAS-Witness-Signature", "sha256="+signature)
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                        true,
			Role:                           "standby",
			PeerAPIURL:                     "https://active.example.test:8083",
			VirtualIP:                      "192.0.2.11",
			HeartbeatIntervalSeconds:       5,
			FailoverTimeoutSeconds:         20,
			SplitBrainProtectionEnabled:    true,
			WitnessAPIURL:                  server.URL,
			WitnessSigningKeyEnv:           "AEGIS_HA_WITNESS_SIGNING_KEY",
			WitnessReplayProtectionEnabled: true,
		},
	}

	_, err := probeWitnessDecision(cfg, server.Client())
	assert.ErrorIs(t, err, errWitnessChallengeMissing)
}

func TestProbeWitnessDecisionRecordsTierReplayChallengeWithoutGlobalReplay(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_SIGNING_KEY", "witness-signing-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.Header.Get("X-AegisNAS-Witness-Challenge")
		assert.NotEmpty(t, challenge)
		body, signature := signWitnessBody(t, "witness-signing-secret", witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
			ObservedAt:     "2026-05-12T10:00:00Z",
			WitnessNode:    "witness-1",
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-AegisNAS-Witness-Signature", "sha256="+signature)
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                     true,
			Role:                        "standby",
			PeerAPIURL:                  "https://active.example.test:8083",
			VirtualIP:                   "192.0.2.11",
			HeartbeatIntervalSeconds:    5,
			FailoverTimeoutSeconds:      20,
			SplitBrainProtectionEnabled: true,
			WitnessAPIURL:               server.URL,
			WitnessSigningKeyEnv:        "AEGIS_HA_WITNESS_SIGNING_KEY",
			WitnessReplayRequiredTiers:  []string{"critical"},
		},
	}

	decision, err := probeWitnessDecision(cfg, server.Client())
	assert.NoError(t, err)
	assert.Equal(t, "missing", decision.ReplayStatus)
	assert.NotEmpty(t, decision.RequestChallenge)
}

func TestProbeWitnessDecisionFailsWhenReplayChallengeMismatches(t *testing.T) {
	t.Setenv("AEGIS_HA_WITNESS_SIGNING_KEY", "witness-signing-secret")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, signature := signWitnessBody(t, "witness-signing-secret", witnessDecision{
			AllowPromotion: true,
			Summary:        "Witness allows promotion.",
			ObservedAt:     "2026-05-12T10:00:00Z",
			WitnessNode:    "witness-1",
			Challenge:      "wrong-challenge",
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-AegisNAS-Witness-Signature", "sha256="+signature)
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	defer server.Close()

	cfg := &config.Config{
		HighAvailability: config.HighAvailabilityConfig{
			Enabled:                        true,
			Role:                           "standby",
			PeerAPIURL:                     "https://active.example.test:8083",
			VirtualIP:                      "192.0.2.11",
			HeartbeatIntervalSeconds:       5,
			FailoverTimeoutSeconds:         20,
			SplitBrainProtectionEnabled:    true,
			WitnessAPIURL:                  server.URL,
			WitnessSigningKeyEnv:           "AEGIS_HA_WITNESS_SIGNING_KEY",
			WitnessReplayProtectionEnabled: true,
		},
	}

	_, err := probeWitnessDecision(cfg, server.Client())
	assert.ErrorIs(t, err, errWitnessChallengeMismatch)
}
