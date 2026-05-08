package ha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const replicationSignatureAlgorithm = "hmac-sha256"

func replicationSigningKey(cfg *config.Config) []byte {
	if cfg == nil {
		return nil
	}
	envName := strings.TrimSpace(cfg.HighAvailability.ReplicationSigningKeyEnv)
	if envName == "" {
		return nil
	}
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return nil
	}
	return []byte(value)
}

func signReplicationFingerprint(cfg *config.Config, fingerprint string) string {
	key := replicationSigningKey(cfg)
	if len(key) == 0 || strings.TrimSpace(fingerprint) == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.TrimSpace(fingerprint)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func verifyReplicationFingerprint(cfg *config.Config, fingerprint, signature string) bool {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return false
	}
	expected := signReplicationFingerprint(cfg, fingerprint)
	if expected == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(signature))
}

func replicationSecurityProfileHash(cfg *config.Config) string {
	parts := []string{"signing:disabled", "encryption:disabled"}
	if key := replicationSigningKey(cfg); len(key) > 0 {
		sum := sha256.Sum256(key)
		parts[0] = "signing:" + replicationSignatureAlgorithm + ":" + hex.EncodeToString(sum[:])
	}
	if key := replicationEncryptionKey(cfg); len(key) > 0 {
		sum := sha256.Sum256(key)
		parts[1] = "encryption:" + replicationEncryptionAlgorithm + ":" + hex.EncodeToString(sum[:])
	}
	return checksumBytes([]byte(strings.Join(parts, "\n")))
}
