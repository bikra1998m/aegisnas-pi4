package ha

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

const (
	replicationEncryptionAlgorithm = "aes-256-gcm"
	replicationEnvelopeType        = "aegisnas-ha-replication-envelope"
	replicationEnvelopeVersion     = 1
)

type replicationEnvelope struct {
	EnvelopeType        string `json:"envelope_type"`
	Version             int    `json:"version"`
	EncryptionAlgorithm string `json:"encryption_algorithm"`
	Nonce               string `json:"nonce"`
	Ciphertext          string `json:"ciphertext"`
}

func replicationEncryptionKey(cfg *config.Config) []byte {
	if cfg == nil {
		return nil
	}
	envName := strings.TrimSpace(cfg.HighAvailability.ReplicationEncryptionKeyEnv)
	if envName == "" {
		return nil
	}
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func encryptReplicationPackage(cfg *config.Config, packageBytes []byte) ([]byte, string, error) {
	key := replicationEncryptionKey(cfg)
	if len(key) == 0 {
		return packageBytes, "", nil
	}
	if len(packageBytes) == 0 {
		return nil, "", errors.New("cannot encrypt an empty HA replication package")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("create HA replication cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("create HA replication gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("generate HA replication nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, packageBytes, nil)
	envelope := replicationEnvelope{
		EnvelopeType:        replicationEnvelopeType,
		Version:             replicationEnvelopeVersion,
		EncryptionAlgorithm: replicationEncryptionAlgorithm,
		Nonce:               base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:          base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("marshal HA replication envelope: %w", err)
	}
	return data, replicationEncryptionAlgorithm, nil
}

func decodeReplicationPackage(cfg *config.Config, packageBytes []byte) ([]byte, string, string, error) {
	keyConfigured := len(replicationEncryptionKey(cfg)) > 0
	envelope, encrypted, err := loadReplicationEnvelope(packageBytes)
	if err != nil {
		return nil, "invalid", "", err
	}
	if !encrypted {
		if keyConfigured {
			return nil, "missing", "", errors.New("encrypted HA replication packages are required when high_availability.replication_encryption_key_env is configured")
		}
		return packageBytes, "unencrypted", "", nil
	}

	algorithm := strings.TrimSpace(envelope.EncryptionAlgorithm)
	if algorithm == "" {
		algorithm = replicationEncryptionAlgorithm
	}
	if algorithm != replicationEncryptionAlgorithm {
		return nil, "invalid", algorithm, fmt.Errorf("unsupported HA replication encryption algorithm %q", algorithm)
	}
	key := replicationEncryptionKey(cfg)
	if len(key) == 0 {
		return nil, "missing", algorithm, errors.New("encrypted HA replication packages require high_availability.replication_encryption_key_env to be configured and loaded in the environment")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "invalid", algorithm, fmt.Errorf("create HA replication cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "invalid", algorithm, fmt.Errorf("create HA replication gcm: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Nonce))
	if err != nil {
		return nil, "invalid", algorithm, fmt.Errorf("decode HA replication nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Ciphertext))
	if err != nil {
		return nil, "invalid", algorithm, fmt.Errorf("decode HA replication ciphertext: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, "invalid", algorithm, errors.New("HA replication package decryption failed")
	}
	return plaintext, "decrypted", algorithm, nil
}

func loadReplicationEnvelope(packageBytes []byte) (replicationEnvelope, bool, error) {
	var envelope replicationEnvelope
	trimmed := strings.TrimSpace(string(packageBytes))
	if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
		return envelope, false, nil
	}
	if err := json.Unmarshal(packageBytes, &envelope); err != nil {
		return envelope, false, nil
	}
	if strings.TrimSpace(envelope.EnvelopeType) == "" &&
		envelope.Version == 0 &&
		strings.TrimSpace(envelope.EncryptionAlgorithm) == "" &&
		strings.TrimSpace(envelope.Nonce) == "" &&
		strings.TrimSpace(envelope.Ciphertext) == "" {
		return envelope, false, nil
	}
	if envelope.EnvelopeType != replicationEnvelopeType {
		return envelope, true, fmt.Errorf("unexpected HA replication envelope type %q", envelope.EnvelopeType)
	}
	if envelope.Version != replicationEnvelopeVersion {
		return envelope, true, fmt.Errorf("unsupported HA replication envelope version %d", envelope.Version)
	}
	if strings.TrimSpace(envelope.Nonce) == "" || strings.TrimSpace(envelope.Ciphertext) == "" {
		return envelope, true, errors.New("HA replication envelope is missing encrypted payload fields")
	}
	return envelope, true, nil
}
