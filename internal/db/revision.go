package db

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
)

var revisionSigningKey []byte

// InitRevisionSigning loads the signing key from environment or file.
func InitRevisionSigning() error {
	key := os.Getenv("AEGIS_REVISION_SIGNING_KEY")
	if key == "" {
		// Try to read from file
		data, err := os.ReadFile("/etc/aegisnas/revision.key")
		if err != nil {
			return errors.New("revision signing key not configured")
		}
		key = string(data)
	}
	revisionSigningKey = []byte(key)
	return nil
}

// signData returns HMAC-SHA256 signature of data.
func signData(data []byte) string {
	if revisionSigningKey == nil {
		return ""
	}
	h := hmac.New(sha256.New, revisionSigningKey)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// verifySignature checks the HMAC signature.
func verifySignature(data []byte, signature string) bool {
	expected := signData(data)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// SaveConfigRevision now also stores a signature.
func SaveConfigRevision(configData, createdBy string) (int, error) {
	db := GetDB()
	checksum := sha256.Sum256([]byte(configData))
	checksumStr := hex.EncodeToString(checksum[:])
	signature := signData([]byte(configData))

	var nextRev int
	err := db.QueryRow("SELECT COALESCE(MAX(revision), 0) + 1 FROM config_revisions").Scan(&nextRev)
	if err != nil {
		return 0, err
	}

	res, err := db.Exec(`INSERT INTO config_revisions (revision, config_data, checksum, signature, created_by)
		VALUES (?, ?, ?, ?, ?)`, nextRev, configData, checksumStr, signature, createdBy)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return int(id), nil
}

// GetConfigRevisionByNumber returns config data and verifies signature if key is present.
func GetConfigRevisionByNumber(rev int) (string, error) {
	db := GetDB()
	var configData, signature string
	err := db.QueryRow(`SELECT config_data, COALESCE(signature, '') FROM config_revisions WHERE revision = ?`, rev).Scan(&configData, &signature)
	if err != nil {
		return "", err
	}
	if revisionSigningKey != nil && !verifySignature([]byte(configData), signature) {
		return "", errors.New("config revision signature verification failed")
	}
	return configData, nil
}

// GetLatestConfigRevision returns the most recent stored config data.
func GetLatestConfigRevision() (string, error) {
	db := GetDB()
	var configData, signature string
	err := db.QueryRow(`SELECT config_data, COALESCE(signature, '') FROM config_revisions ORDER BY revision DESC LIMIT 1`).Scan(&configData, &signature)
	if err != nil {
		return "", err
	}
	if revisionSigningKey != nil && !verifySignature([]byte(configData), signature) {
		return "", errors.New("config revision signature verification failed")
	}
	return configData, nil
}
