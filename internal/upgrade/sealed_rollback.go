package upgrade

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// The format/version and caller-supplied recovery context are authenticated AAD.
// The context comes from the operator's recovery record, never the archive.
const recoveryMagic = "AEGISNAS-RECOVERY\x00\x01"
const MaxSealedRollbackBytes = MaxRollbackPackageBytes + len(recoveryMagic) + 28

var recoveryContextPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

type RecoveryReceipt struct {
	SchemaVersion                  int    `json:"schema_version"`
	Status                         string `json:"status"`
	Algorithm                      string `json:"algorithm"`
	RecoveryContext                string `json:"recovery_context"`
	SealedSHA256                   string `json:"sealed_sha256"`
	PackageSHA256                  string `json:"package_sha256"`
	ProductionActivationAuthorized bool   `json:"production_activation_authorized"`
}

func recoveryCipher(key []byte, context string) (cipher.AEAD, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("recovery key must contain exactly 32 random bytes")
	}
	if !recoveryContextPattern.MatchString(context) {
		return nil, nil, fmt.Errorf("recovery context must contain 1-128 ASCII identifier characters")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	return aead, []byte(recoveryMagic + context), err
}

// SealRollbackPackage encrypts a bounded SQLite recovery ZIP. It is local
// symmetric authentication, not a release signature or permission to activate.
func SealRollbackPackage(payload, key []byte, context string) ([]byte, RecoveryReceipt, error) {
	aead, aad, err := recoveryCipher(key, context)
	if err != nil {
		return nil, RecoveryReceipt{}, err
	}
	contents, err := ReadRollbackPackage(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return nil, RecoveryReceipt{}, err
	}
	if len(contents.ConfigYAML) == 0 || len(contents.SystemSettings) == 0 || len(contents.Database) == 0 {
		return nil, RecoveryReceipt{}, fmt.Errorf("cannot seal an incomplete rollback package")
	}
	sealed := aead.Seal([]byte(recoveryMagic), nil, payload, aad)
	return sealed, recoveryReceipt(sealed, payload, context, "sealed"), nil
}

// OpenSealedRollbackPackage requires the exact sealed digest from an independently
// trusted recovery record. An older, otherwise authentic archive is not silently
// selected. There is deliberately no unsigned fallback or skip-verification flag.
func OpenSealedRollbackPackage(sealed, key []byte, context, expectedSHA256 string) ([]byte, RecoveryReceipt, error) {
	aead, aad, err := recoveryCipher(key, context)
	if err != nil {
		return nil, RecoveryReceipt{}, err
	}
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, RecoveryReceipt{}, fmt.Errorf("expected sealed SHA-256 is required from a trusted recovery record")
	}
	if len(sealed) < len(recoveryMagic)+aead.Overhead() || len(sealed) > MaxSealedRollbackBytes || !bytes.HasPrefix(sealed, []byte(recoveryMagic)) {
		return nil, RecoveryReceipt{}, fmt.Errorf("invalid sealed recovery format or size")
	}
	actual := sha256.Sum256(sealed)
	if !bytes.Equal(actual[:], expected) {
		return nil, RecoveryReceipt{}, fmt.Errorf("sealed recovery does not match the approved SHA-256")
	}
	payload, err := aead.Open(nil, nil, sealed[len(recoveryMagic):], aad)
	if err != nil {
		return nil, RecoveryReceipt{}, fmt.Errorf("recovery authentication failed")
	}
	if _, err = ReadRollbackPackage(bytes.NewReader(payload), int64(len(payload))); err != nil {
		clear(payload)
		return nil, RecoveryReceipt{}, err
	}
	return payload, recoveryReceipt(sealed, payload, context, "authenticated_for_staging"), nil
}

func recoveryReceipt(sealed, payload []byte, context, status string) RecoveryReceipt {
	return RecoveryReceipt{SchemaVersion: 1, Status: status, Algorithm: "AES-256-GCM",
		RecoveryContext: context, SealedSHA256: fmt.Sprintf("%x", sha256.Sum256(sealed)),
		PackageSHA256: fmt.Sprintf("%x", sha256.Sum256(payload))}
}

// ReadRecoveryKey accepts raw random key bytes, not a password or hex string.
// Linux ownership, link and permission checks protect the administrative key.
// Windows tests do not certify ACL enforcement.
func ReadRecoveryKey(path string) ([]byte, error) {
	if err := trustedRecoveryPath(path, true); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recovery key: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, current) || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("recovery key changed while opening")
	}
	if err := recoveryFilePermissions(opened, true, false); err != nil {
		return nil, err
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, fmt.Errorf("recovery key must contain exactly 32 random bytes")
	}
	return key, nil
}

func trustedRecoveryPath(path string, private bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("recovery path contains a link or special file")
		}
		if err := recoveryFilePermissions(info, private && current == absolute, current != absolute); err != nil {
			return err
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

// ReadRecoveryFile bounds input allocation and rejects device/FIFO inputs.
func ReadRecoveryFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("recovery input must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("recovery input exceeds size limit or is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("recovery input exceeds size limit")
	}
	return data, err
}

// WriteSealedRecoveryFile refuses an existing path, including symbolic links.
// An interrupted write may leave an incomplete file; it never replaces a backup.
func WriteSealedRecoveryFile(path string, data []byte) error {
	if err := trustedRecoveryPath(filepath.Dir(path), false); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return writeNewRootFile(root, filepath.Base(path), data)
}
