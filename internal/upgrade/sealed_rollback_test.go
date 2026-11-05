package upgrade

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func recoveryTestZIP(t *testing.T, change func([]recoveryTestEntry) []recoveryTestEntry) []byte {
	t.Helper()
	entries := []recoveryTestEntry{
		{name: "manifest.json", data: []byte(`{"package_version":"1","contains_secrets":true}`)},
		{name: "config/config.yaml", data: []byte("radius:\n  secret: private-test-value\n")},
		{name: "config/system-settings.json", data: []byte(`{"database":{"path":"data.db"}}`)},
		{name: "database/data.db", data: []byte("SQLite format 3\x00test fixture")},
	}
	if change != nil {
		entries = change(entries)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, entry := range entries {
		h := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		h.SetMode(0600 | entry.mode)
		if entry.declared != 0 {
			h.UncompressedSize64 = entry.declared
			_, err := w.CreateRaw(h)
			require.NoError(t, err)
			continue
		}
		f, err := w.CreateHeader(h)
		require.NoError(t, err)
		_, err = f.Write(entry.data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

type recoveryTestEntry struct {
	name     string
	data     []byte
	mode     os.FileMode
	declared uint64
}

func privateRecoveryTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// testing.TempDir's numbered subdirectory uses 0777 before the caller's
	// umask. Provision the protected workspace required by the recovery API.
	require.NoError(t, os.Chmod(dir, 0700))
	return dir
}

func TestSealedRecoveryAuthenticatedRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{23}, 32)
	payload := recoveryTestZIP(t, nil)
	sealed, receipt, err := SealRollbackPackage(payload, key, "lab/appliance-42/epoch-7")
	require.NoError(t, err)
	require.NotContains(t, string(sealed), "private-test-value")
	require.False(t, receipt.ProductionActivationAuthorized)
	opened, verified, err := OpenSealedRollbackPackage(sealed, key, receipt.RecoveryContext, receipt.SealedSHA256)
	require.NoError(t, err)
	require.Equal(t, payload, opened)
	require.Equal(t, receipt.PackageSHA256, verified.PackageSHA256)
	require.Equal(t, "authenticated_for_staging", verified.Status)
	// Check interoperability with the standard nonce-explicit GCM API, rather
	// than relying exclusively on our matching Seal/Open implementations.
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	body := sealed[len(recoveryMagic):]
	plain, err := aead.Open(nil, body[:12], body[12:], []byte(recoveryMagic+receipt.RecoveryContext))
	require.NoError(t, err)
	require.Equal(t, payload, plain)
	second, _, err := SealRollbackPackage(payload, key, receipt.RecoveryContext)
	require.NoError(t, err)
	require.NotEqual(t, sealed, second, "each encryption must use a new random nonce")
	_, _, err = OpenSealedRollbackPackage(second, key, receipt.RecoveryContext, receipt.SealedSHA256)
	require.ErrorContains(t, err, "approved SHA-256")
}

func TestSealedRecoveryRejectsTamperingAndWrongTrustInputs(t *testing.T) {
	key := bytes.Repeat([]byte{43}, 32)
	sealed, receipt, err := SealRollbackPackage(recoveryTestZIP(t, nil), key, "appliance-42")
	require.NoError(t, err)
	for _, offset := range []int{0, len(recoveryMagic) - 1, len(recoveryMagic), len(sealed) / 2, len(sealed) - 1} {
		t.Run(fmt.Sprintf("alter-byte-%d", offset), func(t *testing.T) {
			altered := bytes.Clone(sealed)
			altered[offset] ^= 1
			// A substituted checksum cannot forge authentication.
			plain, _, err := OpenSealedRollbackPackage(altered, key, receipt.RecoveryContext, fmt.Sprintf("%x", sha256.Sum256(altered)))
			require.Error(t, err)
			require.Empty(t, plain)
		})
	}
	for name, item := range map[string]struct {
		key             []byte
		context, digest string
		data            []byte
	}{
		"wrong-key":       {bytes.Repeat([]byte{44}, 32), "appliance-42", receipt.SealedSHA256, sealed},
		"wrong-context":   {key, "appliance-43", receipt.SealedSHA256, sealed},
		"no-digest":       {key, "appliance-42", "", sealed},
		"wrong-digest":    {key, "appliance-42", fmt.Sprintf("%064d", 0), sealed},
		"raw-zip":         {key, "appliance-42", receipt.SealedSHA256, recoveryTestZIP(t, nil)},
		"truncated":       {key, "appliance-42", receipt.SealedSHA256, sealed[:25]},
		"empty-key":       {nil, "appliance-42", receipt.SealedSHA256, sealed},
		"password":        {[]byte("password"), "appliance-42", receipt.SealedSHA256, sealed},
		"empty-context":   {key, "", receipt.SealedSHA256, sealed},
		"control-context": {key, "appliance\n42", receipt.SealedSHA256, sealed},
	} {
		t.Run(name, func(t *testing.T) {
			plain, _, err := OpenSealedRollbackPackage(item.data, item.key, item.context, item.digest)
			require.Error(t, err)
			require.Empty(t, plain)
		})
	}
}

func TestRollbackRejectsHostileArchivesBeforeExtraction(t *testing.T) {
	for name, change := range map[string]func([]recoveryTestEntry) []recoveryTestEntry{
		"duplicate":    func(e []recoveryTestEntry) []recoveryTestEntry { e[3] = e[0]; return e },
		"extra":        func(e []recoveryTestEntry) []recoveryTestEntry { return append(e, e[0]) },
		"traversal":    func(e []recoveryTestEntry) []recoveryTestEntry { e[3].name = "../data.db"; return e },
		"absolute":     func(e []recoveryTestEntry) []recoveryTestEntry { e[3].name = "/data.db"; return e },
		"windows-path": func(e []recoveryTestEntry) []recoveryTestEntry { e[3].name = `C:\data.db`; return e },
		"symlink":      func(e []recoveryTestEntry) []recoveryTestEntry { e[3].mode = os.ModeSymlink; return e },
		"directory":    func(e []recoveryTestEntry) []recoveryTestEntry { e[3].mode = os.ModeDir; return e },
		"wrong-version": func(e []recoveryTestEntry) []recoveryTestEntry {
			e[0].data = []byte(`{"package_version":"2"}`)
			return e
		},
		"missing-manifest": func(e []recoveryTestEntry) []recoveryTestEntry { return e[1:] },
		"manifest-bomb": func(e []recoveryTestEntry) []recoveryTestEntry {
			e[0].data = bytes.Repeat([]byte{' '}, 65537)
			return e
		},
		"database-size":  func(e []recoveryTestEntry) []recoveryTestEntry { e[3].declared = MaxRollbackPackageBytes + 1; return e },
		"aggregate-size": func(e []recoveryTestEntry) []recoveryTestEntry { e[3].declared = MaxRollbackPackageBytes; return e },
	} {
		t.Run(name, func(t *testing.T) {
			archive := recoveryTestZIP(t, change)
			_, err := ReadRollbackPackage(bytes.NewReader(archive), int64(len(archive)))
			require.Error(t, err)
			output := filepath.Join(t.TempDir(), "must-not-exist")
			_, err = ExtractRollbackPackageBytes(archive, output)
			require.Error(t, err)
			_, err = os.Lstat(output)
			require.True(t, os.IsNotExist(err))
		})
	}
	_, err := ReadRollbackPackage(bytes.NewReader(nil), MaxRollbackPackageBytes+1)
	require.ErrorContains(t, err, "size limit")
}

func TestRecoveryCannotSealIncompleteArchive(t *testing.T) {
	payload := recoveryTestZIP(t, func(e []recoveryTestEntry) []recoveryTestEntry { return e[:3] })
	_, _, err := SealRollbackPackage(payload, bytes.Repeat([]byte{1}, 32), "appliance")
	require.ErrorContains(t, err, "incomplete")
}

func TestRecoveryExtractionDoesNotOverwrite(t *testing.T) {
	root := privateRecoveryTestDir(t)
	output := filepath.Join(root, "extracted")
	payload := recoveryTestZIP(t, nil)
	_, err := ExtractRollbackPackageBytes(payload, output)
	require.NoError(t, err)
	sentinel := filepath.Join(output, "database", "data.db")
	require.NoError(t, os.WriteFile(sentinel, []byte("keep this existing database"), 0600))
	_, err = ExtractRollbackPackageBytes(payload, output)
	require.Error(t, err)
	current, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	require.Equal(t, "keep this existing database", string(current))
	if runtime.GOOS == "linux" {
		for _, name := range []string{output, filepath.Join(output, "database"), sentinel} {
			info, err := os.Stat(name)
			require.NoError(t, err)
			require.Zero(t, info.Mode().Perm()&0077)
		}
	}
}

func TestRecoveryKeyAndOutputFiles(t *testing.T) {
	root := privateRecoveryTestDir(t)
	keyPath := filepath.Join(root, "key")
	key := bytes.Repeat([]byte{83}, 32)
	require.NoError(t, os.WriteFile(keyPath, key, 0600))
	read, err := ReadRecoveryKey(keyPath)
	require.NoError(t, err)
	require.Equal(t, key, read)
	for _, size := range []int{0, 31, 33, 64} {
		require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{83}, size), 0600))
		_, err := ReadRecoveryKey(keyPath)
		require.Error(t, err)
	}
	output := filepath.Join(root, "sealed")
	require.NoError(t, WriteSealedRecoveryFile(output, []byte("first")))
	require.Error(t, WriteSealedRecoveryFile(output, []byte("second")))
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, "first", string(data))
	_, err = ReadRecoveryFile(output, 4)
	require.Error(t, err)
	_, err = ReadRecoveryFile(root, 1024)
	require.Error(t, err)
}

func TestRecoveryLinuxTrustBoundary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ownership/mode/link enforcement; Windows ACLs are not certified")
	}
	root := privateRecoveryTestDir(t)
	keyPath := filepath.Join(root, "key")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{5}, 32), 0600))
	require.NoError(t, os.Chmod(keyPath, 0644))
	_, err := ReadRecoveryKey(keyPath)
	require.ErrorContains(t, err, "private")
	require.NoError(t, os.Chmod(keyPath, 0600))
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(keyPath, link))
	_, err = ReadRecoveryKey(link)
	require.Error(t, err)
	_, err = ReadRecoveryFile(link, 32)
	require.Error(t, err)
	require.Error(t, WriteSealedRecoveryFile(link, []byte("replacement")))
	hard := filepath.Join(root, "hard")
	require.NoError(t, os.Link(keyPath, hard))
	_, err = ReadRecoveryKey(keyPath)
	require.ErrorContains(t, err, "hard links")
	parentLink := filepath.Join(root, "parent-link")
	require.NoError(t, os.Symlink(root, parentLink))
	_, err = ExtractRollbackPackageBytes(recoveryTestZIP(t, nil), filepath.Join(parentLink, "extracted"))
	require.Error(t, err)
	unsafe := filepath.Join(root, "unsafe")
	require.NoError(t, os.Mkdir(unsafe, 0700))
	require.NoError(t, os.Chmod(unsafe, 0777))
	require.Error(t, WriteSealedRecoveryFile(filepath.Join(unsafe, "sealed"), []byte("secret")))
}

func TestSQLiteRecoveryRejectsPostgreSQLWithoutTouchingLocalPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "must-not-create.db")
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "postgres", Path: path}}
	_, _, _, err := CreateRollbackPackage(cfg, "unused-config")
	require.ErrorContains(t, err, "cannot back up or restore")
	inspection, err := InspectRollbackPackageBytes(recoveryTestZIP(t, nil), cfg, "unused-config")
	require.NoError(t, err)
	require.False(t, inspection.OnlineRestoreSupported)
	_, err = RestoreRollbackPackage(cfg, "unused-config", recoveryTestZIP(t, nil), rollbackRestoreConfirmationText)
	require.Error(t, err)
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
}
