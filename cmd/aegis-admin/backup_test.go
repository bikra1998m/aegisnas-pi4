package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func legacyDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestLegacyBackupRejectsIncompleteManifest(t *testing.T) {
	for _, document := range []string{"{}", "null", `{"config.yaml":"` + legacyDigest([]byte("config")) + `"}`} {
		t.Run(document, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range map[string]string{"manifest.json": document, "data.db": "database", "config.yaml": "config"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := verifyManifest(dir); err == nil {
				t.Fatal("incomplete manifest accepted")
			}
		})
	}
}

func TestLegacyBackupRejectsManifestEscape(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "staged")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf(`{"../outside":%q}`, legacyDigest([]byte("outside")))
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(dir); err == nil {
		t.Fatal("manifest accepted a path outside the extraction directory")
	}
}

func TestLegacyBackupRejectsUncheckedConfig(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"manifest.json": fmt.Sprintf(`{"data.db":%q}`, legacyDigest([]byte("database"))),
		"data.db":       "database",
		"config.yaml":   "unchecked config",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyManifest(dir); err == nil {
		t.Fatal("unchecked configuration accepted for restore")
	}
}

func TestLegacyBackupRejectsDuplicateManifestKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.db"), []byte("database"), 0600); err != nil {
		t.Fatal(err)
	}
	document := fmt.Sprintf(`{"data.db":"invalid","data.db":%q}`, legacyDigest([]byte("database")))
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(dir); err == nil {
		t.Fatal("ambiguous duplicate manifest keys accepted")
	}
}

type legacyTarEntry struct {
	name, body string
	kind       byte
}

func writeLegacyArchive(t *testing.T, entries ...legacyTarEntry) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "backup.tar.gz")
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	writer := tar.NewWriter(compressed)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: 0600, Size: int64(len(entry.body))}
		if entry.kind == tar.TypeSymlink || entry.kind == tar.TypeLink {
			header.Linkname = "other"
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, close := range []func() error{writer.Close, compressed.Close, file.Close} {
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
	return name
}

func TestLegacyBackupRejectsDuplicateArchiveEntries(t *testing.T) {
	archive := writeLegacyArchive(t, legacyTarEntry{"data.db", "one", tar.TypeReg}, legacyTarEntry{"data.db", "two", tar.TypeReg})
	if err := extractTarGz(archive, t.TempDir()); err == nil {
		t.Fatal("duplicate archive entry replaced an already extracted file")
	}
}

func TestLegacyBackupRejectsArchiveLinks(t *testing.T) {
	for _, kind := range []byte{tar.TypeSymlink, tar.TypeLink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			archive := writeLegacyArchive(t, legacyTarEntry{"data.db", "", kind})
			if err := extractTarGz(archive, t.TempDir()); err == nil {
				t.Fatal("archive link accepted as recovery data")
			}
		})
	}
}

func TestLegacyBackupCapturesCommittedWALAndPreservesSource(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "backup's #+% space")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dir, "live.db")
	handle, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	handle.SetMaxOpenConns(1)
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=0", "CREATE TABLE fixture(id INTEGER PRIMARY KEY, value TEXT)", "INSERT INTO fixture VALUES(1, 'committed in WAL')"} {
		if _, err := handle.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	before := map[string][]byte{}
	for _, name := range []string{database, database + "-wal"} {
		value, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = value
	}
	if len(before[database+"-wal"]) == 0 {
		t.Fatal("test did not create committed WAL pages")
	}
	// The former raw file copy cannot see this committed row.
	raw := filepath.Join(dir, "raw-copy.db")
	if err := os.WriteFile(raw, before[database], 0600); err != nil {
		t.Fatal(err)
	}
	oldCopy, err := openLegacySQLite(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	var value string
	if err := oldCopy.QueryRow("SELECT value FROM fixture WHERE id=1").Scan(&value); err == nil {
		t.Fatal("raw-copy regression fixture unexpectedly included WAL data")
	}
	oldCopy.Close()
	archive := filepath.Join(dir, "snapshot.tar.gz")
	cfg := &config.Config{Database: config.DatabaseConfig{Backend: "sqlite", Path: database}}
	if err := createLegacyBackup(context.Background(), cfg, "", archive); err != nil {
		t.Fatal(err)
	}
	staged := t.TempDir()
	if err := extractTarGz(archive, staged); err != nil {
		t.Fatal(err)
	}
	if err := verifyManifest(staged); err != nil {
		t.Fatal(err)
	}
	snapshot, err := openLegacySQLite(context.Background(), filepath.Join(staged, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := snapshot.QueryRow("SELECT value FROM fixture WHERE id=1").Scan(&value); err != nil || value != "committed in WAL" {
		t.Fatalf("backup lost committed data: %q, %v", value, err)
	}
	for name, expected := range before {
		actual, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("backup changed its source: %s, %v", name, err)
		}
	}
	original, _ := os.ReadFile(archive)
	if err := createLegacyBackup(context.Background(), cfg, "", archive); err == nil {
		t.Fatal("existing backup was overwritten")
	}
	after, _ := os.ReadFile(archive)
	if !bytes.Equal(original, after) {
		t.Fatal("rejected overwrite changed existing backup")
	}
	if runtime.GOOS != "windows" {
		for _, name := range []string{archive, filepath.Join(staged, "data.db"), filepath.Join(staged, "manifest.json")} {
			info, err := os.Stat(name)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatalf("recovery secret file is not private: %s", name)
			}
		}
	}
}

func TestLegacyBackupRejectsOtherBackendsWithoutFiles(t *testing.T) {
	for _, backend := range []string{"postgres", "postgresql", " PostgreSQL ", "unknown"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{Database: config.DatabaseConfig{Backend: backend, Path: filepath.Join(dir, "missing.db")}}
			if err := createLegacyBackup(context.Background(), cfg, "missing-config", filepath.Join(dir, "archive")); err == nil || !strings.Contains(err.Error(), "requires SQLite") {
				t.Fatalf("wrong backend accepted: %v", err)
			}
			if _, err := validateLegacyRestore(context.Background(), cfg, "missing-config", dir); err == nil || !strings.Contains(err.Error(), "requires SQLite") {
				t.Fatalf("wrong backend restore accepted: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("rejected backend created files")
			}
		})
	}
}

func TestLegacyBackupDoesNotCreateMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Database: config.DatabaseConfig{Path: filepath.Join(dir, "missing.db")}}
	if err := createLegacyBackup(context.Background(), cfg, "", filepath.Join(dir, "backup")); err == nil {
		t.Fatal("missing source database accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("missing source or archive was created")
	}
}

func TestLegacyBackupRejectsCorruptGzipAndTrailingData(t *testing.T) {
	manifest := fmt.Sprintf(`{"data.db":%q}`, legacyDigest([]byte("database")))
	archive := writeLegacyArchive(t, legacyTarEntry{"data.db", "database", tar.TypeReg}, legacyTarEntry{"manifest.json", manifest, tar.TypeReg})
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), original...)
	corrupt[len(corrupt)-8] ^= 1
	for name, contents := range map[string][]byte{"crc": corrupt, "truncated": original[:len(original)-5], "trailing": append(append([]byte(nil), original...), 'x'), "concatenated": append(append([]byte(nil), original...), original...)} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "bad.tar.gz")
			if err := os.WriteFile(file, contents, 0600); err != nil {
				t.Fatal(err)
			}
			if err := extractTarGz(file, t.TempDir()); err == nil {
				t.Fatal("corrupt or trailing archive data accepted")
			}
		})
	}
}

func TestLegacyBackupRejectsUnsafeNamesAndDeclaredSize(t *testing.T) {
	for _, name := range []string{"../data.db", "/data.db", "config/../data.db", "extra", "data.db:stream"} {
		t.Run(name, func(t *testing.T) {
			archive := writeLegacyArchive(t, legacyTarEntry{name, "payload", tar.TypeReg})
			if err := extractTarGz(archive, t.TempDir()); err == nil {
				t.Fatal("unexpected archive path accepted")
			}
		})
	}
	var buffer bytes.Buffer
	zipped := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(zipped)
	if err := writer.WriteHeader(&tar.Header{Name: "data.db", Mode: 0600, Size: legacyBackupLimit + 1}); err != nil {
		t.Fatal(err)
	}
	// No giant payload is allocated; the declared size must fail before extraction.
	_ = zipped.Close()
	archive := filepath.Join(t.TempDir(), "oversized.tar.gz")
	if err := os.WriteFile(archive, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if err := extractTarGz(archive, destination); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized entry not rejected at its header: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "data.db")); !os.IsNotExist(err) {
		t.Fatal("oversized database extraction was started")
	}
}

func TestLegacyRestoreCompensatesPublicationFailure(t *testing.T) {
	for _, failRollback := range []bool{false, true} {
		t.Run(fmt.Sprint(failRollback), func(t *testing.T) {
			dir := t.TempDir()
			for name, value := range map[string]string{"live.db": "old database", "live.yaml": "old config", "new.db": "new database", "new.yaml": "new config"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			rename := func(from, to string) error {
				calls++
				if calls == 2 || (failRollback && calls == 3) {
					return errors.New("injected publication failure")
				}
				return os.Rename(from, to)
			}
			targets := []legacyRestoreTarget{{filepath.Join(dir, "new.db"), filepath.Join(dir, "live.db"), true}, {filepath.Join(dir, "new.yaml"), filepath.Join(dir, "live.yaml"), false}}
			err := installLegacyRestore(targets, rename)
			if err == nil {
				t.Fatal("publication failure reported as success")
			}
			configData, _ := os.ReadFile(filepath.Join(dir, "live.yaml"))
			if string(configData) != "old config" {
				t.Fatal("failed configuration publication changed the original")
			}
			if failRollback {
				if !strings.Contains(err.Error(), "compensation failed") {
					t.Fatalf("rollback failure hidden: %v", err)
				}
				files, _ := filepath.Glob(filepath.Join(dir, ".aegis-restore-before-*"))
				found := false
				for _, file := range files {
					data, _ := os.ReadFile(file)
					found = found || string(data) == "old database"
				}
				if !found {
					t.Fatal("original database safety copy was lost")
				}
			} else {
				data, _ := os.ReadFile(filepath.Join(dir, "live.db"))
				if string(data) != "old database" {
					t.Fatal("failed restore did not compensate the database replacement")
				}
			}
		})
	}
}

func TestLegacyRestoreRefusesSidecarsAndAliasedTargets(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "data.db")
	source := filepath.Join(dir, "incoming.db")
	for _, name := range []string{old, source} {
		if err := os.WriteFile(name, []byte("preserved"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err := os.WriteFile(old+suffix, []byte("pending"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := installLegacyRestore([]legacyRestoreTarget{{source, old, true}}, os.Rename); err == nil {
			t.Fatal("database sidecar ignored")
		}
		if err := os.Remove(old + suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := installLegacyRestore([]legacyRestoreTarget{{source, old, true}, {source, old, false}}, os.Rename); err == nil {
		t.Fatal("two restore targets resolve to the same file")
	}
	data, _ := os.ReadFile(old)
	if string(data) != "preserved" {
		t.Fatal("rejected restore changed the original")
	}
}

func TestLegacyRestorePreparesEveryFileBeforeReplacement(t *testing.T) {
	dir := t.TempDir()
	for name, value := range map[string]string{"live.db": "old database", "live.yaml": "old config", "new.db": "new database"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	targets := []legacyRestoreTarget{{filepath.Join(dir, "new.db"), filepath.Join(dir, "live.db"), true}, {filepath.Join(dir, "missing.yaml"), filepath.Join(dir, "live.yaml"), false}}
	if err := installLegacyRestore(targets, func(string, string) error {
		t.Fatal("publication began before every input was staged")
		return nil
	}); err == nil {
		t.Fatal("missing second input accepted")
	}
	for name, expected := range map[string]string{"live.db": "old database", "live.yaml": "old config"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != expected {
			t.Fatalf("failed preflight changed %s", name)
		}
	}
}
