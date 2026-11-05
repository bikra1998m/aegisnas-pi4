package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

// Legacy archives are checksum-protected local recovery data, not authenticated
// production release/recovery artifacts. Keep their historical three-file format.
const legacyBackupLimit int64 = 512 << 20

var legacyEntryLimits = map[string]int64{
	"data.db": legacyBackupLimit, "config.yaml": 4 << 20, "manifest.json": 64 << 10,
}

var backupCmd = &cobra.Command{
	Use: "backup [output-file]", Short: "Create a consistent SQLite database and configuration backup",
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		output := "aegisnas-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
		if len(args) == 1 {
			output = args[0]
		}
		if err := createLegacyBackup(cmd.Context(), cfg, config.Path(), output); err != nil {
			return err
		}
		cmd.Printf("Backup created: %s\n", output)
		return nil
	},
}

var restoreCmd = &cobra.Command{
	Use: "restore [backup-file]", Short: "Restore a local SQLite backup with services stopped",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if err := requireLegacySQLite(cfg); err != nil {
			return err
		}
		workspace, err := os.MkdirTemp("", "aegis-restore-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(workspace)
		if err := extractTarGz(args[0], workspace); err != nil {
			return fmt.Errorf("extract backup: %w", err)
		}
		if err := verifyManifest(workspace); err != nil {
			return fmt.Errorf("backup manifest verification failed: %w", err)
		}
		targets, err := validateLegacyRestore(cmd.Context(), cfg, config.Path(), workspace)
		if err != nil {
			return err
		}
		cmd.Println("WARNING: This replaces local SQLite recovery data. All database clients and services must be stopped.")
		cmd.Print("Continue? (yes/no): ")
		var response string
		if _, err := fmt.Fscanln(cmd.InOrStdin(), &response); err != nil || response != "yes" {
			return fmt.Errorf("restore aborted")
		}
		if err := installLegacyRestore(targets, os.Rename); err != nil {
			return err
		}
		cmd.Println("Restore completed successfully. Start services only after reviewing the restored configuration.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(backupCmd, restoreCmd)
}

func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func requireLegacySQLite(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Database.Backend)) {
	case "", "sqlite":
		return nil
	default:
		return fmt.Errorf("local file backup/restore requires SQLite; use PostgreSQL logical or managed recovery for a PostgreSQL data plane")
	}
}

func openLegacySQLite(ctx context.Context, name string) (*sql.DB, error) {
	f, err := openLegacyRegular(name, legacyBackupLimit)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	u.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(5000)"}}.Encode()
	handle, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	handle.SetMaxOpenConns(1)
	if err := handle.PingContext(ctx); err != nil {
		handle.Close()
		return nil, fmt.Errorf("open existing SQLite database: %w", err)
	}
	return handle, nil
}

func createLegacyBackup(ctx context.Context, cfg *config.Config, configPath, output string) error {
	if err := requireLegacySQLite(cfg); err != nil {
		return err
	}
	handle, err := openLegacySQLite(ctx, cfg.Database.Path)
	if err != nil {
		return err
	}
	defer handle.Close()
	workspace, err := os.MkdirTemp("", "aegis-backup-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workspace)
	snapshot := filepath.Join(workspace, "data.db")
	if _, err := handle.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return fmt.Errorf("create consistent SQLite snapshot: %w", err)
	}
	if err := verifyDatabase(snapshot); err != nil {
		return fmt.Errorf("verify backup snapshot: %w", err)
	}
	sources := []struct{ path, name string }{{snapshot, "data.db"}}
	if configPath != "" {
		// Use the actual config selected by Load, including ./config.yaml.
		sources = append(sources, struct{ path, name string }{configPath, "config.yaml"})
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create NEW backup archive: %w", err)
	}
	defer file.Close()
	compressed := gzip.NewWriter(&legacyBoundedWriter{writer: file, remaining: legacyBackupLimit})
	defer compressed.Close()
	archive := tar.NewWriter(compressed)
	defer archive.Close()
	manifest := map[string]string{}
	var expanded int64
	for _, source := range sources {
		input, err := openLegacyRegular(source.path, legacyEntryLimits[source.name])
		if err != nil {
			return err
		}
		info, err := input.Stat()
		if err != nil {
			input.Close()
			return err
		}
		expanded += info.Size()
		if expanded > legacyBackupLimit {
			input.Close()
			return fmt.Errorf("expanded backup exceeds size limit")
		}
		err = archive.WriteHeader(&tar.Header{Name: source.name, Typeflag: tar.TypeReg, Mode: 0600, Size: info.Size()})
		hash := sha256.New()
		if err == nil {
			_, err = io.CopyN(io.MultiWriter(archive, hash), input, info.Size())
		}
		closeErr := input.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		manifest[source.name] = hex.EncodeToString(hash.Sum(nil))
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if expanded+int64(len(data)) > legacyBackupLimit {
		return fmt.Errorf("expanded backup exceeds size limit")
	}
	if err := archive.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(data))}); err != nil {
		return err
	}
	if _, err := archive.Write(data); err != nil {
		return err
	}
	for _, finish := range []func() error{archive.Close, compressed.Close, file.Sync, file.Close} {
		if err := finish(); err != nil {
			return fmt.Errorf("finish backup archive: %w", err)
		}
	}
	return nil
}

type legacyBoundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *legacyBoundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, fmt.Errorf("compressed backup exceeds size limit")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}

func verifyDatabase(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := openLegacySQLite(ctx, name)
	if err != nil {
		return err
	}
	defer handle.Close()
	var result string
	if err := handle.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("SQLite integrity check failed")
	}
	return nil
}
