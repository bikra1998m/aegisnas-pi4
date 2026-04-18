package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

var backupCmd = &cobra.Command{
	Use:   "backup [output-file]",
	Short: "Create a backup of the database and configuration",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		outputFile := "aegisnas-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
		if len(args) > 0 {
			outputFile = args[0]
		}

		f, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer f.Close()

		gw := gzip.NewWriter(f)
		defer gw.Close()
		tw := tar.NewWriter(gw)
		defer tw.Close()

		manifest := map[string]string{}
		// Backup database
		checksum, err := addFileToTar(tw, cfg.Database.Path, "data.db")
		if err != nil {
			return fmt.Errorf("backup database: %w", err)
		}
		manifest["data.db"] = checksum
		// Backup config file (if exists)
		configPath := cfgFile
		if configPath == "" {
			configPath = "/etc/aegisnas/config.yaml"
		}
		if _, err := os.Stat(configPath); err == nil {
			checksum, err := addFileToTar(tw, configPath, "config.yaml")
			if err != nil {
				return fmt.Errorf("backup config: %w", err)
			}
			manifest["config.yaml"] = checksum
		}
		manifestData, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		if err := addBytesToTar(tw, manifestData, "manifest.json", 0644); err != nil {
			return fmt.Errorf("backup manifest: %w", err)
		}
		fmt.Printf("Backup created: %s\n", outputFile)
		return nil
	},
}

var restoreCmd = &cobra.Command{
	Use:   "restore [backup-file]",
	Short: "Restore from a backup archive",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		backupFile := args[0]

		// Extract to temp dir
		tempDir, err := os.MkdirTemp("", "aegis-restore-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tempDir)

		if err := extractTarGz(backupFile, tempDir); err != nil {
			return fmt.Errorf("extract backup: %w", err)
		}

		if err := verifyManifest(tempDir); err != nil {
			return fmt.Errorf("backup manifest verification failed: %w", err)
		}

		// Stop services (warning)
		fmt.Println("WARNING: This will overwrite current database. Ensure services are stopped.")
		fmt.Print("Continue? (yes/no): ")
		var response string
		fmt.Scanln(&response)
		if response != "yes" {
			return fmt.Errorf("restore aborted")
		}

		// Copy database
		srcDB := filepath.Join(tempDir, "data.db")
		if _, err := os.Stat(srcDB); os.IsNotExist(err) {
			return fmt.Errorf("backup does not contain database")
		}
		// Verify database integrity
		if err := verifyDatabase(srcDB); err != nil {
			return fmt.Errorf("database verification failed: %w", err)
		}
		if err := copyFile(srcDB, cfg.Database.Path); err != nil {
			return fmt.Errorf("restore database: %w", err)
		}
		// Restore config (optional)
		srcCfg := filepath.Join(tempDir, "config.yaml")
		if _, err := os.Stat(srcCfg); err == nil {
			destCfg := cfgFile
			if destCfg == "" {
				destCfg = "/etc/aegisnas/config.yaml"
			}
			os.MkdirAll(filepath.Dir(destCfg), 0755)
			if err := copyFile(srcCfg, destCfg); err != nil {
				return fmt.Errorf("restore config: %w", err)
			}
		}
		fmt.Println("Restore completed successfully.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(backupCmd)
	rootCmd.AddCommand(restoreCmd)
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

// Helper functions for tar/gz
func addFileToTar(tw *tar.Writer, path, name string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return "", err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return "", err
	}
	hasher := sha256.New()
	_, err = io.Copy(io.MultiWriter(tw, hasher), f)
	return hex.EncodeToString(hasher.Sum(nil)), err
}

func addBytesToTar(tw *tar.Writer, data []byte, name string, mode int64) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func extractTarGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		cleanName := filepath.Clean(hdr.Name)
		if cleanName == "." || filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) || cleanName == ".." {
			return fmt.Errorf("unsafe archive path: %s", hdr.Name)
		}
		path := filepath.Join(dest, cleanName)
		if hdr.Typeflag == tar.TypeDir {
			os.MkdirAll(path, 0755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		out, err := os.Create(path)
		if err != nil {
			return err
		}
		io.Copy(out, tr)
		out.Close()
	}
	return nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}

func verifyDatabase(dbPath string) error {
	// Open with SQLite and run integrity check
	tmpDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer tmpDB.Close()
	var ok string
	err = tmpDB.QueryRow("PRAGMA integrity_check").Scan(&ok)
	if err != nil {
		return err
	}
	if ok != "ok" {
		return fmt.Errorf("integrity check failed: %s", ok)
	}
	return nil
}

func verifyManifest(dir string) error {
	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("manifest missing: %w", err)
	}
	var manifest map[string]string
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	for name, expected := range manifest {
		actual, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("%s checksum mismatch", name)
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
