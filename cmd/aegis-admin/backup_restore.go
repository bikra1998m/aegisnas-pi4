package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type legacyRestoreTarget struct {
	source, destination string
	database            bool
}

func sameLegacyPath(left, right string) bool {
	a, aerr := filepath.Abs(left)
	b, berr := filepath.Abs(right)
	if aerr != nil || berr != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func validateLegacyRestore(ctx context.Context, cfg *config.Config, configPath, workspace string) ([]legacyRestoreTarget, error) {
	if err := requireLegacySQLite(cfg); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	database := filepath.Join(workspace, "data.db")
	if err := verifyDatabase(database); err != nil {
		return nil, fmt.Errorf("backup database integrity: %w", err)
	}
	targets := []legacyRestoreTarget{{database, cfg.Database.Path, true}}
	configInput := filepath.Join(workspace, "config.yaml")
	if _, err := os.Lstat(configInput); err == nil {
		candidate, err := config.LoadCandidate(configInput)
		if err != nil {
			return nil, fmt.Errorf("load recovered configuration: %w", err)
		}
		if err := candidate.Validate(); err != nil {
			return nil, fmt.Errorf("validate recovered configuration: %w", err)
		}
		if err := requireLegacySQLite(candidate); err != nil {
			return nil, err
		}
		if !sameLegacyPath(candidate.Database.Path, cfg.Database.Path) {
			return nil, fmt.Errorf("recovered config selects a different database path; use a separately reviewed migration")
		}
		if configPath == "" {
			return nil, fmt.Errorf("an explicit current config path is required to restore configuration")
		}
		targets = append(targets, legacyRestoreTarget{configInput, configPath, false})
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := preflightLegacyTargets(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

func preflightLegacyTargets(targets []legacyRestoreTarget) error {
	for i, target := range targets {
		if strings.TrimSpace(target.destination) == "" {
			return fmt.Errorf("restore destination is required")
		}
		absolute, err := filepath.Abs(target.destination)
		if err != nil {
			return err
		}
		for name := absolute; ; name = filepath.Dir(name) {
			info, err := os.Lstat(name)
			if err != nil && !(name == absolute && os.IsNotExist(err)) {
				return err
			}
			if err == nil && ((name == absolute && !info.Mode().IsRegular()) || (name != absolute && !info.IsDir())) {
				return fmt.Errorf("restore paths must not contain links or special files")
			}
			if filepath.Dir(name) == name {
				break
			}
		}
		for _, earlier := range targets[:i] {
			a, aerr := os.Stat(earlier.destination)
			b, berr := os.Stat(target.destination)
			if sameLegacyPath(earlier.destination, target.destination) || (aerr == nil && berr == nil && os.SameFile(a, b)) {
				return fmt.Errorf("restore destinations must be distinct files")
			}
		}
		if target.database {
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if _, err := os.Lstat(target.destination + suffix); !os.IsNotExist(err) {
					return fmt.Errorf("SQLite sidecar %s exists or cannot be checked; stop all clients and complete SQLite checkpoint/recovery before file restore", suffix)
				}
			}
		}
	}
	return nil
}

// This protects a legacy offline operation against ordinary in-process I/O
// failures. It is NOT an authenticated, cross-service or power-loss transaction.
// Existing clients must be stopped by the operator; sidecar absence is not proof
// that every process has released its SQLite handle.
func installLegacyRestore(targets []legacyRestoreTarget, rename func(string, string) error) error {
	if len(targets) == 0 || len(targets) > 2 {
		return fmt.Errorf("invalid local restore target set")
	}
	if err := preflightLegacyTargets(targets); err != nil {
		return err
	}
	type prepared struct {
		destination, staged, before string
	}
	preparedTargets := []prepared{}
	defer func() {
		for _, target := range preparedTargets {
			_ = os.Remove(target.staged) // Only the temporary file created below.
		}
	}()
	for _, target := range targets {
		staged, err := stageLegacyFile(target.source, filepath.Dir(target.destination), ".aegis-restore-new-*")
		if err != nil {
			return err
		}
		item := prepared{destination: target.destination, staged: staged}
		preparedTargets = append(preparedTargets, item)
		if _, err := os.Lstat(target.destination); err == nil {
			before, err := stageLegacyFile(target.destination, filepath.Dir(target.destination), ".aegis-restore-before-*")
			if err != nil {
				return fmt.Errorf("create private safety copy: %w", err)
			}
			preparedTargets[len(preparedTargets)-1].before = before
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	// Recheck after all staging, before replacing the first destination.
	if err := preflightLegacyTargets(targets); err != nil {
		return err
	}
	for i, target := range preparedTargets {
		if err := rename(target.staged, target.destination); err != nil {
			failure := fmt.Errorf("publish local restore: %w", err)
			for j := i - 1; j >= 0; j-- {
				previous := preparedTargets[j]
				var rollbackErr error
				if previous.before != "" {
					rollbackErr = rename(previous.before, previous.destination)
				} else {
					rollbackErr = os.Remove(previous.destination)
				}
				if rollbackErr != nil {
					failure = errors.Join(failure, fmt.Errorf("restore compensation failed; retain safety file %s: %w", previous.before, rollbackErr))
				}
			}
			return failure
		}
	}
	// Safety copies deliberately remain private beside the original destinations.
	// Operators retain them according to their recovery policy.
	return nil
}

func stageLegacyFile(source, directory, pattern string) (string, error) {
	input, err := openLegacyRegular(source, legacyBackupLimit)
	if err != nil {
		return "", err
	}
	defer input.Close()
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	name := file.Name()
	n, copyErr := io.Copy(file, io.LimitReader(input, legacyBackupLimit+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if n > legacyBackupLimit || copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("stage recovery file: size limit or I/O failure: %w", errors.Join(copyErr, syncErr, closeErr))
	}
	return name, nil
}
