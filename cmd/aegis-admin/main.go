package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

var (
	cfgFile              string
	upgradeReadinessJSON bool
	rollbackPackageOut   string
	rollbackPackageIn    string
	rollbackExtractDir   string
	rootCmd              = &cobra.Command{
		Use:   "aegis-admin",
		Short: "AegisNAS administrative CLI",
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return fmt.Errorf("init logging: %w", err)
		}
		defer logging.Sync()

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		if err := db.Migrate(); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		fmt.Println("Database migration completed successfully.")
		return nil
	},
}

var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Seed database with default data",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return fmt.Errorf("init logging: %w", err)
		}
		defer logging.Sync()

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		if err := db.Migrate(); err != nil {
			return fmt.Errorf("migrate before seed: %w", err)
		}

		if err := db.Seed(); err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		fmt.Println("Database seeded successfully.")
		return nil
	},
}

var validateConfigCmd = &cobra.Command{
	Use:   "validate-config",
	Short: "Validate configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		fmt.Println("Configuration is valid.")
		return nil
	},
}

var upgradeReadinessCmd = &cobra.Command{
	Use:   "upgrade-readiness",
	Short: "Assess upgrade readiness and rehearse database migration on a temporary copy",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		report, err := upgrade.AssessReadiness(cfg, config.Path())
		if err != nil {
			return fmt.Errorf("assess upgrade readiness: %w", err)
		}
		if upgradeReadinessJSON {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(report)
		}

		fmt.Printf("Generated at: %s\n", report.GeneratedAt)
		fmt.Printf("Config path: %s\n", report.ConfigPath)
		fmt.Printf("Database path: %s\n", report.DatabasePath)
		fmt.Printf("Deployment: %s / %s\n", report.DeploymentProfile, report.DeploymentForm)
		fmt.Printf("Config valid: %t\n", report.ConfigValid)
		if report.ConfigValidationError != "" {
			fmt.Printf("Config validation error: %s\n", report.ConfigValidationError)
		}
		fmt.Printf("Schema: current=%d target=%d\n", report.CurrentSchemaVersion, report.TargetSchemaVersion)
		fmt.Printf("Database exists: %t (%d bytes)\n", report.DatabaseExists, report.DatabaseSizeBytes)
		if report.Rehearsal.Ran {
			fmt.Printf("Migration rehearsal: success=%t started=%d result=%d duration_ms=%d\n",
				report.Rehearsal.Succeeded,
				report.Rehearsal.StartedSchemaVersion,
				report.Rehearsal.ResultSchemaVersion,
				report.Rehearsal.DurationMilliseconds,
			)
			if report.Rehearsal.Error != "" {
				fmt.Printf("Migration rehearsal error: %s\n", report.Rehearsal.Error)
			}
		} else {
			fmt.Println("Migration rehearsal: not run")
		}
		if len(report.Recommendations) > 0 {
			fmt.Println("Recommendations:")
			for _, item := range report.Recommendations {
				fmt.Printf("  - %s\n", item)
			}
		}
		return nil
	},
}

var createUpgradeRollbackPackageCmd = &cobra.Command{
	Use:   "create-upgrade-rollback-package",
	Short: "Create a version-aware rollback package with the live config and a consistent database snapshot",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		outputPath := rollbackPackageOut
		if outputPath == "" {
			outputPath = fmt.Sprintf("aegisnas-upgrade-rollback-%s.zip", time.Now().UTC().Format("20060102-150405Z"))
		}
		payload, _, manifest, err := upgrade.CreateRollbackPackage(cfg, config.Path())
		if err != nil {
			return fmt.Errorf("create upgrade rollback package: %w", err)
		}
		if err := os.WriteFile(outputPath, payload, 0600); err != nil {
			return fmt.Errorf("write rollback package: %w", err)
		}
		fmt.Printf("Upgrade rollback package written to %s\n", outputPath)
		fmt.Printf("Schema context: current=%d target=%d\n", manifest.CurrentSchemaVersion, manifest.TargetSchemaVersion)
		return nil
	},
}

var inspectUpgradeRollbackPackageCmd = &cobra.Command{
	Use:   "inspect-upgrade-rollback-package",
	Short: "Inspect an upgrade rollback package and report whether online restore is supported on this runtime",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rollbackPackageIn == "" {
			return fmt.Errorf("--input is required")
		}
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		packageBytes, err := os.ReadFile(rollbackPackageIn)
		if err != nil {
			return fmt.Errorf("read rollback package: %w", err)
		}
		inspection, err := upgrade.InspectRollbackPackageBytes(packageBytes, cfg, config.Path())
		if err != nil {
			return fmt.Errorf("inspect rollback package: %w", err)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inspection)
	},
}

var restoreUpgradeRollbackPackageCmd = &cobra.Command{
	Use:   "restore-upgrade-rollback-package",
	Short: "Restore a compatible upgrade rollback package onto the local appliance",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rollbackPackageIn == "" {
			return fmt.Errorf("--input is required")
		}
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		packageBytes, err := os.ReadFile(rollbackPackageIn)
		if err != nil {
			return fmt.Errorf("read rollback package: %w", err)
		}
		result, err := upgrade.RestoreRollbackPackage(cfg, config.Path(), packageBytes, "RESTORE UPGRADE ROLLBACK")
		if err != nil {
			return fmt.Errorf("restore rollback package: %w", err)
		}
		fmt.Printf("Rollback restore applied. Safety package: %s\n", result.SafetyPackagePath)
		if result.DatabaseBackupPath != "" {
			fmt.Printf("Database backup: %s\n", result.DatabaseBackupPath)
		}
		if result.RestartRequired {
			fmt.Println("Restart required: true")
		}
		return nil
	},
}

var extractUpgradeRollbackPackageCmd = &cobra.Command{
	Use:   "extract-upgrade-rollback-package",
	Short: "Extract an upgrade rollback package into a local workspace for offline restore or review",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rollbackPackageIn == "" {
			return fmt.Errorf("--input is required")
		}
		if rollbackExtractDir == "" {
			return fmt.Errorf("--output-dir is required")
		}
		packageBytes, err := os.ReadFile(rollbackPackageIn)
		if err != nil {
			return fmt.Errorf("read rollback package: %w", err)
		}
		extraction, err := upgrade.ExtractRollbackPackageBytes(packageBytes, rollbackExtractDir)
		if err != nil {
			return fmt.Errorf("extract rollback package: %w", err)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(extraction)
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(seedCmd)
	rootCmd.AddCommand(validateConfigCmd)
	upgradeReadinessCmd.Flags().BoolVar(&upgradeReadinessJSON, "json", false, "print the readiness report as JSON")
	rootCmd.AddCommand(upgradeReadinessCmd)
	createUpgradeRollbackPackageCmd.Flags().StringVar(&rollbackPackageOut, "output", "", "output path for the rollback package zip")
	rootCmd.AddCommand(createUpgradeRollbackPackageCmd)
	inspectUpgradeRollbackPackageCmd.Flags().StringVar(&rollbackPackageIn, "input", "", "input rollback package zip")
	rootCmd.AddCommand(inspectUpgradeRollbackPackageCmd)
	restoreUpgradeRollbackPackageCmd.Flags().StringVar(&rollbackPackageIn, "input", "", "input rollback package zip")
	rootCmd.AddCommand(restoreUpgradeRollbackPackageCmd)
	extractUpgradeRollbackPackageCmd.Flags().StringVar(&rollbackPackageIn, "input", "", "input rollback package zip")
	extractUpgradeRollbackPackageCmd.Flags().StringVar(&rollbackExtractDir, "output-dir", "", "output directory for extracted rollback package contents")
	rootCmd.AddCommand(extractUpgradeRollbackPackageCmd)
}
