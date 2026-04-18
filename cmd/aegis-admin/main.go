package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
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

func init() {
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(seedCmd)
	rootCmd.AddCommand(validateConfigCmd)
}