package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

func newDatabaseConversionCommand() *cobra.Command {
	var source, schema string
	var allowPrecisionLoss bool
	command := &cobra.Command{
		Use: "rehearse-sqlite-to-postgres", Short: "Verify a SQLite snapshot import into a NEW private PostgreSQL schema",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("load target database configuration failed")
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("target database configuration is invalid")
			}
			resolver := secrets.NewResolver(secrets.OptionsFromConfig(cfg))
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
			defer cancel()
			report, conversionErr := db.ConvertSQLiteToPostgreSQL(ctx, source, cfg.Database, resolver.Resolve, db.ConversionOptions{TargetSchema: schema, AllowPrecisionLoss: allowPrecisionLoss})
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(report); err != nil {
				return fmt.Errorf("write conversion receipt failed; inspect the private target schema")
			}
			return conversionErr
		},
	}
	command.Flags().StringVar(&source, "source-sqlite", "", "existing SQLite source (read-only snapshot; at most 8 GiB)")
	command.Flags().StringVar(&schema, "target-schema", "", "new aegis_conversion_ schema; existing schemas are refused")
	command.Flags().BoolVar(&allowPrecisionLoss, "allow-precision-loss", false, "explicitly allow reported timestamp truncation to microseconds and REAL rounding to float32")
	command.MarkFlagRequired("source-sqlite")
	command.MarkFlagRequired("target-schema")
	return command
}

func init() { rootCmd.AddCommand(newDatabaseConversionCommand()) }
