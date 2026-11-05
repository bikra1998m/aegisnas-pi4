package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

func newSealedRollbackCommand(extract bool) *cobra.Command {
	var keyFile, context, input, output, expected string
	command := &cobra.Command{
		Use:   "create-sealed-upgrade-rollback-package",
		Short: "Create an encrypted, authenticated SQLite recovery snapshot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := upgrade.ReadRecoveryKey(keyFile)
			if err != nil {
				return err
			}
			defer clear(key)
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if extract {
				sealed, err := upgrade.ReadRecoveryFile(input, int64(upgrade.MaxSealedRollbackBytes))
				if err != nil {
					return err
				}
				payload, receipt, err := upgrade.OpenSealedRollbackPackage(sealed, key, context, expected)
				if err != nil {
					return err
				}
				defer clear(payload)
				extraction, err := upgrade.ExtractRollbackPackageBytes(payload, output)
				if err != nil {
					return err
				}
				return encoder.Encode(map[string]any{"receipt": receipt, "extraction": extraction})
			}
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			payload, _, _, err := upgrade.CreateRollbackPackage(cfg, config.Path())
			if err != nil {
				return err
			}
			defer clear(payload)
			sealed, receipt, err := upgrade.SealRollbackPackage(payload, key, context)
			if err != nil {
				return err
			}
			if err := upgrade.WriteSealedRecoveryFile(output, sealed); err != nil {
				return err
			}
			return encoder.Encode(receipt)
		},
	}
	command.Flags().StringVar(&keyFile, "key-file", "", "protected file containing exactly 32 random key bytes")
	command.Flags().StringVar(&context, "recovery-context", "", "trusted appliance/recovery-scope identifier")
	command.MarkFlagRequired("key-file")
	command.MarkFlagRequired("recovery-context")
	if extract {
		command.Use = "extract-sealed-upgrade-rollback-package"
		command.Short = "Authenticate a specific recovery snapshot and stage it in a NEW private directory"
		command.Flags().StringVar(&input, "input", "", "encrypted recovery package")
		command.Flags().StringVar(&expected, "expected-sha256", "", "sealed digest from the trusted recovery record")
		command.Flags().StringVar(&output, "output-dir", "", "new staging directory (does not restore or activate services)")
		for _, name := range []string{"input", "expected-sha256", "output-dir"} {
			command.MarkFlagRequired(name)
		}
	} else {
		command.Flags().StringVar(&output, "output", "", "new encrypted recovery file")
		command.MarkFlagRequired("output")
	}
	return command
}

func init() {
	rootCmd.AddCommand(newSealedRollbackCommand(false), newSealedRollbackCommand(true))
}
