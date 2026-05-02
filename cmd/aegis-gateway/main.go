package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/dnsmasq"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
	"github.com/yourorg/aegisnas-pi4/internal/firewall"
	"github.com/yourorg/aegisnas-pi4/internal/health"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/network"
	"github.com/yourorg/aegisnas-pi4/internal/portal"
	"go.uber.org/zap"
)

var (
	cfgFile     string
	dryRun      bool
	rollbackRev int
	rootCmd     = &cobra.Command{
		Use:   "aegis-gateway",
		Short: "AegisNAS Gateway Service - manages nftables firewall and routing",
	}
	stateMachine *portal.StateMachine
)

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the gateway daemon (applies config and monitors)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return err
		}
		defer logging.Sync()
		logger := logging.L()

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		// Initialize portal state machine
		stateMachine = portal.NewStateMachine(logger)
		if err := stateMachine.LoadSessionsFromDB(); err != nil {
			logger.Warn("failed to load sessions from DB", zap.Error(err))
		}
		if err := enforcement.SyncRuntimeEnforcement(cfg); err != nil {
			logger.Warn("failed to restore runtime enforcement state", zap.Error(err))
		}
		if err := network.Apply(cfg); err != nil {
			return fmt.Errorf("apply managed network config: %w", err)
		}

		// Apply firewall
		if err := applyFirewall(cfg, "system-startup"); err != nil {
			return err
		}

		// Apply dnsmasq config
		if err := applyDNSMasq(cfg, false); err != nil {
			logger.Warn("failed to apply dnsmasq config", zap.Error(err))
		}

		go health.StartServer(cfg.Health.Port, logger)

		// Background cleanup of idle portal clients
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				stateMachine.CleanupIdle(10 * time.Minute)
			}
		}()

		logger.Info("aegis-gateway running",
			zap.String("mode", cfg.Mode),
			zap.Int("health_port", cfg.Health.Port))

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Info("shutting down")
		return nil
	},
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply firewall configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return err
		}
		defer logging.Sync()

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		if !dryRun {
			current, err := firewall.GetCurrentRuleset()
			if err == nil {
				_, _ = db.SaveConfigRevision(current, "auto-before-apply")
			}
		}
		if !dryRun {
			if err := network.Apply(cfg); err != nil {
				return fmt.Errorf("apply managed network config: %w", err)
			}
		}

		return applyFirewall(cfg, "manual-apply")
	},
}

func applyDNSMasq(cfg *config.Config, printOnly bool) error {
	if !cfg.DHCP.Enabled {
		if printOnly {
			fmt.Println("# dnsmasq disabled in config")
			return nil
		}
		return exec.Command("systemctl", "stop", "dnsmasq").Run()
	}

	gen := dnsmasq.NewGenerator(cfg)
	dnsCfg, err := gen.Generate()
	if err != nil {
		return err
	}
	if printOnly {
		fmt.Println(dnsCfg.Content)
		return nil
	}
	if err := os.WriteFile("/etc/dnsmasq.conf", []byte(dnsCfg.Content), 0644); err != nil {
		return fmt.Errorf("write dnsmasq.conf: %w", err)
	}
	if err := exec.Command("systemctl", "restart", "dnsmasq").Run(); err != nil {
		return fmt.Errorf("restart dnsmasq: %w", err)
	}
	return nil
}

var dryRunCmd = &cobra.Command{
	Use:   "dry-run",
	Short: "Generate and print nftables rules without applying",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		gen := firewall.NewGenerator(cfg)
		ruleset, err := gen.Generate()
		if err != nil {
			return fmt.Errorf("generate ruleset: %w", err)
		}
		fmt.Println(ruleset.Content)
		return nil
	},
}

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback to a previous configuration revision",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return err
		}
		defer logging.Sync()

		if err := db.Init(cfg.Database.Path); err != nil {
			return fmt.Errorf("init db: %w", err)
		}
		defer db.Close()

		var ruleset string
		if rollbackRev == 0 {
			ruleset, err = db.GetLatestConfigRevision()
		} else {
			ruleset, err = db.GetConfigRevisionByNumber(rollbackRev)
		}
		if err != nil {
			return fmt.Errorf("retrieve revision: %w", err)
		}

		if dryRun {
			fmt.Println("Would restore ruleset:")
			fmt.Println(ruleset)
			return nil
		}

		if err := firewall.RestoreRuleset(ruleset); err != nil {
			return fmt.Errorf("restore ruleset: %w", err)
		}
		fmt.Printf("Successfully rolled back to revision %d\n", rollbackRev)
		return nil
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current firewall status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ruleset, err := firewall.GetCurrentRuleset()
		if err != nil {
			return err
		}
		fmt.Println(ruleset)
		return nil
	},
}

var generateDnsmasqCmd = &cobra.Command{
	Use:   "gen-dnsmasq",
	Short: "Generate dnsmasq configuration and print to stdout",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		return applyDNSMasq(cfg, true)
	},
}

var applyDnsmasqCmd = &cobra.Command{
	Use:   "apply-dnsmasq",
	Short: "Apply dnsmasq configuration (writes to /etc/dnsmasq.conf)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return err
		}
		defer logging.Sync()

		if err := applyDNSMasq(cfg, dryRun); err != nil {
			return err
		}
		logging.L().Info("dnsmasq configuration applied")
		return nil
	},
}

func init() {
	applyCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print rules without applying")
	rollbackCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print rules that would be restored")
	rollbackCmd.Flags().IntVar(&rollbackRev, "revision", 0, "Revision number to rollback to (0 = latest)")
	rootCmd.AddCommand(runCmd, applyCmd, dryRunCmd, rollbackCmd, statusCmd)
	rootCmd.AddCommand(generateDnsmasqCmd, applyDnsmasqCmd)
}

func loadAndValidateConfig() (*config.Config, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return cfg, nil
}

func applyFirewall(cfg *config.Config, triggeredBy string) error {
	gen := firewall.NewGenerator(cfg)
	ruleset, err := gen.Generate()
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Println(ruleset.Content)
		return nil
	}

	revisionID, err := db.SaveConfigRevision(ruleset.Content, triggeredBy)
	if err != nil {
		logging.L().Warn("failed to save config revision", zap.Error(err))
	} else {
		logging.L().Info("saved config revision", zap.Int("revision_id", revisionID))
	}

	if err := firewall.ApplyRuleset(ruleset.Content); err != nil {
		return err
	}

	_, err = firewall.GetCurrentRuleset()
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	logging.L().Info("firewall rules applied successfully")
	return nil
}
