package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/health"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"go.uber.org/zap"
)

var (
	cfgFile       string
	dryRun        bool
	clientNASType string
	rootCmd       = &cobra.Command{
		Use:   "aegis-radius",
		Short: "AegisNAS RADIUS service – manages FreeRADIUS configuration",
	}
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
	Short: "Run the RADIUS daemon (applies config and monitors FreeRADIUS)",
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

		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()

		// Apply RADIUS configuration
		if err := radius.ApplyConfig(cfg); err != nil {
			return err
		}

		// Start health server on a dedicated port so it does not collide with gateway health.
		go health.StartServer(cfg.Health.Port+5, logger)

		logger.Info("aegis-radius running",
			zap.Int("auth_port", cfg.Radius.AuthPort),
			zap.Int("acct_port", cfg.Radius.AcctPort))

		// Wait indefinitely (or until signal)
		select {}
	},
}

var genConfigCmd = &cobra.Command{
	Use:   "gen-config",
	Short: "Generate FreeRADIUS configuration and print to stdout",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		// Initialize DB to read clients
		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()

		gen := radius.NewGenerator(cfg)
		fullCfg, err := gen.Generate()
		if err != nil {
			return err
		}
		fmt.Println("=== clients.conf ===")
		fmt.Println(fullCfg.ClientsConf)
		fmt.Println("=== eap.conf ===")
		fmt.Println(fullCfg.EAPConf)
		fmt.Println("=== users ===")
		fmt.Println(fullCfg.Users)
		fmt.Println("=== mods-enabled/ldap ===")
		fmt.Println(fullCfg.ModsLDAP)
		fmt.Println("=== mods-enabled/sql ===")
		fmt.Println(fullCfg.ModsSQL)
		fmt.Println("=== proxy.conf ===")
		fmt.Println(fullCfg.ProxyConf)
		fmt.Println("=== sites-enabled/default ===")
		fmt.Println(fullCfg.SitesDefault)
		fmt.Println("=== sites-enabled/inner-tunnel ===")
		fmt.Println(fullCfg.SitesInnerTunnel)
		return nil
	},
}

var applyConfigCmd = &cobra.Command{
	Use:   "apply-config",
	Short: "Apply FreeRADIUS configuration to system",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := logging.Init(cfg.Logging.Level, cfg.Logging.Output); err != nil {
			return err
		}
		defer logging.Sync()

		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()

		if dryRun {
			gen := radius.NewGenerator(cfg)
			fullCfg, _ := gen.Generate()
			fmt.Println("Would write FreeRADIUS configuration files.")
			fmt.Println("clients.conf:")
			fmt.Println(fullCfg.ClientsConf)
			return nil
		}
		return radius.ApplyConfig(cfg)
	},
}

// Client management subcommands
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Manage RADIUS clients (APs)",
}

var clientListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all RADIUS clients",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()
		return listRadiusClients(cmd.OutOrStdout())
	},
}

var clientAddCmd = &cobra.Command{
	Use:   "add [shortname] [ip] [secret]",
	Short: "Add a new RADIUS client",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()
		nasType, err := addRadiusClient(args[0], args[1], args[2], clientNASType)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Client added successfully with NAS type %q.\n", nasType)
		return nil
	},
}

var clientRemoveCmd = &cobra.Command{
	Use:   "remove [shortname]",
	Short: "Remove a RADIUS client",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()
		res, err := db.DB.Exec(`DELETE FROM radius_clients WHERE shortname = ?`, args[0])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("client not found")
		}
		fmt.Println("Client removed.")
		return nil
	},
}

var clientEnableCmd = &cobra.Command{
	Use:   "enable [shortname]",
	Short: "Enable a RADIUS client",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()
		res, err := db.DB.Exec(`UPDATE radius_clients SET enabled = 1 WHERE shortname = ?`, args[0])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("client not found")
		}
		fmt.Println("Client enabled.")
		return nil
	},
}

var clientDisableCmd = &cobra.Command{
	Use:   "disable [shortname]",
	Short: "Disable a RADIUS client",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAndValidateConfig()
		if err != nil {
			return err
		}
		if err := initRadiusDB(cfg); err != nil {
			return err
		}
		defer db.Close()
		res, err := db.DB.Exec(`UPDATE radius_clients SET enabled = 0 WHERE shortname = ?`, args[0])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("client not found")
		}
		fmt.Println("Client disabled.")
		return nil
	},
}

func init() {
	applyConfigCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print configuration without applying")
	clientAddCmd.Flags().StringVar(&clientNASType, "nas-type", "other", "NAS type / vendor profile for this AP, switch, or controller")
	rootCmd.AddCommand(runCmd, genConfigCmd, applyConfigCmd)

	clientCmd.AddCommand(clientListCmd, clientAddCmd, clientRemoveCmd, clientEnableCmd, clientDisableCmd)
	rootCmd.AddCommand(clientCmd)
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

func initRadiusDB(cfg *config.Config) error {
	if err := db.Init(cfg.Database.Path); err != nil {
		return fmt.Errorf("init db: %w", err)
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		return fmt.Errorf("migrate db: %w", err)
	}
	return nil
}

func listRadiusClients(w io.Writer) error {
	rows, err := db.DB.Query(`SELECT id, shortname, ipaddr, COALESCE(NULLIF(TRIM(nas_type), ''), 'other'), enabled FROM radius_clients ORDER BY shortname`)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintf(w, "%-4s %-20s %-15s %-14s %-7s\n", "ID", "ShortName", "IP", "NASType", "Enabled")
	for rows.Next() {
		var (
			id      int
			name    string
			ip      string
			nasType string
			enabled bool
		)
		if err := rows.Scan(&id, &name, &ip, &nasType, &enabled); err != nil {
			return err
		}
		fmt.Fprintf(w, "%-4d %-20s %-15s %-14s %-7t\n", id, name, ip, radius.NormalizeClientNASType(nasType), enabled)
	}
	return rows.Err()
}

func addRadiusClient(shortName, ip, secret, nasType string) (string, error) {
	normalizedNASType := radius.NormalizeClientNASType(nasType)
	_, err := db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type) VALUES (?, ?, ?, ?)`,
		shortName, ip, secret, normalizedNASType)
	return normalizedNASType, err
}
