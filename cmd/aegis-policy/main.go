package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/cobra"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/health"
	"github.com/yourorg/aegisnas-pi4/internal/logging"
	"github.com/yourorg/aegisnas-pi4/internal/policy"
	"go.uber.org/zap"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "aegis-policy",
		Short: "AegisNAS Policy Decision Service",
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
	Short: "Run the policy decision API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("validate config: %w", err)
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

		engine := policy.NewEngine(logger)

		r := chi.NewRouter()
		r.Use(middleware.Logger)
		r.Use(middleware.Recoverer)
		r.Use(middleware.Timeout(5 * time.Second))

		// Policy evaluation endpoint
		r.Post("/api/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
			var req policy.Request
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			decision, err := engine.Evaluate(&req)
			if err != nil {
				logger.Error("policy evaluation failed", zap.Error(err))
				http.Error(w, "evaluation error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(decision)
		})

		// Rule management endpoints
		r.Get("/api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
			rows, err := db.DB.Query(`SELECT id, name, description, priority, enabled, match_conditions, action,
				vlan, bandwidth_profile, session_timeout, idle_timeout, portal_profile, quarantine
				FROM policy_rules ORDER BY priority DESC`)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			var rules []policy.Rule
			for rows.Next() {
				var rl policy.Rule
				var vlan sql.NullInt32
				var desc, bw, portal sql.NullString
				var st, it sql.NullInt32
				var matchConditions string
				err := rows.Scan(&rl.ID, &rl.Name, &desc, &rl.Priority, &rl.Enabled, &matchConditions, &rl.Action,
					&vlan, &bw, &st, &it, &portal, &rl.Quarantine)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				rl.MatchConditions = json.RawMessage(matchConditions)
				if desc.Valid {
					rl.Description = desc.String
				}
				if vlan.Valid {
					v := int(vlan.Int32)
					rl.VLAN = &v
				}
				if bw.Valid {
					s := bw.String
					rl.BandwidthProfile = &s
				}
				if st.Valid {
					s := int(st.Int32)
					rl.SessionTimeout = &s
				}
				if it.Valid {
					i := int(it.Int32)
					rl.IdleTimeout = &i
				}
				if portal.Valid {
					p := portal.String
					rl.PortalProfile = &p
				}
				rules = append(rules, rl)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rules)
		})

		health.RegisterRoutes(r)

		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Health.Port+2), // policy API on health.port+2
			Handler: r,
		}

		go func() {
			logger.Info("policy API listening", zap.Int("port", cfg.Health.Port+2))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("server failed", zap.Error(err))
			}
		}()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

		logger.Info("shutting down policy service")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(ctx)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
