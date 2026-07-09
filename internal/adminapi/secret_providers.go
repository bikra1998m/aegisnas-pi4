package adminapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/secrets"
)

func HandleGetSecretProviders(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	stored, err := storedSecretSources()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret provider report unavailable: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, secrets.BuildReport(ctx, cfg, stored))
}

func storedSecretSources() ([]secrets.StoredSource, error) {
	if db.DB == nil {
		return nil, nil
	}
	rows, err := db.DB.Query(`SELECT shortname, secret != '', COALESCE(secret_ref, ''), COALESCE(transport, 'udp'), enabled
		FROM radius_clients ORDER BY shortname`)
	if isMissingRadiusClientSecretRefForAPI(err) {
		rows, err = db.DB.Query(`SELECT shortname, secret != '', '', COALESCE(transport, 'udp'), enabled
			FROM radius_clients ORDER BY shortname`)
	}
	if isMissingRadiusClientsTableForSecretProviders(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []secrets.StoredSource
	for rows.Next() {
		var shortName, secretRef, transport string
		var inlineSecretSet, enabled bool
		if err := rows.Scan(&shortName, &inlineSecretSet, &secretRef, &transport, &enabled); err != nil {
			return nil, err
		}
		if !enabled || strings.EqualFold(strings.TrimSpace(transport), "radsec") {
			continue
		}
		field := fmt.Sprintf("radius_clients[%s].secret", safeSecretSourceName(shortName))
		if strings.TrimSpace(secretRef) != "" {
			sources = append(sources, secrets.StoredSource{Field: field, Scope: "database", Ref: strings.TrimSpace(secretRef), Required: true})
		}
		if inlineSecretSet {
			sources = append(sources, secrets.StoredSource{Field: field, Scope: "database", Inline: true, Required: true})
		}
	}
	return sources, rows.Err()
}

func isMissingRadiusClientsTableForSecretProviders(err error) bool {
	if err == nil || err == sql.ErrNoRows {
		return false
	}
	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "no such table") && strings.Contains(normalized, "radius_clients")
}

func safeSecretSourceName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("[", "_", "]", "_", "\r", "_", "\n", "_", "\x00", "_")
	return replacer.Replace(value)
}
