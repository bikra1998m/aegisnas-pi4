package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandCommercialCatalog(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandCommercialCatalog(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	evidence, err := broadbandCommercialCatalogEvidenceWithLimit(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"report":       report,
		"evidence":     evidence,
	})
}

func HandlePreviewBroadbandCommercialCatalog(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandCommercialCatalog(config.Get(), actor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result": map[string]any{
			"status":   report.Status,
			"event_id": eventID,
		},
		"report": report,
	})
}

func HandleApplyBroadbandCommercialCatalog(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandCommercialCatalog(context.Background(), config.Get(), actor)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"event_id":     eventID,
			"report":       report,
			"error":        err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"event_id":     eventID,
		"result": map[string]any{
			"status":   report.Status,
			"event_id": eventID,
		},
		"report": report,
	})
}

func HandleListBroadbandCommercialCatalogHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	evidence, err := broadbandCommercialCatalogEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":         time.Now().UTC().Format(time.RFC3339),
		"feature_id":           enforcement.BroadbandCommercialCatalogFeatureID,
		"summary":              evidence["summary"],
		"events":               evidence["recent_events"],
		"accounts":             evidence["accounts"],
		"plans":                evidence["plans"],
		"bundles":              evidence["bundles"],
		"subscriptions":        evidence["subscriptions"],
		"concurrency_policies": evidence["concurrency_policies"],
	})
}

func broadbandCommercialCatalogEvidenceWithLimit(limit int) (map[string]any, error) {
	summary, err := db.GetBroadbandCommercialCatalogSummary()
	if err != nil {
		return nil, err
	}
	events, err := db.ListBroadbandCommercialCatalogEvents(limit)
	if err != nil {
		return nil, err
	}
	accounts, err := db.ListBroadbandCommercialAccounts(limit)
	if err != nil {
		return nil, err
	}
	plans, err := db.ListBroadbandCommercialPlans(limit)
	if err != nil {
		return nil, err
	}
	bundles, err := db.ListBroadbandCommercialBundles(limit)
	if err != nil {
		return nil, err
	}
	subscriptions, err := db.ListBroadbandCommercialSubscriptions(limit)
	if err != nil {
		return nil, err
	}
	policies, err := db.ListBroadbandCommercialConcurrencyPolicies(limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"summary":              summary,
		"recent_events":        events,
		"accounts":             accounts,
		"plans":                plans,
		"bundles":              bundles,
		"subscriptions":        subscriptions,
		"concurrency_policies": policies,
	}, nil
}
