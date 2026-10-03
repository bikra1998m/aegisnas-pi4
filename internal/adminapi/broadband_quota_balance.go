package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/enforcement"
)

func HandleGetBroadbandQuotaBalance(w http.ResponseWriter, r *http.Request) {
	report, err := enforcement.PreviewBroadbandQuotaBalance(config.Get())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	evidence, err := broadbandQuotaBalanceEvidenceWithLimit(20)
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

func HandlePreviewBroadbandQuotaBalance(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.PreviewAndRecordBroadbandQuotaBalance(config.Get(), actor)
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

func HandleApplyBroadbandQuotaBalance(w http.ResponseWriter, r *http.Request) {
	actor := firstNonEmptyAdminString(adminIdentityFromRequest(r).Subject, userFromRequest(r), "admin")
	report, eventID, err := enforcement.ApplyBroadbandQuotaBalance(context.Background(), config.Get(), actor)
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

func HandleListBroadbandQuotaBalanceHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseVLANLifecycleLimit(r.URL.Query().Get("limit"), 100)
	evidence, err := broadbandQuotaBalanceEvidenceWithLimit(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"feature_id":     enforcement.BroadbandQuotaBalanceFeatureID,
		"summary":        evidence["summary"],
		"events":         evidence["recent_events"],
		"wallets":        evidence["wallets"],
		"quota_profiles": evidence["quota_profiles"],
		"top_ups":        evidence["top_ups"],
		"rating_rules":   evidence["rating_rules"],
		"reset_policies": evidence["reset_policies"],
	})
}

func broadbandQuotaBalanceEvidenceWithLimit(limit int) (map[string]any, error) {
	summary, err := db.GetBroadbandQuotaBalanceSummary()
	if err != nil {
		return nil, err
	}
	events, err := db.ListBroadbandQuotaBalanceEvents(limit)
	if err != nil {
		return nil, err
	}
	wallets, err := db.ListBroadbandQuotaWallets(limit)
	if err != nil {
		return nil, err
	}
	profiles, err := db.ListBroadbandQuotaProfiles(limit)
	if err != nil {
		return nil, err
	}
	topUps, err := db.ListBroadbandTopUpGrants(limit)
	if err != nil {
		return nil, err
	}
	rules, err := db.ListBroadbandQuotaRatingRules(limit)
	if err != nil {
		return nil, err
	}
	resetPolicies, err := db.ListBroadbandQuotaResetPolicies(limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"summary":        summary,
		"recent_events":  events,
		"wallets":        wallets,
		"quota_profiles": profiles,
		"top_ups":        topUps,
		"rating_rules":   rules,
		"reset_policies": resetPolicies,
	}, nil
}
