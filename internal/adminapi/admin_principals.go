package adminapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

func HandleListAdminPrincipals(w http.ResponseWriter, r *http.Request) {
	items, err := listAdminPrincipals()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func HandleUpdateAdminPrincipal(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{}
	if err := decodeBody(r, &payload); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil || id <= 0 {
		http.Error(w, "invalid principal id", http.StatusBadRequest)
		return
	}
	role := strings.TrimSpace(principalStringValue(payload["role"]))
	disabled, _ := payload["disabled"].(bool)
	tenants := principalArrayStringValue(payload["tenants"])
	if err := updateAdminPrincipal(id, role, tenants, disabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit(r, "update_admin_principal", chi.URLParam(r, "id"), "updated")
	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

func principalStringValue(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func principalArrayStringValue(value any) []string {
	switch typed := value.(type) {
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				out = append(out, text)
			}
		}
		return uniqueStrings(out)
	case []string:
		return uniqueStrings(typed)
	default:
		if text := strings.TrimSpace(fmt.Sprint(value)); text != "" && text != "<nil>" {
			return uniqueStrings(strings.Split(text, ","))
		}
		return nil
	}
}
