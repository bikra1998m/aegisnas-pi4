package adminapi

import (
	"net/http"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

type dictionaryReleaseProfilesResponse struct {
	DefaultProfileID string                                    `json:"default_profile_id"`
	ActiveProfileID  string                                    `json:"active_profile_id"`
	Profiles         []productconfigs.DictionaryReleaseProfile `json:"profiles"`
}

func HandleGetDictionaryReleaseProfiles(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	activeProfileID := productconfigs.DefaultDictionaryReleaseProfileID
	if cfg != nil {
		activeProfileID = productconfigs.EffectiveDictionaryReleaseProfileID(cfg.Radius.Vendor.DictionaryRelease)
	}
	if !productconfigs.ValidDictionaryReleaseProfileID(activeProfileID) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "active dictionary release profile is unavailable"})
		return
	}
	profiles := productconfigs.BuiltInDictionaryReleaseProfiles()
	filter := strings.TrimSpace(r.URL.Query().Get("id"))
	if filter != "" {
		profile, ok := productconfigs.DictionaryReleaseProfileByID(filter)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "dictionary release profile not found"})
			return
		}
		profiles = []productconfigs.DictionaryReleaseProfile{profile}
	}
	writeJSON(w, http.StatusOK, dictionaryReleaseProfilesResponse{
		DefaultProfileID: productconfigs.DefaultDictionaryReleaseProfileID,
		ActiveProfileID:  activeProfileID,
		Profiles:         profiles,
	})
}
