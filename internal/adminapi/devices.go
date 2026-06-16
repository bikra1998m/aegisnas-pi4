package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/onboarding"
)

func HandleListDevices(w http.ResponseWriter, r *http.Request) {
	service := onboarding.New(config.Get(), nil)
	devices, err := service.ListDevices(250, adminTenantScopesFromRequest(r)...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func HandleObserveDeviceProfile(w http.ResponseWriter, r *http.Request) {
	var observation onboarding.DeviceProfileObservation
	if err := json.NewDecoder(r.Body).Decode(&observation); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	service := onboarding.New(config.Get(), nil)
	result, err := service.ObserveProfileSignals(observation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if result != nil && result.Device != nil {
		audit(r, "observe_device_profile", result.Device.MAC, "updated")
	}
	writeJSON(w, http.StatusOK, result)
}

func HandleDownloadDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	service := onboarding.New(config.Get(), nil)
	item, certPEM, keyPEM, caPEM, err := service.LoadCertificateBundle(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	device, lookupErr := service.GetDeviceByMAC(item.DeviceMAC)
	if lookupErr != nil {
		http.Error(w, lookupErr.Error(), http.StatusNotFound)
		return
	}
	if !tenantAllowed(r, device.Tenant) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	audit(r, "download_device_certificate", item.ID, "downloaded")
	filename := fmt.Sprintf("%s-%s.pem", item.Username, item.DeviceMAC)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	_, _ = fmt.Fprintf(w, "%s\n%s\n%s", certPEM, keyPEM, caPEM)
}
