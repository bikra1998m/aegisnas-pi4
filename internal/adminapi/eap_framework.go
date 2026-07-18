package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	eappkg "github.com/yourorg/aegisnas-pi4/internal/eap"
)

type eapFrameworkResponse struct {
	eappkg.Report
	TEAP        eappkg.TEAPReport        `json:"teap"`
	MachineUser eappkg.MachineUserReport `json:"machine_user"`
	FASTPWD     eappkg.FASTPWDReport     `json:"fast_pwd"`
	SIMAKA      eappkg.SIMAKAReport      `json:"sim_aka"`
	Events      []db.EAPMethodEvent      `json:"events,omitempty"`
}

type eapEvaluationRequest struct {
	Method                      string            `json:"method"`
	InnerMethod                 string            `json:"inner_method"`
	NASType                     string            `json:"nas_type"`
	NASIdentifier               string            `json:"nas_identifier"`
	UserName                    string            `json:"user_name"`
	CallingStationID            string            `json:"calling_station_id"`
	IdentitySource              string            `json:"identity_source"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	CertificatePresented        bool              `json:"certificate_presented"`
	TLSVersion                  string            `json:"tls_version"`
	OuterIdentity               string            `json:"outer_identity"`
	UserIdentity                string            `json:"user_identity"`
	MachineIdentity             string            `json:"machine_identity"`
	CryptoBindingValid          bool              `json:"crypto_binding_valid"`
	ChannelBindingPresent       bool              `json:"channel_binding_present"`
	ChannelBindingValid         bool              `json:"channel_binding_valid"`
	IdentityTypePresented       bool              `json:"identity_type_presented"`
	PACPresented                bool              `json:"pac_presented"`
	PACProvisioningRequested    bool              `json:"pac_provisioning_requested"`
	PACOpaqueKeyAvailable       bool              `json:"pac_opaque_key_available"`
	AnonymousProvisioning       bool              `json:"anonymous_provisioning"`
	EAPPayloadPresent           bool              `json:"eap_payload_present"`
	BasicPasswordAuth           bool              `json:"basic_password_auth"`
	IntermediateResultPresent   bool              `json:"intermediate_result_present"`
	IntermediateResultSuccess   bool              `json:"intermediate_result_success"`
	FinalResultPresent          bool              `json:"final_result_present"`
	FinalResultSuccess          bool              `json:"final_result_success"`
	StepCount                   int               `json:"step_count"`
	ProvisioningAttemptCount    int               `json:"provisioning_attempt_count"`
	PasswordProofValid          bool              `json:"password_proof_valid"`
	ReplayDetected              bool              `json:"replay_detected"`
	PWDGroup                    int               `json:"pwd_group"`
	PWDServerID                 string            `json:"pwd_server_id"`
	PermanentIdentity           string            `json:"permanent_identity"`
	PseudonymIdentity           string            `json:"pseudonym_identity"`
	ReauthIdentity              string            `json:"reauth_identity"`
	VectorProviderAvailable     bool              `json:"vector_provider_available"`
	VectorAvailable             bool              `json:"vector_available"`
	VectorFresh                 bool              `json:"vector_fresh"`
	VectorAgeSeconds            int               `json:"vector_age_seconds"`
	TripletCount                int               `json:"triplet_count"`
	QuintupletCount             int               `json:"quintuplet_count"`
	RESValid                    bool              `json:"res_valid"`
	MACValid                    bool              `json:"mac_valid"`
	AUTNValid                   bool              `json:"autn_valid"`
	AUTSValid                   bool              `json:"auts_valid"`
	ResynchronizationRequested  bool              `json:"resynchronization_requested"`
	ResyncAgeSeconds            int               `json:"resync_age_seconds"`
	NetworkName                 string            `json:"network_name"`
	KDFValid                    bool              `json:"kdf_valid"`
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

type teapFrameworkResponse struct {
	eappkg.TEAPReport
	Events []db.TEAPChainEvent `json:"events,omitempty"`
}

type machineUserFrameworkResponse struct {
	eappkg.MachineUserReport
	Events []db.MachineUserCorrelationEvent `json:"events,omitempty"`
	State  []db.MachineUserCorrelationState `json:"state,omitempty"`
}

type fastPWDFrameworkResponse struct {
	eappkg.FASTPWDReport
	Events []db.FASTPWDEvent `json:"events,omitempty"`
}

type simAKAFrameworkResponse struct {
	eappkg.SIMAKAReport
	Events []db.SIMAKAEvent `json:"events,omitempty"`
}

type teapEvaluationRequest struct {
	InnerMethod                 string            `json:"inner_method"`
	NASType                     string            `json:"nas_type"`
	NASIdentifier               string            `json:"nas_identifier"`
	OuterIdentity               string            `json:"outer_identity"`
	UserIdentity                string            `json:"user_identity"`
	MachineIdentity             string            `json:"machine_identity"`
	CallingStationID            string            `json:"calling_station_id"`
	IdentitySource              string            `json:"identity_source"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	CertificatePresented        bool              `json:"certificate_presented"`
	TLSVersion                  string            `json:"tls_version"`
	CryptoBindingValid          bool              `json:"crypto_binding_valid"`
	ChannelBindingPresent       bool              `json:"channel_binding_present"`
	ChannelBindingValid         bool              `json:"channel_binding_valid"`
	IdentityTypePresented       bool              `json:"identity_type_presented"`
	PACPresented                bool              `json:"pac_presented"`
	PACProvisioningRequested    bool              `json:"pac_provisioning_requested"`
	EAPPayloadPresent           bool              `json:"eap_payload_present"`
	BasicPasswordAuth           bool              `json:"basic_password_auth"`
	IntermediateResultPresent   bool              `json:"intermediate_result_present"`
	IntermediateResultSuccess   bool              `json:"intermediate_result_success"`
	FinalResultPresent          bool              `json:"final_result_present"`
	FinalResultSuccess          bool              `json:"final_result_success"`
	StepCount                   int               `json:"step_count"`
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

type machineUserEvaluationRequest struct {
	NASType                     string            `json:"nas_type"`
	NASIdentifier               string            `json:"nas_identifier"`
	CorrelationID               string            `json:"correlation_id"`
	OuterIdentity               string            `json:"outer_identity"`
	MachineIdentity             string            `json:"machine_identity"`
	UserIdentity                string            `json:"user_identity"`
	CallingStationID            string            `json:"calling_station_id"`
	MachineCallingStationID     string            `json:"machine_calling_station_id"`
	UserCallingStationID        string            `json:"user_calling_station_id"`
	MachineNASIdentifier        string            `json:"machine_nas_identifier"`
	UserNASIdentifier           string            `json:"user_nas_identifier"`
	IdentitySource              string            `json:"identity_source"`
	MachineMethod               string            `json:"machine_method"`
	UserMethod                  string            `json:"user_method"`
	MachineAuthenticated        bool              `json:"machine_authenticated"`
	UserAuthenticated           bool              `json:"user_authenticated"`
	MachineAuthAgeSeconds       int               `json:"machine_auth_age_seconds"`
	UserAuthAgeSeconds          int               `json:"user_auth_age_seconds"`
	MachineRole                 string            `json:"machine_role"`
	UserRole                    string            `json:"user_role"`
	DevicePosture               string            `json:"device_posture"`
	ExistingMachineSession      bool              `json:"existing_machine_session"`
	ExistingUserSession         bool              `json:"existing_user_session"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	TEAPChainComplete           bool              `json:"teap_chain_complete"`
	IdentityTypePresented       bool              `json:"identity_type_presented"`
	CryptoBindingValid          bool              `json:"crypto_binding_valid"`
	ChannelBindingValid         bool              `json:"channel_binding_valid"`
	ReplayDetected              bool              `json:"replay_detected"`
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

type fastPWDEvaluationRequest struct {
	Method                      string            `json:"method"`
	InnerMethod                 string            `json:"inner_method"`
	NASType                     string            `json:"nas_type"`
	NASIdentifier               string            `json:"nas_identifier"`
	Identity                    string            `json:"identity"`
	CallingStationID            string            `json:"calling_station_id"`
	IdentitySource              string            `json:"identity_source"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	TLSVersion                  string            `json:"tls_version"`
	CryptoBindingValid          bool              `json:"crypto_binding_valid"`
	PACPresented                bool              `json:"pac_presented"`
	PACProvisioningRequested    bool              `json:"pac_provisioning_requested"`
	PACOpaqueKeyAvailable       bool              `json:"pac_opaque_key_available"`
	AnonymousProvisioning       bool              `json:"anonymous_provisioning"`
	EAPPayloadPresent           bool              `json:"eap_payload_present"`
	ProvisioningAttemptCount    int               `json:"provisioning_attempt_count"`
	PasswordProofValid          bool              `json:"password_proof_valid"`
	ReplayDetected              bool              `json:"replay_detected"`
	PWDGroup                    int               `json:"pwd_group"`
	PWDServerID                 string            `json:"pwd_server_id"`
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

type simAKAEvaluationRequest struct {
	Method                      string            `json:"method"`
	NASType                     string            `json:"nas_type"`
	NASIdentifier               string            `json:"nas_identifier"`
	Identity                    string            `json:"identity"`
	PermanentIdentity           string            `json:"permanent_identity"`
	PseudonymIdentity           string            `json:"pseudonym_identity"`
	ReauthIdentity              string            `json:"reauth_identity"`
	CallingStationID            string            `json:"calling_station_id"`
	IdentitySource              string            `json:"identity_source"`
	EAPMessagePresent           bool              `json:"eap_message_present"`
	MessageAuthenticatorPresent bool              `json:"message_authenticator_present"`
	VectorProviderAvailable     bool              `json:"vector_provider_available"`
	VectorAvailable             bool              `json:"vector_available"`
	VectorFresh                 bool              `json:"vector_fresh"`
	VectorAgeSeconds            int               `json:"vector_age_seconds"`
	TripletCount                int               `json:"triplet_count"`
	QuintupletCount             int               `json:"quintuplet_count"`
	RESValid                    bool              `json:"res_valid"`
	MACValid                    bool              `json:"mac_valid"`
	AUTNValid                   bool              `json:"autn_valid"`
	AUTSValid                   bool              `json:"auts_valid"`
	ResynchronizationRequested  bool              `json:"resynchronization_requested"`
	ResyncAgeSeconds            int               `json:"resync_age_seconds"`
	NetworkName                 string            `json:"network_name"`
	KDFValid                    bool              `json:"kdf_valid"`
	ReplayDetected              bool              `json:"replay_detected"`
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

func HandleGetEAPFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	filter := db.EAPMethodEventFilter{
		Method:   r.URL.Query().Get("method"),
		Decision: r.URL.Query().Get("decision"),
		NASType:  r.URL.Query().Get("nas_type"),
		Limit:    limit,
	}
	events, err := db.ListEAPMethodEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeEAPMethodEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	teapSummary, err := db.SummarizeTEAPChainEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	machineUserSummary, err := db.SummarizeMachineUserCorrelations(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fastPWDSummary, err := db.SummarizeFASTPWDEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	simAKASummary, err := db.SummarizeSIMAKAEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildFrameworkReport(cfg, eapRuntimeSummaryFromDB(summary))
	teapReport := eappkg.BuildTEAPReport(cfg, teapRuntimeSummaryFromDB(teapSummary))
	machineUserReport := eappkg.BuildMachineUserReport(cfg, machineUserRuntimeSummaryFromDB(machineUserSummary))
	fastPWDReport := eappkg.BuildFASTPWDReport(cfg, fastPWDRuntimeSummaryFromDB(fastPWDSummary))
	simAKAReport := eappkg.BuildSIMAKAReport(cfg, simAKARuntimeSummaryFromDB(simAKASummary))
	writeJSON(w, http.StatusOK, eapFrameworkResponse{Report: report, TEAP: teapReport, MachineUser: machineUserReport, FASTPWD: fastPWDReport, SIMAKA: simAKAReport, Events: events})
}

func HandleEvaluateEAPFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req eapEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := eappkg.Evaluate(cfg, eappkg.EvaluationRequest{
		Method:                      req.Method,
		InnerMethod:                 req.InnerMethod,
		NASType:                     req.NASType,
		IdentitySource:              req.IdentitySource,
		EAPMessagePresent:           req.EAPMessagePresent,
		MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
		CertificatePresented:        req.CertificatePresented,
		TLSVersion:                  req.TLSVersion,
		OuterIdentity:               req.OuterIdentity,
		UserIdentity:                req.UserIdentity,
		MachineIdentity:             req.MachineIdentity,
		CryptoBindingValid:          req.CryptoBindingValid,
		ChannelBindingPresent:       req.ChannelBindingPresent,
		ChannelBindingValid:         req.ChannelBindingValid,
		IdentityTypePresented:       req.IdentityTypePresented,
		PACPresented:                req.PACPresented,
		PACProvisioningRequested:    req.PACProvisioningRequested,
		PACOpaqueKeyAvailable:       req.PACOpaqueKeyAvailable,
		AnonymousProvisioning:       req.AnonymousProvisioning,
		EAPPayloadPresent:           req.EAPPayloadPresent,
		BasicPasswordAuth:           req.BasicPasswordAuth,
		IntermediateResultPresent:   req.IntermediateResultPresent,
		IntermediateResultSuccess:   req.IntermediateResultSuccess,
		FinalResultPresent:          req.FinalResultPresent,
		FinalResultSuccess:          req.FinalResultSuccess,
		StepCount:                   req.StepCount,
		ProvisioningAttemptCount:    req.ProvisioningAttemptCount,
		PasswordProofValid:          req.PasswordProofValid,
		ReplayDetected:              req.ReplayDetected,
		PWDGroup:                    req.PWDGroup,
		PWDServerID:                 req.PWDServerID,
		PermanentIdentity:           req.PermanentIdentity,
		PseudonymIdentity:           req.PseudonymIdentity,
		ReauthIdentity:              req.ReauthIdentity,
		VectorProviderAvailable:     req.VectorProviderAvailable,
		VectorAvailable:             req.VectorAvailable,
		VectorFresh:                 req.VectorFresh,
		VectorAgeSeconds:            req.VectorAgeSeconds,
		TripletCount:                req.TripletCount,
		QuintupletCount:             req.QuintupletCount,
		RESValid:                    req.RESValid,
		MACValid:                    req.MACValid,
		AUTNValid:                   req.AUTNValid,
		AUTSValid:                   req.AUTSValid,
		ResynchronizationRequested:  req.ResynchronizationRequested,
		ResyncAgeSeconds:            req.ResyncAgeSeconds,
		NetworkName:                 req.NetworkName,
		KDFValid:                    req.KDFValid,
	})
	if req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		_ = db.RecordEAPMethodEvent(db.EAPMethodEvent{
			ObservedAt:                  time.Now().UTC(),
			Method:                      decision.Method,
			InnerMethod:                 decision.InnerMethod,
			Decision:                    decision.Decision,
			Reason:                      decision.Reason,
			NASIdentifier:               req.NASIdentifier,
			NASType:                     req.NASType,
			UserNameHash:                db.HashEAPIdentity(req.UserName),
			CallingStationHash:          db.HashEAPIdentity(req.CallingStationID),
			IdentitySource:              decision.IdentitySource,
			EAPMessagePresent:           req.EAPMessagePresent,
			MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
			CertificatePresented:        req.CertificatePresented,
			TLSVersion:                  req.TLSVersion,
			PolicyMode:                  decision.PolicyMode,
			LatencyMS:                   latency,
			Details:                     req.Details,
		}, cfg.Radius.EAP.Framework.EventRetentionLimit)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled,
	})
}

func HandleGetFASTPWDFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	filter := db.FASTPWDEventFilter{
		Method:   r.URL.Query().Get("method"),
		Decision: r.URL.Query().Get("decision"),
		NASType:  r.URL.Query().Get("nas_type"),
		Limit:    limit,
	}
	events, err := db.ListFASTPWDEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeFASTPWDEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildFASTPWDReport(cfg, fastPWDRuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, fastPWDFrameworkResponse{FASTPWDReport: report, Events: events})
}

func HandleEvaluateFASTPWD(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req fastPWDEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := eappkg.EvaluateFASTPWD(cfg, eappkg.FASTPWDEvaluationRequest{
		Method:                      req.Method,
		InnerMethod:                 req.InnerMethod,
		NASType:                     req.NASType,
		Identity:                    req.Identity,
		IdentitySource:              req.IdentitySource,
		EAPMessagePresent:           req.EAPMessagePresent,
		MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
		TLSVersion:                  req.TLSVersion,
		CryptoBindingValid:          req.CryptoBindingValid,
		PACPresented:                req.PACPresented,
		PACProvisioningRequested:    req.PACProvisioningRequested,
		PACOpaqueKeyAvailable:       req.PACOpaqueKeyAvailable,
		AnonymousProvisioning:       req.AnonymousProvisioning,
		EAPPayloadPresent:           req.EAPPayloadPresent,
		ProvisioningAttemptCount:    req.ProvisioningAttemptCount,
		PasswordProofValid:          req.PasswordProofValid,
		ReplayDetected:              req.ReplayDetected,
		PWDGroup:                    req.PWDGroup,
		PWDServerID:                 req.PWDServerID,
	})
	audited := req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled
	if audited {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		retention := cfg.Radius.EAP.Framework.EventRetentionLimit
		switch decision.Method {
		case "fast":
			if cfg.Radius.EAP.FAST.EventRetentionLimit > 0 {
				retention = cfg.Radius.EAP.FAST.EventRetentionLimit
			}
		case "pwd":
			if cfg.Radius.EAP.PWD.EventRetentionLimit > 0 {
				retention = cfg.Radius.EAP.PWD.EventRetentionLimit
			}
		}
		_ = db.RecordFASTPWDEvent(db.FASTPWDEvent{
			ObservedAt:               time.Now().UTC(),
			Method:                   decision.Method,
			Decision:                 decision.Decision,
			Reason:                   decision.Reason,
			NASIdentifier:            req.NASIdentifier,
			NASType:                  req.NASType,
			IdentityHash:             db.HashEAPIdentity(req.Identity),
			CallingStationHash:       db.HashEAPIdentity(req.CallingStationID),
			IdentitySource:           decision.IdentitySource,
			InnerMethod:              decision.InnerMethod,
			CryptoBindingValid:       req.CryptoBindingValid,
			PACPresented:             req.PACPresented,
			PACProvisioningRequested: req.PACProvisioningRequested,
			PACOpaqueKeyAvailable:    req.PACOpaqueKeyAvailable,
			AnonymousProvisioning:    req.AnonymousProvisioning,
			EAPPayloadPresent:        req.EAPPayloadPresent,
			ProvisioningAttemptCount: req.ProvisioningAttemptCount,
			PasswordProofValid:       req.PasswordProofValid,
			ReplayDetected:           req.ReplayDetected,
			PWDGroup:                 req.PWDGroup,
			PWDServerIDHash:          db.HashEAPIdentity(req.PWDServerID),
			TLSVersion:               req.TLSVersion,
			PolicyMode:               decision.PolicyMode,
			LatencyMS:                latency,
			Details:                  req.Details,
		}, retention)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  audited,
	})
}

func HandleGetSIMAKAFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	filter := db.SIMAKAEventFilter{
		Method:   r.URL.Query().Get("method"),
		Decision: r.URL.Query().Get("decision"),
		NASType:  r.URL.Query().Get("nas_type"),
		Limit:    limit,
	}
	events, err := db.ListSIMAKAEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeSIMAKAEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildSIMAKAReport(cfg, simAKARuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, simAKAFrameworkResponse{SIMAKAReport: report, Events: events})
}

func HandleEvaluateSIMAKA(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req simAKAEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := eappkg.EvaluateSIMAKA(cfg, eappkg.SIMAKAEvaluationRequest{
		Method:                      req.Method,
		NASType:                     req.NASType,
		Identity:                    req.Identity,
		PermanentIdentity:           req.PermanentIdentity,
		PseudonymIdentity:           req.PseudonymIdentity,
		ReauthIdentity:              req.ReauthIdentity,
		IdentitySource:              req.IdentitySource,
		EAPMessagePresent:           req.EAPMessagePresent,
		MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
		VectorProviderAvailable:     req.VectorProviderAvailable,
		VectorAvailable:             req.VectorAvailable,
		VectorFresh:                 req.VectorFresh,
		VectorAgeSeconds:            req.VectorAgeSeconds,
		TripletCount:                req.TripletCount,
		QuintupletCount:             req.QuintupletCount,
		RESValid:                    req.RESValid,
		MACValid:                    req.MACValid,
		AUTNValid:                   req.AUTNValid,
		AUTSValid:                   req.AUTSValid,
		ResynchronizationRequested:  req.ResynchronizationRequested,
		ResyncAgeSeconds:            req.ResyncAgeSeconds,
		NetworkName:                 req.NetworkName,
		KDFValid:                    req.KDFValid,
		ReplayDetected:              req.ReplayDetected,
	})
	audited := req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled
	if audited {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		retention := cfg.Radius.EAP.SIMAKA.EventRetentionLimit
		if retention <= 0 {
			retention = cfg.Radius.EAP.Framework.EventRetentionLimit
		}
		_ = db.RecordSIMAKAEvent(db.SIMAKAEvent{
			ObservedAt:              time.Now().UTC(),
			Method:                  decision.Method,
			Decision:                decision.Decision,
			Reason:                  decision.Reason,
			NASIdentifier:           req.NASIdentifier,
			NASType:                 req.NASType,
			IdentityHash:            db.HashEAPIdentity(req.Identity),
			PermanentIdentityHash:   db.HashEAPIdentity(req.PermanentIdentity),
			PseudonymIdentityHash:   db.HashEAPIdentity(req.PseudonymIdentity),
			ReauthIdentityHash:      db.HashEAPIdentity(req.ReauthIdentity),
			CallingStationHash:      db.HashEAPIdentity(req.CallingStationID),
			IdentitySource:          decision.IdentitySource,
			VectorProvider:          cfg.Radius.EAP.SIMAKA.VectorProvider,
			VectorProviderAvailable: req.VectorProviderAvailable,
			VectorAvailable:         req.VectorAvailable,
			VectorFresh:             req.VectorFresh,
			VectorAgeSeconds:        req.VectorAgeSeconds,
			TripletCount:            req.TripletCount,
			QuintupletCount:         req.QuintupletCount,
			RESValid:                req.RESValid,
			MACValid:                req.MACValid,
			AUTNValid:               req.AUTNValid,
			AUTSValid:               req.AUTSValid,
			ResyncRequested:         req.ResynchronizationRequested,
			ResyncAgeSeconds:        req.ResyncAgeSeconds,
			NetworkNameHash:         db.HashEAPIdentity(req.NetworkName),
			KDFValid:                req.KDFValid,
			ReplayDetected:          req.ReplayDetected,
			PolicyMode:              decision.PolicyMode,
			LatencyMS:               latency,
			Details:                 req.Details,
		}, retention)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  audited,
	})
}

func HandleGetTEAPFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	filter := db.TEAPChainEventFilter{
		Decision:  r.URL.Query().Get("decision"),
		ChainMode: r.URL.Query().Get("chain_mode"),
		NASType:   r.URL.Query().Get("nas_type"),
		Limit:     limit,
	}
	events, err := db.ListTEAPChainEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeTEAPChainEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildTEAPReport(cfg, teapRuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, teapFrameworkResponse{TEAPReport: report, Events: events})
}

func HandleEvaluateTEAPChain(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req teapEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := eappkg.EvaluateTEAPChain(cfg, eappkg.TEAPChainEvaluationRequest{
		InnerMethod:                 req.InnerMethod,
		NASType:                     req.NASType,
		OuterIdentity:               req.OuterIdentity,
		UserIdentity:                req.UserIdentity,
		MachineIdentity:             req.MachineIdentity,
		IdentitySource:              req.IdentitySource,
		EAPMessagePresent:           req.EAPMessagePresent,
		MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
		CertificatePresented:        req.CertificatePresented,
		TLSVersion:                  req.TLSVersion,
		CryptoBindingValid:          req.CryptoBindingValid,
		ChannelBindingPresent:       req.ChannelBindingPresent,
		ChannelBindingValid:         req.ChannelBindingValid,
		IdentityTypePresented:       req.IdentityTypePresented,
		PACPresented:                req.PACPresented,
		PACProvisioningRequested:    req.PACProvisioningRequested,
		EAPPayloadPresent:           req.EAPPayloadPresent,
		BasicPasswordAuth:           req.BasicPasswordAuth,
		IntermediateResultPresent:   req.IntermediateResultPresent,
		IntermediateResultSuccess:   req.IntermediateResultSuccess,
		FinalResultPresent:          req.FinalResultPresent,
		FinalResultSuccess:          req.FinalResultSuccess,
		StepCount:                   req.StepCount,
	})
	audited := req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled
	if audited {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		retention := cfg.Radius.EAP.TEAP.EventRetentionLimit
		if retention <= 0 {
			retention = cfg.Radius.EAP.Framework.EventRetentionLimit
		}
		_ = db.RecordTEAPChainEvent(db.TEAPChainEvent{
			ObservedAt:                time.Now().UTC(),
			Decision:                  decision.Decision,
			Reason:                    decision.Reason,
			ChainMode:                 decision.ChainMode,
			ChainState:                decision.ChainState,
			NASIdentifier:             req.NASIdentifier,
			NASType:                   req.NASType,
			OuterIdentityHash:         db.HashEAPIdentity(req.OuterIdentity),
			UserIdentityHash:          db.HashEAPIdentity(req.UserIdentity),
			MachineIdentityHash:       db.HashEAPIdentity(req.MachineIdentity),
			IdentitySource:            decision.IdentitySource,
			InnerMethod:               decision.InnerMethod,
			CryptoBindingValid:        req.CryptoBindingValid,
			ChannelBindingPresent:     req.ChannelBindingPresent,
			ChannelBindingValid:       req.ChannelBindingValid,
			IdentityTypePresent:       req.IdentityTypePresented,
			PACPresented:              req.PACPresented,
			PACProvisioningRequested:  req.PACProvisioningRequested,
			EAPPayloadPresent:         req.EAPPayloadPresent,
			BasicPasswordAuth:         req.BasicPasswordAuth,
			IntermediateResultPresent: req.IntermediateResultPresent,
			IntermediateResultSuccess: req.IntermediateResultSuccess,
			FinalResultPresent:        req.FinalResultPresent,
			FinalResultSuccess:        req.FinalResultSuccess,
			StepCount:                 req.StepCount,
			TLSVersion:                req.TLSVersion,
			PolicyMode:                decision.PolicyMode,
			LatencyMS:                 latency,
			Details:                   req.Details,
		}, retention)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  audited,
	})
}

func HandleGetMachineUserFramework(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 100, 1, 5000)
	filter := db.MachineUserCorrelationFilter{
		Decision:        r.URL.Query().Get("decision"),
		CorrelationMode: r.URL.Query().Get("correlation_mode"),
		NASType:         r.URL.Query().Get("nas_type"),
		Limit:           limit,
	}
	events, err := db.ListMachineUserCorrelationEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state, err := db.ListMachineUserCorrelationState(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	summary, err := db.SummarizeMachineUserCorrelations(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildMachineUserReport(cfg, machineUserRuntimeSummaryFromDB(summary))
	writeJSON(w, http.StatusOK, machineUserFrameworkResponse{MachineUserReport: report, Events: events, State: state})
}

func HandleEvaluateMachineUserCorrelation(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		http.Error(w, "configuration not loaded", http.StatusInternalServerError)
		return
	}
	var req machineUserEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	start := time.Now()
	decision := eappkg.EvaluateMachineUserCorrelation(cfg, eappkg.MachineUserEvaluationRequest{
		NASType:                     req.NASType,
		NASIdentifier:               req.NASIdentifier,
		CorrelationID:               req.CorrelationID,
		OuterIdentity:               req.OuterIdentity,
		MachineIdentity:             req.MachineIdentity,
		UserIdentity:                req.UserIdentity,
		CallingStationID:            req.CallingStationID,
		MachineCallingStationID:     req.MachineCallingStationID,
		UserCallingStationID:        req.UserCallingStationID,
		MachineNASIdentifier:        req.MachineNASIdentifier,
		UserNASIdentifier:           req.UserNASIdentifier,
		IdentitySource:              req.IdentitySource,
		MachineMethod:               req.MachineMethod,
		UserMethod:                  req.UserMethod,
		MachineAuthenticated:        req.MachineAuthenticated,
		UserAuthenticated:           req.UserAuthenticated,
		MachineAuthAgeSeconds:       req.MachineAuthAgeSeconds,
		UserAuthAgeSeconds:          req.UserAuthAgeSeconds,
		MachineRole:                 req.MachineRole,
		UserRole:                    req.UserRole,
		DevicePosture:               req.DevicePosture,
		ExistingMachineSession:      req.ExistingMachineSession,
		ExistingUserSession:         req.ExistingUserSession,
		EAPMessagePresent:           req.EAPMessagePresent,
		MessageAuthenticatorPresent: req.MessageAuthenticatorPresent,
		TEAPChainComplete:           req.TEAPChainComplete,
		IdentityTypePresented:       req.IdentityTypePresented,
		CryptoBindingValid:          req.CryptoBindingValid,
		ChannelBindingValid:         req.ChannelBindingValid,
		ReplayDetected:              req.ReplayDetected,
	})
	audited := req.Audit && cfg.Radius.EAP.Framework.TelemetryEnabled && cfg.Radius.EAP.MachineUser.AuditEnabled
	if audited {
		latency := req.LatencyMS
		if latency <= 0 {
			latency = int(time.Since(start).Milliseconds())
		}
		correlationIDHash := db.HashEAPIdentity(req.CorrelationID)
		callingStationHash := db.HashEAPIdentity(req.CallingStationID)
		machineCallingHash := db.HashEAPIdentity(req.MachineCallingStationID)
		userCallingHash := db.HashEAPIdentity(req.UserCallingStationID)
		if machineCallingHash == "" {
			machineCallingHash = callingStationHash
		}
		if userCallingHash == "" {
			userCallingHash = callingStationHash
		}
		event := db.MachineUserCorrelationEvent{
			ObservedAt:                time.Now().UTC(),
			Decision:                  decision.Decision,
			Reason:                    decision.Reason,
			CorrelationIDHash:         correlationIDHash,
			CorrelationMode:           decision.CorrelationMode,
			CorrelationState:          decision.CorrelationState,
			NASIdentifier:             req.NASIdentifier,
			NASType:                   req.NASType,
			CallingStationHash:        callingStationHash,
			MachineCallingStationHash: machineCallingHash,
			UserCallingStationHash:    userCallingHash,
			MachineNASIdentifier:      req.MachineNASIdentifier,
			UserNASIdentifier:         req.UserNASIdentifier,
			OuterIdentityHash:         db.HashEAPIdentity(req.OuterIdentity),
			MachineIdentityHash:       db.HashEAPIdentity(req.MachineIdentity),
			UserIdentityHash:          db.HashEAPIdentity(req.UserIdentity),
			IdentitySource:            decision.IdentitySource,
			MachineMethod:             req.MachineMethod,
			UserMethod:                req.UserMethod,
			MachineAuthenticated:      req.MachineAuthenticated,
			UserAuthenticated:         req.UserAuthenticated,
			SameCallingStation:        decision.SameCallingStation,
			SameNAS:                   decision.SameNAS,
			MachineBeforeUser:         decision.MachineBeforeUser,
			MachineAuthAgeSeconds:     req.MachineAuthAgeSeconds,
			UserAuthAgeSeconds:        req.UserAuthAgeSeconds,
			MachineRole:               req.MachineRole,
			UserRole:                  req.UserRole,
			EffectiveRole:             decision.EffectiveRole,
			DevicePosture:             decision.DevicePosture,
			ConflictDetected:          decision.ConflictDetected,
			StaleMachineAuth:          decision.StaleMachineAuth,
			TEAPChainComplete:         req.TEAPChainComplete,
			IdentityTypePresent:       req.IdentityTypePresented,
			CryptoBindingValid:        req.CryptoBindingValid,
			ChannelBindingValid:       req.ChannelBindingValid,
			ReplayDetected:            req.ReplayDetected,
			PolicyMode:                decision.PolicyMode,
			LatencyMS:                 latency,
			Details:                   req.Details,
		}
		event.CorrelationKey = db.BuildMachineUserCorrelationKey(event.CorrelationIDHash, event.MachineIdentityHash, event.UserIdentityHash, event.CallingStationHash)
		_ = db.RecordMachineUserCorrelationEvent(event, cfg.Radius.EAP.MachineUser.EventRetentionLimit, cfg.Radius.EAP.MachineUser.MaxActiveCorrelations)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"audited":  audited,
	})
}

func eapRuntimeSummaryFromDB(summary db.EAPMethodEventSummary) eappkg.RuntimeSummary {
	return eappkg.RuntimeSummary{
		TotalEvents:        summary.TotalEvents,
		Accepted:           summary.Accepted,
		Rejected:           summary.Rejected,
		MonitorAllowed:     summary.MonitorAllowed,
		Unsupported:        summary.Unsupported,
		ByMethod:           summary.ByMethod,
		ByDecision:         summary.ByDecision,
		LastEventAt:        summary.LastEventAt,
		LastRejectedReason: summary.LastRejectedReason,
	}
}

func teapRuntimeSummaryFromDB(summary db.TEAPChainEventSummary) eappkg.TEAPRuntimeSummary {
	return eappkg.TEAPRuntimeSummary{
		TotalEvents:            summary.TotalEvents,
		Accepted:               summary.Accepted,
		Rejected:               summary.Rejected,
		MonitorAllowed:         summary.MonitorAllowed,
		ByDecision:             summary.ByDecision,
		ByChainMode:            summary.ByChainMode,
		MissingMachineIdentity: summary.MissingMachineIdentity,
		MissingUserIdentity:    summary.MissingUserIdentity,
		InvalidCryptoBinding:   summary.InvalidCryptoBinding,
		InvalidChannelBinding:  summary.InvalidChannelBinding,
		PACRequiredMissing:     summary.PACRequiredMissing,
		LastEventAt:            summary.LastEventAt,
		LastRejectedReason:     summary.LastRejectedReason,
	}
}

func machineUserRuntimeSummaryFromDB(summary db.MachineUserCorrelationSummary) eappkg.MachineUserRuntimeSummary {
	return eappkg.MachineUserRuntimeSummary{
		TotalEvents:              summary.TotalEvents,
		Accepted:                 summary.Accepted,
		Rejected:                 summary.Rejected,
		MonitorAllowed:           summary.MonitorAllowed,
		Quarantined:              summary.Quarantined,
		ActiveCorrelations:       summary.ActiveCorrelations,
		ByDecision:               summary.ByDecision,
		ByCorrelationMode:        summary.ByCorrelationMode,
		MissingMachineIdentity:   summary.MissingMachineIdentity,
		MissingUserIdentity:      summary.MissingUserIdentity,
		StaleMachineAuth:         summary.StaleMachineAuth,
		RoleConflict:             summary.RoleConflict,
		CallingStationMismatch:   summary.CallingStationMismatch,
		NASMismatch:              summary.NASMismatch,
		MachineBeforeUserFailure: summary.MachineBeforeUserFailure,
		LastEventAt:              summary.LastEventAt,
		LastRejectedReason:       summary.LastRejectedReason,
	}
}

func fastPWDRuntimeSummaryFromDB(summary db.FASTPWDEventSummary) eappkg.FASTPWDRuntimeSummary {
	return eappkg.FASTPWDRuntimeSummary{
		TotalEvents:           summary.TotalEvents,
		Accepted:              summary.Accepted,
		Rejected:              summary.Rejected,
		MonitorAllowed:        summary.MonitorAllowed,
		ByMethod:              summary.ByMethod,
		ByDecision:            summary.ByDecision,
		MissingPAC:            summary.MissingPAC,
		InvalidCryptoBinding:  summary.InvalidCryptoBinding,
		AnonymousProvisioning: summary.AnonymousProvisioning,
		MissingPasswordProof:  summary.MissingPasswordProof,
		WeakPWDGroup:          summary.WeakPWDGroup,
		ReplayRejected:        summary.ReplayRejected,
		LastEventAt:           summary.LastEventAt,
		LastRejectedReason:    summary.LastRejectedReason,
	}
}

func simAKARuntimeSummaryFromDB(summary db.SIMAKAEventSummary) eappkg.SIMAKARuntimeSummary {
	return eappkg.SIMAKARuntimeSummary{
		TotalEvents:          summary.TotalEvents,
		Accepted:             summary.Accepted,
		Rejected:             summary.Rejected,
		MonitorAllowed:       summary.MonitorAllowed,
		ByMethod:             summary.ByMethod,
		ByDecision:           summary.ByDecision,
		MissingIdentity:      summary.MissingIdentity,
		MissingVector:        summary.MissingVector,
		StaleVector:          summary.StaleVector,
		InvalidAuthenticator: summary.InvalidAuthenticator,
		ResyncEvents:         summary.ResyncEvents,
		ReplayRejected:       summary.ReplayRejected,
		LastEventAt:          summary.LastEventAt,
		LastRejectedReason:   summary.LastRejectedReason,
	}
}

func parseBoundedInt(raw string, fallback, min, max int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
