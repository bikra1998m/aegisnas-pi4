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
	TEAP    eappkg.TEAPReport    `json:"teap"`
	FASTPWD eappkg.FASTPWDReport `json:"fast_pwd"`
	Events  []db.EAPMethodEvent  `json:"events,omitempty"`
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
	LatencyMS                   int               `json:"latency_ms"`
	Audit                       bool              `json:"audit"`
	Details                     map[string]string `json:"details"`
}

type teapFrameworkResponse struct {
	eappkg.TEAPReport
	Events []db.TEAPChainEvent `json:"events,omitempty"`
}

type fastPWDFrameworkResponse struct {
	eappkg.FASTPWDReport
	Events []db.FASTPWDEvent `json:"events,omitempty"`
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
	fastPWDSummary, err := db.SummarizeFASTPWDEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	report := eappkg.BuildFrameworkReport(cfg, eapRuntimeSummaryFromDB(summary))
	teapReport := eappkg.BuildTEAPReport(cfg, teapRuntimeSummaryFromDB(teapSummary))
	fastPWDReport := eappkg.BuildFASTPWDReport(cfg, fastPWDRuntimeSummaryFromDB(fastPWDSummary))
	writeJSON(w, http.StatusOK, eapFrameworkResponse{Report: report, TEAP: teapReport, FASTPWD: fastPWDReport, Events: events})
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
