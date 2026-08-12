package radius

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
	"github.com/yourorg/aegisnas-pi4/internal/qos"
)

type RateCompilerRequest struct {
	PackKeys                   []string `json:"pack_keys,omitempty"`
	DownloadRateKbps           int      `json:"download_rate_kbps"`
	UploadRateKbps             int      `json:"upload_rate_kbps"`
	DownloadBurstRateKbps      int      `json:"download_burst_rate_kbps,omitempty"`
	UploadBurstRateKbps        int      `json:"upload_burst_rate_kbps,omitempty"`
	DownloadBurstThresholdKbps int      `json:"download_burst_threshold_kbps,omitempty"`
	UploadBurstThresholdKbps   int      `json:"upload_burst_threshold_kbps,omitempty"`
	DownloadBurstTimeSeconds   int      `json:"download_burst_time_seconds,omitempty"`
	UploadBurstTimeSeconds     int      `json:"upload_burst_time_seconds,omitempty"`
	Priority                   int      `json:"priority,omitempty"`
	DownloadMinRateKbps        int      `json:"download_min_rate_kbps,omitempty"`
	UploadMinRateKbps          int      `json:"upload_min_rate_kbps,omitempty"`
}

type RateDecompilerRequest struct {
	PackKey    string                  `json:"pack_key"`
	Attributes []RateCompilerAttribute `json:"attributes"`
}

type RateCompilerAttribute struct {
	PackKey  string `json:"pack_key"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Quoted   bool   `json:"quoted"`
	Unit     string `json:"unit"`
	Semantic string `json:"semantic"`
}

type RateCompilerDiagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	PackKey  string `json:"pack_key,omitempty"`
	Field    string `json:"field,omitempty"`
}

type RateCompilerResult struct {
	GeneratedAt     string                   `json:"generated_at"`
	Status          string                   `json:"status"`
	DownloadKbps    int                      `json:"download_kbps"`
	UploadKbps      int                      `json:"upload_kbps"`
	Attributes      []RateCompilerAttribute  `json:"attributes"`
	Diagnostics     []RateCompilerDiagnostic `json:"diagnostics"`
	AttributeCount  int                      `json:"attribute_count"`
	CompilerVersion int                      `json:"compiler_version"`
}

type RateDecompilerResult struct {
	GeneratedAt     string                   `json:"generated_at"`
	Status          string                   `json:"status"`
	PackKey         string                   `json:"pack_key"`
	Intent          RateCompilerRequest      `json:"intent"`
	Diagnostics     []RateCompilerDiagnostic `json:"diagnostics"`
	AttributeCount  int                      `json:"attribute_count"`
	CompilerVersion int                      `json:"compiler_version"`
}

type RateCompilerCapability struct {
	PackKey    string   `json:"pack_key"`
	Attributes []string `json:"attributes"`
	Units      []string `json:"units"`
	Notes      string   `json:"notes"`
}

type RateCompilerReport struct {
	GeneratedAt     string                   `json:"generated_at"`
	Status          string                   `json:"status"`
	CompilerVersion int                      `json:"compiler_version"`
	RFCs            []string                 `json:"rfcs"`
	Capabilities    []RateCompilerCapability `json:"capabilities"`
}

const RateCompilerVersion = 1

func BuildRateCompilerReport() RateCompilerReport {
	return RateCompilerReport{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Status:          "ready",
		CompilerVersion: RateCompilerVersion,
		RFCs:            []string{"RFC 2865", "RFC 2866", "RFC 5176"},
		Capabilities: []RateCompilerCapability{
			{PackKey: productconfigs.VendorPackMikroTik, Attributes: []string{"Mikrotik-Rate-Limit"}, Units: []string{"k-suffix-pair", "seconds-pair"}, Notes: "Supports basic and extended RouterOS rate grammar with explicit burst, threshold, time, priority, and min-rate fields."},
			{PackKey: productconfigs.VendorPackWISPr, Attributes: []string{"WISPr-Bandwidth-Max-Down", "WISPr-Bandwidth-Max-Up"}, Units: []string{"integer-kbps"}, Notes: "Preserves current AegisNAS WISPr integer-kbps behavior for backward compatibility."},
			{PackKey: productconfigs.VendorPackUBNT, Attributes: []string{"UBNT-Data-Rate-DL", "UBNT-Data-Rate-UL"}, Units: []string{"integer-bps"}, Notes: "Compiles from normalized kbps to bps with 32-bit overflow checks."},
			{PackKey: productconfigs.VendorPackHuawei, Attributes: []string{"Huawei-Output-Average-Rate", "Huawei-Input-Average-Rate"}, Units: []string{"integer-kbps"}, Notes: "Compiles Huawei average-rate VSAs from normalized kbps."},
			{PackKey: productconfigs.VendorPackH3C, Attributes: []string{"H3C-Output-Average-Rate", "H3C-Input-Average-Rate"}, Units: []string{"integer-kbps"}, Notes: "Compiles H3C average-rate VSAs from normalized kbps."},
			{PackKey: productconfigs.VendorPackTPLink, Attributes: []string{"TPLink-Xmit-limit", "TPLink-Recv-limit"}, Units: []string{"integer-kbps"}, Notes: "Compiles Omada rate limits from normalized kbps."},
			{PackKey: productconfigs.VendorPackZTE, Attributes: []string{"Rate-Ctrl-SCR-Down", "Rate-Ctrl-SCR-Up"}, Units: []string{"integer-kbps"}, Notes: "Compiles ZTE SCR values from normalized kbps."},
			{PackKey: "generic-kbps", Attributes: []string{"Cambium", "Airespace", "HP", "Nomadix", "ChilliSpot", "D-Link"}, Units: []string{"integer-kbps"}, Notes: "Shared integer-kbps compiler and decompiler are used by the named vendor packs."},
		},
	}
}

func CompileVendorRates(req RateCompilerRequest) RateCompilerResult {
	result := RateCompilerResult{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Status:          "ready",
		DownloadKbps:    req.DownloadRateKbps,
		UploadKbps:      req.UploadRateKbps,
		CompilerVersion: RateCompilerVersion,
	}
	if err := qos.ValidatePair(qos.RatePairKbps{DownloadKbps: req.DownloadRateKbps, UploadKbps: req.UploadRateKbps}); err != nil {
		result.Status = "blocked"
		result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_rate", Message: err.Error(), Field: "download_rate_kbps/upload_rate_kbps"})
		return result
	}
	if req.Priority < 0 || req.Priority > 8 {
		result.Status = "blocked"
		result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_priority", Message: "priority must be between 0 and 8", Field: "priority"})
		return result
	}
	explicitPacks := len(req.PackKeys) > 0
	packs := normalizeReplyPackKeys(req.PackKeys)
	if len(packs) == 0 {
		packs = []string{productconfigs.VendorPackMikroTik, productconfigs.VendorPackWISPr, productconfigs.VendorPackUBNT}
	}
	seen := map[string]struct{}{}
	appendAttr := func(attr RateCompilerAttribute) {
		if strings.TrimSpace(attr.Value) == "" {
			return
		}
		key := attr.PackKey + "\x00" + attr.Name + "\x00" + attr.Value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		result.Attributes = append(result.Attributes, attr)
	}
	addKbpsPair := func(packKey, downName, upName string) {
		down, err := qos.IntegerKbps(req.DownloadRateKbps)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_download_rate", Message: err.Error(), PackKey: packKey, Field: "download_rate_kbps"})
			return
		}
		up, err := qos.IntegerKbps(req.UploadRateKbps)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_upload_rate", Message: err.Error(), PackKey: packKey, Field: "upload_rate_kbps"})
			return
		}
		appendAttr(RateCompilerAttribute{PackKey: packKey, Name: downName, Value: down, Unit: "integer-kbps", Semantic: productconfigs.VendorSemanticDownloadBandwidth})
		appendAttr(RateCompilerAttribute{PackKey: packKey, Name: upName, Value: up, Unit: "integer-kbps", Semantic: productconfigs.VendorSemanticUploadBandwidth})
	}
	for _, pack := range packs {
		switch pack {
		case productconfigs.VendorPackMikroTik:
			value, err := CompileMikroTikRateLimit(req)
			if err != nil {
				result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_mikrotik_rate_limit", Message: err.Error(), PackKey: pack})
				continue
			}
			appendAttr(RateCompilerAttribute{PackKey: pack, Name: "Mikrotik-Rate-Limit", Value: value, Quoted: true, Unit: "mikrotik-rate-grammar", Semantic: productconfigs.VendorSemanticBandwidthProfile})
		case productconfigs.VendorPackWISPr:
			addKbpsPair(pack, "WISPr-Bandwidth-Max-Down", "WISPr-Bandwidth-Max-Up")
		case productconfigs.VendorPackUBNT:
			down, err := qos.IntegerBpsFromKbps(req.DownloadRateKbps)
			if err != nil {
				result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "rate_bps_overflow", Message: err.Error(), PackKey: pack, Field: "download_rate_kbps"})
				continue
			}
			up, err := qos.IntegerBpsFromKbps(req.UploadRateKbps)
			if err != nil {
				result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "rate_bps_overflow", Message: err.Error(), PackKey: pack, Field: "upload_rate_kbps"})
				continue
			}
			appendAttr(RateCompilerAttribute{PackKey: pack, Name: "UBNT-Data-Rate-DL", Value: down, Unit: "integer-bps", Semantic: productconfigs.VendorSemanticDownloadBandwidth})
			appendAttr(RateCompilerAttribute{PackKey: pack, Name: "UBNT-Data-Rate-UL", Value: up, Unit: "integer-bps", Semantic: productconfigs.VendorSemanticUploadBandwidth})
		case productconfigs.VendorPackCambium:
			addKbpsPair(pack, "Cambium-ePMP-Max-Burst-Downlink-Rate", "Cambium-ePMP-Max-Burst-Uplink-Rate")
		case productconfigs.VendorPackHuawei:
			addKbpsPair(pack, "Huawei-Output-Average-Rate", "Huawei-Input-Average-Rate")
		case productconfigs.VendorPackH3C:
			addKbpsPair(pack, "H3C-Output-Average-Rate", "H3C-Input-Average-Rate")
		case productconfigs.VendorPackTPLink:
			addKbpsPair(pack, "TPLink-Xmit-limit", "TPLink-Recv-limit")
		case productconfigs.VendorPackAirespace:
			addKbpsPair(pack, "Data-Bandwidth-Average-Contract", "Data-Bandwidth-Average-Contract-Upstream")
		case productconfigs.VendorPackHP:
			addKbpsPair(pack, "Bandwidth-Max-Egress", "Bandwidth-Max-Ingress")
		case productconfigs.VendorPackNomadix:
			addKbpsPair(pack, "Nomadix-Bw-Down", "Nomadix-Bw-Up")
		case productconfigs.VendorPackChilliSpot:
			addKbpsPair(pack, "ChilliSpot-Bandwidth-Max-Down", "ChilliSpot-Bandwidth-Max-Up")
		case productconfigs.VendorPackDLink:
			addKbpsPair(pack, "Egress-Bandwidth-Assignment", "Ingress-Bandwidth-Assignment")
		case productconfigs.VendorPackZTE:
			addKbpsPair(pack, "Rate-Ctrl-SCR-Down", "Rate-Ctrl-SCR-Up")
		default:
			if pack == productconfigs.VendorPackStandard {
				continue
			}
			severity := "warning"
			if explicitPacks {
				severity = "error"
			}
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: severity, Code: "unsupported_pack", Message: fmt.Sprintf("pack %q has no rate compiler", pack), PackKey: pack, Field: "pack_keys"})
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Severity == "error" {
			result.Status = "blocked"
			break
		}
	}
	result.AttributeCount = len(result.Attributes)
	return result
}

func DecompileVendorRates(req RateDecompilerRequest) RateDecompilerResult {
	pack := productconfigs.NormalizeVendorCompatibilityPackKey(req.PackKey)
	result := RateDecompilerResult{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Status:          "ready",
		PackKey:         pack,
		CompilerVersion: RateCompilerVersion,
	}
	if pack == "" {
		result.Status = "blocked"
		result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_pack", Message: "pack_key is required", Field: "pack_key"})
		return result
	}
	result.AttributeCount = len(req.Attributes)
	values := map[string]string{}
	for _, attr := range req.Attributes {
		name := strings.ToLower(strings.TrimSpace(attr.Name))
		if name == "" {
			continue
		}
		values[name] = strings.TrimSpace(attr.Value)
	}
	setKbpsPair := func(downName, upName string) {
		down, err := parseRateCompilerKbpsValue(values[strings.ToLower(downName)])
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_download_rate", Message: err.Error(), PackKey: pack, Field: downName})
			return
		}
		up, err := parseRateCompilerKbpsValue(values[strings.ToLower(upName)])
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_upload_rate", Message: err.Error(), PackKey: pack, Field: upName})
			return
		}
		result.Intent.DownloadRateKbps = down
		result.Intent.UploadRateKbps = up
	}
	switch pack {
	case productconfigs.VendorPackMikroTik:
		intent, err := DecompileMikroTikRateLimit(values["mikrotik-rate-limit"])
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_mikrotik_rate_limit", Message: err.Error(), PackKey: pack, Field: "Mikrotik-Rate-Limit"})
		}
		result.Intent = intent
	case productconfigs.VendorPackWISPr:
		setKbpsPair("WISPr-Bandwidth-Max-Down", "WISPr-Bandwidth-Max-Up")
	case productconfigs.VendorPackUBNT:
		down, err := parseRateCompilerBpsValue(values["ubnt-data-rate-dl"])
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_download_rate", Message: err.Error(), PackKey: pack, Field: "UBNT-Data-Rate-DL"})
			break
		}
		up, err := parseRateCompilerBpsValue(values["ubnt-data-rate-ul"])
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "invalid_upload_rate", Message: err.Error(), PackKey: pack, Field: "UBNT-Data-Rate-UL"})
			break
		}
		result.Intent.DownloadRateKbps = down
		result.Intent.UploadRateKbps = up
	case productconfigs.VendorPackCambium:
		setKbpsPair("Cambium-ePMP-Max-Burst-Downlink-Rate", "Cambium-ePMP-Max-Burst-Uplink-Rate")
	case productconfigs.VendorPackHuawei:
		setKbpsPair("Huawei-Output-Average-Rate", "Huawei-Input-Average-Rate")
	case productconfigs.VendorPackH3C:
		setKbpsPair("H3C-Output-Average-Rate", "H3C-Input-Average-Rate")
	case productconfigs.VendorPackTPLink:
		setKbpsPair("TPLink-Xmit-limit", "TPLink-Recv-limit")
	case productconfigs.VendorPackAirespace:
		setKbpsPair("Data-Bandwidth-Average-Contract", "Data-Bandwidth-Average-Contract-Upstream")
	case productconfigs.VendorPackHP:
		setKbpsPair("Bandwidth-Max-Egress", "Bandwidth-Max-Ingress")
	case productconfigs.VendorPackNomadix:
		setKbpsPair("Nomadix-Bw-Down", "Nomadix-Bw-Up")
	case productconfigs.VendorPackChilliSpot:
		setKbpsPair("ChilliSpot-Bandwidth-Max-Down", "ChilliSpot-Bandwidth-Max-Up")
	case productconfigs.VendorPackDLink:
		setKbpsPair("Egress-Bandwidth-Assignment", "Ingress-Bandwidth-Assignment")
	case productconfigs.VendorPackZTE:
		setKbpsPair("Rate-Ctrl-SCR-Down", "Rate-Ctrl-SCR-Up")
	default:
		result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "unsupported_pack", Message: fmt.Sprintf("pack %q has no rate decompiler", pack), PackKey: pack, Field: "pack_key"})
	}
	if len(result.Diagnostics) > 0 {
		result.Status = "blocked"
		return result
	}
	if err := qos.ValidatePair(qos.RatePairKbps{DownloadKbps: result.Intent.DownloadRateKbps, UploadKbps: result.Intent.UploadRateKbps}); err != nil {
		result.Status = "blocked"
		result.Diagnostics = append(result.Diagnostics, RateCompilerDiagnostic{Severity: "error", Code: "missing_rate_pair", Message: err.Error(), PackKey: pack})
		return result
	}
	result.Intent.PackKeys = []string{pack}
	return result
}

func CompileMikroTikRateLimit(req RateCompilerRequest) (string, error) {
	base, err := qos.PairKSuffix(req.DownloadRateKbps, req.UploadRateKbps)
	if err != nil {
		return "", err
	}
	extended := req.DownloadBurstRateKbps > 0 || req.UploadBurstRateKbps > 0 ||
		req.DownloadBurstThresholdKbps > 0 || req.UploadBurstThresholdKbps > 0 ||
		req.DownloadBurstTimeSeconds > 0 || req.UploadBurstTimeSeconds > 0 ||
		req.Priority > 0 || req.DownloadMinRateKbps > 0 || req.UploadMinRateKbps > 0
	if !extended {
		return base, nil
	}
	if req.DownloadBurstRateKbps <= 0 || req.UploadBurstRateKbps <= 0 ||
		req.DownloadBurstThresholdKbps <= 0 || req.UploadBurstThresholdKbps <= 0 ||
		req.DownloadBurstTimeSeconds <= 0 || req.UploadBurstTimeSeconds <= 0 ||
		req.Priority <= 0 || req.DownloadMinRateKbps <= 0 || req.UploadMinRateKbps <= 0 {
		return "", fmt.Errorf("extended MikroTik rate grammar requires burst rates, burst thresholds, burst times, priority, and min rates")
	}
	burst, err := qos.PairKSuffix(req.DownloadBurstRateKbps, req.UploadBurstRateKbps)
	if err != nil {
		return "", err
	}
	threshold, err := qos.PairKSuffix(req.DownloadBurstThresholdKbps, req.UploadBurstThresholdKbps)
	if err != nil {
		return "", err
	}
	burstTime, err := qos.PairSeconds(req.DownloadBurstTimeSeconds, req.UploadBurstTimeSeconds)
	if err != nil {
		return "", err
	}
	minRate, err := qos.PairKSuffix(req.DownloadMinRateKbps, req.UploadMinRateKbps)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{base, burst, threshold, burstTime, strconv.Itoa(req.Priority), minRate}, " "), nil
}

func DecompileMikroTikRateLimit(value string) (RateCompilerRequest, error) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) != 1 && len(fields) != 6 {
		return RateCompilerRequest{}, fmt.Errorf("MikroTik rate grammar requires one field or six extended fields")
	}
	down, up, err := parseRateCompilerKPair(fields[0])
	if err != nil {
		return RateCompilerRequest{}, err
	}
	intent := RateCompilerRequest{DownloadRateKbps: down, UploadRateKbps: up}
	if len(fields) == 1 {
		return intent, nil
	}
	if intent.DownloadBurstRateKbps, intent.UploadBurstRateKbps, err = parseRateCompilerKPair(fields[1]); err != nil {
		return RateCompilerRequest{}, err
	}
	if intent.DownloadBurstThresholdKbps, intent.UploadBurstThresholdKbps, err = parseRateCompilerKPair(fields[2]); err != nil {
		return RateCompilerRequest{}, err
	}
	if intent.DownloadBurstTimeSeconds, intent.UploadBurstTimeSeconds, err = parseRateCompilerSecondPair(fields[3]); err != nil {
		return RateCompilerRequest{}, err
	}
	priority, err := strconv.Atoi(fields[4])
	if err != nil || priority <= 0 || priority > 8 {
		return RateCompilerRequest{}, fmt.Errorf("MikroTik priority must be between 1 and 8")
	}
	intent.Priority = priority
	if intent.DownloadMinRateKbps, intent.UploadMinRateKbps, err = parseRateCompilerKPair(fields[5]); err != nil {
		return RateCompilerRequest{}, err
	}
	return intent, nil
}

func FormatMikroTikRateLimit(downloadKbps, uploadKbps int) string {
	value, err := CompileMikroTikRateLimit(RateCompilerRequest{DownloadRateKbps: downloadKbps, UploadRateKbps: uploadKbps})
	if err != nil {
		return ""
	}
	return value
}

func FormatRateKbps(value int) string {
	out, err := qos.IntegerKbps(value)
	if err != nil {
		return ""
	}
	return out
}

func FormatRateBpsFromKbps(value int) string {
	out, err := qos.IntegerBpsFromKbps(value)
	if err != nil {
		return ""
	}
	return out
}

func parseRateCompilerKbpsValue(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("rate value is required")
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("rate value must be an unsigned 32-bit integer")
	}
	if parsed == 0 {
		return 0, fmt.Errorf("rate value must be greater than zero")
	}
	return int(parsed), nil
}

func parseRateCompilerBpsValue(value string) (int, error) {
	parsed, err := parseRateCompilerKbpsValue(value)
	if err != nil {
		return 0, err
	}
	if parsed%1000 != 0 {
		return 0, fmt.Errorf("bps value must be exactly divisible into integer kbps")
	}
	return parsed / 1000, nil
}

func parseRateCompilerKPair(value string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("rate pair must use download/upload grammar")
	}
	down, err := parseRateCompilerKSuffix(parts[0])
	if err != nil {
		return 0, 0, err
	}
	up, err := parseRateCompilerKSuffix(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return down, up, nil
}

func parseRateCompilerKSuffix(value string) (int, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if !strings.HasSuffix(value, "k") {
		return 0, fmt.Errorf("rate value must use k suffix")
	}
	return parseRateCompilerKbpsValue(strings.TrimSuffix(value, "k"))
}

func parseRateCompilerSecondPair(value string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("time pair must use download/upload grammar")
	}
	down, err := parseRateCompilerSecondSuffix(parts[0])
	if err != nil {
		return 0, 0, err
	}
	up, err := parseRateCompilerSecondSuffix(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return down, up, nil
}

func parseRateCompilerSecondSuffix(value string) (int, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if !strings.HasSuffix(value, "s") {
		return 0, fmt.Errorf("time value must use s suffix")
	}
	parsed, err := strconv.ParseUint(strings.TrimSuffix(value, "s"), 10, 31)
	if err != nil {
		return 0, fmt.Errorf("time value must be a non-negative integer")
	}
	if parsed == 0 {
		return 0, fmt.Errorf("time value must be greater than zero")
	}
	return int(parsed), nil
}
