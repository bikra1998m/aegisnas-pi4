package qos

import (
	"fmt"
	"math"
	"strconv"
)

const MaxRADIUSInteger = math.MaxUint32

type RatePairKbps struct {
	DownloadKbps int `json:"download_kbps"`
	UploadKbps   int `json:"upload_kbps"`
}

func ValidateKbps(value int, field string) error {
	if value <= 0 {
		return fmt.Errorf("%s must be greater than zero", field)
	}
	if uint64(value) > MaxRADIUSInteger {
		return fmt.Errorf("%s exceeds 32-bit RADIUS integer range", field)
	}
	return nil
}

func ValidatePair(pair RatePairKbps) error {
	if err := ValidateKbps(pair.DownloadKbps, "download_kbps"); err != nil {
		return err
	}
	if err := ValidateKbps(pair.UploadKbps, "upload_kbps"); err != nil {
		return err
	}
	return nil
}

func IntegerKbps(value int) (string, error) {
	if err := ValidateKbps(value, "rate_kbps"); err != nil {
		return "", err
	}
	return strconv.Itoa(value), nil
}

func IntegerBpsFromKbps(value int) (string, error) {
	if err := ValidateKbps(value, "rate_kbps"); err != nil {
		return "", err
	}
	bps := uint64(value) * 1000
	if bps > MaxRADIUSInteger {
		return "", fmt.Errorf("rate_bps exceeds 32-bit RADIUS integer range")
	}
	return strconv.FormatUint(bps, 10), nil
}

func PairKSuffix(downloadKbps, uploadKbps int) (string, error) {
	if err := ValidatePair(RatePairKbps{DownloadKbps: downloadKbps, UploadKbps: uploadKbps}); err != nil {
		return "", err
	}
	return fmt.Sprintf("%dk/%dk", downloadKbps, uploadKbps), nil
}

func PairSeconds(downloadSeconds, uploadSeconds int) (string, error) {
	if downloadSeconds < 0 || uploadSeconds < 0 {
		return "", fmt.Errorf("burst time values must be non-negative")
	}
	return fmt.Sprintf("%ds/%ds", downloadSeconds, uploadSeconds), nil
}

func TCRateKbit(value int, fallback int) string {
	if value <= 0 {
		value = fallback
	}
	return fmt.Sprintf("%dkbit", value)
}

func TCBurstK(value int, fallback int) string {
	if value <= 0 {
		value = fallback
	}
	return fmt.Sprintf("%dk", value)
}
