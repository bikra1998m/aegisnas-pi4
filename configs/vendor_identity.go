package configs

import (
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	AegisNASVendorName                      = "AegisNAS"
	AegisNASPlaceholderVendorID             = 55555
	AegisNASVendorIDEnv                     = "AEGISNAS_VENDOR_ID"
	AegisNASVendorDictionaryFilename        = "dictionary.aegisnas"
	AegisNASLegacyVendorDictionaryFilename  = "aegisnas-vendor.dictionery"
	AegisNASFreeRADIUSInstallDir            = "/etc/freeradius/3.0"
	IANAPrivateEnterpriseNumbersURL         = "https://www.iana.org/assignments/enterprise-numbers/"
	IANAPrivateEnterpriseNumberApplyURL     = "https://www.iana.org/assignments/enterprise-numbers/assignment/apply/"
	IANAPrivateEnterpriseNumberRegistryName = "Private Enterprise Numbers"
)

type VendorIdentity struct {
	Name                     string   `json:"name"`
	ID                       int      `json:"id"`
	IDSource                 string   `json:"id_source"`
	Placeholder              bool     `json:"placeholder"`
	DictionaryFilename       string   `json:"dictionary_filename"`
	LegacyDictionaryFilename string   `json:"legacy_dictionary_filename,omitempty"`
	InstallPath              string   `json:"install_path"`
	IncludeLine              string   `json:"include_line"`
	RegistryName             string   `json:"registry_name"`
	RegistryURL              string   `json:"registry_url"`
	ApplyURL                 string   `json:"apply_url"`
	Warnings                 []string `json:"warnings,omitempty"`
}

func AegisNASVendorIdentity() VendorIdentity {
	id, source := AegisNASVendorID()
	identity := VendorIdentity{
		Name:                     AegisNASVendorName,
		ID:                       id,
		IDSource:                 source,
		Placeholder:              id == AegisNASPlaceholderVendorID,
		DictionaryFilename:       AegisNASVendorDictionaryFilename,
		LegacyDictionaryFilename: AegisNASLegacyVendorDictionaryFilename,
		InstallPath:              AegisNASVendorDictionaryInstallPath(AegisNASFreeRADIUSInstallDir),
		IncludeLine:              "$INCLUDE " + AegisNASVendorDictionaryFilename,
		RegistryName:             IANAPrivateEnterpriseNumberRegistryName,
		RegistryURL:              IANAPrivateEnterpriseNumbersURL,
		ApplyURL:                 IANAPrivateEnterpriseNumberApplyURL,
	}
	if identity.Placeholder {
		identity.Warnings = append(identity.Warnings, "AegisNAS is using the lab placeholder vendor ID; request an IANA Private Enterprise Number and set AEGISNAS_VENDOR_ID before production VSA use.")
	}
	return identity
}

func AegisNASVendorID() (int, string) {
	raw := strings.TrimSpace(os.Getenv(AegisNASVendorIDEnv))
	if raw == "" {
		return AegisNASPlaceholderVendorID, "placeholder"
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed < 1 || parsed == 4294967295 || parsed > 4294967294 {
		return AegisNASPlaceholderVendorID, "invalid_env"
	}
	return int(parsed), "env:" + AegisNASVendorIDEnv
}

func AegisNASVendorDictionaryInstallPath(raddb string) string {
	raddb = strings.TrimSpace(raddb)
	if raddb == "" {
		raddb = AegisNASFreeRADIUSInstallDir
	}
	return path.Join(raddb, AegisNASVendorDictionaryFilename)
}
