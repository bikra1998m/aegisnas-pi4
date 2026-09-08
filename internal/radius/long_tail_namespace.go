package radius

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const LongTailNamespaceMaxValueLength = 240

func isLongTailNamespacePackKey(packKey string) bool {
	return productconfigs.NormalizeVendorCompatibilityPackKey(packKey) == productconfigs.VendorPackLongTail
}

func applyLongTailNamespaceAttributeString(result *BrokerAuthResult, mapping inboundVendorMapping, value string) bool {
	if result == nil || !safeInboundVendorString(value, LongTailNamespaceMaxValueLength) {
		return false
	}
	if longTailNamespaceSensitiveAttribute(mapping.Attribute) {
		appendUniqueVendorAVPair(result, mapping.Attribute+"=<redacted:"+shortLongTailDigest(value)+">")
		setStringIfEmpty(&result.VendorPolicyTag, mapping.Attribute+"=<redacted>")
		return true
	}

	applied := false
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticDynamicACL) {
		setStringIfEmpty(&result.VendorInboundACL, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticACL) {
		applyInboundVendorACL(result, mapping.Attribute, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticRole) {
		setStringIfEmpty(&result.VendorRole, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticVLAN) {
		setStringIfEmpty(&result.VendorVLANPool, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticBandwidthProfile) {
		setStringIfEmpty(&result.VendorBandwidthProfile, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticPortalProfile) {
		setStringIfEmpty(&result.VendorPortalProfile, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticGuestLifecycle) {
		setStringIfEmpty(&result.VendorSessionAction, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticDeviceGroup) {
		setStringIfEmpty(&result.VendorDeviceGroup, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticDevicePosture) {
		setStringIfEmpty(&result.VendorDevicePosture, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticTenant) {
		setStringIfEmpty(&result.VendorTenant, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticAccountingIdentity) || longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticAccountingCounters) {
		setStringIfEmpty(&result.VendorAccountingIdentity, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticRoute) {
		setStringIfEmpty(&result.VendorRoutePolicy, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticVRF) {
		setStringIfEmpty(&result.VendorVRF, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticAddressPool) {
		applyInboundVendorAddressPoolString(result, mapping.Attribute, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticIPv4Address) {
		applyInboundVendorIPv4String(result, mapping.Attribute, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticIPv6Address) {
		setStringIfEmpty(&result.VendorIPv6Pool, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticDelegatedIPv6Prefix) {
		setStringIfEmpty(&result.VendorDelegatedIPv6Pool, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticTranslationPolicy) {
		setStringIfEmpty(&result.VendorTranslationPolicy, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticTranslationPublicIPv4) {
		setStringIfEmpty(&result.VendorTranslationPublicIPv4Address, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticTranslationPortBlock) {
		applyInboundVendorTranslationPortString(result, mapping.Attribute, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticNAT64Prefix) {
		setStringIfEmpty(&result.VendorTranslationNAT64Prefix, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticCoAReauth) || longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticCoADisconnect) || longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticSessionAction) {
		setStringIfEmpty(&result.VendorSessionAction, value)
		applied = true
	}
	if longTailMappingHasSemantic(mapping, productconfigs.VendorSemanticCertificateOnboarding) {
		setStringIfEmpty(&result.VendorDevicePosture, mapping.Attribute+"=certificate-context")
		applied = true
	}
	if !applied {
		setStringIfEmpty(&result.VendorPolicyTag, mapping.Attribute+"="+value)
	}
	appendUniqueVendorAVPair(result, mapping.Attribute+"="+value)
	return true
}

func longTailMappingHasSemantic(mapping inboundVendorMapping, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, semantic := range strings.Split(mapping.Semantic, ",") {
		if strings.ToLower(strings.TrimSpace(semantic)) == target {
			return true
		}
	}
	return false
}

func longTailNamespaceSensitiveAttribute(attribute string) bool {
	name := strings.ToLower(strings.TrimSpace(attribute))
	for _, token := range []string{"password", "passwd", "secret", "shared-secret", "key", "psk", "dpsk", "mpkey", "token", "nonce", "challenge", "response", "signature", "cookie", "otp", "pin", "triplet", "quint", "private", "credential"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func shortLongTailDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}
