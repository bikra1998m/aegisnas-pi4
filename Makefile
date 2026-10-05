.PHONY: build test frontend clean all admin gateway radius portal session policy admin-api ai-lite test-acceptance test-vendor-certification test-vendor-identity test-attribute-registry test-dictionary-release-profiles test-compatibility-evidence test-vendor-mapping-certification test-cisco-family-pack test-aruba-family-pack test-juniper-extreme-pack test-ruckus-icx-pack test-fortinet-paloalto-pack test-cloud-controller-pack test-access-vendor-pack test-broadband-vendor-pack test-nokia-alu-pack test-mikrotik-pack test-switching-vendor-pack test-long-tail-namespace test-external-vendor-intake test-hostapd-vlan-lifecycle test-wireless-roaming-lifecycle test-passpoint-lifecycle test-ppsk-lifecycle test-controller-estate-lifecycle test-rf-planning-lifecycle test-wireless-security-lifecycle test-cwa-portal-lifecycle test-pppoe-access-lifecycle test-broadband-subscriber-state test-broadband-commercial-catalog test-broadband-quota-balance test-broadband-address-leases test-broadband-qos-service-flows test-broadband-l2tp-wholesale test-broadband-dhcp-security test-vsa-codec test-opaque-passthrough test-secret-providers test-postgres-data-plane test-radius-packet-hardening test-radius-proxy-routing test-radius-transport-policy test-radius-proxy-policy test-radius-accounting-spool test-radius-accounting-ingest-spool test-radius-sql-accounting test-radius-accounting-ordering test-radius-accounting-counters test-radius-accounting-ip test-radius-accounting-services test-radius-accounting-charging test-radius-outbound-dac-client test-radius-fallback-policy test-atomic-enforcement-transactions test-subscriber-route-export test-active-directory test-identity-failover test-mfa test-admin-webauthn test-eap-framework test-eap-teap test-eap-machine-user test-eap-fast-pwd test-eap-sim-aka test-certificate-lifecycle test-supplicant-lifecycle test-typed-policy-engine test-policy-set-governance test-policy-simulation-analysis test-subscriber-service-chains test-tacacs test-tenant-isolation test-mab test-dynamic-nas-clients test-radsec-credentials install-radius-dictionary scan-radius-dictionaries

all: build frontend admin gateway radius portal session policy admin-api ai-lite

admin:
	go build -o bin/aegis-admin ./cmd/aegis-admin

gateway:
	go build -o bin/aegis-gateway ./cmd/aegis-gateway

radius:
	go build -o bin/aegis-radius ./cmd/aegis-radius

portal:
	go build -o bin/aegis-portal ./cmd/aegis-portal

session:
	go build -o bin/aegis-session ./cmd/aegis-session

policy:
	go build -o bin/aegis-policy ./cmd/aegis-policy

admin-api:
	go build -o bin/aegis-admin-api ./cmd/aegis-admin-api

ai-lite:
	go build -o bin/aegis-ai-lite ./cmd/aegis-ai-lite

test-acceptance:
	cd test/acceptance && ./run.sh

test-vendor-certification:
	bash -n scripts/vendor-certification-lab.sh
	bash scripts/vendor-certification-lab.sh --self-test
	bash -n scripts/openwifi-controller-smoke-test.sh
	bash scripts/openwifi-controller-smoke-test.sh --self-test
	go test ./internal/radius -run TestVendorPackCertificationMatrix -count=1

test-vendor-identity:
	bash -n scripts/install-aegisnas-freeradius-dictionary.sh
	bash -n scripts/vendor-identity-smoke-test.sh
	go test ./internal/vendoridentity ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'IANA|VendorIdentity|ProductVendorMigration' -count=1
	cd web/admin-ui && npm run build

test-attribute-registry:
	go run ./cmd/aegis-attribute-registry-gen -input docs/freeradius-3.2.8-vsa-audit.csv -output configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv -check -expected-sha256 54453e66c66a19622d94ace7f9b613020bf008d4c6c3aa04a4b2589031c43e75
	go test ./configs ./cmd/aegis-attribute-registry-gen ./internal/radius ./internal/adminapi -run 'AttributeRegistry|GeneratedAttributeRegistry' -count=1

test-dictionary-release-profiles:
	go test ./configs -run 'DictionaryRelease|VendorCompatibility' -count=1
	go test ./internal/config -run 'DictionaryRelease' -count=1
	go test ./internal/adminapi -run '^(TestHandleGetDictionaryReleaseProfiles|TestHandleGetDictionaryReleaseProfilesFiltersAndRejectsUnknown|TestDictionaryReleaseProfileProductionReadinessCheck|TestAuthorizeRequestByRole|TestHandleGetOpenAPI)$$' -count=1

test-compatibility-evidence:
	go test ./configs ./internal/adminapi -run 'CompatibilityEvidence|VendorCompatibility|Authorize|OpenAPI|ProductionReadiness' -count=1

test-vendor-mapping-certification:
	go test ./configs -run 'VendorMappingCertification' -count=1
	go test ./internal/db -run 'VendorMappingCertification' -count=1
	go test ./internal/adminapi -run 'VendorMappingCertificationAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-cisco-family-pack:
	go test ./configs -run 'CiscoFamilyPack' -count=1
	go test ./internal/radius -run 'CiscoAVPair|RenderReplyAttributesIncludesCiscoFamilyAVPairs|CiscoAVPairInboundNormalization' -count=1
	go test ./internal/db -run '^TestCiscoFamilyPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'CiscoFamilyPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-aruba-family-pack:
	go test ./configs -run 'ArubaFamilyPack|AttributeRegistry|VendorCompatibility' -count=1
	go test ./internal/radius -run 'ArubaFamily|RenderReplyAttributesIncludesArubaFamilyFields' -count=1
	go test ./internal/db -run '^TestArubaFamilyPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'ArubaFamilyPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-juniper-extreme-pack:
	go test ./configs -run 'JuniperExtremePack|AttributeRegistry|VendorCompatibility' -count=1
	go test ./internal/radius -run 'JuniperExtreme|RenderReplyAttributesIncludesJuniperExtremeFamilyFields' -count=1
	go test ./internal/db -run '^TestJuniperExtremePackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'JuniperExtremePackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-ruckus-icx-pack:
	go test ./configs -run 'RuckusICXPack|AttributeRegistry|VendorCompatibility|DictionaryRelease' -count=1
	go test ./internal/radius -run 'RuckusICX|RenderReplyAttributesIncludesRuckusICXFamilyFields|GeneratedAttributeRegistry' -count=1
	go test ./internal/db -run '^TestRuckusICXPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'RuckusICXPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-fortinet-paloalto-pack:
	go test ./configs -run 'FortinetPaloAltoPack|AttributeRegistry|VendorCompatibility|DictionaryRelease' -count=1
	go test ./internal/radius -run 'FortinetPaloAlto|RenderReplyAttributesIncludesFortinetPaloAltoFamilyFields|GeneratedAttributeRegistry|PreviewOutboundDACCompilesFortinetSecurityPackActions' -count=1
	go test ./internal/db -run '^TestFortinetPaloAltoPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'FortinetPaloAltoPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-cloud-controller-pack:
	go test ./configs -run 'CloudControllerPack|AttributeRegistry|VendorCompatibility|DictionaryRelease' -count=1
	go test ./internal/radius -run 'CloudControllerPack|GeneratedAttributeRegistry|RenderReplyAttributes' -count=1
	go test ./internal/db -run '^TestCloudControllerPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'CloudControllerPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-access-vendor-pack:
	go test ./configs -run 'AccessVendorPack|AttributeRegistry|VendorCompatibility|DictionaryRelease' -count=1
	go test ./internal/radius -run 'AccessVendorPack|GeneratedAttributeRegistry|RenderReplyAttributes|ACLCompiler|ExportDynamicACLs' -count=1
	go test ./internal/db -run '^TestAccessVendorPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'AccessVendorPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-broadband-vendor-pack:
	go test ./configs -run 'BroadbandVendorPack|AttributeRegistry|VendorCompatibility|DictionaryRelease|VendorScan' -count=1
	go test ./internal/radius -run 'BroadbandVendorPack|GeneratedAttributeRegistry|RenderReplyAttributes|RateCompiler|TranslationPolicy' -count=1
	go test ./internal/db -run '^TestBroadbandVendorPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'BroadbandVendorPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-nokia-alu-pack:
	go test ./configs -run 'NokiaALUPack|AttributeRegistry|VendorCompatibility|DictionaryRelease|VendorScan' -count=1
	go test ./internal/radius -run 'NokiaALUPack|GeneratedAttributeRegistry|RenderReplyAttributes|ACLCompiler|TranslationPolicy|RoutePolicy|AddressPolicy' -count=1
	go test ./internal/db -run '^TestNokiaALUPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'NokiaALUPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-mikrotik-pack:
	go test ./configs -run 'MikroTikPack|AttributeRegistry|VendorCompatibility|DictionaryRelease|VendorScan' -count=1
	go test ./internal/config -run 'ConfigValidationRadiusVendor' -count=1
	go test ./internal/radius -run 'MikroTikPack|GeneratedAttributeRegistry|RenderReplyAttributes|ACLCompiler|OutboundDACVendorAction|RateCompiler|AddressPolicy' -count=1
	go test ./internal/db -run '^TestMikroTikPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'MikroTikPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-switching-vendor-pack:
	go test ./configs -run 'SwitchingVendorPack|AttributeRegistry|VendorCompatibility|DictionaryRelease|VendorScan' -count=1
	go test ./internal/config -run 'ConfigValidationRadiusVendor' -count=1
	go test ./internal/radius -run 'SwitchingVendorPack|GeneratedAttributeRegistry|RenderReplyAttributes|ACLCompiler|OutboundDACVendorAction|RateCompiler|AddressPolicy|JuniperExtreme|RuckusICX' -count=1
	go test ./internal/db -run '^TestSwitchingVendorPackEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'SwitchingVendorPackAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-long-tail-namespace:
	go test ./configs -run 'LongTailNamespace|AttributeRegistry|VendorCompatibility|DictionaryRelease|VendorScan' -count=1
	go test ./internal/config -run 'ConfigValidationRadiusVendor' -count=1
	go test ./internal/radius -run 'LongTailNamespace|GeneratedAttributeRegistry|RenderReplyAttributes|ACLCompiler|OutboundDACVendorAction|RateCompiler|AddressPolicy' -count=1
	go test ./internal/db -run '^TestLongTailNamespaceEventLifecycle$$' -count=1
	go test ./internal/adminapi -run 'LongTailNamespaceAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-external-vendor-intake:
	go test ./configs -run 'ExternalVendorIntake|VendorDictionary|AttributeRegistry|DictionaryRelease|VendorScan' -count=1
	go test ./internal/db -run '^TestExternalVendorIntakeEventLifecycle$$' -count=1
	go test ./internal/radius -run '^TestExternalVendorIntakeVSASpecs' -count=1
	go test ./internal/adminapi -run 'ExternalVendorIntakeAPIHistoryOpenAPIReadinessSupportBundleAndRBAC' -count=1
	cd web/admin-ui && npm run build

test-hostapd-vlan-lifecycle:
	go test ./internal/wireless -run 'Hostapd|DynamicVLAN' -count=1
	go test ./internal/enforcement -run 'VLANLifecycle|HostapdVLANLifecycle' -count=1
	go test ./internal/adminapi -run 'HostapdVLANLifecycle|^TestVLANLifecycle' -count=1
	cd web/admin-ui && npm run build

test-wireless-roaming-lifecycle:
	go test ./internal/config -run 'ConfigValidationWirelessRoaming' -count=1
	go test ./internal/wireless -run 'RoamingLifecycle|Hostapd' -count=1
	go test ./internal/enforcement -run 'WirelessRoamingLifecycle' -count=1
	go test -timeout=600s ./internal/db -run 'WirelessRoaming|Migrate' -count=1
	go test ./internal/adminapi -run 'WirelessRoamingLifecycle' -count=1
	cd web/admin-ui && npm run build

test-passpoint-lifecycle:
	go test ./internal/config -run 'ConfigValidationPasspoint' -count=1
	go test ./internal/wireless -run 'Passpoint' -count=1
	go test ./internal/enforcement -run 'PasspointLifecycle' -count=1
	go test ./internal/db -run 'PasspointLifecycle' -count=1
	go test ./internal/adminapi -run 'PasspointLifecycle' -count=1
	cd web/admin-ui && npm run build

test-ppsk-lifecycle:
	go test ./internal/config -run 'ConfigValidationPPSK' -count=1
	go test ./internal/wireless -run 'PPSK' -count=1
	go test ./internal/enforcement -run 'PPSKLifecycle' -count=1
	go test ./internal/db -run 'PPSKLifecycle' -count=1
	go test ./internal/adminapi -run 'PPSKLifecycle' -count=1
	cd web/admin-ui && npm run build

test-controller-estate-lifecycle:
	go test ./internal/integrations -run 'ControllerEstate' -count=1
	go test -timeout=600s ./internal/db -run 'ControllerEstate|Migrate' -count=1
	go test ./internal/adminapi -run 'ControllerEstate' -count=1
	cd web/admin-ui && npm run build

test-rf-planning-lifecycle:
	go test ./internal/config -run 'WirelessRFPlanning' -count=1
	go test ./internal/enforcement -run 'RFPlanning' -count=1
	go test -timeout=600s ./internal/db -run 'RFPlanning|Migrate' -count=1
	go test ./internal/adminapi -run 'RFPlanning' -count=1
	cd web/admin-ui && npm run build

test-wireless-security-lifecycle:
	go test ./internal/config -run 'WirelessSecurityLifecycle' -count=1
	go test ./internal/enforcement -run 'WirelessSecurityLifecycle' -count=1
	go test -timeout=600s ./internal/db -run 'WirelessSecurity|Migrate' -count=1
	go test ./internal/adminapi -run 'WirelessSecurityLifecycle' -count=1

test-cwa-portal-lifecycle:
	go test ./internal/config -run 'CWAPortalLifecycle' -count=1
	go test ./internal/enforcement -run 'CWAPortalLifecycle' -count=1
	go test -timeout=600s ./internal/db -run 'CWAPortal|Migrate' -count=1
	go test ./internal/adminapi -run 'CWAPortalLifecycle' -count=1
	go test ./internal/portal/server -run 'CaptivePortalAPI' -count=1
	cd web/admin-ui && npm run build

test-pppoe-access-lifecycle:
	go test ./internal/broadband/pppoe -count=1
	go test ./internal/config -run 'BroadbandPPPoEAccessLifecycle' -count=1
	go test ./internal/enforcement -run 'PPPoEAccessLifecycle' -count=1
	go test -timeout=600s ./internal/db -run 'PPPoEAccess|Migrate' -count=1
	go test ./internal/adminapi -run 'PPPoEAccessLifecycle' -count=1
	cd web/admin-ui && npm run build

test-broadband-subscriber-state:
	go test ./internal/broadband/subscriber -count=1
	go test ./internal/config -run 'BroadbandSubscriberState|BroadbandPPPoEAccessLifecycle' -count=1
	go test ./internal/enforcement -run 'BroadbandSubscriberState' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandSubscriberState|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandSubscriberState' -count=1
	cd web/admin-ui && npm run build

test-broadband-commercial-catalog:
	go test ./internal/config -run 'BroadbandCommercialCatalog|BroadbandSubscriberState' -count=1
	go test ./internal/enforcement -run 'BroadbandCommercialCatalog' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandCommercialCatalog|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandCommercialCatalog' -count=1
	cd web/admin-ui && npm run build

test-broadband-quota-balance:
	go test ./internal/config -run 'BroadbandQuotaBalance|BroadbandCommercialCatalog|BroadbandSubscriberState' -count=1
	go test ./internal/enforcement -run 'BroadbandQuotaBalance|BroadbandCommercialCatalog' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandQuotaBalance|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandQuotaBalance|BroadbandCommercialCatalog' -count=1
	cd web/admin-ui && npm run build

test-broadband-address-leases:
	go test ./internal/config -run 'BroadbandAddressLease|BroadbandSubscriberState|BroadbandPPPoEAccessLifecycle' -count=1
	go test ./internal/enforcement -run 'BroadbandAddressLease' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandAddressLease|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandAddressLease' -count=1
	cd web/admin-ui && npm run build

test-broadband-qos-service-flows:
	go test ./internal/config -run 'BroadbandQoSServiceFlow|BroadbandCommercialCatalog|BroadbandSubscriberState' -count=1
	go test ./internal/enforcement -run 'BroadbandQoSServiceFlow|BroadbandCommercialCatalog' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandQoSServiceFlow|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandQoSServiceFlow|RuntimeQoS|RateCompiler|ProductionReadiness|SupportBundle|OpenAPI|Authorize' -count=1
	cd web/admin-ui && npm run build

test-broadband-l2tp-wholesale:
	go test ./internal/config -run 'BroadbandL2TPWholesale|BroadbandSubscriberState|BroadbandPPPoEAccessLifecycle' -count=1
	go test ./internal/enforcement -run 'BroadbandL2TPWholesale' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandL2TPWholesale|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandL2TPWholesale|ProductionReadiness|SupportBundle|OpenAPI|Authorize' -count=1
	cd web/admin-ui && npm run build

test-broadband-dhcp-security:
	go test ./internal/config -run 'BroadbandDHCPSecurity|BroadbandAddressLease|BroadbandSubscriberState' -count=1
	go test ./internal/enforcement -run 'BroadbandDHCPSecurity' -count=1
	go test -timeout=600s ./internal/db -run 'BroadbandDHCPSecurity|Migrate' -count=1
	go test ./internal/adminapi -run 'BroadbandDHCPSecurity|ProductionReadiness|SupportBundle|OpenAPI|Authorize' -count=1
	cd web/admin-ui && npm run build

test-vsa-codec:
	go test ./configs ./internal/radius ./internal/adminapi -run 'VSACodec|VendorAttributeFormat|AttributeRegistry|GeneratedAttributeRegistry|Authorize|OpenAPI|ProductionReadiness' -count=1

test-opaque-passthrough:
	go test ./internal/config ./internal/radius ./internal/adminapi -run 'OpaquePassThrough|ConfigValidationRadiusVendor|Authorize|OpenAPI|ProductionReadiness' -count=1

test-secret-providers:
	go test ./internal/secrets ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'Secret|ConfigValidation|RadiusClient|Generator|Migrate|OpenAPI|Authorize|ProductionReadiness' -count=1

test-postgres-data-plane:
	go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'Database|PostgreSQL|Migrate|Generator|OpenAPI|Authorize|ProductionReadiness|SupportBundle|Secret' -count=1

test-radius-packet-hardening:
	go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi ./internal/sessions -run 'PacketHardening|RadiusHardening|Generator|OpenAPI|Authorize|ProductionReadiness|Migrate|DynamicAuth' -count=1

test-radius-proxy-routing:
	go test ./internal/config ./internal/radius ./internal/adminapi -run 'ProxyRoute|ProxyRouting|Generator|OpenAPI|Authorize|ProductionReadiness' -count=1

test-radius-transport-policy:
	go test ./internal/config ./internal/radius ./internal/adminapi -run 'TransportPolicy|TransportDowngrade|ProxyRoute|Generator|OpenAPI|Authorize|ProductionReadiness' -count=1

test-radius-proxy-policy:
	go test ./internal/config ./internal/radius ./internal/adminapi -run 'ProxyPolicy|ProxyRoute|ProxyRouting|Generator|OpenAPI|Authorize|ProductionReadiness' -count=1

test-radius-accounting-spool:
	go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'AccountingSpool|Migrate|OpenAPI|Authorize|ProductionReadiness' -count=1

test-radius-accounting-ingest-spool:
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'AccountingIngestSpool|AccountingEvent|FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'AccountingIngestSpool|ProcessAccountingMirrorsRadAcct|AccountingServices|AccountingIP|AccountingCounters|AccountingOrdering' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'AccountingIngestSpool|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting|SupportBundle' -count=1

test-radius-sql-accounting:
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'SQLAccounting|ProcessAccountingMirrorsRadAcct|Generator' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'HandleGetSQLAccounting|HandleReconcileSQLAccounting|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting' -count=1

test-radius-accounting-ordering:
	go test -p=1 -timeout=600s ./internal/config -run 'AccountingOrdering|ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'AccountingEvent|FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'AccountingOrdering|ProcessAccountingMirrorsRadAcct' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'AccountingOrdering|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting' -count=1

test-radius-accounting-counters:
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'AccountingCounter|FreeRADIUSAccountingGigaword|AccountingEvent|FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'AccountingCounters|AccountingOrdering|ProcessAccountingMirrorsRadAcct' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'AccountingCounters|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting' -count=1

test-radius-accounting-ip:
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'AccountingIP|FreeRADIUSAccountingIPv6|AccountingEvent|FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'AccountingIP|AccountingCounters|AccountingOrdering|ProcessAccountingMirrorsRadAcct' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'AccountingIP|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting' -count=1

test-radius-accounting-services:
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'AccountingService|FreeRADIUSAccountingService|AccountingEvent|FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'AccountingServices|AccountingIP|AccountingCounters|AccountingOrdering|ProcessAccountingMirrorsRadAcct' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'AccountingServices|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting|SupportBundle' -count=1

test-radius-accounting-charging:
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationRadiusSQLAccounting' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'AccountingCharging|AccountingEvent|FreeRADIUSAccounting|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'AccountingCharging|AccountingServices|AccountingCounters|AccountingOrdering|ProcessAccountingMirrorsRadAcct' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'AccountingCharging|OpenAPIAndSupportBundleIncludeSQLAccounting|AuthorizeSQLAccounting|ProductionReadinessIncludesSQLAccounting|SupportBundle' -count=1

test-radius-outbound-dac-client:
	go test -p=1 -timeout=600s ./internal/config -run 'DynamicAuth|ConfigLoad' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'OutboundDAC|TestMigrate' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'OutboundDAC' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'OutboundDACClient|TestHandleGetOpenAPI|TestAuthorizeRequestByRole|TestHandleDownloadSupportBundle|TestHandleGetSupportBundleSummary|TestHandleGetProductionReadinessReportsVendorBlockers' -count=1
	cd web/admin-ui && npm run build

test-radius-fallback-policy:
	go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'FallbackPolicy|RadiusFallback|Migrate|OpenAPI|Authorize|ProductionReadiness|SupportBundle' -count=1

test-atomic-enforcement-transactions:
	go test -p=1 -timeout=600s ./internal/config -run 'EnforcementTransaction' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'EnforcementTransaction' -count=1
	go test -p=1 -timeout=600s ./internal/enforcement -run 'AtomicEnforcement' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'EnforcementTransactions' -count=1
	cd web/admin-ui && npm run build

test-subscriber-route-export:
	go test -p=1 -timeout=600s ./internal/config -run 'ValidateRadiusRoutePolicy|ConfigLoad' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'SubscriberRouteExport|RoutePolicy' -count=1
	go test -p=1 -timeout=600s ./internal/enforcement -run 'SubscriberRouteExport|AtomicEnforcement' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'SubscriberRouteExport' -count=1
	cd web/admin-ui && npm run build

test-active-directory:
	go test -p=1 -timeout=600s ./internal/activedirectory ./internal/config ./internal/db ./internal/identity ./internal/portal/auth ./internal/radius ./internal/adminapi -run 'ActiveDirectory|PolicyAndAuthenticate|KerberosCommand|BuildReportReflectsBlocked|ConfigValidationActiveDirectory|BuildSourcePlanIncludesActiveDirectory|AuthenticateFallbackUsesActiveDirectory|Migrate|MSCHAP|OpenAPI|Authorize|ProductionReadinessIncludesActiveDirectory|SupportBundle' -count=1

test-identity-failover:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/identity ./internal/portal/auth ./internal/adminapi -run 'IdentityFailover|IdentitySourceEvents|IdentitySourceCredential|ConfigValidationIdentity|BuildSourcePlan|BuildFailoverReport|HandleGetIdentityFailover|ProductionReadinessIncludesIdentityFailover|AuthenticateFallbackUsesIdentityFailover|ValidateUserDetailed|OpenAPI|Authorize|SupportBundleIncludesIdentityFailoverCapture' -count=1

test-mfa:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/mfa ./internal/radius ./internal/portal/auth ./internal/adminapi -run 'MFA|TOTP|Challenge|ConfigValidationMFA|AccessChallenge|AuthenticateUserRequiresAndVerifiesMFA|OpenAPI|Authorize|ProductionReadinessIncludesMFACheck|SupportBundle' -count=1

test-admin-webauthn:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/webauthn ./internal/adminapi -run 'AdminWebAuthn|WebAuthn|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesAdminWebAuthn|SupportBundle' -count=1

test-eap-framework:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/eap ./internal/radius ./internal/adminapi -run 'EAPFramework|EAPMethod|ConfigValidationEAP|GenerateEAPConfig|OpenAPI|Authorize|ProductionReadinessIncludesEAP|SupportBundle|MigrationCreatesExpectedTables' -count=1

test-eap-teap:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/eap ./internal/radius ./internal/adminapi -run 'TEAP|ConfigValidationEAP|GenerateEAPConfigIncludesTEAP|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesTEAP|SupportBundle' -count=1

test-eap-machine-user:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/eap ./internal/radius ./internal/adminapi -run 'MachineUser|ConfigValidationEAP|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesMachineUser|SupportBundle' -count=1

test-eap-fast-pwd:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/eap ./internal/radius ./internal/adminapi -run 'FASTPWD|FAST|PWD|ConfigValidationEAP|GenerateEAPConfigIncludesFAST|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesFAST|SupportBundle' -count=1

test-eap-sim-aka:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/eap ./internal/radius ./internal/adminapi -run 'SIMAKA|SIM|AKA|ConfigValidationEAP|GenerateEAPConfigIncludesSIM|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesSIM|SupportBundle' -count=1

test-certificate-lifecycle:
	go test -p=1 -timeout=600s ./internal/certlifecycle ./internal/config ./internal/db ./internal/adminapi -run 'CertificateLifecycle|ConfigValidationCertificateLifecycle|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesCertificateLifecycle|SupportBundle' -count=1

test-supplicant-lifecycle:
	go test -p=1 -timeout=600s ./internal/supplicantprofile ./internal/config ./internal/db ./internal/adminapi -run 'SupplicantLifecycle|ConfigValidationSupplicantLifecycle|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesSupplicantLifecycle|SupportBundle' -count=1

test-typed-policy-engine:
	go test -p=1 -timeout=600s ./internal/policy ./internal/config ./internal/db ./internal/adminapi ./cmd/aegis-policy -run 'TypedPolicy|PolicyEngine|ConfigValidationTypedPolicyEngine|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadiness|SupportBundle' -count=1

test-policy-set-governance:
	go test -p=1 -timeout=600s ./internal/policy -run 'PolicySet|TypedPolicy|Engine' -count=1
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationTypedPolicyEngine' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'PolicySet|PolicyEngine|MigrationCreatesExpectedTables' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'PolicySet|PolicyEngine|OpenAPI|Authorize' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run '^TestHandleGetProductionReadinessReportsVendorBlockers$$|^TestHandleDownloadSupportBundle$$|^TestHandleGetSupportBundleSummary$$' -count=1

test-policy-simulation-analysis:
	go test -p=1 -timeout=600s ./internal/policy -run 'SimulationAnalysis|PolicySet|TypedPolicy|Engine' -count=1
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationTypedPolicyEngine' -count=1
	go test -p=1 -timeout=900s ./internal/db -run 'PolicySimulation|PolicySet|PolicyEngine|MigrationCreatesExpectedTables' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'PolicySet|PolicyEngine|OpenAPI|Authorize' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run '^TestHandleGetProductionReadinessReportsVendorBlockers$$|^TestHandleDownloadSupportBundle$$|^TestHandleGetSupportBundleSummary$$' -count=1

test-subscriber-service-chains:
	go test -p=1 -timeout=600s ./internal/policy -run 'ServiceChain|SimulationAnalysis' -count=1
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationTypedPolicyEngine' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'SubscriberService' -count=1
	go test -p=1 -timeout=600s ./internal/radius -run 'RenderReplyAttributesForVendorPacks' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'TestSubscriberServiceChain' -count=1
	cd web/admin-ui && npm run build

test-tacacs:
	go test -p=1 -timeout=600s ./internal/tacacs -count=1
	go test -p=1 -timeout=600s ./internal/config -run 'ConfigValidationTACACS' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'TACACS' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'TestTACACS|TestOpenAPIIncludesTACACS' -count=1
	cd web/admin-ui && npm run build

test-tenant-isolation:
	go test -p=1 -timeout=600s ./internal/config -run 'TenantIsolation' -count=1
	go test -p=1 -timeout=600s ./internal/db -run 'TenantIsolation|PolicySetTenant|Migrate' -count=1
	go test -p=1 -timeout=600s ./internal/policy -run 'Tenant' -count=1
	go test -p=1 -timeout=600s ./internal/adminapi -run 'TenantIsolation|PolicySetTenant|OpenAPIAndSupportBundleIncludeTenantIsolation|AuthorizeTenantIsolation|ProductionReadinessIncludesTenantIsolation' -count=1
	cd web/admin-ui && npm run build

test-mab:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/mab ./internal/radius ./internal/adminapi -run 'MAB|Evaluate|MACVariants|ConfigValidationMAB|GeneratorRendersMAB|OpenAPI|AuthorizeMAB|ProductionReadinessIncludesMAB|SupportBundleIncludeMAB|Migrate' -count=1

test-dynamic-nas-clients:
	go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'DynamicNAS|RadiusDynamicClients|NASClient|Migrate|OpenAPI|Authorize|ProductionReadiness|RadiusClient' -count=1

test-radsec-credentials:
	go test ./internal/config ./internal/radius ./internal/adminapi -run 'RadSec|Generator|OpenAPI|Authorize|ProductionReadiness' -count=1

build:
	go build ./...

test:
	go test -v ./...

frontend:
	cd web/admin-ui && npm install && npm run build

clean:
	rm -rf web/admin-ui/dist bin/
	go clean -cache

lint:
	golangci-lint run

migrate: admin
	./bin/aegis-admin migrate --config configs/config.yaml

seed: admin
	./bin/aegis-admin seed --config configs/config.yaml

validate-config: admin
	./bin/aegis-admin validate-config --config configs/config.yaml

install-radius-dictionary:
	bash scripts/install-aegisnas-freeradius-dictionary.sh

scan-radius-dictionaries: admin
	./bin/aegis-admin scan-radius-dictionaries
