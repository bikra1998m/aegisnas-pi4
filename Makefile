.PHONY: build test frontend clean all admin gateway radius portal session policy admin-api ai-lite test-acceptance test-vendor-certification test-vendor-identity test-attribute-registry test-dictionary-release-profiles test-compatibility-evidence test-vsa-codec test-opaque-passthrough test-secret-providers test-postgres-data-plane test-radius-packet-hardening test-radius-proxy-routing test-radius-transport-policy test-radius-proxy-policy test-radius-accounting-spool test-radius-fallback-policy test-active-directory test-identity-failover test-mfa test-admin-webauthn test-mab test-dynamic-nas-clients test-radsec-credentials install-radius-dictionary scan-radius-dictionaries

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
	go run ./cmd/aegis-attribute-registry-gen -input docs/freeradius-3.2.8-vsa-audit.csv -output configs/attribute_registry/freeradius-3.2.8-vsa-audit.csv -check -expected-sha256 60748478d30ea16b609601aacda83ff3e28a584a9bddb6b704991a0412f5bf4d
	go test ./configs ./cmd/aegis-attribute-registry-gen ./internal/radius ./internal/adminapi -run 'AttributeRegistry|GeneratedAttributeRegistry' -count=1

test-dictionary-release-profiles:
	go test ./configs ./internal/config ./internal/adminapi -run 'DictionaryRelease|VendorCompatibility|Authorize|OpenAPI|ProductionReadiness' -count=1

test-compatibility-evidence:
	go test ./configs ./internal/adminapi -run 'CompatibilityEvidence|VendorCompatibility|Authorize|OpenAPI|ProductionReadiness' -count=1

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

test-radius-fallback-policy:
	go test ./internal/config ./internal/db ./internal/radius ./internal/adminapi -run 'FallbackPolicy|RadiusFallback|Migrate|OpenAPI|Authorize|ProductionReadiness|SupportBundle' -count=1

test-active-directory:
	go test -p=1 -timeout=600s ./internal/activedirectory ./internal/config ./internal/db ./internal/identity ./internal/portal/auth ./internal/radius ./internal/adminapi -run 'ActiveDirectory|PolicyAndAuthenticate|KerberosCommand|BuildReportReflectsBlocked|ConfigValidationActiveDirectory|BuildSourcePlanIncludesActiveDirectory|AuthenticateFallbackUsesActiveDirectory|Migrate|MSCHAP|OpenAPI|Authorize|ProductionReadinessIncludesActiveDirectory|SupportBundle' -count=1

test-identity-failover:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/identity ./internal/portal/auth ./internal/adminapi -run 'IdentityFailover|IdentitySourceEvents|IdentitySourceCredential|ConfigValidationIdentity|BuildSourcePlan|BuildFailoverReport|HandleGetIdentityFailover|ProductionReadinessIncludesIdentityFailover|AuthenticateFallbackUsesIdentityFailover|ValidateUserDetailed|OpenAPI|Authorize|SupportBundleIncludesIdentityFailoverCapture' -count=1

test-mfa:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/mfa ./internal/radius ./internal/portal/auth ./internal/adminapi -run 'MFA|TOTP|Challenge|ConfigValidationMFA|AccessChallenge|AuthenticateUserRequiresAndVerifiesMFA|OpenAPI|Authorize|ProductionReadinessIncludesMFACheck|SupportBundle' -count=1

test-admin-webauthn:
	go test -p=1 -timeout=600s ./internal/config ./internal/db ./internal/webauthn ./internal/adminapi -run 'AdminWebAuthn|WebAuthn|MigrationCreatesExpectedTables|OpenAPI|Authorize|ProductionReadinessIncludesAdminWebAuthn|SupportBundle' -count=1

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
