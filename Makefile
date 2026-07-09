.PHONY: build test frontend clean all admin gateway radius portal session policy admin-api ai-lite test-acceptance test-vendor-certification test-vendor-identity test-attribute-registry test-dictionary-release-profiles install-radius-dictionary scan-radius-dictionaries

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
