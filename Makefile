.PHONY: build test frontend clean all admin gateway radius portal session policy admin-api ai-lite test-acceptance install-radius-dictionary

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
