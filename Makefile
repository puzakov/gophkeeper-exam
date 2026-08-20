.PHONY: proto build-server build-client build test lint clean run-db

# Build info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS = -X github.com/puzakov/gophkeeper-exam/internal/build.Version=$(VERSION) \
          -X github.com/puzakov/gophkeeper-exam/internal/build.Date=$(DATE) \
          -X github.com/puzakov/gophkeeper-exam/internal/build.Commit=$(COMMIT)

# Proto
PROTO_DIR = api/proto/v1
PROTO_OUT = internal/proto/v1

proto:
	rm -f $(PROTO_OUT)/*.pb.go $(PROTO_OUT)/*_grpc.pb.go
	protoc \
		--go_out=. \
		--go_opt=module=github.com/puzakov/gophkeeper-exam \
		--go_opt=default_api_level=API_OPAQUE \
		--go-grpc_out=. \
		--go-grpc_opt=module=github.com/puzakov/gophkeeper-exam \
		-I $(PROTO_DIR) \
		$(PROTO_DIR)/*.proto

proto-check: proto
	@if [ -n "$$(git diff --stat $(PROTO_OUT))" ]; then \
		echo "ERROR: generated proto files are out of date. Run 'make proto' and commit."; \
		git diff --stat $(PROTO_OUT); \
		exit 1; \
	fi
	@echo "Proto files are up to date."

# Build
build-server:
	go build -ldflags "$(LDFLAGS)" -o gophkeeper-server ./cmd/server/

build-client:
	go build -ldflags "$(LDFLAGS)" -o gophkeeper-client ./cmd/client/

build: build-server build-client

# Cross-compile
build-all:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o gophkeeper-server-linux-amd64   ./cmd/server/
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o gophkeeper-client-linux-amd64   ./cmd/client/
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o gophkeeper-server-darwin-amd64  ./cmd/server/
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o gophkeeper-client-darwin-amd64  ./cmd/client/
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o gophkeeper-server-windows-amd64.exe ./cmd/server/
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o gophkeeper-client-windows-amd64.exe ./cmd/client/

# Test
test:
	go test -v -race ./...

# generated proto code (internal/proto/v1) is excluded.
COVER_PKGS := $(shell go list ./internal/... | grep -v /proto/ | tr '\n' ',')

test-cover:
	go test -race -coverprofile=coverage.out -coverpkg=$(COVER_PKGS) ./...
	go tool cover -func=coverage.out | tail -15
	@echo ""
	@echo -n "TOTAL: "
	@go tool cover -func=coverage.out | tail -1 | awk '{print $$3}'

bench:
	go test -bench=. -benchmem ./...

# Lint
lint:
	go vet ./...

# Docker
run-db:
	docker compose up -d postgres
	docker compose ps

stop-db:
	docker compose down

# Clean
clean:
	rm -f gophkeeper-server gophkeeper-client
	rm -f gophkeeper-server-* gophkeeper-client-*
	rm -f coverage.out
