# Blocks Makefile
# Builds both standard and fully-static Linux binaries.

BINARY      := blocks
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MODULE      := github.com/matthewgall/blocks

LDFLAGS     := -X $(MODULE)/internal/version.Version=$(VERSION) \
               -X $(MODULE)/internal/version.Commit=$(COMMIT) \
               -X $(MODULE)/internal/version.BuildDate=$(BUILD_DATE)

STATIC_TAGS := osusergo,netgo
STATIC_LDFLAGS := $(LDFLAGS) -s -w -extldflags '-static'

GO          := go
GOFLAGS     := -trimpath
BUILD_DIR   := bin

.PHONY: all build build-static clean test lint install install-static uninstall run help

all: build build-static ## Build both standard and static binaries.

build: ## Build the standard binary (bin/blocks).
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/blocks

build-static: ## Build a fully-static Linux binary (bin/blocks-static).
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux $(GO) build $(GOFLAGS) -tags "$(STATIC_TAGS)" \
		-ldflags "$(STATIC_LDFLAGS)" \
		-o $(BUILD_DIR)/$(BINARY)-static ./cmd/blocks

clean: ## Remove build artifacts and coverage output.
	rm -rf $(BUILD_DIR) coverage.out coverage.html

test: ## Run all Go tests.
	$(GO) test ./...

lint: ## Run golangci-lint.
	golangci-lint run ./...

install: build ## Build and install the standard binary to /opt/blocks.
	install -d $(DESTDIR)/opt/blocks
	install -m 0755 $(BUILD_DIR)/$(BINARY) $(DESTDIR)/opt/blocks/$(BINARY)
	install -m 0644 config.example.yaml $(DESTDIR)/opt/blocks/config.yaml.example
	@echo "Install complete. Copy /opt/blocks/config.yaml.example to /opt/blocks/config.yaml and edit."

install-static: build-static ## Build and install the static binary to /opt/blocks.
	install -d $(DESTDIR)/opt/blocks
	install -m 0755 $(BUILD_DIR)/$(BINARY)-static $(DESTDIR)/opt/blocks/$(BINARY)
	install -m 0644 config.example.yaml $(DESTDIR)/opt/blocks/config.yaml.example
	@echo "Static install complete. Copy /opt/blocks/config.yaml.example to /opt/blocks/config.yaml and edit."

uninstall: ## Remove /opt/blocks.
	rm -rf $(DESTDIR)/opt/blocks

run: build ## Build and run the standard binary locally.
	./$(BUILD_DIR)/$(BINARY)

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
