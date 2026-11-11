.PHONY: all agents build test test-race lint fmt release clean clean-all

GO := go

# All build artifacts live under /build/ at the repo root. Gitignored.
BUILD_DIR := build

VERSION_PKG := github.com/md2k/subnet-tunnel/internal/version
LDFLAGS := -X $(VERSION_PKG).GitSHA=$(shell git rev-parse --short HEAD) \
           -X $(VERSION_PKG).BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ) \
           -X $(VERSION_PKG).Version=$(shell git describe --tags --always)

# Linux agents are embedded into every subtun build (internal/agentbin/dist/).
AGENT_DIR    := internal/agentbin/dist
AGENT_ARCHES := amd64 arm64

all: test build

# Build the Linux agents that subtun uploads into pods/containers.
agents:
	@for arch in $(AGENT_ARCHES); do \
		echo "agent linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags "-s -w $(LDFLAGS)" \
			-o $(AGENT_DIR)/subtun-agent-linux-$$arch ./cmd/subtun-agent || exit 1; \
	done

# subtun for this machine, agents embedded.
build: agents
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(BUILD_DIR)/subtun ./cmd/subtun

test:
	$(GO) test ./...

# Race detector needs cgo (a C toolchain), so it is not part of `make test`.
test-race:
	$(GO) test -race ./...

lint:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

fmt:
	gofmt -w .

# Cut a release: tag + cross-OS subtun binaries (agents embedded) + GitHub release.
#   make release VERSION=v0.1.0
#   make release VERSION=v0.1.0 ARGS="--dry-run"          # build all archives only
#   make release VERSION=v0.1.0 ARGS="--notes-file X.md"
release:
	@test -n "$(VERSION)" || { echo 'usage: make release VERSION=vX.Y.Z [ARGS="--dry-run|--notes-file X"]'; exit 1; }
	./scripts/release.sh $(VERSION) $(ARGS)

clean:
	rm -f $(BUILD_DIR)/subtun
	rm -f $(AGENT_DIR)/subtun-agent-linux-*

# Like `clean` but also wipes release archives and benchmark files under /build/.
clean-all: clean
	rm -rf $(BUILD_DIR)
