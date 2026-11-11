MODULE   := github.com/md2k/subnet-tunnel
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS  := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT)
GOBUILD  := CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)'

AGENT_DIR    := internal/agentbin/dist
AGENT_ARCHES := amd64 arm64

.PHONY: all build agents test vet fmt clean

all: build

## agents: build the Linux agents that get embedded into subtun
agents:
	@for arch in $(AGENT_ARCHES); do \
		echo "agent linux/$$arch"; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $(AGENT_DIR)/subtun-agent-linux-$$arch ./cmd/subtun-agent || exit 1; \
	done

## build: build bin/subtun for this machine, with the agents embedded
build: agents
	$(GOBUILD) -o bin/subtun ./cmd/subtun

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf bin dist $(AGENT_DIR)/subtun-agent-linux-*
