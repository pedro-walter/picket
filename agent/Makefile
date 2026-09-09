VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := picket-agent

.PHONY: build test vet cross clean oneshot

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/picket-agent

test:
	go test ./...

vet:
	go vet ./...

# static binaries for release (see PLAN.md build step 7)
cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BIN)_$(VERSION)_linux_amd64 ./cmd/picket-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BIN)_$(VERSION)_linux_arm64 ./cmd/picket-agent

# run once against a local `wrangler dev`; expects ./dev-agent.yaml + token
oneshot: build
	./$(BIN) --config ./dev-agent.yaml --state-dir ./.state --oneshot

clean:
	rm -rf $(BIN) dist .state
