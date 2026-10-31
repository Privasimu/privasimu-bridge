# Release builds of privasimu-bridge: static binaries without cgo.
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/privasimu/bridge/internal/buildinfo.Version=$(VERSION) -X github.com/privasimu/bridge/internal/buildinfo.Commit=$(COMMIT)
PLATFORMS := linux/amd64 linux/arm64 windows/amd64

.PHONY: build dist test vet vuln integration clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/privasimu-bridge ./cmd/privasimu-bridge

dist:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/privasimu-bridge-$(VERSION)-$$os-$$arch$$ext ./cmd/privasimu-bridge || exit 1; \
	done
	cd dist && sha256sum privasimu-bridge-* > SHA256SUMS

test:
	go test ./...

vet:
	go vet ./...
	GOOS=linux go vet ./...
	GOOS=windows go vet ./...

vuln:
	govulncheck ./...

# Needs the BRIDGE_IT_* variables; see internal/dbsource/integration_test.go.
integration:
	go test -tags integration ./internal/dbsource/

clean:
	rm -rf bin dist
