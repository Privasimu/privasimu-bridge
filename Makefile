# Release builds of privasimu-bridge: static binaries without cgo.
VERSION ?= 0.1.0-dev
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/privasimu/bridge/internal/buildinfo.Version=$(VERSION) -X github.com/privasimu/bridge/internal/buildinfo.Commit=$(COMMIT)
PLATFORMS := linux/amd64 linux/arm64 windows/amd64
IMAGE ?= privasimu-bridge
# Path of the minisign secret key (kept off the repository). When set, "make dist" also
# writes dist/SHA256SUMS.sig; see docs/RELEASE-SIGNING.md.
MINISIGN_SECRET_KEY ?=

.PHONY: build dist sign verify-release image image-scan test vet vuln integration clean

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
	@if [ -n "$(MINISIGN_SECRET_KEY)" ]; then \
		VERSION=$(VERSION) MINISIGN_SECRET_KEY="$(MINISIGN_SECRET_KEY)" sh scripts/release/sign.sh; \
	else \
		echo "dist/SHA256SUMS is not signed: set MINISIGN_SECRET_KEY for a release (docs/RELEASE-SIGNING.md)"; \
	fi

# Signs an existing dist/SHA256SUMS.
sign:
	VERSION=$(VERSION) MINISIGN_SECRET_KEY="$(MINISIGN_SECRET_KEY)" sh scripts/release/sign.sh

# Verifies dist/ the way users do.
verify-release:
	sh scripts/release/verify.sh dist

# The default image (distroless, bridge only) and the -scan image (with pinned Syft and
# Grype for scan_packages). Sign pushed images by digest with scripts/release/sign-image.sh.
image:
	docker build -t $(IMAGE):$(VERSION) --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .

image-scan:
	docker build -f Dockerfile.scan -t $(IMAGE):$(VERSION)-scan --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .

test:
	go test ./...

vet:
	go vet ./...
	GOOS=linux go vet ./...
	GOOS=windows go vet ./...

vuln:
	govulncheck ./...

# Needs the BRIDGE_IT_* variables of internal/testutil/itenv (databases loaded with
# internal/dbsource/testdata/integration) and, for internal/packages, real Syft and Grype
# installed by you. Engines and tools without variables are skipped.
integration:
	go test -p 1 -tags integration ./internal/dbsource/ ./internal/server/ ./internal/agent/ ./internal/packages/

clean:
	rm -rf bin dist
