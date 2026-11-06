# syntax=docker/dockerfile:1
#
# Privasimu Bridge container image: a static binary on distroless, running as a non-root
# user. Base images are pinned by digest (resolved 2026-10-31); update both the tag and
# the digest together.
#
#   docker build -t privasimu-bridge:0.1.0 --build-arg VERSION=0.1.0 .

FROM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X github.com/privasimu/bridge/internal/buildinfo.Version=${VERSION} -X github.com/privasimu/bridge/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/privasimu-bridge ./cmd/privasimu-bridge
# An empty directory, copied below as the state directory owned by the runtime user.
RUN mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/privasimu-bridge /usr/local/bin/privasimu-bridge
# The state directory exists in the image and belongs to the user the bridge runs as. Docker
# creates a mount point that is missing from the image as root, which the bridge cannot
# write; a new named volume copies this directory's owner instead. A volume or a bind mount
# made before must be given to 65532 once (install guide, section 1, Docker).
COPY --from=build --chown=65532:65532 /out/state /var/lib/privasimu-bridge
# 65532 is the "nonroot" user of the distroless image.
USER 65532:65532
ENV PRIVASIMU_BRIDGE_CONFIG=/etc/privasimu-bridge/bridge.yaml
# Configuration (read-only mount) and state (writable volume: reports, agent status,
# encrypted secret store, audit log).
VOLUME ["/var/lib/privasimu-bridge"]
EXPOSE 8443
# For mode B override with: healthcheck --mode agent
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/privasimu-bridge", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/privasimu-bridge"]
CMD ["serve"]
