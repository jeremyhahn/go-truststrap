# syntax=docker/dockerfile:1.7
# The syntax directive pins the BuildKit frontend that provides the secret
# mount below. Without it an older frontend rejects the RUN as a parse error
# rather than building without the secret.
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /build
COPY go.mod go.sum ./
# go-enclave resolves through an optional BuildKit secret carrying only the tokenised GIT_CONFIG_KEY_0, read by quoted substitution and never kept in a layer.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -s /run/secrets/gomodauth ]; then \
        export GOPRIVATE='github.com/jeremyhahn/*'; \
        export GIT_CONFIG_COUNT=1; \
        export GIT_CONFIG_KEY_0="$(cat /run/secrets/gomodauth)"; \
        export GIT_CONFIG_VALUE_0='https://github.com/jeremyhahn/'; \
    fi; \
    go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /build/bin/truststrap ./cmd/truststrap

FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/bin/truststrap /usr/local/bin/truststrap
ENTRYPOINT ["truststrap"]
