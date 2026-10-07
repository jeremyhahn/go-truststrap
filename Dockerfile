# syntax=docker/dockerfile:1.7
# The syntax directive pins the BuildKit frontend that provides the secret
# mount below. Without it an older frontend rejects the RUN as a parse error
# rather than building without the secret.
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /build
COPY go.mod go.sum ./
# go.mod requires the internal first-party module github.com/jeremyhahn/go-enclave,
# published to the internal Gitea rather than to github.com. Resolving it needs
# GOPRIVATE plus git's insteadOf rewrite carrying a read-only token
# (conventions/dependency-resolution.md section 6), supplied as an OPTIONAL
# BuildKit secret carrying ONLY the tokenised GIT_CONFIG_KEY_0 value. It is
# mounted on tmpfs for this RUN alone and read through a QUOTED command
# substitution -- never sourced as shell, so a credential containing shell
# metacharacters is assigned literally rather than executed. It is never a build
# arg or an ENV (both recoverable from docker history) and never lands in a
# layer. The public halves of the rewrite are the literals below; only the
# token-bearing key is secret.
#
# The mount is OPTIONAL, so this same Dockerfile still builds against the public
# proxy wherever no secret is provided -- GitHub Actions, and any public
# consumer once the tags are mirrored.
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
