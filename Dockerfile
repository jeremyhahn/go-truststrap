FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /build/bin/truststrap ./cmd/truststrap

FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/bin/truststrap /usr/local/bin/truststrap
ENTRYPOINT ["truststrap"]
