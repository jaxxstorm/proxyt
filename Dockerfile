# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git dumb-init

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Use Docker's platform args for cross-compilation
ARG TARGETOS
ARG TARGETARCH

# Build the binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X github.com/jaxxstorm/proxyt/cmd.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o proxyt .

# Create the certs directory with proper ownership
RUN mkdir -p /certs && chown 65532:65532 /certs

# Final stage - using distroless base
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app/

# Copy dumb-init from builder
COPY --from=builder /usr/bin/dumb-init /usr/local/bin/dumb-init

# Copy the pre-created certs directory from builder
COPY --from=builder --chown=65532:65532 /certs /certs

# Copy the binary from builder
COPY --from=builder /build/proxyt /app/proxyt

# Expose ports
EXPOSE 80 443 8080

# Set dumb-init as PID 1 with the binary as entrypoint
ENTRYPOINT ["/usr/local/bin/dumb-init", "--", "/app/proxyt"]

# Default command
CMD ["serve"]
