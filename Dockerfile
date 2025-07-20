# Builder stage for dumb-init and directory setup
FROM alpine:3.19 AS builder
RUN apk add --no-cache dumb-init
# Create the certs directory with proper ownership
RUN mkdir -p /certs && chown 65532:65532 /certs

# Final stage - using distroless base
FROM gcr.io/distroless/static-debian12:nonroot

# Copy dumb-init from builder
COPY --from=builder /usr/bin/dumb-init /usr/bin/dumb-init

# Copy the pre-created certs directory from builder
COPY --from=builder --chown=65532:65532 /certs /certs

# Copy the binary from GoReleaser context
COPY proxyt /proxyt

# Expose ports
EXPOSE 80 443 8080

# Set dumb-init as PID 1 with the binary as entrypoint
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/proxyt"]

# Default command
CMD ["serve", "--help"]
