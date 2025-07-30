# Build stage
FROM golang:1.21-alpine AS builder

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o oidc-proxy .

# Final stage
FROM scratch

# Copy ca-certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/oidc-proxy /oidc-proxy

# Expose port 8080
EXPOSE 8080

# Set default environment variables
ENV LOG_LEVEL=info
ENV PORT=8080

# Run the binary
ENTRYPOINT ["/oidc-proxy"]
