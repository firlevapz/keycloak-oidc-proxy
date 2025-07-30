# Keycloak OIDC Redirect Service

A lightweight Go-based redirect service that translates Keycloak-style OIDC endpoints to any OIDC provider by fetching configuration from a well-known OpenID Connect configuration endpoint and redirecting clients with preserved query parameters.

## Features

- Fetches OIDC configuration from any `.well-known/openid-configuration` endpoint
- Redirects Keycloak-style URLs to the actual OIDC provider endpoints (preserving all query parameters):
  - `/protocol/openid-connect/auth` → `authorization_endpoint`
  - `/protocol/openid-connect/token` → `token_endpoint`
- Configurable logging levels (trace, debug, info, warn, error, fatal, panic)
- Health check endpoint
- Graceful shutdown
- Minimal Docker image (~6MB) using multi-stage build with scratch base
- Security best practices with timeout configurations

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OIDC_CONFIGURATION_URL` | Yes | - | URL to the OIDC well-known configuration endpoint |
| `LOG_LEVEL` | No | `info` | Log level (trace, debug, info, warn, error, fatal, panic) |
| `PORT` | No | `8080` | Port to listen on |

## Usage

### Running with Go

```bash
export OIDC_CONFIGURATION_URL="https://auth.hoad.at/application/o/audiobookshelf/.well-known/openid-configuration"
export LOG_LEVEL="debug"
go run main.go
```

### Building and Running

```bash
go build -o oidc-proxy .
export OIDC_CONFIGURATION_URL="https://auth.hoad.at/application/o/audiobookshelf/.well-known/openid-configuration"
./oidc-proxy
```

### Docker Compose (Recommended for local testing)

1. Copy the environment template:
```bash
cp .env.example .env
```

2. Edit `.env` file with your OIDC configuration URL:
```bash
OIDC_CONFIGURATION_URL=https://auth.hoad.at/application/o/audiobookshelf/.well-known/openid-configuration
LOG_LEVEL=debug
```

3. Start the service:
```bash
docker-compose up --build
```

4. The service will be available at http://localhost:8080

5. To stop the service:
```bash
docker-compose down
```

You can also use the pre-built image by updating your `docker-compose.yml`:
```yaml
services:
  oidc-proxy:
    image: ghcr.io/firlevapz/keycloak-oidc-proxy:latest
    # ... rest of configuration
```

### Docker

#### Using Pre-built Image (Recommended)

Use the latest image from GitHub Container Registry:
```bash
docker run -p 8080:8080 \
  -e OIDC_CONFIGURATION_URL="https://auth.hoad.at/application/o/audiobookshelf/.well-known/openid-configuration" \
  -e LOG_LEVEL="info" \
  ghcr.io/firlevapz/keycloak-oidc-proxy:latest
```

#### Building Locally

Build the image:
```bash
docker build -t keycloak-oidc-proxy .
```

Run the container:
```bash
docker run -p 8080:8080 \
  -e OIDC_CONFIGURATION_URL="https://auth.hoad.at/application/o/audiobookshelf/.well-known/openid-configuration" \
  -e LOG_LEVEL="info" \
  keycloak-oidc-proxy
```

## Endpoints

- `GET /protocol/openid-connect/auth` - Redirects to the authorization endpoint (HTTP 302)
- `POST /protocol/openid-connect/token` - Redirects to the token endpoint (HTTP 302)
- `GET /health` - Health check endpoint

## Example

If your OIDC provider configuration is:
```json
{
  "authorization_endpoint": "https://auth.hoad.at/application/o/authorize/",
  "token_endpoint": "https://auth.hoad.at/application/o/token/"
}
```

Then:
- `http://localhost:8080/protocol/openid-connect/auth?client_id=test&response_type=code` will redirect to `https://auth.hoad.at/application/o/authorize/?client_id=test&response_type=code`
- `http://localhost:8080/protocol/openid-connect/token` will redirect to `https://auth.hoad.at/application/o/token/`

All query parameters are preserved during the redirect.

## Logging

The application supports various log levels:

- **trace**: Extremely verbose logging
- **debug**: Detailed request/response information including headers, body, and redirect URLs
- **info**: General operational information including redirect actions (default)
- **warn**: Warning messages
- **error**: Error messages
- **fatal**: Fatal errors that cause the application to exit
- **panic**: Panic level logging

Set `LOG_LEVEL=debug` to see detailed request and redirect information.

## Security Features

- Request timeouts to prevent hanging connections during OIDC configuration fetching
- Graceful shutdown handling
- Minimal attack surface with scratch-based Docker image
- No unnecessary dependencies in production image
- URL validation for redirect endpoints

## Docker Image Size

The final Docker image is extremely small (~6MB) thanks to:
- Multi-stage build
- Scratch base image
- Static binary compilation
- Only essential certificates included

## CI/CD

The project includes GitHub Actions workflows for:

### Continuous Integration (CI)
- **Workflow**: `.github/workflows/ci.yml`
- **Triggers**: Push/PR to main branch
- **Actions**:
  - Go code formatting check (`go fmt`)
  - Static analysis (`go vet`)
  - Unit tests with race detection
  - Code coverage reporting
  - Build verification

### Docker Image Building
- **Workflow**: `.github/workflows/docker-build.yml`
- **Triggers**: 
  - Push to main branch (builds `latest` tag)
  - Pull requests (builds PR-specific tags)
  - Releases (builds version tags)
- **Features**:
  - Multi-architecture builds (AMD64, ARM64)
  - Automatic tagging based on Git refs
  - GitHub Container Registry publishing
  - Build caching for faster builds
  - SLSA attestation for supply chain security

### Available Images

| Tag | Description | Example |
|-----|-------------|---------|
| `latest` | Latest build from main branch | `ghcr.io/firlevapz/keycloak-oidc-proxy:latest` |
| `main` | Latest build from main branch | `ghcr.io/firlevapz/keycloak-oidc-proxy:main` |
| `pr-N` | Pull request builds | `ghcr.io/firlevapz/keycloak-oidc-proxy:pr-123` |
| `v1.0.0` | Release tags | `ghcr.io/firlevapz/keycloak-oidc-proxy:v1.0.0` |

Images are automatically built for both `linux/amd64` and `linux/arm64` architectures.
