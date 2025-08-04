# Keycloak OIDC Hybrid Service

A lightweight Go-based service that provides Keycloak-compatible OIDC endpoints with hybrid redirect/proxy behavior by fetching configuration from a well-known OpenID Connect configuration endpoint.

## Features

- Fetches OIDC configuration from any `.well-known/openid-configuration` endpoint
- **Hybrid approach** for Keycloak-style URLs:
  - `/protocol/openid-connect/auth` → **Redirects** to `authorization_endpoint` (preserving all query parameters)
  - `/protocol/openid-connect/token` → **Proxies** to `token_endpoint` (transparent backend handling)
  - `/protocol/openid-connect/userinfo` → **Proxies** to `userinfo_endpoint` (transparent backend handling)
- **Automatic OIDC scope injection**: Ensures `oidc` scope is always included in authorization requests for proper OpenID Connect flow
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

## Debug Logging

The service provides comprehensive debug logging when `LOG_LEVEL=debug` is set. This includes:

- **Request Details**: Method, URL, headers, body content
- **Response Analysis**: Status codes, headers, content type, encoding
- **JSON Parsing**: Pretty-printed JSON responses for token and userinfo endpoints
- **Content Encoding**: Automatic detection and reporting of compression
- **UTF-8 Validation**: Character encoding validation for response bodies
- **Proxy Behavior**: Detailed logs of request transformation and forwarding

**Note**: To ensure proper JSON response logging, the service automatically sets `Accept-Encoding: identity` header for token and userinfo endpoint requests, which disables gzip compression and allows for plaintext response analysis.

## Endpoints

- `GET /protocol/openid-connect/auth` - **Redirects** to the authorization endpoint (HTTP 302) with preserved query parameters
- `POST /protocol/openid-connect/token` - **Proxies** to the token endpoint (transparent handling)
- `GET /protocol/openid-connect/userinfo` - **Proxies** to the userinfo endpoint (transparent handling)
- `GET /health` - Health check endpoint

## OIDC Scope Injection

The service automatically ensures that the `oidc` scope is included in authorization requests to guarantee proper OpenID Connect authentication flow:

- **No existing scope**: Adds `scope=oidc`
- **Existing scopes without oidc**: Appends `oidc` to existing scopes (e.g., `scope=openid profile` becomes `scope=openid profile oidc`)
- **OIDC scope already present**: Leaves scopes unchanged
- **Multiple scope parameters**: Consolidates all scopes and ensures `oidc` is included

This ensures that ID tokens are properly issued by the OIDC provider, even when client applications forget to request the `oidc` scope.

## Example

If your OIDC provider configuration is:
```json
{
  "authorization_endpoint": "https://auth.hoad.at/application/o/authorize/",
  "token_endpoint": "https://auth.hoad.at/application/o/token/",
  "userinfo_endpoint": "https://auth.hoad.at/application/o/userinfo/"
}
```

### Authorization Endpoint (Redirect with OIDC scope)
- `http://localhost:8080/protocol/openid-connect/auth?client_id=test&response_type=code` will redirect (HTTP 302) to `https://auth.hoad.at/application/o/authorize/?client_id=test&response_type=code&scope=oidc`
- `http://localhost:8080/protocol/openid-connect/auth?client_id=test&scope=openid+profile` will redirect to `https://auth.hoad.at/application/o/authorize/?client_id=test&scope=openid+profile+oidc`
- All query parameters are preserved during the redirect

### Token Endpoint (Proxy)
- `POST http://localhost:8080/protocol/openid-connect/token` will proxy the request to `https://auth.hoad.at/application/o/token/`

### Userinfo Endpoint (Proxy)
- `GET http://localhost:8080/protocol/openid-connect/userinfo` will proxy the request to `https://auth.hoad.at/application/o/userinfo/`
- Request body, headers, and response are transparently handled
- Client receives the response as if calling the token endpoint directly

## Logging

The application supports various log levels:

- **trace**: Extremely verbose logging
- **debug**: **Highly detailed** request/response information including:
  - Complete request headers, body, and parsed form data
  - Response headers, body, and status codes
  - Token response analysis (access_token, refresh_token, id_token details)
  - Request/response timing and performance metrics
  - URL transformations and proxy routing details
  - Sensitive data redaction for security
- **info**: General operational information including redirect and proxy actions (default)
- **warn**: Warning messages
- **error**: Error messages
- **fatal**: Fatal errors that cause the application to exit
- **panic**: Panic level logging

Set `LOG_LEVEL=debug` to see **extremely detailed** request, redirect, and proxy information with full request/response analysis.

### Debug Logging Features

When `LOG_LEVEL=debug` is enabled for token endpoint proxying, you get:

**Request Analysis:**
- Complete HTTP headers and metadata
- Request body parsing (form data, JSON)
- Query parameter extraction
- Cookie analysis
- Protocol version details
- Timing information (start time, duration)

**Response Analysis:**
- Full response headers and status codes
- Response body content
- Token response parsing (access_token, refresh_token, id_token)
- Content type and cache header analysis
- Response size and timing metrics

**Security Features:**
- Automatic redaction of sensitive fields (passwords, tokens, secrets)
- Safe logging of token previews (first 20 characters only)
- Protection of authorization headers and credentials

## Why Hybrid Approach?

This service uses a **hybrid approach** for optimal OIDC compatibility:

### Authorization Endpoint - Redirect (HTTP 302)
- **Use case**: Interactive user authentication in web browsers
- **Why redirect**: Browsers need to navigate to the authorization server for user login
- **Benefits**: 
  - Preserves all query parameters (client_id, response_type, redirect_uri, etc.)
  - Works with browser-based flows
  - No server-side session handling needed

### Token Endpoint - Proxy (Transparent)
- **Use case**: Backend token exchange by applications
- **Why proxy**: Applications expect direct API responses, not redirects
- **Benefits**:
  - Transparent to the calling application
  - Preserves request/response body and headers
  - Compatible with existing OAuth2/OIDC client libraries
  - No application code changes needed

## Security Features

- Request timeouts to prevent hanging connections during OIDC configuration fetching and proxying
- Graceful shutdown handling
- Proper X-Forwarded headers for proxied requests
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
