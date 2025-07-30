# Keycloak OIDC Proxy

A lightweight Go-based proxy server that translates Keycloak-style OIDC endpoints to any OIDC provider by fetching configuration from a well-known OpenID Connect configuration endpoint.

## Features

- Fetches OIDC configuration from any `.well-known/openid-configuration` endpoint
- Proxies Keycloak-style URLs to the actual OIDC provider endpoints:
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

### Docker

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

- `GET /protocol/openid-connect/auth` - Proxies to the authorization endpoint
- `POST /protocol/openid-connect/token` - Proxies to the token endpoint  
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
- `http://localhost:8080/protocol/openid-connect/auth` will proxy to `https://auth.hoad.at/application/o/authorize/`
- `http://localhost:8080/protocol/openid-connect/token` will proxy to `https://auth.hoad.at/application/o/token/`

## Logging

The application supports various log levels:

- **trace**: Extremely verbose logging
- **debug**: Detailed request/response information including headers and body
- **info**: General operational information (default)
- **warn**: Warning messages
- **error**: Error messages
- **fatal**: Fatal errors that cause the application to exit
- **panic**: Panic level logging

Set `LOG_LEVEL=debug` to see detailed request forwarding information.

## Security Features

- Request timeouts to prevent hanging connections
- Graceful shutdown handling
- Proper X-Forwarded headers
- Minimal attack surface with scratch-based Docker image
- No unnecessary dependencies in production image

## Docker Image Size

The final Docker image is extremely small (~6MB) thanks to:
- Multi-stage build
- Scratch base image
- Static binary compilation
- Only essential certificates included
