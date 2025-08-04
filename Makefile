.PHONY: build run test clean docker-build docker-run compose-up compose-down compose-logs

# Variables
BINARY_NAME=oidc-redirect
DOCKER_IMAGE=keycloak-oidc-proxy

# Build the application
build:
	go build -o $(BINARY_NAME) .

# Run the application (requires OIDC_CONFIGURATION_URL env var)
run:
	go run main.go

# Test the application
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)

# Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE) .

# Run Docker container (requires OIDC_CONFIGURATION_URL env var)
docker-run:
	docker run -p 8080:8080 \
		-e OIDC_CONFIGURATION_URL="$(OIDC_CONFIGURATION_URL)" \
		-e LOG_LEVEL="$(LOG_LEVEL)" \
		$(DOCKER_IMAGE)

# Start services with docker-compose
compose-up:
	docker-compose up --build -d

# Stop services with docker-compose
compose-down:
	docker-compose down

# View logs from docker-compose services
compose-logs:
	docker-compose logs -f

# Show help
help:
	@echo "Available targets:"
	@echo "  build        - Build the application binary"
	@echo "  run          - Run the application"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  compose-up   - Start services with docker-compose"
	@echo "  compose-down - Stop services with docker-compose"
	@echo "  compose-logs - View logs from docker-compose services"
	@echo ""
	@echo "This service provides hybrid OIDC endpoint handling:"
	@echo "  /protocol/openid-connect/auth  - Redirects to authorization endpoint"
	@echo "  /protocol/openid-connect/token - Proxies to token endpoint"
	@echo ""
	@echo "Environment variables:"
	@echo "  OIDC_CONFIGURATION_URL - Required: OIDC well-known config URL"
	@echo "  LOG_LEVEL              - Optional: Log level (default: info)"
