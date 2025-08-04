package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// OIDCConfiguration represents the OpenID Connect configuration
type OIDCConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer               string `json:"issuer"`
}

// ProxyServer holds the configuration and handlers for the OIDC redirect/proxy server
type ProxyServer struct {
	config     *OIDCConfiguration
	logger     *logrus.Logger
	tokenProxy *httputil.ReverseProxy
}

// NewProxyServer creates a new redirect server instance
func NewProxyServer(configURL string, logger *logrus.Logger) (*ProxyServer, error) {
	config, err := fetchOIDCConfiguration(configURL, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"authorization_endpoint": config.AuthorizationEndpoint,
		"token_endpoint":        config.TokenEndpoint,
		"issuer":               config.Issuer,
	}).Info("OIDC configuration loaded successfully")

	server := &ProxyServer{
		config: config,
		logger: logger,
	}

	// Create reverse proxy for token endpoint only
	if err := server.createTokenProxy(); err != nil {
		return nil, fmt.Errorf("failed to create token proxy: %w", err)
	}

	return server, nil
}

// fetchOIDCConfiguration retrieves the OIDC configuration from the well-known endpoint
func fetchOIDCConfiguration(configURL string, logger *logrus.Logger) (*OIDCConfiguration, error) {
	logger.WithField("url", configURL).Info("Fetching OIDC configuration")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logger.WithField("response_body", string(body)).Debug("Received OIDC configuration response")

	var config OIDCConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	return &config, nil
}

// createTokenProxy sets up the reverse proxy for the token endpoint
func (ps *ProxyServer) createTokenProxy() error {
	tokenURL, err := url.Parse(ps.config.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse token endpoint: %w", err)
	}
	
	ps.tokenProxy = httputil.NewSingleHostReverseProxy(tokenURL)
	ps.tokenProxy.Director = ps.createTokenDirector(tokenURL)
	
	return nil
}

// createTokenDirector creates a custom director function for the token proxy
func (ps *ProxyServer) createTokenDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":  "token",
			"original_path":  req.URL.Path,
			"target_host":    target.Host,
			"target_scheme":  target.Scheme,
			"method":         req.Method,
			"remote_addr":    req.RemoteAddr,
			"user_agent":     req.UserAgent(),
		}).Info("Proxying token request")

		if ps.logger.Level >= logrus.DebugLevel {
			ps.logProxyRequestDetails(req, "token")
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.Host = target.Host

		// Add X-Forwarded headers
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
		if req.Header.Get("X-Forwarded-For") == "" {
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}
	}
}

// buildRedirectURL constructs the redirect URL by preserving all query parameters
func (ps *ProxyServer) buildRedirectURL(targetEndpoint string, originalQuery url.Values) (string, error) {
	targetURL, err := url.Parse(targetEndpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse target endpoint: %w", err)
	}

	// Merge original query parameters with any existing parameters in the target URL
	if len(originalQuery) > 0 {
		// Parse existing query parameters from target URL
		existingQuery := targetURL.Query()
		
		// Add original query parameters (original takes precedence if there are conflicts)
		for key, values := range originalQuery {
			for _, value := range values {
				existingQuery.Add(key, value)
			}
		}
		
		targetURL.RawQuery = existingQuery.Encode()
	}

	return targetURL.String(), nil
}

// handleAuth handles requests to /protocol/openid-connect/auth by redirecting to authorization endpoint
func (ps *ProxyServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	ps.logger.WithFields(logrus.Fields{
		"endpoint_type": "auth",
		"original_path": r.URL.Path,
		"method":        r.Method,
		"remote_addr":   r.RemoteAddr,
		"user_agent":    r.UserAgent(),
		"query_params":  r.URL.RawQuery,
	}).Info("Redirecting to authorization endpoint")

	if ps.logger.Level >= logrus.DebugLevel {
		ps.logRequestDetails(r, "auth")
	}

	redirectURL, err := ps.buildRedirectURL(ps.config.AuthorizationEndpoint, r.URL.Query())
	if err != nil {
		ps.logger.WithError(err).Error("Failed to build redirect URL for auth endpoint")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type": "auth",
		"redirect_url":  redirectURL,
	}).Info("Performing redirect")

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken handles requests to /protocol/openid-connect/token by proxying to token endpoint
func (ps *ProxyServer) handleToken(w http.ResponseWriter, r *http.Request) {
	ps.logger.WithFields(logrus.Fields{
		"endpoint_type": "token",
		"original_path": r.URL.Path,
		"method":        r.Method,
		"remote_addr":   r.RemoteAddr,
		"user_agent":    r.UserAgent(),
		"query_params":  r.URL.RawQuery,
	}).Info("Proxying to token endpoint")

	ps.tokenProxy.ServeHTTP(w, r)
}

// logRequestDetails logs detailed request information at debug level for redirects
func (ps *ProxyServer) logRequestDetails(req *http.Request, endpointType string) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		// Note: We don't restore the body since this is a redirect, not a proxy
	}

	headers := make(map[string]string)
	for key, values := range req.Header {
		headers[key] = strings.Join(values, ", ")
	}

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type": endpointType,
		"headers":       headers,
		"body":          string(bodyBytes),
		"query":         req.URL.RawQuery,
	}).Debug("Request details")
}

// logProxyRequestDetails logs detailed request information at debug level for proxy requests
func (ps *ProxyServer) logProxyRequestDetails(req *http.Request, endpointType string) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	headers := make(map[string]string)
	for key, values := range req.Header {
		headers[key] = strings.Join(values, ", ")
	}

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type": endpointType,
		"headers":       headers,
		"body":          string(bodyBytes),
		"query":         req.URL.RawQuery,
	}).Debug("Proxy request details")
}

// handleHealth provides a health check endpoint
func (ps *ProxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"issuer": ps.config.Issuer,
	})
}

// setupRoutes configures the HTTP routes
func (ps *ProxyServer) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/protocol/openid-connect/auth", ps.handleAuth)
	mux.HandleFunc("/protocol/openid-connect/token", ps.handleToken)
	mux.HandleFunc("/health", ps.handleHealth)
	
	return mux
}

// setupLogger configures the logger based on environment variables
func setupLogger() *logrus.Logger {
	logger := logrus.New()
	
	// Set log level from environment variable
	logLevel := strings.ToLower(os.Getenv("LOG_LEVEL"))
	switch logLevel {
	case "trace":
		logger.SetLevel(logrus.TraceLevel)
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info", "":
		logger.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logger.SetLevel(logrus.FatalLevel)
	case "panic":
		logger.SetLevel(logrus.PanicLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
		logger.WithField("invalid_level", logLevel).Warn("Invalid log level, defaulting to info")
	}

	// Set formatter
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})

	return logger
}

func main() {
	logger := setupLogger()

	// Get configuration URL from environment
	configURL := os.Getenv("OIDC_CONFIGURATION_URL")
	if configURL == "" {
		logger.Fatal("OIDC_CONFIGURATION_URL environment variable is required")
	}

	// Get port from environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create redirect/proxy server
	proxyServer, err := NewProxyServer(configURL, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create redirect/proxy server")
	}

	// Setup HTTP server
	mux := proxyServer.setupRoutes()
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start server in a goroutine
	go func() {
		logger.WithField("port", port).Info("Starting OIDC redirect/proxy server")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Server failed to start")
		}
	}()

	// Wait for interrupt signal
	<-ctx.Done()
	logger.Info("Shutting down server...")

	// Shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server shutdown complete")
	}
}
