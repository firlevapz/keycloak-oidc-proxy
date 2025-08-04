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
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isValidUTF8 checks if a string is valid UTF-8
func isValidUTF8(s string) bool {
	return utf8.ValidString(s)
}

// extractCharsetFromContentType extracts charset from Content-Type header
func extractCharsetFromContentType(contentType string) string {
	if contentType == "" {
		return "unknown"
	}

	// Look for charset parameter in Content-Type header
	re := regexp.MustCompile(`charset=([^;]+)`)
	matches := re.FindStringSubmatch(contentType)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	// Default charset for JSON is UTF-8
	if strings.Contains(contentType, "application/json") {
		return "utf-8"
	}

	return "unknown"
}

// responseWriter wraps http.ResponseWriter to capture response details
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *strings.Builder
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// OIDCConfiguration represents the OpenID Connect configuration
type OIDCConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

// ProxyServer holds the configuration and handlers for the OIDC redirect/proxy server
type ProxyServer struct {
	config        *OIDCConfiguration
	logger        *logrus.Logger
	tokenProxy    *httputil.ReverseProxy
	userinfoProxy *httputil.ReverseProxy
}

// NewProxyServer creates a new redirect server instance
func NewProxyServer(configURL string, logger *logrus.Logger) (*ProxyServer, error) {
	config, err := fetchOIDCConfiguration(configURL, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"authorization_endpoint": config.AuthorizationEndpoint,
		"token_endpoint":         config.TokenEndpoint,
		"userinfo_endpoint":      config.UserinfoEndpoint,
		"issuer":                 config.Issuer,
	}).Info("OIDC configuration loaded successfully")

	server := &ProxyServer{
		config: config,
		logger: logger,
	}

	// Create reverse proxy for token endpoint only
	if err := server.createTokenProxy(); err != nil {
		return nil, fmt.Errorf("failed to create token proxy: %w", err)
	}

	// Create reverse proxy for userinfo endpoint
	if err := server.createUserinfoProxy(); err != nil {
		return nil, fmt.Errorf("failed to create userinfo proxy: %w", err)
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

	// Add response modifier for detailed logging
	if ps.logger.Level >= logrus.DebugLevel {
		ps.tokenProxy.ModifyResponse = ps.modifyTokenResponse
	}

	return nil
}

// createTokenDirector creates a custom director function for the token proxy
func (ps *ProxyServer) createTokenDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		originalScheme := req.URL.Scheme
		originalHost := req.URL.Host
		originalPath := req.URL.Path

		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":     "token",
			"original_path":     originalPath,
			"original_host":     originalHost,
			"original_scheme":   originalScheme,
			"target_host":       target.Host,
			"target_scheme":     target.Scheme,
			"target_path":       target.Path,
			"method":            req.Method,
			"remote_addr":       req.RemoteAddr,
			"user_agent":        req.UserAgent(),
			"content_length":    req.ContentLength,
			"transfer_encoding": req.TransferEncoding,
		}).Info("Proxying token request")

		if ps.logger.Level >= logrus.DebugLevel {
			ps.logProxyRequestDetails(req, "token")
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.Host = target.Host

		// Disable gzip compression to ensure plaintext responses
		req.Header.Set("Accept-Encoding", "identity")
		// Alternative: req.Header.Del("Accept-Encoding") - completely remove the header

		// Add X-Forwarded headers
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", originalScheme)
		}
		if req.Header.Get("X-Forwarded-For") == "" {
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", originalHost)
		}

		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":   "token",
			"final_url":       req.URL.String(),
			"final_host":      req.Host,
			"accept_encoding": req.Header.Get("Accept-Encoding"),
		}).Debug("Token request URL transformation complete")
	}
}

// createUserinfoProxy sets up the reverse proxy for the userinfo endpoint
func (ps *ProxyServer) createUserinfoProxy() error {
	if ps.config.UserinfoEndpoint == "" {
		ps.logger.Warn("No userinfo endpoint configured, userinfo proxy will not be available")
		return nil
	}

	userinfoURL, err := url.Parse(ps.config.UserinfoEndpoint)
	if err != nil {
		return fmt.Errorf("failed to parse userinfo endpoint: %w", err)
	}

	ps.userinfoProxy = httputil.NewSingleHostReverseProxy(userinfoURL)
	ps.userinfoProxy.Director = ps.createUserinfoDirector(userinfoURL)

	// Add response modifier for detailed logging
	if ps.logger.Level >= logrus.DebugLevel {
		ps.userinfoProxy.ModifyResponse = ps.modifyUserinfoResponse
	}

	return nil
}

// createUserinfoDirector creates a custom director function for the userinfo proxy
func (ps *ProxyServer) createUserinfoDirector(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		originalScheme := req.URL.Scheme
		originalHost := req.URL.Host
		originalPath := req.URL.Path

		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":     "userinfo",
			"original_path":     originalPath,
			"original_host":     originalHost,
			"original_scheme":   originalScheme,
			"target_host":       target.Host,
			"target_scheme":     target.Scheme,
			"target_path":       target.Path,
			"method":            req.Method,
			"remote_addr":       req.RemoteAddr,
			"user_agent":        req.UserAgent(),
			"content_length":    req.ContentLength,
			"transfer_encoding": req.TransferEncoding,
		}).Info("Proxying userinfo request")

		if ps.logger.Level >= logrus.DebugLevel {
			ps.logProxyRequestDetails(req, "userinfo")
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.Host = target.Host

		// Disable gzip compression to ensure plaintext responses
		req.Header.Set("Accept-Encoding", "identity")

		// Add X-Forwarded headers
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", originalScheme)
		}
		if req.Header.Get("X-Forwarded-For") == "" {
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", originalHost)
		}

		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":   "userinfo",
			"final_url":       req.URL.String(),
			"final_host":      req.Host,
			"accept_encoding": req.Header.Get("Accept-Encoding"),
		}).Debug("Userinfo request URL transformation complete")
	}
}

// modifyTokenResponse logs detailed response information for token endpoint
func (ps *ProxyServer) modifyTokenResponse(resp *http.Response) error {
	if resp == nil {
		ps.logger.Error("Received nil response from token endpoint")
		return nil
	}

	// Read the response body for logging
	var responseBody []byte
	var responseBodyStr string
	if resp.Body != nil {
		var err error
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			ps.logger.WithError(err).Error("Failed to read token response body for logging")
		} else {
			// Convert to string handling UTF-8 encoding properly
			responseBodyStr = string(responseBody)
			// Restore the response body with a new reader
			resp.Body = io.NopCloser(strings.NewReader(responseBodyStr))

			ps.logger.WithFields(logrus.Fields{
				"endpoint_type":      "token",
				"body_bytes_length":  len(responseBody),
				"body_string_length": len(responseBodyStr),
				"body_is_utf8":       isValidUTF8(responseBodyStr),
			}).Debug("Response body reading completed")
		}
	}

	// Collect response headers
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		responseHeaders[key] = strings.Join(values, ", ")
	}

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type":         "token",
		"response_status":       resp.Status,
		"response_status_code":  resp.StatusCode,
		"response_headers":      responseHeaders,
		"response_body":         responseBodyStr,
		"response_length":       len(responseBodyStr),
		"response_bytes_length": len(responseBody),
		"content_type":          resp.Header.Get("Content-Type"),
		"cache_control":         resp.Header.Get("Cache-Control"),
		"expires":               resp.Header.Get("Expires"),
		"content_encoding":      resp.Header.Get("Content-Encoding"),
		"charset":               extractCharsetFromContentType(resp.Header.Get("Content-Type")),
	}).Debug("Token endpoint response details")

	// Log specific token response analysis for JSON content
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") && len(responseBodyStr) > 0 {
		ps.analyzeTokenResponse(responseBodyStr)
	} else if len(responseBodyStr) > 0 {
		// Log non-JSON responses with a preview
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":    "token",
			"response_preview": responseBodyStr[:min(500, len(responseBodyStr))],
			"is_json":          false,
		}).Debug("Non-JSON token response preview")
	}

	return nil
}

// analyzeTokenResponse analyzes and logs token response content
func (ps *ProxyServer) analyzeTokenResponse(responseBodyStr string) {
	// First, try to validate and pretty-print the JSON
	var jsonCheck interface{}
	if err := json.Unmarshal([]byte(responseBodyStr), &jsonCheck); err != nil {
		ps.logger.WithError(err).WithFields(logrus.Fields{
			"endpoint_type":        "token",
			"response_preview":     responseBodyStr[:min(200, len(responseBodyStr))],
			"response_full_length": len(responseBodyStr),
		}).Debug("Invalid JSON in token response")
		return
	}

	// Pretty print the JSON for better readability in debug logs
	if prettyJSON, err := json.MarshalIndent(jsonCheck, "", "  "); err == nil {
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type": "token",
			"pretty_json":   string(prettyJSON),
		}).Debug("Pretty-printed token response JSON")
	}

	// Now parse specifically for token analysis
	var tokenData map[string]interface{}
	if err := json.Unmarshal([]byte(responseBodyStr), &tokenData); err != nil {
		ps.logger.WithError(err).WithFields(logrus.Fields{
			"endpoint_type":    "token",
			"response_preview": responseBodyStr[:min(200, len(responseBodyStr))],
		}).Debug("Failed to parse token response as JSON object")
		return
	}

	// Log token response analysis
	analysis := logrus.Fields{
		"endpoint_type": "token",
	}

	// Check for standard OAuth2/OIDC fields
	if accessToken, ok := tokenData["access_token"].(string); ok {
		analysis["has_access_token"] = true
		analysis["access_token_length"] = len(accessToken)
		analysis["access_token_preview"] = accessToken[:min(20, len(accessToken))] + "..."
	}

	if refreshToken, ok := tokenData["refresh_token"].(string); ok {
		analysis["has_refresh_token"] = true
		analysis["refresh_token_length"] = len(refreshToken)
	}

	if idToken, ok := tokenData["id_token"].(string); ok {
		analysis["has_id_token"] = true
		analysis["id_token_length"] = len(idToken)
		analysis["id_token_preview"] = idToken[:min(50, len(idToken))] + "..."
	}

	if tokenType, ok := tokenData["token_type"].(string); ok {
		analysis["token_type"] = tokenType
	}

	if expiresIn, ok := tokenData["expires_in"].(float64); ok {
		analysis["expires_in_seconds"] = int(expiresIn)
	}

	if scope, ok := tokenData["scope"].(string); ok {
		analysis["scope"] = scope
	}

	// Check for error fields
	if errorCode, ok := tokenData["error"].(string); ok {
		analysis["error_code"] = errorCode
	}

	if errorDesc, ok := tokenData["error_description"].(string); ok {
		analysis["error_description"] = errorDesc
	}

	ps.logger.WithFields(analysis).Debug("Token response analysis")
}

// modifyUserinfoResponse logs detailed response information for userinfo endpoint
func (ps *ProxyServer) modifyUserinfoResponse(resp *http.Response) error {
	if resp == nil {
		ps.logger.Error("Received nil response from userinfo endpoint")
		return nil
	}

	// Read the response body for logging
	var responseBody []byte
	var responseBodyStr string
	if resp.Body != nil {
		var err error
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			ps.logger.WithError(err).Error("Failed to read userinfo response body for logging")
		} else {
			// Convert to string handling UTF-8 encoding properly
			responseBodyStr = string(responseBody)
			// Restore the response body with a new reader
			resp.Body = io.NopCloser(strings.NewReader(responseBodyStr))

			ps.logger.WithFields(logrus.Fields{
				"endpoint_type":      "userinfo",
				"body_bytes_length":  len(responseBody),
				"body_string_length": len(responseBodyStr),
				"body_is_utf8":       isValidUTF8(responseBodyStr),
			}).Debug("Response body reading completed")
		}
	}

	// Collect response headers
	responseHeaders := make(map[string]string)
	for key, values := range resp.Header {
		responseHeaders[key] = strings.Join(values, ", ")
	}

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type":         "userinfo",
		"response_status":       resp.Status,
		"response_status_code":  resp.StatusCode,
		"response_headers":      responseHeaders,
		"response_body":         responseBodyStr,
		"response_length":       len(responseBodyStr),
		"response_bytes_length": len(responseBody),
		"content_type":          resp.Header.Get("Content-Type"),
		"cache_control":         resp.Header.Get("Cache-Control"),
		"expires":               resp.Header.Get("Expires"),
		"content_encoding":      resp.Header.Get("Content-Encoding"),
		"charset":               extractCharsetFromContentType(resp.Header.Get("Content-Type")),
	}).Debug("Userinfo endpoint response details")

	// Log specific userinfo response analysis for JSON content
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") && len(responseBodyStr) > 0 {
		ps.analyzeUserinfoResponse(responseBodyStr)
	} else if len(responseBodyStr) > 0 {
		// Log non-JSON responses with a preview
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":    "userinfo",
			"response_preview": responseBodyStr[:min(500, len(responseBodyStr))],
			"is_json":          false,
		}).Debug("Non-JSON userinfo response preview")
	}

	return nil
}

// analyzeUserinfoResponse analyzes and logs userinfo response content
func (ps *ProxyServer) analyzeUserinfoResponse(responseBodyStr string) {
	// First, try to validate and pretty-print the JSON
	var jsonCheck interface{}
	if err := json.Unmarshal([]byte(responseBodyStr), &jsonCheck); err != nil {
		ps.logger.WithError(err).WithFields(logrus.Fields{
			"endpoint_type":        "userinfo",
			"response_preview":     responseBodyStr[:min(200, len(responseBodyStr))],
			"response_full_length": len(responseBodyStr),
		}).Debug("Invalid JSON in userinfo response")
		return
	}

	// Pretty print the JSON for better readability in debug logs
	if prettyJSON, err := json.MarshalIndent(jsonCheck, "", "  "); err == nil {
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type": "userinfo",
			"pretty_json":   string(prettyJSON),
		}).Debug("Pretty-printed userinfo response JSON")
	}

	// Now parse specifically for userinfo analysis
	var userinfoData map[string]interface{}
	if err := json.Unmarshal([]byte(responseBodyStr), &userinfoData); err != nil {
		ps.logger.WithError(err).WithFields(logrus.Fields{
			"endpoint_type":    "userinfo",
			"response_preview": responseBodyStr[:min(200, len(responseBodyStr))],
		}).Debug("Failed to parse userinfo response as JSON object")
		return
	}

	// Log userinfo response analysis
	analysis := logrus.Fields{
		"endpoint_type": "userinfo",
	}

	// Check for standard OIDC userinfo fields
	if sub, ok := userinfoData["sub"].(string); ok {
		analysis["subject"] = sub
	}

	if name, ok := userinfoData["name"].(string); ok {
		analysis["has_name"] = true
		analysis["name"] = name
	}

	if email, ok := userinfoData["email"].(string); ok {
		analysis["has_email"] = true
		analysis["email"] = email
	}

	if emailVerified, ok := userinfoData["email_verified"].(bool); ok {
		analysis["email_verified"] = emailVerified
	}

	if givenName, ok := userinfoData["given_name"].(string); ok {
		analysis["has_given_name"] = true
		analysis["given_name"] = givenName
	}

	if familyName, ok := userinfoData["family_name"].(string); ok {
		analysis["has_family_name"] = true
		analysis["family_name"] = familyName
	}

	if preferredUsername, ok := userinfoData["preferred_username"].(string); ok {
		analysis["has_preferred_username"] = true
		analysis["preferred_username"] = preferredUsername
	}

	if picture, ok := userinfoData["picture"].(string); ok {
		analysis["has_picture"] = true
		analysis["picture_url"] = picture
	}

	// Check for error fields
	if errorCode, ok := userinfoData["error"].(string); ok {
		analysis["error_code"] = errorCode
	}

	if errorDesc, ok := userinfoData["error_description"].(string); ok {
		analysis["error_description"] = errorDesc
	}

	// Count total fields
	analysis["total_fields"] = len(userinfoData)

	ps.logger.WithFields(analysis).Debug("Userinfo response analysis")
}

// buildRedirectURL constructs the redirect URL by preserving all query parameters
func (ps *ProxyServer) buildRedirectURL(targetEndpoint string, originalQuery url.Values) (string, error) {
	targetURL, err := url.Parse(targetEndpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse target endpoint: %w", err)
	}

	// Parse existing query parameters from target URL
	existingQuery := targetURL.Query()

	// Add original query parameters (original takes precedence if there are conflicts)
	for key, values := range originalQuery {
		for _, value := range values {
			existingQuery.Add(key, value)
		}
	}

	// Ensure "oidc" scope is present for proper OpenID Connect authentication
	ps.ensureOidcScope(&existingQuery)

	targetURL.RawQuery = existingQuery.Encode()
	return targetURL.String(), nil
}

// ensureOidcScope ensures that the "oidc" scope is included in the scope parameter
func (ps *ProxyServer) ensureOidcScope(query *url.Values) {
	scopeValues := (*query)["scope"]
	
	// Check if we have any scope parameters
	if len(scopeValues) == 0 {
		// No scope parameter exists, add "oidc" scope
		query.Set("scope", "oidc")
		ps.logger.WithField("action", "added_oidc_scope").Debug("Added 'oidc' scope to auth request (no existing scope)")
		return
	}

	// Check all scope values to see if "oidc" is already present
	var allScopes []string
	oidcPresent := false
	
	for _, scopeValue := range scopeValues {
		// Split scope value by spaces (standard OAuth2 scope separator)
		scopes := strings.Fields(scopeValue)
		for _, scope := range scopes {
			scope = strings.TrimSpace(scope)
			if scope == "oidc" {
				oidcPresent = true
			}
			if scope != "" {
				allScopes = append(allScopes, scope)
			}
		}
	}

	if !oidcPresent {
		// Add "oidc" to the list of scopes
		allScopes = append(allScopes, "oidc")
		
		// Replace all scope parameters with a single consolidated scope parameter
		query.Del("scope")
		query.Set("scope", strings.Join(allScopes, " "))
		
		ps.logger.WithFields(logrus.Fields{
			"action": "added_oidc_scope",
			"final_scopes": strings.Join(allScopes, " "),
		}).Debug("Added 'oidc' scope to existing scopes in auth request")
	} else {
		ps.logger.WithFields(logrus.Fields{
			"action": "oidc_scope_already_present",
			"existing_scopes": strings.Join(allScopes, " "),
		}).Debug("OIDC scope already present in auth request")
	}
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
	startTime := time.Now()

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type": "token",
		"original_path": r.URL.Path,
		"method":        r.Method,
		"remote_addr":   r.RemoteAddr,
		"user_agent":    r.UserAgent(),
		"query_params":  r.URL.RawQuery,
		"start_time":    startTime.Format(time.RFC3339Nano),
	}).Info("Proxying to token endpoint")

	// Create a response writer wrapper to capture response details
	if ps.logger.Level >= logrus.DebugLevel {
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     200, // default
			body:           &strings.Builder{},
		}

		ps.tokenProxy.ServeHTTP(wrappedWriter, r)

		duration := time.Since(startTime)
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":   "token",
			"duration_ms":     duration.Milliseconds(),
			"duration_ns":     duration.Nanoseconds(),
			"response_status": wrappedWriter.statusCode,
			"response_size":   wrappedWriter.body.Len(),
			"end_time":        time.Now().Format(time.RFC3339Nano),
		}).Debug("Token proxy request completed")
	} else {
		ps.tokenProxy.ServeHTTP(w, r)
		duration := time.Since(startTime)
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type": "token",
			"duration_ms":   duration.Milliseconds(),
		}).Info("Token proxy request completed")
	}
}

// handleUserinfo handles requests to /protocol/openid-connect/userinfo by proxying to userinfo endpoint
func (ps *ProxyServer) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	if ps.userinfoProxy == nil {
		ps.logger.Error("Userinfo proxy not configured")
		http.Error(w, "Userinfo endpoint not available", http.StatusNotImplemented)
		return
	}

	startTime := time.Now()

	ps.logger.WithFields(logrus.Fields{
		"endpoint_type":   "userinfo",
		"original_path":   r.URL.Path,
		"method":          r.Method,
		"remote_addr":     r.RemoteAddr,
		"user_agent":      r.UserAgent(),
		"query_params":    r.URL.RawQuery,
		"start_time":      startTime.Format(time.RFC3339Nano),
		"has_auth_header": r.Header.Get("Authorization") != "",
	}).Info("Proxying to userinfo endpoint")

	// Create a response writer wrapper to capture response details
	if ps.logger.Level >= logrus.DebugLevel {
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     200, // default
			body:           &strings.Builder{},
		}

		ps.userinfoProxy.ServeHTTP(wrappedWriter, r)

		duration := time.Since(startTime)
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":   "userinfo",
			"duration_ms":     duration.Milliseconds(),
			"duration_ns":     duration.Nanoseconds(),
			"response_status": wrappedWriter.statusCode,
			"response_size":   wrappedWriter.body.Len(),
			"end_time":        time.Now().Format(time.RFC3339Nano),
		}).Debug("Userinfo proxy request completed")
	} else {
		ps.userinfoProxy.ServeHTTP(w, r)
		duration := time.Since(startTime)
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type": "userinfo",
			"duration_ms":   duration.Milliseconds(),
		}).Info("Userinfo proxy request completed")
	}
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
	var bodyStr string
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		bodyStr = string(bodyBytes)
		req.Body = io.NopCloser(strings.NewReader(bodyStr))
	}

	// Collect all headers
	headers := make(map[string]string)
	for key, values := range req.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// Parse form data if present
	var formData map[string][]string
	var parsedBody interface{}
	contentType := req.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/x-www-form-urlencoded") && len(bodyStr) > 0 {
		if values, err := url.ParseQuery(bodyStr); err == nil {
			formData = values

			// Create a sanitized version for logging (hide sensitive data)
			sanitizedForm := make(map[string]string)
			for key, vals := range values {
				if ps.isSensitiveField(key) {
					sanitizedForm[key] = "[REDACTED]"
				} else {
					sanitizedForm[key] = strings.Join(vals, ", ")
				}
			}
			parsedBody = sanitizedForm
		}
	} else if strings.Contains(contentType, "application/json") && len(bodyStr) > 0 {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(bodyStr), &jsonData); err == nil {
			// Sanitize sensitive fields in JSON
			sanitizedJson := make(map[string]interface{})
			for key, value := range jsonData {
				if ps.isSensitiveField(key) {
					sanitizedJson[key] = "[REDACTED]"
				} else {
					sanitizedJson[key] = value
				}
			}
			parsedBody = sanitizedJson
		} else {
			ps.logger.WithError(err).WithFields(logrus.Fields{
				"endpoint_type": endpointType,
				"content_type":  contentType,
				"body_preview":  bodyStr[:min(200, len(bodyStr))],
			}).Debug("Failed to parse request body as JSON")
		}
	}

	// Log comprehensive request details
	ps.logger.WithFields(logrus.Fields{
		"endpoint_type":     endpointType,
		"method":            req.Method,
		"url":               req.URL.String(),
		"raw_query":         req.URL.RawQuery,
		"headers":           headers,
		"content_type":      contentType,
		"content_length":    req.ContentLength,
		"transfer_encoding": req.TransferEncoding,
		"host":              req.Host,
		"remote_addr":       req.RemoteAddr,
		"request_uri":       req.RequestURI,
		"proto":             req.Proto,
		"proto_major":       req.ProtoMajor,
		"proto_minor":       req.ProtoMinor,
		"body_raw":          bodyStr,
		"body_length":       len(bodyStr),
		"body_bytes_length": len(bodyBytes),
		"body_is_utf8":      isValidUTF8(bodyStr),
		"charset":           extractCharsetFromContentType(contentType),
		"parsed_body":       parsedBody,
		"form_data_fields":  len(formData),
		"has_auth_header":   req.Header.Get("Authorization") != "",
		"user_agent":        req.UserAgent(),
		"referer":           req.Header.Get("Referer"),
		"origin":            req.Header.Get("Origin"),
	}).Debug("Detailed proxy request information")

	// Log query parameters separately if they exist
	if len(req.URL.Query()) > 0 {
		queryParams := make(map[string]string)
		for key, values := range req.URL.Query() {
			if ps.isSensitiveField(key) {
				queryParams[key] = "[REDACTED]"
			} else {
				queryParams[key] = strings.Join(values, ", ")
			}
		}
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type":    endpointType,
			"query_parameters": queryParams,
		}).Debug("Query parameters details")
	}

	// Log cookies if present
	if len(req.Cookies()) > 0 {
		cookieDetails := make(map[string]string)
		for _, cookie := range req.Cookies() {
			if ps.isSensitiveField(cookie.Name) {
				cookieDetails[cookie.Name] = "[REDACTED]"
			} else {
				cookieDetails[cookie.Name] = cookie.Value
			}
		}
		ps.logger.WithFields(logrus.Fields{
			"endpoint_type": endpointType,
			"cookies":       cookieDetails,
		}).Debug("Request cookies")
	}
}

// isSensitiveField checks if a field name contains sensitive information
func (ps *ProxyServer) isSensitiveField(fieldName string) bool {
	sensitiveFields := []string{
		"password", "client_secret", "refresh_token", "access_token",
		"id_token", "authorization", "auth", "secret", "key", "token",
		"credential", "pass", "pwd",
	}

	fieldLower := strings.ToLower(fieldName)
	for _, sensitive := range sensitiveFields {
		if strings.Contains(fieldLower, sensitive) {
			return true
		}
	}
	return false
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
	mux.HandleFunc("/protocol/openid-connect/userinfo", ps.handleUserinfo)
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
		Addr:         ":" + port,
		Handler:      mux,
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
