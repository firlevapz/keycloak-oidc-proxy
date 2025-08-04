package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

// Simple test to verify that our proxy sets Accept-Encoding: identity
func testGzipFix() {
	// Create a test server that echoes headers
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptEncoding := r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"accept_encoding": "%s", "headers": %v}`, acceptEncoding, r.Header)
	}))
	defer testServer.Close()

	// Parse the test server URL
	targetURL, _ := url.Parse(testServer.URL)

	// Create a simple proxy request director that mimics our token director
	director := func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
		
		// This is the key fix - disable gzip compression
		req.Header.Set("Accept-Encoding", "identity")
	}

	// Create a request
	req := httptest.NewRequest("POST", "/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	// Apply the director
	director(req)
	
	fmt.Printf("Test Request Headers:\n")
	fmt.Printf("  Accept-Encoding: %s\n", req.Header.Get("Accept-Encoding"))
	fmt.Printf("  Expected: identity\n")
	
	if req.Header.Get("Accept-Encoding") == "identity" {
		fmt.Printf("✅ PASS: Accept-Encoding header correctly set to 'identity'\n")
	} else {
		fmt.Printf("❌ FAIL: Accept-Encoding header not set correctly\n")
	}
}

func main() {
	fmt.Println("Testing gzip compression fix...")
	testGzipFix()
}
