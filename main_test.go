package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseAllowedOrigins_All(t *testing.T) {
	allowAll, exact, patterns := parseAllowedOrigins("https://a.suncoast.systems,*")
	if !allowAll {
		t.Fatalf("expected allowAll=true")
	}
	if len(exact) != 0 {
		t.Fatalf("expected no exact origins when allowAll=true")
	}
	if len(patterns) != 0 {
		t.Fatalf("expected no patterns when allowAll=true")
	}
}

func TestParseAllowedOrigins_PatternsAndExact(t *testing.T) {
	allowAll, exact, patterns := parseAllowedOrigins("https://app.suncoast.systems,*.suncoast.systems,localhost")
	if allowAll {
		t.Fatalf("expected allowAll=false")
	}
	if _, ok := exact["https://app.suncoast.systems"]; !ok {
		t.Fatalf("missing exact origin")
	}
	if len(patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(patterns))
	}
}

func TestOriginMatchesPattern_WildcardAndLocalhost(t *testing.T) {
	allowAll, exact, patterns := parseAllowedOrigins("*.suncoast.systems,localhost")
	s := server{
		cfg: config{
			CORSAllowAll:        allowAll,
			CORSAllowedOrigins:  exact,
			CORSAllowedPatterns: patterns,
		},
	}

	cases := []struct {
		origin  string
		allowed bool
	}{
		{origin: "https://external.suncoast.systems", allowed: true},
		{origin: "http://external.suncoast.systems", allowed: true},
		{origin: "https://foo.bar.suncoast.systems", allowed: true},
		{origin: "https://suncoast.systems", allowed: false},
		{origin: "https://example.com", allowed: false},
		{origin: "http://localhost:4173", allowed: true},
		{origin: "https://localhost", allowed: true},
		{origin: "http://127.0.0.1:4173", allowed: false},
	}

	for _, tc := range cases {
		got := s.isOriginAllowed(tc.origin)
		if got != tc.allowed {
			t.Fatalf("origin=%q expected %t got %t", tc.origin, tc.allowed, got)
		}
	}
}

func TestOriginMatchesPattern_SchemeAndPort(t *testing.T) {
	pattern, ok := parseOriginPattern("https://*.suncoast.systems:8443")
	if !ok {
		t.Fatalf("expected pattern parse success")
	}

	parseOrigin := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("failed to parse origin %q: %v", raw, err)
		}
		return u
	}

	if !originMatchesPattern(parseOrigin("https://app.suncoast.systems:8443"), pattern) {
		t.Fatalf("expected https://app.suncoast.systems:8443 to match")
	}
	if originMatchesPattern(parseOrigin("https://app.suncoast.systems"), pattern) {
		t.Fatalf("expected default https port to not match explicit 8443 pattern")
	}
	if originMatchesPattern(parseOrigin("http://app.suncoast.systems:8443"), pattern) {
		t.Fatalf("expected http scheme to not match https pattern")
	}
}

func TestExchangeAuthorizationCodeRetriesTransientTokenEndpointFailure(t *testing.T) {
	var attempts int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protocol/openid-connect/token" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("unexpected content-type %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if values.Get("grant_type") != "authorization_code" {
			t.Fatalf("unexpected grant_type %q", values.Get("grant_type"))
		}
		if values.Get("code") != "auth-code" {
			t.Fatalf("unexpected code %q", values.Get("code"))
		}

		if atomic.AddInt32(&attempts, 1) == 1 {
			http.Error(w, `{"error":"unknown_error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access","id_token":"id","expires_in":900}`))
	}))
	defer tokenServer.Close()

	s := server{
		cfg: config{
			Issuer:          tokenServer.URL,
			ClientID:        "auth-gateway-public",
			ClientSecret:    "secret",
			ExternalBaseURL: "https://login-internal.suncoast.systems",
			CallbackPath:    "/callback",
		},
		http:   tokenServer.Client(),
		logger: log.New(io.Discard, "", 0),
	}

	tokens, err := s.exchangeAuthorizationCode(context.Background(), "auth-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeAuthorizationCode returned error: %v", err)
	}
	if tokens.AccessToken != "access" {
		t.Fatalf("unexpected access token %q", tokens.AccessToken)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

func TestExchangeAuthorizationCodeDoesNotRetryInvalidGrant(t *testing.T) {
	var attempts int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	s := server{
		cfg: config{
			Issuer:          tokenServer.URL,
			ClientID:        "auth-gateway-public",
			ExternalBaseURL: "https://login-internal.suncoast.systems",
			CallbackPath:    "/callback",
		},
		http:   tokenServer.Client(),
		logger: log.New(io.Discard, "", 0),
	}

	_, err := s.exchangeAuthorizationCode(context.Background(), "auth-code", "verifier")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected status in error, got %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("expected 1 attempt, got %d", got)
	}
}
