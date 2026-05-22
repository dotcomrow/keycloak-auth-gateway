package main

import (
	"net/url"
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

