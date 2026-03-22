package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

var (
	errNotFound = errors.New("not found")
	errExpired  = errors.New("expired")
)

type config struct {
	ListenAddr         string
	DatabaseURL        string
	ExternalBaseURL    string
	CallbackPath       string
	Issuer             string
	ClientID           string
	ClientSecret       string
	Scope              string
	StateTTL           time.Duration
	ExchangeCodeTTL    time.Duration
	CleanupInterval    time.Duration
	AppCodeParam       string
	AdminAPIToken      string
	CORSAllowAll       bool
	CORSAllowedOrigins map[string]struct{}
}

type server struct {
	cfg    config
	db     *sql.DB
	http   *http.Client
	logger *log.Logger
}

type appRecord struct {
	Slug        string    `json:"slug"`
	DisplayName string    `json:"display_name"`
	BaseURL     string    `json:"base_url"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type createAppRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	BaseURL     string `json:"base_url"`
	Enabled     *bool  `json:"enabled"`
}

type updateAppRequest struct {
	DisplayName string `json:"display_name"`
	BaseURL     string `json:"base_url"`
	Enabled     *bool  `json:"enabled"`
}

type stateRecord struct {
	AppSlug      string
	ReturnTo     string
	CodeVerifier string
	Nonce        string
	ExpiresAt    time.Time
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type exchangeResponse struct {
	AppSlug      string    `json:"app_slug"`
	Subject      string    `json:"subject,omitempty"`
	AccessToken  string    `json:"access_token"`
	IDToken      string    `json:"id_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	logger := log.New(os.Stdout, "auth-gateway ", log.LstdFlags|log.LUTC)

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		logger.Fatalf("open database: %v", err)
	}
	defer db.Close()

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		logger.Fatalf("database ping failed: %v", err)
	}

	s := &server{
		cfg:    cfg,
		db:     db,
		http:   &http.Client{Timeout: 15 * time.Second},
		logger: logger,
	}

	if err := s.initSchema(context.Background()); err != nil {
		logger.Fatalf("init schema failed: %v", err)
	}

	if cfg.AdminAPIToken == "" {
		logger.Printf("warning: ADMIN_API_TOKEN not set; app management APIs are open")
	}

	shutdownCtx, shutdownCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer shutdownCancel()
	go s.cleanupLoop(shutdownCtx)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/start", s.handleStart)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/v1/auth/exchange", s.handleExchange)
	mux.HandleFunc("/v1/apps", s.withAdminAuth(s.handleApps))
	mux.HandleFunc("/v1/apps/", s.withAdminAuth(s.handleAppBySlug))

	handler := s.withCORS(mux)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		s.logger.Printf("listening on %s", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fatalf("server error: %v", err)
		}
	}()

	<-shutdownCtx.Done()
	s.logger.Printf("shutdown signal received")

	sdCtx, sdCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer sdCancel()
	if err := server.Shutdown(sdCtx); err != nil {
		s.logger.Printf("graceful shutdown failed: %v", err)
	}
}

func loadConfig() (config, error) {
	cfg := config{
		ListenAddr:      getEnv("LISTEN_ADDR", ":8080"),
		ExternalBaseURL: strings.TrimRight(getEnv("EXTERNAL_BASE_URL", "https://login.suncoast.systems"), "/"),
		CallbackPath:    normalizeCallbackPath(getEnv("CALLBACK_PATH", "/callback")),
		Issuer:          strings.TrimRight(getEnv("KEYCLOAK_ISSUER", "https://auth.suncoast.systems/realms/external"), "/"),
		ClientID:        getEnv("OIDC_CLIENT_ID", "auth-gateway-public"),
		Scope:           getEnv("OIDC_SCOPE", "openid profile email"),
		StateTTL:        parseDurationEnv("STATE_TTL", 10*time.Minute),
		ExchangeCodeTTL: parseDurationEnv("EXCHANGE_CODE_TTL", 2*time.Minute),
		CleanupInterval: parseDurationEnv("CLEANUP_INTERVAL", 5*time.Minute),
		AppCodeParam:    getEnv("APP_CODE_PARAM", "gateway_code"),
	}

	if cfg.AppCodeParam == "" {
		cfg.AppCodeParam = "gateway_code"
	}

	if !isValidExternalBaseURL(cfg.ExternalBaseURL) {
		return cfg, fmt.Errorf("invalid EXTERNAL_BASE_URL: %q", cfg.ExternalBaseURL)
	}

	if !strings.HasPrefix(cfg.Issuer, "http://") && !strings.HasPrefix(cfg.Issuer, "https://") {
		return cfg, fmt.Errorf("KEYCLOAK_ISSUER must be absolute URL")
	}
	if cfg.ClientID == "" {
		return cfg, fmt.Errorf("OIDC_CLIENT_ID is required")
	}

	clientSecret, err := envOrFile("OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET_FILE")
	if err != nil {
		return cfg, err
	}
	cfg.ClientSecret = clientSecret

	adminToken, err := envOrFile("ADMIN_API_TOKEN", "ADMIN_API_TOKEN_FILE")
	if err != nil {
		return cfg, err
	}
	cfg.AdminAPIToken = adminToken

	cfg.CORSAllowAll, cfg.CORSAllowedOrigins = parseAllowedOrigins(getEnv("CORS_ALLOW_ORIGINS", ""))

	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		dsn, err = buildDSNFromComponents()
		if err != nil {
			return cfg, err
		}
	}
	cfg.DatabaseURL = dsn

	return cfg, nil
}

func buildDSNFromComponents() (string, error) {
	host := getEnv("DB_HOST", "yb-tserver-service.yugabyte.svc.cluster.local")
	port := getEnv("DB_PORT", "5433")
	name := getEnv("DB_NAME", "keycloak")
	sslMode := getEnv("DB_SSLMODE", "disable")
	searchPath := getEnv("DB_SEARCH_PATH", "keycloak")

	user, err := envOrFile("DB_USER", "DB_USER_FILE")
	if err != nil {
		return "", err
	}
	pass, err := envOrFile("DB_PASSWORD", "DB_PASSWORD_FILE")
	if err != nil {
		return "", err
	}
	if user == "" || pass == "" {
		return "", fmt.Errorf("database credentials missing: set DATABASE_URL or DB_USER/DB_PASSWORD (or *_FILE)")
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, pass),
		Host:   fmt.Sprintf("%s:%s", host, port),
		Path:   "/" + name,
	}
	q := u.Query()
	q.Set("sslmode", sslMode)
	if searchPath != "" {
		q.Set("search_path", searchPath)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *server) initSchema(ctx context.Context) error {
	const schemaSQL = `
CREATE TABLE IF NOT EXISTS auth_gateway_allowed_apps (
  id BIGSERIAL PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_gateway_login_state (
  state TEXT PRIMARY KEY,
  app_slug TEXT NOT NULL REFERENCES auth_gateway_allowed_apps(slug) ON DELETE CASCADE,
  return_to TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_gateway_exchange_codes (
  code TEXT PRIMARY KEY,
  app_slug TEXT NOT NULL REFERENCES auth_gateway_allowed_apps(slug) ON DELETE CASCADE,
  subject TEXT,
  access_token TEXT NOT NULL,
  id_token TEXT,
  refresh_token TEXT,
  token_type TEXT,
  expires_in INTEGER,
  scope TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS auth_gateway_allowed_apps_enabled_idx
  ON auth_gateway_allowed_apps(enabled);

CREATE INDEX IF NOT EXISTS auth_gateway_login_state_expires_idx
  ON auth_gateway_login_state(expires_at);

CREATE INDEX IF NOT EXISTS auth_gateway_exchange_codes_expires_idx
  ON auth_gateway_exchange_codes(expires_at);
`

	_, err := s.db.ExecContext(ctx, schemaSQL)
	return err
}

func (s *server) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.cleanupExpired(context.Background()); err != nil {
				s.logger.Printf("cleanup failed: %v", err)
			}
		}
	}
}

func (s *server) cleanupExpired(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_gateway_login_state WHERE expires_at < NOW()`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
DELETE FROM auth_gateway_exchange_codes
WHERE expires_at < NOW() OR (consumed_at IS NOT NULL AND consumed_at < NOW() - INTERVAL '1 day')`)
	return err
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	appSlug := strings.TrimSpace(r.URL.Query().Get("app"))
	if appSlug == "" {
		writeError(w, http.StatusBadRequest, "missing app query parameter")
		return
	}

	app, err := s.getApp(r.Context(), appSlug)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, "app not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load app")
		return
	}
	if !app.Enabled {
		writeError(w, http.StatusForbidden, "app is disabled")
		return
	}

	returnTo, err := normalizeReturnTo(app.BaseURL, strings.TrimSpace(r.URL.Query().Get("return_to")))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	state, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}
	codeVerifier, err := randomToken(64)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate verifier")
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate nonce")
		return
	}

	expiresAt := time.Now().UTC().Add(s.cfg.StateTTL)
	if err := s.insertState(r.Context(), stateRecord{
		AppSlug:      appSlug,
		ReturnTo:     returnTo,
		CodeVerifier: codeVerifier,
		Nonce:        nonce,
		ExpiresAt:    expiresAt,
	}, state); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist login state")
		return
	}

	authorizeURL := s.buildAuthorizeURL(state, nonce, codeVerifier)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if oidcErr := strings.TrimSpace(r.URL.Query().Get("error")); oidcErr != "" {
		desc := strings.TrimSpace(r.URL.Query().Get("error_description"))
		if desc == "" {
			desc = "identity provider returned error"
		}
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s: %s", oidcErr, desc))
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, "missing state or code")
		return
	}

	st, err := s.consumeState(r.Context(), state)
	if err != nil {
		if errors.Is(err, errNotFound) || errors.Is(err, errExpired) {
			writeError(w, http.StatusBadRequest, "invalid or expired state")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to validate state")
		return
	}

	tokens, err := s.exchangeAuthorizationCode(r.Context(), code, st.CodeVerifier)
	if err != nil {
		s.logger.Printf("token exchange failed: %v", err)
		writeError(w, http.StatusBadGateway, "token exchange failed")
		return
	}

	exchangeCode, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate exchange code")
		return
	}

	subject := extractSubject(tokens.IDToken)
	expiresAt := time.Now().UTC().Add(s.cfg.ExchangeCodeTTL)
	if err := s.insertExchangeCode(r.Context(), exchangeCode, st.AppSlug, subject, tokens, expiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist exchange code")
		return
	}

	redirectURL, err := addQueryParam(st.ReturnTo, s.cfg.AppCodeParam, exchangeCode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build return redirect")
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *server) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Code    string `json:"code"`
		AppSlug string `json:"app_slug"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	req.AppSlug = strings.TrimSpace(req.AppSlug)
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	resp, err := s.consumeExchangeCode(r.Context(), req.Code)
	if err != nil {
		if errors.Is(err, errNotFound) || errors.Is(err, errExpired) {
			writeError(w, http.StatusBadRequest, "invalid or expired code")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to consume code")
		return
	}

	if req.AppSlug != "" && req.AppSlug != resp.AppSlug {
		writeError(w, http.StatusForbidden, "code does not belong to requested app")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		apps, err := s.listApps(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list apps")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
	case http.MethodPost:
		var req createAppRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		app, err := validateAndBuildCreate(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		created, err := s.createApp(r.Context(), app)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				writeError(w, http.StatusConflict, "app slug already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to create app")
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) handleAppBySlug(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/v1/apps/")
	slug = strings.TrimSpace(slug)
	if slug == "" || strings.Contains(slug, "/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		app, err := s.getApp(r.Context(), slug)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "app not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load app")
			return
		}
		writeJSON(w, http.StatusOK, app)
	case http.MethodPut:
		var req updateAppRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		upd, err := validateAndBuildUpdate(slug, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		updated, err := s.updateApp(r.Context(), upd)
		if err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "app not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to update app")
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if err := s.deleteApp(r.Context(), slug); err != nil {
			if errors.Is(err, errNotFound) {
				writeError(w, http.StatusNotFound, "app not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to delete app")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *server) listApps(ctx context.Context) ([]appRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT slug, display_name, base_url, enabled, created_at, updated_at
FROM auth_gateway_allowed_apps
ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apps := make([]appRecord, 0)
	for rows.Next() {
		var a appRecord
		if err := rows.Scan(&a.Slug, &a.DisplayName, &a.BaseURL, &a.Enabled, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func (s *server) getApp(ctx context.Context, slug string) (appRecord, error) {
	var a appRecord
	err := s.db.QueryRowContext(ctx, `
SELECT slug, display_name, base_url, enabled, created_at, updated_at
FROM auth_gateway_allowed_apps
WHERE slug=$1`, slug).Scan(&a.Slug, &a.DisplayName, &a.BaseURL, &a.Enabled, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appRecord{}, errNotFound
		}
		return appRecord{}, err
	}
	return a, nil
}

func (s *server) createApp(ctx context.Context, app appRecord) (appRecord, error) {
	var out appRecord
	err := s.db.QueryRowContext(ctx, `
INSERT INTO auth_gateway_allowed_apps (slug, display_name, base_url, enabled)
VALUES ($1,$2,$3,$4)
RETURNING slug, display_name, base_url, enabled, created_at, updated_at`,
		app.Slug, app.DisplayName, app.BaseURL, app.Enabled,
	).Scan(&out.Slug, &out.DisplayName, &out.BaseURL, &out.Enabled, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		return appRecord{}, err
	}
	return out, nil
}

func (s *server) updateApp(ctx context.Context, app appRecord) (appRecord, error) {
	var out appRecord
	err := s.db.QueryRowContext(ctx, `
UPDATE auth_gateway_allowed_apps
SET display_name=$2, base_url=$3, enabled=$4, updated_at=NOW()
WHERE slug=$1
RETURNING slug, display_name, base_url, enabled, created_at, updated_at`,
		app.Slug, app.DisplayName, app.BaseURL, app.Enabled,
	).Scan(&out.Slug, &out.DisplayName, &out.BaseURL, &out.Enabled, &out.CreatedAt, &out.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return appRecord{}, errNotFound
		}
		return appRecord{}, err
	}
	return out, nil
}

func (s *server) deleteApp(ctx context.Context, slug string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_gateway_allowed_apps WHERE slug=$1`, slug)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errNotFound
	}
	return nil
}

func (s *server) insertState(ctx context.Context, state stateRecord, rawState string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO auth_gateway_login_state (state, app_slug, return_to, code_verifier, nonce, expires_at)
VALUES ($1,$2,$3,$4,$5,$6)`, rawState, state.AppSlug, state.ReturnTo, state.CodeVerifier, state.Nonce, state.ExpiresAt)
	return err
}

func (s *server) consumeState(ctx context.Context, rawState string) (stateRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return stateRecord{}, err
	}
	defer tx.Rollback()

	var st stateRecord
	err = tx.QueryRowContext(ctx, `
SELECT app_slug, return_to, code_verifier, nonce, expires_at
FROM auth_gateway_login_state
WHERE state=$1`, rawState).Scan(&st.AppSlug, &st.ReturnTo, &st.CodeVerifier, &st.Nonce, &st.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return stateRecord{}, errNotFound
		}
		return stateRecord{}, err
	}

	_, _ = tx.ExecContext(ctx, `DELETE FROM auth_gateway_login_state WHERE state=$1`, rawState)

	if time.Now().UTC().After(st.ExpiresAt) {
		if err := tx.Commit(); err != nil {
			return stateRecord{}, err
		}
		return stateRecord{}, errExpired
	}

	if err := tx.Commit(); err != nil {
		return stateRecord{}, err
	}
	return st, nil
}

func (s *server) insertExchangeCode(ctx context.Context, code, appSlug, subject string, tokens tokenResponse, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO auth_gateway_exchange_codes (
  code, app_slug, subject, access_token, id_token, refresh_token, token_type, expires_in, scope, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		code, appSlug, subject, tokens.AccessToken, tokens.IDToken, tokens.RefreshToken, tokens.TokenType, tokens.ExpiresIn, tokens.Scope, expiresAt)
	return err
}

func (s *server) consumeExchangeCode(ctx context.Context, code string) (exchangeResponse, error) {
	var resp exchangeResponse
	err := s.db.QueryRowContext(ctx, `
UPDATE auth_gateway_exchange_codes
SET consumed_at = NOW()
WHERE code=$1
  AND consumed_at IS NULL
  AND expires_at > NOW()
RETURNING app_slug, subject, access_token, id_token, refresh_token, token_type, expires_in, scope, expires_at`, code).
		Scan(&resp.AppSlug, &resp.Subject, &resp.AccessToken, &resp.IDToken, &resp.RefreshToken, &resp.TokenType, &resp.ExpiresIn, &resp.Scope, &resp.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return exchangeResponse{}, errNotFound
		}
		return exchangeResponse{}, err
	}
	return resp, nil
}

func (s *server) exchangeAuthorizationCode(ctx context.Context, code, codeVerifier string) (tokenResponse, error) {
	endpoint := s.cfg.Issuer + "/protocol/openid-connect/token"
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", s.cfg.ClientID)
	form.Set("redirect_uri", s.redirectURI())
	form.Set("code_verifier", codeVerifier)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.http.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return tokenResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("token endpoint returned %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var out tokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return tokenResponse{}, err
	}
	if out.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("token response missing access_token")
	}
	return out, nil
}

func (s *server) buildAuthorizeURL(state, nonce, codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	u, _ := url.Parse(s.cfg.Issuer + "/protocol/openid-connect/auth")
	q := u.Query()
	q.Set("client_id", s.cfg.ClientID)
	q.Set("redirect_uri", s.redirectURI())
	q.Set("response_type", "code")
	q.Set("scope", s.cfg.Scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *server) redirectURI() string {
	return strings.TrimRight(s.cfg.ExternalBaseURL, "/") + s.cfg.CallbackPath
}

func (s *server) withAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	if strings.TrimSpace(s.cfg.AdminAPIToken) == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if token != s.cfg.AdminAPIToken {
			writeError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		next(w, r)
	}
}

func (s *server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if !s.isOriginAllowed(origin) {
				if r.Method == http.MethodOptions {
					writeError(w, http.StatusForbidden, "origin not allowed")
					return
				}
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				addVaryHeader(w.Header(), "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) isOriginAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	if s.cfg.CORSAllowAll {
		return true
	}
	_, ok := s.cfg.CORSAllowedOrigins[origin]
	return ok
}

func validateAndBuildCreate(req createAppRequest) (appRecord, error) {
	slug := strings.TrimSpace(strings.ToLower(req.Slug))
	if !slugRE.MatchString(slug) {
		return appRecord{}, fmt.Errorf("slug must match %s", slugRE.String())
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return appRecord{}, fmt.Errorf("display_name is required")
	}
	baseURL, err := normalizeBaseURL(req.BaseURL)
	if err != nil {
		return appRecord{}, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return appRecord{Slug: slug, DisplayName: displayName, BaseURL: baseURL, Enabled: enabled}, nil
}

func validateAndBuildUpdate(slug string, req updateAppRequest) (appRecord, error) {
	slug = strings.TrimSpace(strings.ToLower(slug))
	if !slugRE.MatchString(slug) {
		return appRecord{}, fmt.Errorf("invalid slug")
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return appRecord{}, fmt.Errorf("display_name is required")
	}
	baseURL, err := normalizeBaseURL(req.BaseURL)
	if err != nil {
		return appRecord{}, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return appRecord{Slug: slug, DisplayName: displayName, BaseURL: baseURL, Enabled: enabled}, nil
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("base_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid base_url")
	}
	if !u.IsAbs() {
		return "", fmt.Errorf("base_url must be absolute")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("base_url scheme must be http or https")
	}
	if u.Host == "" {
		return "", fmt.Errorf("base_url host is required")
	}
	u.RawQuery = ""
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func normalizeReturnTo(baseRaw, returnRaw string) (string, error) {
	base, err := url.Parse(baseRaw)
	if err != nil {
		return "", fmt.Errorf("configured base_url is invalid")
	}

	if strings.TrimSpace(returnRaw) == "" {
		return base.String(), nil
	}

	candidate, err := url.Parse(strings.TrimSpace(returnRaw))
	if err != nil {
		return "", fmt.Errorf("return_to is invalid")
	}

	if candidate.IsAbs() {
		if !sameOrigin(base, candidate) {
			return "", fmt.Errorf("return_to host is not allowed")
		}
		if !pathAllowed(base.Path, candidate.Path) {
			return "", fmt.Errorf("return_to path is outside app base_url")
		}
		return candidate.String(), nil
	}

	if !strings.HasPrefix(returnRaw, "/") {
		return "", fmt.Errorf("relative return_to must start with '/'")
	}
	if !pathAllowed(base.Path, candidate.Path) {
		return "", fmt.Errorf("return_to path is outside app base_url")
	}

	resolved := &url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     candidate.Path,
		RawQuery: candidate.RawQuery,
		Fragment: candidate.Fragment,
	}
	return resolved.String(), nil
}

func pathAllowed(basePath, candidatePath string) bool {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		basePath = "/"
	}
	if basePath == "/" {
		return true
	}
	if candidatePath == "" {
		candidatePath = "/"
	}
	if candidatePath == basePath {
		return true
	}
	return strings.HasPrefix(candidatePath, strings.TrimRight(basePath, "/")+"/")
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func addQueryParam(rawURL, key, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func extractSubject(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	sub, _ := claims["sub"].(string)
	return sub
}

func randomToken(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func parseAllowedOrigins(raw string) (bool, map[string]struct{}) {
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "*" {
			return true, map[string]struct{}{}
		}
		out[part] = struct{}{}
	}
	return false, out
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func addVaryHeader(h http.Header, value string) {
	existing := h.Get("Vary")
	if existing == "" {
		h.Set("Vary", value)
		return
	}
	for _, part := range strings.Split(existing, ",") {
		if strings.TrimSpace(part) == value {
			return
		}
	}
	h.Set("Vary", existing+", "+value)
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func normalizeCallbackPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/callback"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func isValidExternalBaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	return u.Host != ""
}

func envOrFile(envKey, fileEnvKey string) (string, error) {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v, nil
	}
	path := strings.TrimSpace(os.Getenv(fileEnvKey))
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileEnvKey, err)
	}
	return strings.TrimSpace(string(b)), nil
}
