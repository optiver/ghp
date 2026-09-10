package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
)

// newTestStore returns an in-memory SQLite store with migrations applied.
// Used by handler tests that need real session/oauth_state/device_auth
// persistence (which is now everything that touches a Handler).
func newTestStore(t *testing.T) database.Store {
	t.Helper()
	store, err := database.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mig := database.NewMigrator(store, "sqlite")
	if err := mig.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return store
}

func TestSecureCookies(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		want    bool
	}{
		{
			name: "no TLS, no BaseURL",
			cfg:  &config.Config{},
			want: false,
		},
		{
			name: "https BaseURL",
			cfg: &config.Config{
				Server: config.ServerConfig{BaseURL: "https://example.com"},
			},
			want: true,
		},
		{
			name: "http BaseURL",
			cfg: &config.Config{
				Server: config.ServerConfig{BaseURL: "http://example.com"},
			},
			want: false,
		},
		{
			name: "TLS certificates configured",
			cfg: &config.Config{
				TLS: config.TLSConfig{
					Certificates: []config.CertificateConfig{
						{CertFile: "cert.pem", KeyFile: "key.pem"},
					},
				},
			},
			want: true,
		},
		{
			name: "TLS configured and http BaseURL",
			cfg: &config.Config{
				Server: config.ServerConfig{BaseURL: "http://example.com"},
				TLS: config.TLSConfig{
					Certificates: []config.CertificateConfig{
						{CertFile: "cert.pem", KeyFile: "key.pem"},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(tt.cfg, newTestStore(t), nil, slog.Default())
			got := h.secureCookies()
			if got != tt.want {
				t.Errorf("secureCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleTestLogin_BodyTooLarge(t *testing.T) {
	cfg := &config.Config{DevMode: true}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	// Body must be valid-looking JSON so the decoder reads past the 1 MB limit.
	body := strings.NewReader(`{"username":"` + strings.Repeat("x", maxRequestBodySize) + `"}`)
	req := httptest.NewRequest("POST", "/auth/test-login", body)
	w := httptest.NewRecorder()
	h.handleTestLogin(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected %d, got %d", http.StatusRequestEntityTooLarge, w.Code)
	}
}

func TestHandleTestLogin_InvalidJSON(t *testing.T) {
	cfg := &config.Config{DevMode: true}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("POST", "/auth/test-login", strings.NewReader("not valid json"))
	w := httptest.NewRecorder()
	h.handleTestLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestExchangeCode_URLEncoding verifies that special characters in client_id,
// client_secret, code, and redirect_uri are correctly percent-encoded in the
// application/x-www-form-urlencoded request body sent to GitHub.
func TestExchangeCode_URLEncoding(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		code         string
		redirectURI  string
	}{
		{
			name:         "ampersand in client_secret",
			clientID:     "id&injected=1",
			clientSecret: "secret&extra=bad",
			code:         "code123",
		},
		{
			name:         "equals sign in code",
			clientID:     "myid",
			clientSecret: "mysecret",
			code:         "code=broken",
		},
		{
			name:         "plus sign in client_id",
			clientID:     "id+plus",
			clientSecret: "secret",
			code:         "abc",
		},
		{
			name:         "special chars in redirect_uri",
			clientID:     "myid",
			clientSecret: "mysecret",
			code:         "abc",
			redirectURI:  "https://app.example.com/cb?foo=bar&baz=qux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedBody string
			ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				capturedBody = string(raw)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "gho_test",
					"expires_in":   28800,
				})
			}))
			defer ghServer.Close()

			cfg := &config.Config{
				GitHub: config.GitHubConfig{
					ClientID:     tt.clientID,
					ClientSecret: tt.clientSecret,
				},
			}
			h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
			h.githubBaseURL = ghServer.URL

			_, _, _, err := h.exchangeCode(context.Background(), tt.code, tt.redirectURI)
			if err != nil {
				t.Fatalf("exchangeCode returned error: %v", err)
			}

			parsed, err := url.ParseQuery(capturedBody)
			if err != nil {
				t.Fatalf("failed to parse captured body %q: %v", capturedBody, err)
			}

			if got := parsed.Get("client_id"); got != tt.clientID {
				t.Errorf("client_id: got %q, want %q", got, tt.clientID)
			}
			if got := parsed.Get("client_secret"); got != tt.clientSecret {
				t.Errorf("client_secret: got %q, want %q", got, tt.clientSecret)
			}
			if got := parsed.Get("code"); got != tt.code {
				t.Errorf("code: got %q, want %q", got, tt.code)
			}
			if tt.redirectURI != "" {
				if got := parsed.Get("redirect_uri"); got != tt.redirectURI {
					t.Errorf("redirect_uri: got %q, want %q", got, tt.redirectURI)
				}
			} else {
				if _, ok := parsed["redirect_uri"]; ok {
					t.Error("redirect_uri should not be present when empty")
				}
			}
		})
	}
}

// TestExchangeCode_HTTPError verifies that a non-200 response from GitHub's
// token endpoint is returned as an error rather than being silently ignored.
func TestExchangeCode_HTTPError(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad_verification_code"}`))
	}))
	defer ghServer.Close()

	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "id", ClientSecret: "secret"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
	h.githubBaseURL = ghServer.URL

	_, _, _, err := h.exchangeCode(context.Background(), "bad-code", "")
	if err == nil {
		t.Fatal("expected error for HTTP 400, got nil")
	}
}

// TestExchangeCode_EmptyAccessToken verifies that an OAuth response with an
// empty access_token is treated as an error.
func TestExchangeCode_EmptyAccessToken(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "",
			"expires_in":   28800,
		})
	}))
	defer ghServer.Close()

	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "id", ClientSecret: "secret"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
	h.githubBaseURL = ghServer.URL

	_, _, _, err := h.exchangeCode(context.Background(), "code", "")
	if err == nil {
		t.Fatal("expected error for empty access token, got nil")
	}
}

// TestExchangeCode_ErrorDescription verifies that when GitHub returns both an
// error code and an error_description, both are included in the returned error.
func TestExchangeCode_ErrorDescription(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "bad_verification_code",
			"error_description": "The code passed is incorrect or expired.",
		})
	}))
	defer ghServer.Close()

	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "id", ClientSecret: "secret"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
	h.githubBaseURL = ghServer.URL

	_, _, _, err := h.exchangeCode(context.Background(), "expired-code", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bad_verification_code") {
		t.Errorf("error should contain error code, got: %v", err)
	}
	if !strings.Contains(err.Error(), "incorrect or expired") {
		t.Errorf("error should contain error_description, got: %v", err)
	}
}

// TestHandleGitHubCallback_JSONModeRedirectURI verifies that the code exchange
// in handleGitHubCallback uses a redirect_uri that includes ?format=json when
// the callback is invoked in CLI mode (format=json query param present).
// GitHub requires the redirect_uri in the token exchange to exactly match the
// one sent in the authorization request.
func TestHandleGitHubCallback_JSONModeRedirectURI(t *testing.T) {
	var capturedRedirectURI string
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(body))
		capturedRedirectURI = vals.Get("redirect_uri")
		// Return an error so we short-circuit without needing a store mock.
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad_verification_code"}`))
	}))
	defer ghServer.Close()

	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "id", ClientSecret: "secret"},
		Server: config.ServerConfig{BaseURL: "https://proxy.example.com"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())
	h.githubBaseURL = ghServer.URL

	// Pre-load a state so state validation passes.
	state := "teststate456"
	if err := h.store.CreateOAuthState(context.Background(), &database.OAuthState{
		State:     state,
		Kind:      database.OAuthStateKindLogin,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	req := httptest.NewRequest("GET",
		"/auth/github/callback?code=testcode&state="+state+"&format=json", nil)
	w := httptest.NewRecorder()
	h.handleGitHubCallback(w, req)

	// The exchange fails (500 from handler), but the redirect_uri sent to
	// GitHub must include ?format=json to match the authorize request.
	const want = "https://proxy.example.com/auth/github/callback?format=json"
	if capturedRedirectURI != want {
		t.Errorf("token-exchange redirect_uri = %q, want %q", capturedRedirectURI, want)
	}
}

// TestHandleGitHubLogin_JSONResponse verifies that CLI clients (Accept: application/json)
// receive a JSON body containing the GitHub authorization URL, and that the
// redirect_uri in that URL has ?format=json appended so the callback will
// return the session token as JSON rather than setting a browser cookie.
func TestHandleGitHubLogin_JSONResponse(t *testing.T) {
	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "test-client-id"},
		Server: config.ServerConfig{BaseURL: "https://proxy.example.com"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/github", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.handleGitHubLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON Content-Type, got %q", ct)
	}

	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body.URL == "" {
		t.Fatal("expected non-empty url in JSON response")
	}

	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatalf("invalid auth URL %q: %v", body.URL, err)
	}

	redirectURI := parsed.Query().Get("redirect_uri")
	const wantRedirectURI = "https://proxy.example.com/auth/github/callback?format=json"
	if redirectURI != wantRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", redirectURI, wantRedirectURI)
	}
}

// TestHandleGitHubLogin_IncludesRedirectURI verifies that the GitHub
// authorization URL constructed by handleGitHubLogin includes an explicit
// redirect_uri parameter pointing to the callback endpoint.
func TestHandleGitHubLogin_IncludesRedirectURI(t *testing.T) {
	cfg := &config.Config{
		GitHub: config.GitHubConfig{ClientID: "test-client-id"},
		Server: config.ServerConfig{BaseURL: "https://proxy.example.com"},
	}
	h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

	req := httptest.NewRequest("GET", "/auth/github", nil)
	w := httptest.NewRecorder()
	h.handleGitHubLogin(w, req)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d", w.Code)
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("invalid Location header: %v", err)
	}

	redirectURI := loc.Query().Get("redirect_uri")
	if redirectURI == "" {
		t.Fatal("expected redirect_uri parameter in authorization URL")
	}
	const wantRedirectURI = "https://proxy.example.com/auth/github/callback"
	if redirectURI != wantRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", redirectURI, wantRedirectURI)
	}
}

// TestMainCallbackURL verifies that mainCallbackURL correctly derives the
// callback URL from the configured BaseURL or from the incoming request.
func TestMainCallbackURL(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		trustProxy bool
		reqHost    string
		tls        bool
		xfProto    string
		xfHost     string
		forwarded  string
		want       string
	}{
		{
			name:    "with base URL",
			baseURL: "https://proxy.example.com",
			want:    "https://proxy.example.com/auth/github/callback",
		},
		{
			name:    "base URL with trailing slash",
			baseURL: "https://proxy.example.com/",
			want:    "https://proxy.example.com/auth/github/callback",
		},
		{
			name:    "no base URL, HTTPS",
			reqHost: "proxy.example.com",
			tls:     true,
			want:    "https://proxy.example.com/auth/github/callback",
		},
		{
			name:    "no base URL, HTTP",
			reqHost: "proxy.example.com:8080",
			want:    "http://proxy.example.com:8080/auth/github/callback",
		},
		{
			// Without trust_proxy_headers an internet-reachable instance must
			// not honour client-spoofable headers; r.Host wins.
			name:    "no base URL, X-Forwarded-Proto ignored when trust_proxy_headers=false",
			reqHost: "internal.local",
			xfProto: "https",
			xfHost:  "attacker.example.com",
			want:    "http://internal.local/auth/github/callback",
		},
		{
			name:       "no base URL, X-Forwarded-Proto trusted when trust_proxy_headers=true",
			reqHost:    "proxy.example.com",
			trustProxy: true,
			xfProto:    "https",
			want:       "https://proxy.example.com/auth/github/callback",
		},
		{
			name:       "no base URL, X-Forwarded-Host trusted when trust_proxy_headers=true",
			reqHost:    "internal.local",
			trustProxy: true,
			xfHost:     "ghp.example.com",
			xfProto:    "https",
			want:       "https://ghp.example.com/auth/github/callback",
		},
		{
			name:       "no base URL, RFC 7239 Forwarded trusted when trust_proxy_headers=true",
			reqHost:    "internal.local",
			trustProxy: true,
			forwarded:  `for=10.0.0.1;proto=https;host=ghp.example.com`,
			want:       "https://ghp.example.com/auth/github/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{BaseURL: tt.baseURL, TrustProxyHeaders: tt.trustProxy},
			}
			h := NewHandler(cfg, newTestStore(t), nil, slog.Default())

			req := httptest.NewRequest("GET", "/", nil)
			if tt.reqHost != "" {
				req.Host = tt.reqHost
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.xfProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xfProto)
			}
			if tt.xfHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.xfHost)
			}
			if tt.forwarded != "" {
				req.Header.Set("Forwarded", tt.forwarded)
			}

			got := h.mainCallbackURL(req)
			if got != tt.want {
				t.Errorf("mainCallbackURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
