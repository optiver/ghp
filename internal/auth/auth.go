// Package auth handles GitHub OAuth authentication, browser session management,
// and the optional OAuth broker feature. It provides:
//
//   - GitHub OAuth login flow for the web UI (code exchange, user info)
//   - Persistent (database-backed) session store
//   - CLI device-authorization flow against ghp itself (no GitHub round-trip)
//   - OAuth broker endpoints that allow downstream services to authenticate
//     users via ghp without needing their own GitHub OAuth credentials
//   - RS256 JWT signing for broker tokens, with JWKS endpoint for key discovery
//   - Per-endpoint IP rate limiting on sensitive auth endpoints
//   - Dev-mode test login endpoint (bypasses OAuth for development/testing)
//
// All transient auth state (sessions, OAuth state tokens, CLI device records)
// is stored in the database via the Store interface so that flows that span
// multiple HTTP round-trips remain correct in HA deployments where each
// request may land on a different ghp instance.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

const (
	// SessionCookieName is the name of the browser session cookie.
	SessionCookieName = "ghp_session"
	// SessionDuration is how long a browser session lasts.
	SessionDuration = 30 * 24 * time.Hour

	// maxRequestBodySize is the maximum allowed request body size for API endpoints.
	maxRequestBodySize = 1 << 20 // 1 MB
	// maxTokenResponseSize is the maximum number of bytes read from GitHub's
	// OAuth token and user-info endpoints. This guards against unbounded reads.
	maxTokenResponseSize = 64 * 1024 // 64 KB
	// stateTTL is how long an OAuth state token remains valid.
	stateTTL = 10 * time.Minute
	// brokerStateTTL is how long a broker OAuth state token remains valid.
	brokerStateTTL = 10 * time.Minute
	// authHTTPTimeout is the timeout for outbound HTTP requests made by the
	// auth handler (OAuth token exchange and GitHub user-info calls).
	authHTTPTimeout = 30 * time.Second
	// authStateCleanupInterval is how often the cleanup goroutine sweeps
	// expired sessions, oauth_states, and cli_device_authorizations rows.
	authStateCleanupInterval = 5 * time.Minute
)

// Session represents an authenticated user session.
type Session struct {
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

// Handler manages OAuth flows and sessions. All transient state (sessions,
// in-flight OAuth state tokens, CLI device-authorization records) is held in
// the Store, which makes the auth flows correct under HA load balancing.
type Handler struct {
	cfg       *config.Config
	store     database.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger

	// rsaPrivKey is the RSA private key used to sign broker JWTs with RS256.
	// When nil, broker endpoints are disabled entirely.
	// Note: this key is set once at NewHandler time; config hot-reload (SIGUSR1)
	// does not update it — a server restart is required to change the signing key.
	rsaPrivKey *rsa.PrivateKey

	// Rate limiters for sensitive endpoints (keyed by IP address).
	loginLimiter      *IPRateLimiter // POST /auth/test-login
	githubLimiter     *IPRateLimiter // GET  /auth/github
	authorizeLimiter  *IPRateLimiter // GET  /auth/authorize
	deviceStartLimiter *IPRateLimiter // POST /cli/auth/device
	devicePollLimiter  *IPRateLimiter // POST /cli/auth/device/token

	// httpClient is used for all outbound OAuth and GitHub API requests.
	// It has a finite timeout to prevent goroutine/connection leaks.
	httpClient *http.Client

	// Overridable base URLs for GitHub endpoints (used in tests).
	githubBaseURL    string // defaults to "https://github.com"
	githubAPIBaseURL string // defaults to "https://api.github.com"

	// cleanupCancel stops the background cleanup goroutine when the handler
	// is shut down. Set by StartCleanup; nil if no cleanup is running.
	cleanupCancel context.CancelFunc
}

// NewHandler creates a new auth handler.
func NewHandler(cfg *config.Config, store database.Store, enc *crypto.Encryptor, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:              cfg,
		store:            store,
		encryptor:        enc,
		logger:           logger,
		loginLimiter:     NewIPRateLimiter(100, time.Minute, "/auth/test-login", cfg.Server.TrustProxyHeaders, logger),
		githubLimiter:    NewIPRateLimiter(10, time.Minute, "/auth/github", cfg.Server.TrustProxyHeaders, logger),
		authorizeLimiter: NewIPRateLimiter(10, time.Minute, "/auth/authorize", cfg.Server.TrustProxyHeaders, logger),
		// /cli/auth/device kicks off a flow that creates a database row, so
		// it gets the same conservative ceiling as /auth/github. The polling
		// endpoint is more permissive — a single CLI run polls every few
		// seconds for up to 10 minutes, which is up to ~300 hits, and
		// multiple CLI processes may run from the same NAT'd IP.
		deviceStartLimiter: NewIPRateLimiter(10, time.Minute, "/cli/auth/device", cfg.Server.TrustProxyHeaders, logger),
		devicePollLimiter:  NewIPRateLimiter(600, time.Minute, "/cli/auth/device/token", cfg.Server.TrustProxyHeaders, logger),
		httpClient:         &http.Client{Timeout: authHTTPTimeout},
	}
	if cfg.Auth.JWTPrivateKey != "" || cfg.Auth.JWTPrivateKeyFile != "" {
		var pemData string
		if cfg.Auth.JWTPrivateKey != "" {
			pemData = cfg.Auth.JWTPrivateKey
		} else {
			data, err := os.ReadFile(cfg.Auth.JWTPrivateKeyFile)
			if err != nil {
				logger.Error("failed to read JWT private key file", "error", err)
			} else {
				pemData = string(data)
			}
		}
		if pemData != "" {
			key, err := crypto.ParseRSAPrivateKey(pemData)
			if err != nil {
				logger.Error("failed to load JWT RSA private key", "error", err)
			} else {
				h.rsaPrivKey = key
			}
		}
	}
	return h
}

// secureCookies returns true when cookies should be sent with the Secure flag.
// This is the case when TLS certificates are configured or when the BaseURL
// uses an https:// scheme.
func (h *Handler) secureCookies() bool {
	if len(h.cfg.TLS.Certificates) > 0 {
		return true
	}
	return strings.HasPrefix(h.cfg.Server.BaseURL, "https://")
}

// RegisterRoutes adds auth routes to the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /auth/github", h.githubLimiter.Middleware(http.HandlerFunc(h.handleGitHubLogin)))
	mux.HandleFunc("GET /auth/github/callback", h.handleGitHubCallback)
	mux.HandleFunc("POST /auth/logout", h.handleLogout)
	mux.HandleFunc("GET /auth/status", h.handleStatus)

	// CLI device-authorization flow (no GitHub round-trip from the CLI).
	h.registerDeviceRoutes(mux)

	// OAuth broker endpoints: delegate authentication to this proxy.
	if h.cfg.Auth.JWTPrivateKey != "" || h.cfg.Auth.JWTPrivateKeyFile != "" {
		if h.rsaPrivKey == nil {
			h.logger.Error("jwt_private_key configuration is invalid; oauth broker endpoints disabled")
		} else {
			mux.Handle("GET /auth/authorize", h.authorizeLimiter.Middleware(http.HandlerFunc(h.handleBrokerAuthorize)))
			mux.HandleFunc("GET /auth/callback", h.handleBrokerCallback)
			mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)
			h.logger.Info("oauth broker endpoints enabled")
			if len(h.cfg.Auth.AllowedRedirects) == 0 {
				h.logger.Warn("oauth broker enabled but no allowed redirects configured; all broker authorization requests will fail with \"redirect_uri not allowed\"")
			}
		}
	}

	// Dev-mode only: test login endpoint that bypasses GitHub OAuth.
	if h.cfg.DevMode {
		h.logger.Warn("dev mode enabled: /auth/test-login endpoint is active")
		mux.Handle("POST /auth/test-login", h.loginLimiter.Middleware(http.HandlerFunc(h.handleTestLogin)))
	}
}

// GetSession returns the session for the given request, or nil.
func (h *Handler) GetSession(r *http.Request) *Session {
	// Check cookie first.
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		return h.lookupSession(r.Context(), cookie.Value)
	}

	// Check Authorization header for service tokens (CLI usage).
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ghpr_") {
		return h.lookupSession(r.Context(), strings.TrimPrefix(auth, "Bearer "))
	}

	return nil
}

// RequireAuth is middleware that enforces authentication.
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := h.GetSession(r)
		if session == nil {
			http.Error(w, `{"message":"Authentication required"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin is middleware that enforces admin role.
func (h *Handler) RequireAdmin(next http.Handler) http.Handler {
	return h.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := SessionFromContext(r.Context())
		if session == nil || session.Role != "admin" {
			http.Error(w, `{"message":"Admin access required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

type sessionKey struct{}

// SessionFromContext retrieves the session from context.
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey{}).(*Session)
	return s
}

// NewContextWithSession returns a copy of ctx carrying s as the authenticated
// session. This is intended for use in tests that bypass the HTTP middleware.
func NewContextWithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// hashSessionToken returns the SHA-256 hex digest of a raw session bearer.
// The Store keys sessions by this value so the unhashed token never lives
// in the database.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (h *Handler) lookupSession(ctx context.Context, token string) *Session {
	if token == "" {
		return nil
	}
	row, err := h.store.GetSessionByTokenHash(ctx, hashSessionToken(token))
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			h.logger.Error("session lookup failed", "error", err)
		}
		return nil
	}
	return &Session{
		UserID:    row.UserID,
		Username:  row.Username,
		Role:      row.Role,
		ExpiresAt: row.ExpiresAt,
	}
}

// createSession persists a new session row and returns the raw bearer token
// to hand to the client (cookie or JSON response). The DB stores only the
// hash of this value.
func (h *Handler) createSession(ctx context.Context, userID, username, role string) (string, error) {
	token := generateSessionToken()
	expiresAt := time.Now().Add(SessionDuration).UTC()
	if err := h.store.CreateSession(ctx, &database.Session{
		TokenHash: hashSessionToken(token),
		UserID:    userID,
		Username:  username,
		Role:      role,
		ExpiresAt: expiresAt,
	}); err != nil {
		return "", err
	}
	return token, nil
}

// CreateTestSession creates a session for E2E testing without OAuth.
// Returns the session token that should be set as the ghp_session cookie.
// Errors from the underlying store are logged and swallowed — test setup is
// expected to be run against a healthy store, and historical callers don't
// have an error return.
func (h *Handler) CreateTestSession(userID, username, role string) string {
	tok, err := h.createSession(context.Background(), userID, username, role)
	if err != nil {
		h.logger.Error("CreateTestSession failed", "error", err)
		return ""
	}
	return tok
}

func (h *Handler) deleteSession(ctx context.Context, token string) {
	if token == "" {
		return
	}
	if err := h.store.DeleteSession(ctx, hashSessionToken(token)); err != nil {
		h.logger.Warn("session delete failed", "error", err)
	}
}

// StartCleanup launches a background goroutine that periodically purges
// expired sessions, oauth_states, and cli_device_authorizations rows. It
// returns immediately; the caller should arrange for the returned context's
// cancellation when the server shuts down.
//
// Calling StartCleanup more than once on the same Handler replaces any
// previously-running cleanup goroutine.
func (h *Handler) StartCleanup(ctx context.Context) {
	if h.cleanupCancel != nil {
		h.cleanupCancel()
	}
	cleanupCtx, cancel := context.WithCancel(ctx)
	h.cleanupCancel = cancel
	go h.cleanupLoop(cleanupCtx)
}

// StopCleanup stops a previously-started cleanup goroutine. Safe to call
// even if cleanup was never started.
func (h *Handler) StopCleanup() {
	if h.cleanupCancel != nil {
		h.cleanupCancel()
		h.cleanupCancel = nil
	}
}

func (h *Handler) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(authStateCleanupInterval)
	defer t.Stop()
	// Run once immediately so a long-running prior process's leftovers are
	// purged on startup.
	h.runCleanup(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.runCleanup(ctx)
		}
	}
}

func (h *Handler) runCleanup(ctx context.Context) {
	if n, err := h.store.DeleteExpiredSessions(ctx); err != nil {
		// context.Canceled is expected when the server is shutting down
		// mid-sweep; demote those to Debug so shutdown logs stay quiet.
		h.logCleanupError("session cleanup failed", err)
	} else if n > 0 {
		h.logger.Debug("expired sessions purged", "count", n)
	}
	if n, err := h.store.DeleteExpiredOAuthStates(ctx); err != nil {
		h.logCleanupError("oauth state cleanup failed", err)
	} else if n > 0 {
		h.logger.Debug("expired oauth states purged", "count", n)
	}
	if n, err := h.store.DeleteExpiredDeviceAuths(ctx); err != nil {
		h.logCleanupError("device auth cleanup failed", err)
	} else if n > 0 {
		h.logger.Debug("expired device auth records purged", "count", n)
		// Surface the count under the same metric the device-flow handlers
		// use. This means ghp_cli_auth_device_completed_total{result="expired"}
		// reports records that timed out before the user acted, complementing
		// the "approved" and "denied" results emitted from the poll endpoint.
		metrics.CLIDeviceCompletedTotal.WithLabelValues("expired").Add(float64(n))
	}
}

// logCleanupError logs a cleanup-loop error at the appropriate level. A
// context.Canceled error during shutdown is expected and would otherwise
// produce a noisy Warn on every server stop, so it is logged at Debug.
func (h *Handler) logCleanupError(msg string, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		h.logger.Debug(msg, "error", err)
		return
	}
	h.logger.Warn(msg, "error", err)
}

func (h *Handler) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()

	// return_to lets a browser flow request that the user be sent back to a
	// specific path after successful login (e.g. the device-authorization
	// verification page). It is restricted to local paths to prevent open
	// redirects. Stored alongside the state row so any ghp instance handling
	// the GitHub callback can read it.
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
	if err := h.store.CreateOAuthState(r.Context(), &database.OAuthState{
		State:     state,
		Kind:      database.OAuthStateKindLogin,
		ReturnTo:  returnTo,
		ExpiresAt: time.Now().Add(stateTTL).UTC(),
	}); err != nil {
		h.logger.Error("failed to persist oauth state", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// CLI clients (Accept: application/json) need the callback to return JSON
	// with the session token rather than setting a cookie and redirecting.
	// Appending ?format=json to the redirect_uri instructs the callback handler
	// to return the token as JSON so the user can copy it from the browser.
	cliRequest := strings.Contains(r.Header.Get("Accept"), "application/json")
	callbackURL := h.mainCallbackURL(r)
	if cliRequest {
		callbackURL += "?format=json"
	}

	params := url.Values{}
	params.Set("client_id", h.cfg.GitHub.ClientID)
	params.Set("redirect_uri", callbackURL)
	params.Set("state", state)
	authURL := h.getGitHubBaseURL() + "/login/oauth/authorize?" + params.Encode()

	// Response body depends on Accept; signal this to intermediary caches so
	// a redirect response can't be served to a CLI client (or vice versa).
	// Both branches embed a single-use `state` value in the destination URL,
	// so neither response is safe to cache.
	w.Header().Set("Vary", "Accept")
	w.Header().Set("Cache-Control", "no-store")

	// If the request accepts JSON (CLI), return the URL; otherwise redirect.
	if cliRequest {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"url": authURL})
		return
	}
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *Handler) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	// Handle GitHub App installation callback.
	// When a user installs the app, GitHub redirects here with installation_id
	// and setup_action params instead of the OAuth code/state.
	if r.URL.Query().Get("installation_id") != "" {
		h.logger.Info("github_app_installed", "installation_id", r.URL.Query().Get("installation_id"), "action", r.URL.Query().Get("setup_action"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	code := r.URL.Query().Get("code")
	setupAction := r.URL.Query().Get("setup_action")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	// When GitHub redirects after app installation/authorization it sends
	// code + setup_action but no state parameter. Skip state validation in
	// that case — the code exchange itself authenticates the request.
	if setupAction == "" {
		if state == "" {
			http.Error(w, "Missing state parameter", http.StatusBadRequest)
			return
		}

		// Atomically read-and-delete the state row. Returns ErrNotFound for
		// missing, expired, or wrong-kind entries.
		st, err := h.store.ConsumeOAuthState(r.Context(), state, database.OAuthStateKindLogin)
		if err != nil {
			if !errors.Is(err, database.ErrNotFound) {
				h.logger.Error("oauth state consume failed", "error", err)
			}
			http.Error(w, "Invalid or expired state", http.StatusBadRequest)
			return
		}
		if st.ReturnTo != "" {
			// Defer to the returnTo path after authentication completes.
			// handleGitHubCallback's redirect target is hardcoded to "/" by
			// default; threading the path through the request context lets
			// the redirect at the bottom of this handler honour it without
			// changing its signature.
			r = r.WithContext(context.WithValue(r.Context(), returnToCtxKey{}, st.ReturnTo))
		}
	}

	// Exchange code for access token.
	// For the normal OAuth flow, pass the same redirect_uri that was sent in
	// the authorization request so GitHub can verify the two values match.
	// For the app installation flow (setup_action is set), the redirect_uri
	// was not sent in the authorization request so we omit it here.
	//
	// CLI clients trigger the login with ?format=json appended to the
	// redirect_uri (see handleGitHubLogin). GitHub requires the redirect_uri
	// in the token exchange to exactly match the one in the authorize request,
	// so we must include ?format=json here too when it is present.
	redirectURI := ""
	if setupAction == "" {
		redirectURI = h.mainCallbackURL(r)
		if r.URL.Query().Get("format") == "json" {
			redirectURI += "?format=json"
		}
	}
	accessToken, refreshToken, expiresIn, err := h.exchangeCode(code, redirectURI)
	if err != nil {
		h.logger.Error("OAuth code exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Get user info from GitHub.
	ghUser, err := h.getGitHubUser(accessToken)
	if err != nil {
		h.logger.Error("Failed to get GitHub user", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Encrypt tokens before storage.
	encAccess, err := h.encryptor.Encrypt(accessToken)
	if err != nil {
		h.logger.Error("Failed to encrypt access token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	encRefresh, err := h.encryptor.Encrypt(refreshToken)
	if err != nil {
		h.logger.Error("Failed to encrypt refresh token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Determine role.
	role := "user"
	if h.cfg.IsAdmin(ghUser.Login) {
		role = "admin"
	}

	// Upsert user.
	user := &database.User{
		GitHubID:      ghUser.ID,
		GitHubUsername: ghUser.Login,
		GitHubEmail:   ghUser.Email,
		Role:          role,
	}
	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		h.logger.Error("Failed to upsert user", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Store GitHub token.
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encAccess,
		RefreshToken:          encRefresh,
		AccessTokenExpiresAt:  time.Now().Add(time.Duration(expiresIn) * time.Second),
		RefreshTokenExpiresAt: time.Now().Add(6 * 30 * 24 * time.Hour), // ~6 months
		Scopes:                "",
	}
	if err := h.store.UpsertGitHubToken(r.Context(), gt); err != nil {
		h.logger.Error("Failed to store GitHub token", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("auth_login", "user", ghUser.Login, "github_id", ghUser.ID)

	// Create session.
	sessionToken, err := h.createSession(r.Context(), user.ID, user.GitHubUsername, user.Role)
	if err != nil {
		h.logger.Error("failed to persist session", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// If the request wants JSON (CLI client), return the token.
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"session_token": sessionToken,
			"username":      ghUser.Login,
		})
		return
	}

	// Set cookie for web UI.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})

	target := "/"
	if v, ok := r.Context().Value(returnToCtxKey{}).(string); ok && v != "" {
		target = v
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

type returnToCtxKey struct{}

// sanitizeReturnTo restricts return_to to local paths only, preventing open
// redirects. It must begin with "/" and must not begin with "//" or "/\\"
// (which browsers can interpret as a protocol-relative URL). The value also
// cannot contain ASCII control characters (CR/LF in particular) because the
// final destination is the `Location:` response header — embedded CRLF
// would split the header and risk response-splitting on lenient clients.
func sanitizeReturnTo(v string) string {
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "/") {
		return ""
	}
	if strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/\\") {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		// Reject the ASCII control range (NUL..US) and DEL. A legitimate
		// path/query never contains these — clients that need raw bytes
		// percent-encode them.
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}
	return v
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		h.deleteSession(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies(),
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	session := h.GetSession(r)
	if session == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"username":      session.Username,
		"role":          session.Role,
		"user_id":       session.UserID,
	})
}

// handleTestLogin creates a test user and session without GitHub OAuth.
// Only available when DevMode is enabled. This must never be used in production.
func (h *Handler) handleTestLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
		}
		return
	}
	if req.Username == "" {
		req.Username = "testuser"
	}
	if req.Role == "" {
		req.Role = "user"
	}

	// Create or find the test user. Derive a unique GitHub ID from the username
	// so different test usernames create distinct users with separate tokens.
	var ghID int64
	for _, c := range req.Username {
		ghID = ghID*31 + int64(c)
	}
	if ghID < 0 {
		ghID = -ghID
	}
	ghID += 900000 // offset to avoid collisions with real GitHub IDs

	user := &database.User{
		GitHubID:       ghID,
		GitHubUsername:  req.Username,
		GitHubEmail:    req.Username + "@test.local",
		Role:           req.Role,
	}
	if err := h.store.UpsertUser(r.Context(), user); err != nil {
		h.logger.Error("failed to create test user", "error", err)
		http.Error(w, "Failed to create test user", http.StatusInternalServerError)
		return
	}

	// Create a dummy GitHub token so token creation works.
	encDummy, _ := h.encryptor.Encrypt("gho_test_dummy_token")
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encDummy,
		RefreshToken:          encDummy,
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
		Scopes:                "",
	}
	if err := h.store.UpsertGitHubToken(r.Context(), gt); err != nil {
		h.logger.Error("failed to create test github token", "error", err)
		http.Error(w, "Failed to create test GitHub token", http.StatusInternalServerError)
		return
	}

	// Create session.
	sessionToken, err := h.createSession(r.Context(), user.ID, user.GitHubUsername, user.Role)
	if err != nil {
		h.logger.Error("failed to persist test session", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Set cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionDuration.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"username":      user.GitHubUsername,
		"user_id":       user.ID,
		"role":          user.Role,
	})
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (h *Handler) exchangeCode(code string, redirectURI string) (accessToken, refreshToken string, expiresIn int, err error) {
	params := url.Values{
		"client_id":     {h.cfg.GitHub.ClientID},
		"client_secret": {h.cfg.GitHub.ClientSecret},
		"code":          {code},
	}
	if redirectURI != "" {
		params.Set("redirect_uri", redirectURI)
	}

	req, err := http.NewRequest("POST", h.getGitHubBaseURL()+"/login/oauth/access_token",
		strings.NewReader(params.Encode()))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		return "", "", 0, fmt.Errorf("GitHub token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize)).Decode(&result); err != nil {
		return "", "", 0, err
	}
	if result.Error != "" {
		if result.ErrorDescription != "" {
			return "", "", 0, fmt.Errorf("OAuth error: %s: %s", result.Error, result.ErrorDescription)
		}
		return "", "", 0, fmt.Errorf("OAuth error: %s", result.Error)
	}
	if result.AccessToken == "" {
		return "", "", 0, errors.New("OAuth response contained no access token")
	}

	if result.ExpiresIn == 0 {
		result.ExpiresIn = 28800 // 8 hours default
	}

	return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
}

func (h *Handler) getGitHubUser(accessToken string) (*githubUser, error) {
	req, err := http.NewRequest("GET", h.getGitHubAPIBaseURL()+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, body)
	}

	var user githubUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponseSize)).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "ghpr_" + hex.EncodeToString(b)
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) getGitHubBaseURL() string {
	if h.githubBaseURL != "" {
		return h.githubBaseURL
	}
	return "https://github.com"
}

func (h *Handler) getGitHubAPIBaseURL() string {
	if h.githubAPIBaseURL != "" {
		return h.githubAPIBaseURL
	}
	return "https://api.github.com"
}

// mainCallbackURL returns the absolute URL of the GitHub OAuth callback
// endpoint for the main login flow. It uses the configured BaseURL if
// available, otherwise derives the URL from the incoming request. The
// shared requestScheme/requestHost helpers honour Forwarded / X-Forwarded-*
// only when server.trust_proxy_headers is true (matches the device-flow
// verification URL so the two stay consistent under both deployment
// patterns).
func (h *Handler) mainCallbackURL(r *http.Request) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/") + "/auth/github/callback"
	}
	trustProxy := h.cfg.Server.TrustProxyHeaders
	return fmt.Sprintf("%s://%s/auth/github/callback", requestScheme(r, trustProxy), requestHost(r, trustProxy))
}
