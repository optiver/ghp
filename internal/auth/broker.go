package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/goodtune/ghp/internal/database"
)

// BrokerClaims are the JWT claims minted by the OAuth broker.
type BrokerClaims struct {
	AvatarURL string `json:"avatar_url"`
	jwt.RegisteredClaims
}

// handleBrokerAuthorize is the entry point for downstream services to initiate
// authentication. It validates the redirect_uri, stores the broker state, and
// redirects the user to GitHub OAuth.
func (h *Handler) handleBrokerAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "Missing redirect_uri parameter", http.StatusBadRequest)
		return
	}

	if !h.validateRedirectURI(redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	downstreamState := r.URL.Query().Get("state")

	state := generateState()
	if err := h.store.CreateOAuthState(r.Context(), &database.OAuthState{
		State:                 state,
		Kind:                  database.OAuthStateKindBroker,
		BrokerRedirectURI:     redirectURI,
		BrokerDownstreamState: downstreamState,
		ExpiresAt:             time.Now().Add(brokerStateTTL).UTC(),
	}); err != nil {
		h.logger.Error("failed to persist broker oauth state", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	callbackURL := h.brokerCallbackURL(r)
	params := url.Values{}
	params.Set("client_id", h.cfg.GitHub.ClientID)
	params.Set("redirect_uri", callbackURL)
	params.Set("state", state)

	authURL := h.getGitHubBaseURL() + "/login/oauth/authorize?" + params.Encode()
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleBrokerCallback handles the GitHub OAuth callback for broker flows.
// It exchanges the code for an access token, fetches the user's identity,
// mints a short-lived signed JWT, and redirects to the downstream service.
func (h *Handler) handleBrokerCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}
	if state == "" {
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	bs, err := h.store.ConsumeOAuthState(r.Context(), state, database.OAuthStateKindBroker)
	if err != nil {
		if !errors.Is(err, database.ErrNotFound) {
			h.logger.Error("broker oauth state consume failed", "error", err)
		}
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	// Exchange code for access token, including the redirect_uri that was
	// sent in the authorize request (GitHub requires it to match).
	callbackURL := h.brokerCallbackURL(r)
	accessToken, _, _, exErr := h.exchangeCode(r.Context(), code, callbackURL)
	if exErr != nil {
		h.logger.Error("broker: OAuth code exchange failed", "error", exErr)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Fetch user identity from GitHub. The access token is not stored;
	// it is only used to retrieve the user's login and avatar.
	user, err := h.getGitHubUser(r.Context(), accessToken)
	if err != nil {
		h.logger.Error("broker: failed to get GitHub user", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Mint a short-lived JWT containing the user's identity.
	now := time.Now()
	claims := BrokerClaims{
		AvatarURL: user.AvatarURL,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.brokerIssuer(),
			Subject:   user.Login,
			Audience:  jwt.ClaimStrings{bs.BrokerRedirectURI},
			ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = h.jwksKeyID()
	signed, err := token.SignedString(h.rsaPrivKey)
	if err != nil {
		h.logger.Error("broker: failed to sign JWT", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Redirect to the downstream service with the signed token.
	redirectURL, err := url.Parse(bs.BrokerRedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusInternalServerError)
		return
	}
	q := redirectURL.Query()
	q.Set("token", signed)
	if bs.BrokerDownstreamState != "" {
		q.Set("state", bs.BrokerDownstreamState)
	}
	redirectURL.RawQuery = q.Encode()

	h.logger.Info("broker_auth_complete", "user", user.Login, "redirect_uri", bs.BrokerRedirectURI)
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

// handleJWKS serves the RSA public key as a JSON Web Key Set (JWKS), allowing
// downstream services to verify RS256-signed broker JWTs without possessing
// the private key.
func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if h.rsaPrivKey == nil {
		http.Error(w, "JWKS not available", http.StatusNotFound)
		return
	}
	pub := &h.rsaPrivKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	// Encode the public exponent as big-endian bytes with leading zeros stripped.
	e := pub.E
	var eBytes []byte
	for e > 0 {
		eBytes = append([]byte{byte(e & 0xff)}, eBytes...)
		e >>= 8
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": h.jwksKeyID(),
				"n":   n,
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	})
}

// validateRedirectURI checks whether uri is permitted by the configured allowlist.
func (h *Handler) validateRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}

	// Require HTTPS. Allow HTTP only for localhost when dev mode is on.
	if parsed.Scheme != "https" {
		if !h.cfg.DevMode || !isLocalhost(parsed.Host) {
			return false
		}
	}

	for _, pattern := range h.cfg.Auth.AllowedRedirects {
		if matchesRedirectPattern(uri, parsed, pattern) {
			return true
		}
	}
	return false
}

// matchesRedirectPattern checks whether a parsed URI matches a single allowlist
// entry. Patterns can be exact URLs or wildcard domains like "*.example.com".
// Wildcard patterns may include a path prefix (e.g. "*.example.com/auth/callback")
// to limit which paths are trusted on the matching subdomains.
func matchesRedirectPattern(rawURI string, parsed *url.URL, pattern string) bool {
	// Wildcard domain pattern: *.example.com or *.example.com/path
	if strings.HasPrefix(pattern, "*.") {
		// Separate the host portion from an optional path in the pattern.
		patternHost := pattern
		patternPath := ""
		if idx := strings.Index(pattern[2:], "/"); idx >= 0 {
			patternHost = pattern[:idx+2]
			patternPath = pattern[idx+2:]
		}

		suffix := patternHost[1:] // ".example.com"
		host := parsed.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !strings.HasSuffix(host, suffix) || len(host) <= len(suffix) {
			return false
		}

		// If the pattern includes a path, require the URI path to match.
		if patternPath != "" {
			return strings.HasPrefix(parsed.Path, patternPath)
		}
		return true
	}

	// Exact URL match (normalize trailing slashes).
	return strings.TrimRight(rawURI, "/") == strings.TrimRight(pattern, "/")
}

func isLocalhost(host string) bool {
	h := host
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// jwksKeyID returns a stable key identifier derived from the RSA public key.
// It is used as the "kid" header in signed JWTs and the "kid" field in the JWKS
// endpoint, allowing downstream services to match tokens to keys.
func (h *Handler) jwksKeyID() string {
	pub := &h.rsaPrivKey.PublicKey
	// SHA-256 of the modulus gives a stable, collision-resistant identifier.
	sum := sha256.Sum256(pub.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// brokerIssuer returns the issuer claim value for broker JWTs. When the
// server's BaseURL is configured it is used; otherwise a generic identifier
// is returned.
func (h *Handler) brokerIssuer() string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/")
	}
	return "ghp"
}

// brokerCallbackURL returns the URL that GitHub should redirect to after
// the user authorizes. It uses the configured BaseURL if available, otherwise
// it derives the URL from the incoming request.
func (h *Handler) brokerCallbackURL(r *http.Request) string {
	if h.cfg.Server.BaseURL != "" {
		return strings.TrimRight(h.cfg.Server.BaseURL, "/") + "/auth/callback"
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/auth/callback", scheme, r.Host)
}
