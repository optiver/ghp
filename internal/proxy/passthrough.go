package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/token"
)

// TokenResolver resolves a client token (ghx_/gha_) to a real GitHub access token.
type TokenResolver interface {
	ResolveToGitHubToken(ctx context.Context, clientToken string) (string, error)
}

// NewPassthroughHandler creates a transparent reverse proxy to the given
// upstream URL. If a client token (ghx_/gha_) is found in the Authorization
// header, it is resolved and replaced with the real GitHub credential.
// Enterprise access restriction enforcement lives in
// NewScopedPassthroughHandler (the production wrapper for this handler) so
// that its evaluation is charged to pre-forward decision time rather than
// the upstream roundtrip, and so the managed client token type is still
// known when the policy runs.
// The transport parameter allows callers to supply a custom RoundTripper
// (e.g. for test TLS); pass nil to use http.DefaultTransport.
func NewPassthroughHandler(upstream string, resolver TokenResolver, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	target, _ := url.Parse(upstream)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host

			if resolver != nil {
				if clientTok, _, rewriteAuth := extractClientToken(req); clientTok != "" {
					realToken, err := resolver.ResolveToGitHubToken(req.Context(), clientTok)
					if err != nil {
						if logger != nil {
							logger.Warn("passthrough token resolution failed", "error", err)
						}
						req.Header.Del("Authorization")
						return
					}
					req.Header.Set("Authorization", rewriteAuth(realToken))
				}
			}
		},
	}

	if transport != nil {
		proxy.Transport = transport
	}

	return proxy
}

// ScopeEnforcer resolves a client token string to the full ProxyToken record
// so that repository and permission scopes can be checked.
type ScopeEnforcer interface {
	Resolve(ctx context.Context, clientToken string) (*database.ProxyToken, error)
}

// NewScopedPassthroughHandler wraps a passthrough reverse proxy with git smart
// HTTP scope enforcement. For requests carrying a client token (ghx_/gha_) that
// match a git smart HTTP path, the token's repository and permission scopes are
// verified before the request is forwarded. Non-git paths and non-client tokens
// pass through unchanged.
//
// When cfg is non-nil, the token type border policy (cfg.Block) is enforced:
// requests bearing a raw GitHub token whose type prefix is blocked are rejected
// with 403 before they reach the upstream.
//
// The optional usernameResolver is used to resolve GitHub usernames for both
// client tokens (via the database) and raw GitHub tokens (via the GitHub API)
// so that they appear in metrics and access logs.
//
// When enterprise is non-nil, the enterprise access restriction policy is
// applied to the request (header injection or exception-driven omission,
// optionally substituting a managed identity) after token resolution and
// scope enforcement, immediately before the upstream forward — so its
// evaluation is charged to pre-forward decision time and labeled with the
// managed client token type.
func NewScopedPassthroughHandler(inner http.Handler, enforcer ScopeEnforcer, resolver TokenResolver, ur *UsernameResolver, enterprise *EnterprisePolicy, logger *slog.Logger, cfg ...*config.Config) http.Handler {
	var blockCfg *config.Config
	if len(cfg) > 0 {
		blockCfg = cfg[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decisionStart := time.Now()
		extractStart := time.Now()
		clientTok, rawCredential, rewriteAuth := extractClientToken(r)
		extractTokenType := ""
		if tt, ok := token.TokenTypeFromPrefix(clientTok); ok {
			extractTokenType = string(tt)
		}
		metrics.ObserveDecision(metrics.StageTokenExtraction, extractTokenType, time.Since(extractStart))
		if extractTokenType != "" {
			SetTokenType(r, extractTokenType)
		}

		// applyEnterprise evaluates the enterprise restriction policy against
		// the request's target, mutating r.Header (the reverse proxy copies
		// it to the outbound request). githubToken is the resolved credential
		// used to identify the caller for team-gated and identity-substituting
		// exceptions; identity is derived exclusively from it, so
		// cookie-authenticated github.com web requests fail those exception
		// types closed by design (see docs/admin/github-app.md).
		applyEnterprise := func(githubToken string) {
			if enterprise == nil {
				return
			}
			owner, repo := enterpriseTargetFromWebPath(r.URL.Path)
			usernameFn := func(ctx context.Context) string {
				if u := GetUsername(r); u != "" {
					return u
				}
				return ur.ResolveFromGitHubTokenSync(ctx, githubToken)
			}
			if identityTok := enterprise.Apply(r.Context(), r.Header, owner, repo, usernameFn, extractTokenType); identityTok != "" {
				// Identity substitution only fires for callers whose
				// credential resolved to a GitHub identity (Apply fails
				// closed otherwise), so an Authorization header is present
				// here; preserve its scheme. The Basic fallback is defensive
				// only.
				if orig := r.Header.Get("Authorization"); orig != "" {
					r.Header.Set("Authorization", substituteAuthHeader(orig, identityTok))
				} else {
					r.Header.Set("Authorization", basicAuthIdentityHeader(identityTok))
				}
			}
		}
		if clientTok == "" {
			// Check the token type border policy before forwarding.
			borderStart := time.Now()
			// Anonymous git blocking: short-circuit requests that carry a Git-Protocol
			// header but no Authorization header before they egress to GitHub.
			if blockCfg != nil && blockCfg.Block.AnonymousGit && rawCredential == "" && r.Header.Get("Git-Protocol") != "" {
				metrics.BlockAnonymousGitTotal.Inc()
				metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
				metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
				w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
				writeError(w, http.StatusUnauthorized, "Anonymous git access is not permitted")
				return
			}
			if blockCfg != nil && blockCfg.IsTokenBlocked(rawCredential) {
				metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
				metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
				writeError(w, http.StatusForbidden, "Token type is not permitted by the border policy")
				return
			}
			metrics.ObserveDecision(metrics.StageBorderPolicyCheck, "", time.Since(borderStart))
			// Extract the raw GitHub token and trigger an async username
			// lookup before the upstream roundtrip so the background
			// goroutine can run concurrently with the upstream request.
			raw := extractRawGitHubToken(r)
			SetTokenType(r, passthroughTokenType(raw))
			if ur != nil && raw != "" {
				ur.ResolveFromGitHubToken(r.Context(), raw)
			}
			applyEnterprise(raw)
			metrics.ObserveDecision(metrics.StageTotal, "unknown", time.Since(decisionStart))
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			upstreamStart := time.Now()
			inner.ServeHTTP(rec, r)
			metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, "unknown", time.Since(upstreamStart))
			// Check the username cache after the roundtrip; the async
			// lookup may have completed during the upstream wait.
			if ur != nil && raw != "" && GetUsername(r) == "" {
				if u := ur.CheckCache(raw); u != "" {
					SetUsername(r, u)
				}
			}
			// Emit proxy-level metrics for passthrough traffic (token type may be "unknown").
			metrics.ObservePassthroughRequest(backend.GitHub, r.Method, rec.status, time.Since(decisionStart), "git", passthroughTokenType(raw), GetUsername(r))
			return
		}

		repo, permission, level := GitSmartHTTPScope(r.Method, r.URL.Path, r.URL.RawQuery)
		if permission == "" {
			// Not a git smart HTTP path — resolve the GitHub token here rather
			// than relying on inner's Director, so that token resolution time is
			// charged to StageGitHubTokenResolution (pre-forward overhead) rather
			// than incorrectly to StageUpstreamRoundtrip.
			ghTokenStart := time.Now()
			realToken, err := resolver.ResolveToGitHubToken(r.Context(), clientTok)
			metrics.ObserveDecision(metrics.StageGitHubTokenResolution, extractTokenType, time.Since(ghTokenStart))
			if err != nil {
				if logger != nil {
					logger.Warn("git scope enforcement: GitHub token resolution failed", "error", err)
				}
				metrics.ObserveDecision(metrics.StageTotal, extractTokenType, time.Since(decisionStart))
				writeError(w, http.StatusUnauthorized, "Token resolution failed")
				return
			}
			r.Header.Set("Authorization", rewriteAuth(realToken))
			applyEnterprise(realToken)
			metrics.ObserveDecision(metrics.StageTotal, extractTokenType, time.Since(decisionStart))
			upstreamStart := time.Now()
			inner.ServeHTTP(w, r)
			metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, extractTokenType, time.Since(upstreamStart))
			return
		}

		start := time.Now()

		// Derive token type from prefix for pre-resolution metrics.
		resolveTokenType := ""
		if tt, ok := token.TokenTypeFromPrefix(clientTok); ok {
			resolveTokenType = string(tt)
		}

		// Resolve the full proxy token for scope checking.
		resolveStart := time.Now()
		pt, err := enforcer.Resolve(r.Context(), clientTok)
		metrics.ObserveDecision(metrics.StageTokenResolution, resolveTokenType, time.Since(resolveStart))
		if err != nil {
			if logger != nil {
				logger.Warn("git scope enforcement: token resolution failed", "error", err)
			}
			metrics.ObserveDecision(metrics.StageTotal, resolveTokenType, time.Since(decisionStart))
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}
		if pt == nil {
			metrics.ObserveDecision(metrics.StageTotal, resolveTokenType, time.Since(decisionStart))
			writeError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		tokenType := pt.TokenType

		// Inject the token creator's user ID for auditing. The actual GitHub
		// username is resolved later via the GraphQL viewer endpoint, after the
		// real GitHub token is obtained — giving the authenticated identity
		// (bot account for gha_ tokens, human for ghx_ tokens).
		username := ""
		if pt.UserID != nil {
			SetUserID(r, *pt.UserID)
		}

		// Wrap response writer to capture status code for metrics.
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			metrics.ObserveProxyRequest(backend.GitHub, pt, r.Method, rec.status, time.Since(start), "git", username)
		}()

		// Parse the token's scope restrictions once; fail-closed on corrupt JSON.
		scopeParseStart := time.Now()
		si, err := parseScopeInfo(pt)
		metrics.ObserveDecision(metrics.StageScopeParsing, tokenType, time.Since(scopeParseStart))
		if err != nil {
			if logger != nil {
				logger.Error("git scope enforcement: failed to parse token scope", "error", err)
			}
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			writeError(rec, http.StatusInternalServerError, "Internal error")
			return
		}

		// Open-scoped tokens (no repos AND no scopes) skip all filtering — forward directly.
		if si.isOpenScoped() {
			ghTokenStart := time.Now()
			realToken, err := resolver.ResolveToGitHubToken(r.Context(), clientTok)
			metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
			if err != nil {
				if logger != nil {
					logger.Warn("git scope enforcement: GitHub token resolution failed", "error", err)
				}
				metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
				writeError(rec, http.StatusUnauthorized, "Token resolution failed")
				return
			}
			usernameStart := time.Now()
			if ur != nil {
				if u := ur.ResolveFromGitHubToken(r.Context(), realToken); u != "" {
					username = u
					SetUsername(r, username)
				}
			}
			metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))
			r.Header.Set("Authorization", rewriteAuth(realToken))
			applyEnterprise(realToken)
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			upstreamStart := time.Now()
			inner.ServeHTTP(rec, r)
			metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))
			username = resolveUsernameAfterRoundtrip(r, realToken, username, ur, pt)
			return
		}

		// Enforce repository scope only when the token has repo restrictions.
		// A token with repos=null carries no repo restriction (applies to any repo).
		scopeEnforceStart := time.Now()
		if len(si.Repos) > 0 && !si.repoAllowed(repo) {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			writeError(rec, http.StatusForbidden,
				fmt.Sprintf("Token is not scoped to %s", repo))
			return
		}

		// Enforce permission scope only when the token has scope restrictions.
		// A token with scopes=null carries no permission restriction (any endpoint allowed).
		if len(si.Scopes) > 0 && !si.Scopes.HasPermission(permission, level) {
			metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			writeError(rec, http.StatusForbidden,
				fmt.Sprintf("Token does not have permission for %s:%s on %s", permission, level, repo))
			return
		}
		metrics.ObserveDecision(metrics.StageScopeEnforcement, tokenType, time.Since(scopeEnforceStart))

		// Scope checks passed (or dimension is unrestricted) — forward with resolved token.
		ghTokenStart := time.Now()
		realToken, err := resolver.ResolveToGitHubToken(r.Context(), clientTok)
		metrics.ObserveDecision(metrics.StageGitHubTokenResolution, tokenType, time.Since(ghTokenStart))
		if err != nil {
			if logger != nil {
				logger.Warn("git scope enforcement: GitHub token resolution failed", "error", err)
			}
			metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
			writeError(rec, http.StatusUnauthorized, "Token resolution failed")
			return
		}
		usernameStart := time.Now()
		if ur != nil {
			if u := ur.ResolveFromGitHubToken(r.Context(), realToken); u != "" {
				username = u
				SetUsername(r, username)
			}
		}
		metrics.ObserveDecision(metrics.StageUsernameResolution, tokenType, time.Since(usernameStart))
		r.Header.Set("Authorization", rewriteAuth(realToken))
		applyEnterprise(realToken)
		metrics.ObserveDecision(metrics.StageTotal, tokenType, time.Since(decisionStart))
		upstreamStart := time.Now()
		inner.ServeHTTP(rec, r)
		metrics.ObserveDecision(metrics.StageUpstreamRoundtrip, tokenType, time.Since(upstreamStart))
		username = resolveUsernameAfterRoundtrip(r, realToken, username, ur, pt)
	})
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

// Flush implements http.Flusher by delegating to the underlying writer.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter so callers can access
// optional interfaces (e.g. http.Hijacker) via httputil helpers.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// NewCopilotPassthroughHandler creates a transparent reverse proxy for
// *.githubcopilot.com traffic. The original Host header is preserved so the
// correct subdomain reaches the real Copilot service. No token interception
// or scope enforcement is performed; credentials in the Authorization header
// are forwarded verbatim. Caddy-compatible access logging and Prometheus
// metrics are applied consistently by the server layer (accessLogHandler),
// so this handler only concerns itself with proxying.
// The upstream parameter sets the network destination (scheme + host:port).
// The transport parameter allows callers to supply a custom RoundTripper;
// pass nil to use http.DefaultTransport.
func NewCopilotPassthroughHandler(upstream string, enterpriseSlug string, logger *slog.Logger, transport http.RoundTripper) http.Handler {
	target, _ := url.Parse(upstream)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = originalHost

			if enterpriseSlug != "" {
				req.Header.Set("sec-GitHub-allowed-enterprise", enterpriseSlug)
			}
		},
	}

	if transport != nil {
		proxy.Transport = transport
	}

	return proxy
}

// extractClientToken checks for a client token (ghx_/gha_) in the Authorization header.
// Supports "Bearer ghx_xxx", "token ghx_xxx", and Basic auth with
// username "x-access-token" and a client token password (as used by git credential helpers).
//
// Returns the plaintext client token (or "" if none found), the raw credential
// extracted from the header (for border-policy evaluation; "" if unparseable),
// and a rewrite function that builds a new Authorization header value preserving
// the original scheme.
func extractClientToken(r *http.Request) (string, string, func(realToken string) string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", nil
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return "", "", nil
	}
	scheme := strings.ToLower(parts[0])
	originalScheme := parts[0] // preserve original casing
	credential := parts[1]
	if scheme == "token" || scheme == "bearer" {
		if _, ok := token.TokenTypeFromPrefix(credential); ok {
			return credential, credential, func(realToken string) string {
				return originalScheme + " " + realToken
			}
		}
		// Not a managed client token — return raw credential for block-policy check.
		return "", credential, nil
	}
	if scheme == "basic" {
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return "", "", nil
		}
		user, pass, ok := strings.Cut(string(decoded), ":")
		if ok && strings.EqualFold(user, "x-access-token") {
			if _, ok := token.TokenTypeFromPrefix(pass); ok {
				return pass, pass, func(realToken string) string {
					return originalScheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+realToken))
				}
			}
		}
		// Basic auth (x-access-token or otherwise) — return the password for
		// block-policy evaluation. A non-client-token password may still carry
		// a GitHub token type that should be subject to the border policy.
		if ok {
			return "", pass, nil
		}
	}
	return "", "", nil
}

// tokenScopeInfo holds the parsed repository and permission scopes for a proxy
// token. A nil/empty slice or map means no restriction for that dimension.
type tokenScopeInfo struct {
	Repos  []string
	Scopes database.Scopes
}

// isOpenScoped returns true when neither repository nor permission restrictions
// are set, meaning the token carries the full permissions of the underlying
// credential without any filtering.
func (si tokenScopeInfo) isOpenScoped() bool {
	return len(si.Repos) == 0 && len(si.Scopes) == 0
}

// repoAllowed returns true if repo is in the token's repository allowlist.
// Must only be called when len(si.Repos) > 0.
func (si tokenScopeInfo) repoAllowed(repo string) bool {
	for _, r := range si.Repos {
		if strings.EqualFold(r, repo) {
			return true
		}
	}
	return false
}

// parseScopeInfo parses the Repositories and Scopes JSON fields of a proxy
// token. JSON null decodes to a nil slice/map and JSON empty arrays/maps
// decode to zero-length values; both are treated as "no restriction" by
// callers that check len(...) == 0. Returns an error for invalid JSON so
// callers fail safely rather than silently treating corrupt data as open-scoped.
func parseScopeInfo(pt *database.ProxyToken) (tokenScopeInfo, error) {
	var repos []string
	if err := json.Unmarshal(pt.Repositories, &repos); err != nil {
		return tokenScopeInfo{}, fmt.Errorf("parsing token repositories: %w", err)
	}
	var scopes database.Scopes
	if err := json.Unmarshal(pt.Scopes, &scopes); err != nil {
		return tokenScopeInfo{}, fmt.Errorf("parsing token scopes: %w", err)
	}
	return tokenScopeInfo{Repos: repos, Scopes: scopes}, nil
}
