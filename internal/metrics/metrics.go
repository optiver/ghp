// Package metrics registers all Prometheus metrics for ghp and provides helper
// functions for recording observations. Metrics are registered via promauto
// (auto-registering with the default registry) and exposed at /metrics on the
// dedicated metrics server (default port 9136).
//
// The package covers four metric categories:
//   - HTTP-level: request count and duration for all traffic by backend
//   - Proxy-level: detailed metrics for ghx_/gha_ authenticated and native GitHub token traffic (API and git smart-HTTP)
//   - Token lifecycle: creation, revocation, and active token counts
//   - Decision pipeline: per-stage latency breakdown of the proxy overhead
package metrics

import (
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP-level metrics for all requests, labeled by backend.
	HttpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_http_request_duration_seconds",
		Help:    "Duration of HTTP requests by backend.",
		Buckets: prometheus.DefBuckets,
	}, []string{"backend", "method", "status"})

	HttpRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_http_request_total",
		Help: "Total number of HTTP requests by backend.",
	}, []string{"backend", "method", "status"})

	ClientRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_client_request_total",
		Help: "Total number of requests by client source IP, backend, token type, and status.",
	}, []string{"client", "backend", "token_type", "status"})

	// Proxy-level metrics for ghx_/gha_ authenticated requests.
	ProxyRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_proxy_request_duration_seconds",
		Help:    "Duration of proxied requests to GitHub.",
		Buckets: prometheus.DefBuckets,
	}, []string{"backend", "method", "status", "token_type", "type", "user", "app"})

	ProxyRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_proxy_request_total",
		Help: "Total number of proxied requests.",
	}, []string{"backend", "method", "status", "token_type", "type", "user", "app"})

	// Note: this gauge is driven by in-process increment/decrement calls and is
	// not seeded from the database on startup. After a process restart it begins
	// at zero rather than reflecting the real count of active tokens in the store.
	TokenActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_token_active",
		Help: "Number of active tokens per user.",
	}, []string{"user"})

	TokenCreatedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_token_created_total",
		Help: "Total number of tokens created.",
	}, []string{"user"})

	TokenRevokedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_token_revoked_total",
		Help: "Total number of tokens revoked.",
	}, []string{"user"})

	// TokenCleanupDeletedTotal counts proxy tokens hard-deleted by the
	// periodic expired-token cleanup goroutine.
	TokenCleanupDeletedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_token_cleanup_deleted_total",
		Help: "Total number of expired or revoked proxy tokens hard-deleted by the cleanup goroutine.",
	})

	GitHubRateLimitRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_github_ratelimit_remaining",
		Help: "GitHub API rate limit remaining.",
	}, []string{"user"})

	GitHubRateLimitLimit = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_github_ratelimit_limit",
		Help: "GitHub API rate limit total.",
	}, []string{"user"})

	GitHubTokenRefreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_github_token_refresh_total",
		Help: "Total number of GitHub token refresh attempts.",
	}, []string{"user", "status"})

	// RateLimitTotal counts requests rejected by the auth/API rate limiters,
	// labelled by endpoint. Use this metric to alert on sustained abuse.
	RateLimitTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_auth_rate_limit_total",
		Help: "Total number of requests rejected by the auth rate limiter, by endpoint.",
	}, []string{"endpoint"})

	// ReleasesRedirectHeadCheckTotal counts the outcomes of HEAD requests
	// made to the redirect target when releases.redirect_head_check is enabled.
	// The "result" label is one of "found" (non-404 response, redirect proceeds),
	// "not_found" (404 returned, friendly error page served), or "error" (network
	// failure, redirect proceeds).
	ReleasesRedirectHeadCheckTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_releases_redirect_head_check_total",
		Help: "Total number of HEAD checks against the release redirect target, by result.",
	}, []string{"result"})

	// CodeloadRedirectTotal counts archive download requests handled by the
	// codeload.github.com handler, labeled by owner, repo, archive format
	// ("tar.gz", "zip", "legacy.tar.gz", "legacy.zip"), and result:
	//   "redirect"    — 302 issued to the configured caching mirror
	//   "passthrough" — request forwarded transparently to upstream codeload
	//                   (allow list match or no redirect_to configured)
	//
	// The full ref (SHA, branch, or tag) is not included as a label to keep
	// cardinality bounded; it is captured in access logs as part of the URL.
	// Cardinality: bounded by (cached repos × archive formats × results).
	CodeloadRedirectTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_codeload_redirect_total",
		Help: "Total codeload.github.com archive requests handled, by owner, repo, archive format, and result.",
	}, []string{"owner", "repo", "archive", "result"})

	// BlockAnonymousGitEnabled reflects whether the anonymous git blocking
	// feature is currently active (1) or inactive (0). Set at server startup
	// and on config reload (SIGUSR1); not updated per-request.
	BlockAnonymousGitEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_block_anonymous_git_enabled",
		Help: "Set to 1 when anonymous git blocking (block.anonymous_git) is enabled, 0 otherwise.",
	})

	// BlockAnonymousGitTotal counts the number of anonymous git requests
	// that were short-circuited before egressing to GitHub.
	BlockAnonymousGitTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_block_anonymous_git_total",
		Help: "Total number of anonymous git requests blocked by the anonymous git blocking feature.",
	})

	// EnterpriseExceptionTotal counts evaluations of enterprise access
	// restriction exceptions that matched a request's target, labeled by
	// outcome:
	//   "header_omitted"       — exception applied; restriction header not injected
	//   "identity_substituted" — exception applied and the caller's credential
	//                            was replaced with a managed installation token
	//   "team_denied"          — target matched but the caller is not a member
	//                            of any required team (or could not be
	//                            identified); restriction header kept
	//   "unauthenticated_denied" — target matched an identity-substituting
	//                            exception but the caller's identity could not
	//                            be resolved (anonymous or unverifiable
	//                            credential); restriction header kept
	//   "identity_error"       — target matched but the managed identity could
	//                            not be minted; restriction header kept (fail closed)
	EnterpriseExceptionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_enterprise_exception_total",
		Help: "Total number of enterprise access restriction exception matches, by outcome.",
	}, []string{"outcome"})

	// decisionBuckets covers internal decision-making stages (typically µs–ms)
	// as well as the upstream_roundtrip stage, which includes the actual GitHub
	// API call and can easily exceed 1s under load or on slow networks.
	decisionBuckets = []float64{
		0.00005, // 50µs
		0.0001,  // 100µs
		0.0005,  // 500µs
		0.001,   // 1ms
		0.005,   // 5ms
		0.01,    // 10ms
		0.025,   // 25ms
		0.05,    // 50ms
		0.1,     // 100ms
		0.25,    // 250ms
		0.5,     // 500ms
		1.0,     // 1s
		2.5,     // 2.5s
		5.0,     // 5s
		10.0,    // 10s
	}

	// ProxyDecisionDuration records time spent in each stage of the proxy
	// decision-making pipeline. Internal stages (token_extraction through
	// github_token_resolution) measure pre-forward overhead; upstream_roundtrip
	// measures the actual GitHub API call; total measures only the pre-forward
	// decision-making overhead (i.e., arrival to just before the upstream call).
	// The "stage" label identifies the pipeline step:
	//
	//   total                  – arrival to completion of proxy decision (pre-forward only; upstream not included)
	//   token_extraction       – unpacking the Authorization header
	//   border_policy_check    – evaluating the token type border policy (block config)
	//   token_resolution       – SHA-256 hash + database lookup + expiry/revocation check
	//   username_resolution    – resolving GitHub username from user ID
	//   scope_parsing          – JSON unmarshalling of repository & permission scopes
	//   scope_enforcement      – repository allowlist + permission level checks
	//   github_token_resolution – loading & decrypting (or refreshing) the real GitHub credential
	//   upstream_roundtrip     – proxying the upstream GitHub request and streaming the response (network + GitHub processing + response body transfer)
	//   redirect_head_check   – HEAD request to the release redirect target to verify asset availability (releases handler only)
	//   graphql_analysis      – parsing a GraphQL request body and computing the static scope/repository requirements (GraphQL handler only)
	ProxyDecisionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ghp_proxy_decision_duration_seconds",
		Help:    "Duration of each stage in the proxy decision pipeline.",
		Buckets: decisionBuckets,
	}, []string{"stage", "token_type"})

	// --- Git Cache Metrics ---

	// CacheFetchTotal counts git fetch requests to cache-enabled repositories,
	// labeled by result: "hit" (served from cache), "miss" (fetched from upstream
	// first), "rejected" (access denied), "error" (cache or upstream failure).
	// Per-repo breakdown is available via access logs to avoid unbounded label
	// cardinality.
	CacheFetchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_fetch_total",
		Help: "Total git fetch requests to cache-enabled repositories, by result.",
	}, []string{"result"})

	// CacheLsRefsTotal counts ls-refs commands forwarded to upstream for
	// cache-enabled repositories.
	CacheLsRefsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_cache_lsrefs_total",
		Help: "Total ls-refs commands forwarded to upstream for cached repos.",
	})

	// CacheWarmTotal counts async cache warming operations triggered when
	// refs change, labeled by result ("success" or "error").
	CacheWarmTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_warm_total",
		Help: "Total cache warming operations triggered by ref changes, by result.",
	}, []string{"result"})

	// CacheReposActive is a gauge reflecting how many repositories currently
	// have caching enabled in the database.
	CacheReposActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ghp_cache_repos_active",
		Help: "Number of repositories with caching currently enabled.",
	})

	// CacheRequestTotal counts git smart HTTP requests per repository with
	// cache outcome. Labels: owner, repo, result. Result values:
	//   "hit"     — served from local cache
	//   "miss"    — cache miss, fetched upstream then served
	//   "nocache" — repository not configured for caching
	//   "bypass"  — repository configured but caching disabled
	//   "error"   — cache operation failed
	//   "rejected"    — upstream rejected access
	//   "passthrough" — delegated to upstream proxy
	//
	// Cardinality note: bounded by the number of distinct repositories
	// accessed through the proxy (typically hundreds). Intended for
	// identifying cache candidate repositories via PromQL.
	CacheRequestTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_request_total",
		Help: "Git smart HTTP requests per repository with cache outcome.",
	}, []string{"owner", "repo", "result"})

	// CachePackfileTotal counts packfile response cache operations, labeled
	// by result: "hit" (served from disk), "miss" (proxied upstream and cached).
	// This is distinct from CacheFetchTotal which tracks the broader fetch flow
	// including rejections and errors. Use this metric to measure the disk cache
	// effectiveness and inform TTL eviction tuning.
	//
	// Labels: owner, repo, user (GitHub username), result.
	// Cardinality: bounded by (cached repos × active users × 2 results).
	CachePackfileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_packfile_total",
		Help: "Packfile response cache operations by result (hit = served from disk, miss = proxied upstream).",
	}, []string{"owner", "repo", "user", "result"})

	// CachePackfileBytesTotal counts the total bytes served from the packfile
	// response cache, labeled by result. Comparing hit vs miss bytes shows the
	// upstream bandwidth saved by caching.
	//
	// Labels: owner, repo, user (GitHub username), result.
	CachePackfileBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_packfile_bytes_total",
		Help: "Total bytes served from packfile response cache by result.",
	}, []string{"owner", "repo", "user", "result"})

	// CacheEvictionTotal counts the number of cached protocol response files
	// evicted by the size-limit cleanup goroutine, labeled by owner and repo.
	CacheEvictionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cache_eviction_total",
		Help: "Total cached protocol response files evicted by size-limit cleanup.",
	}, []string{"owner", "repo"})

	// CacheResponseSizeBytes reports the current total size (in bytes) of
	// cached protocol response files per repository, updated each cleanup cycle.
	CacheResponseSizeBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_cache_response_size_bytes",
		Help: "Current total size of cached protocol response files per repository.",
	}, []string{"owner", "repo"})

	// CLIDeviceStartedTotal counts CLI device-authorization requests
	// initiated via POST /cli/auth/device. Each "ghp auth login" invocation
	// increments this counter exactly once.
	CLIDeviceStartedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ghp_cli_auth_device_started_total",
		Help: "Total number of CLI device-authorization requests initiated.",
	})

	// CLIDeviceCompletedTotal counts CLI device-authorization requests that
	// reached a terminal state, labeled by result: "approved" (user
	// authorized and CLI received a session token), "denied" (user clicked
	// deny), or "expired" (record TTL'd before the user acted).
	CLIDeviceCompletedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ghp_cli_auth_device_completed_total",
		Help: "Total number of CLI device-authorization requests that reached a terminal state.",
	}, []string{"result"})

	// BuildInfo is a gauge with a constant value of 1 labeled by build
	// metadata. It follows the node_exporter_build_info convention.
	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ghp_build_info",
		Help: "A metric with a constant '1' value labeled by version, revision, goversion, goos, and goarch from which ghp was built.",
	}, []string{"version", "revision", "goversion", "goos", "goarch"})
)

// Decision pipeline stage constants.
const (
	StageTotal                 = "total"
	StageTokenExtraction       = "token_extraction"
	StageBorderPolicyCheck     = "border_policy_check"
	StageTokenResolution       = "token_resolution"
	StageUsernameResolution    = "username_resolution"
	StageScopeParsing          = "scope_parsing"
	StageScopeEnforcement      = "scope_enforcement"
	StageGitHubTokenResolution = "github_token_resolution"
	StageUpstreamRoundtrip     = "upstream_roundtrip"
	StageRedirectHeadCheck     = "redirect_head_check"
	StageCacheLookup           = "cache_lookup"
	StageGraphQLAnalysis       = "graphql_analysis"
	StageEnterpriseException   = "enterprise_exception"
)

// ObserveDecision records the duration of a single stage in the proxy
// decision pipeline. tokenType should be "proxy", "agent", or "" for stages
// that run before the token type is known (normalised to "unknown").
func ObserveDecision(stage, tokenType string, dur time.Duration) {
	if tokenType == "" {
		tokenType = "unknown"
	}
	ProxyDecisionDuration.WithLabelValues(stage, tokenType).Observe(dur.Seconds())
}

// ObserveProxyRequest records proxy-level request metrics for a completed request.
// If pt is nil the call is a no-op. apiType describes the request type (for example
// "rest", "graphql", or "git") used for the "type" metric label; callers should pass
// an appropriate value or "" if the type is unknown. The username parameter should be
// the GitHub username of the token owner (not the internal user ID).
func ObserveProxyRequest(backend string, pt *database.ProxyToken, method string, status int, dur time.Duration, apiType string, username string) {
	if pt == nil {
		return
	}
	if username == "" {
		username = "unknown"
	}
	app := ""
	if pt.InstallationID != nil {
		app = strconv.FormatInt(*pt.InstallationID, 10)
	}
	statusStr := strconv.Itoa(status)

	ProxyRequestDuration.WithLabelValues(backend, method, statusStr, pt.TokenType, apiType, username, app).Observe(dur.Seconds())
	ProxyRequestTotal.WithLabelValues(backend, method, statusStr, pt.TokenType, apiType, username, app).Inc()
}

// ObservePassthroughRequest records proxy-level request metrics for passthrough
// traffic forwarded without ghx_/gha_ token resolution. It uses the same
// ProxyRequestDuration and ProxyRequestTotal vectors as managed tokens, with an
// empty "app" label. Token type and username are best-effort: when no native
// token is present they are recorded as "unknown".
func ObservePassthroughRequest(backendName, method string, status int, dur time.Duration, apiType, tokenType, username string) {
	if username == "" {
		username = "unknown"
	}
	if tokenType == "" {
		tokenType = "unknown"
	}
	statusStr := strconv.Itoa(status)
	ProxyRequestDuration.WithLabelValues(backendName, method, statusStr, tokenType, apiType, username, "").Observe(dur.Seconds())
	ProxyRequestTotal.WithLabelValues(backendName, method, statusStr, tokenType, apiType, username, "").Inc()
}

func ObserveClientRequest(client, backendName, tokenType string, status int) {
	if client == "" {
		client = "unknown"
	}
	if tokenType == "" {
		tokenType = "unknown"
	}
	ClientRequestTotal.WithLabelValues(client, backendName, tokenType, strconv.Itoa(status)).Inc()
}

// SetBuildInfo records build metadata as a gauge with a constant value of 1.
// It should be called once at server startup. The revision is extracted from
// Go's debug.ReadBuildInfo VCS metadata; if unavailable it defaults to "unknown".
func SetBuildInfo(version string) {
	revision := "unknown"
	if info, ok := runtimeDebugReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				revision = s.Value
				break
			}
		}
	}
	BuildInfo.WithLabelValues(version, revision, runtime.Version(), runtime.GOOS, runtime.GOARCH).Set(1)
}

// runtimeDebugReadBuildInfo is an indirection over debug.ReadBuildInfo so that
// tests can inject a fake. It is package-level so tests can swap it.
var runtimeDebugReadBuildInfo = defaultReadBuildInfo

func defaultReadBuildInfo() (*debug.BuildInfo, bool) {
	return debug.ReadBuildInfo()
}
