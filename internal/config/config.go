// Package config handles loading and managing the ghp server configuration.
// Configuration is loaded from a YAML file and/or environment variables with
// the GHP_ prefix. The package supports hot-reloading of a subset of fields
// via SIGUSR1: config is reloaded, and settings that are read on each request
// (for example admins, auth and block policies, release handling, and the token
// default duration) take effect without restart. Settings that are bound at
// startup, such as logging level/output, metrics server enable/disable, token
// maximum duration and allow-no-expiry, and infrastructure-related fields (database, TLS, listen
// addresses, encryption key), are only applied on process start.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/goodtune/ghp/internal/netutil"
)

// Config represents the complete server configuration.
//
// Hot-reloadable fields (Admins, Tokens, Logging, Metrics, Auth, Block,
// Releases, Codeload, Cache) are mutated in place by ReloadFrom on SIGUSR1.
// To make per-request reads race-free with that mutation, an unexported mu
// guards those fields; ReloadFrom takes the write lock for the duration of
// the update.
//
// Reads on the hot request path should go through the locking accessor
// methods on this type — IsAdmin, IsTokenBlocked, IsReleaseAllowed,
// IsCodeloadAllowed, and CodeloadRedirectTo — which take the read lock and
// return values that are safe to use after the lock is released. Reads of
// the embedded structs (e.g. cfg.Releases.Mode) are NOT race-free; existing
// call sites that pre-date this PR fall into that category and should be
// migrated to accessor methods (or new ones added — see the CodeloadRedirectTo
// pattern) as they're touched.
//
// Static fields (GitHub, Database, Server, TLS, EncryptionKey, DevMode) are
// populated once at startup and never mutated, so they're safe to read
// directly.
type Config struct {
	// mu guards all hot-reloadable fields below. Held for the duration of
	// ReloadFrom so a single SIGUSR1 either fully replaces the runtime
	// fields or is invisible to a reader that has the read lock.
	mu sync.RWMutex

	GitHub   GitHubConfig   `koanf:"github"`
	Database DatabaseConfig `koanf:"database"`
	Server   ServerConfig   `koanf:"server"`
	TLS      TLSConfig      `koanf:"tls"`
	Tokens   TokensConfig   `koanf:"tokens"`
	Logging  LoggingConfig  `koanf:"logging"`
	Metrics  MetricsConfig  `koanf:"metrics"`
	OTEL     OTELConfig     `koanf:"otel"`
	Admins   []string       `koanf:"admins"`
	Auth     AuthConfig     `koanf:"auth"`
	Block    BlockConfig    `koanf:"block"`
	Releases ReleasesConfig `koanf:"releases"`
	Codeload CodeloadConfig `koanf:"codeload"`

	Cache CacheConfig `koanf:"cache"`

	EncryptionKey string `koanf:"encryption_key"`

	// DevMode enables test-only endpoints (e.g. /auth/test-login).
	// Must never be enabled in production.
	DevMode bool `koanf:"dev_mode"`
}

// BlockConfig defines which GitHub token prefixes are blocked from
// passing through the proxy, and enables other opt-in blocking features.
// Each GH* field corresponds to one of the five token types minted by
// GitHub. When a field is true, any request bearing a token of that type
// is rejected with 403. AnonymousGit enables short-circuiting of anonymous
// git smart HTTP requests (requests bearing a Git-Protocol header and no
// Authorization header) before they egress to GitHub.
//
// Blocking ghp's own token types (ghx_, gha_) is not valid and will
// produce a warning at startup — those tokens are managed internally
// and never reach the passthrough path.
type BlockConfig struct {
	GHP          bool `koanf:"ghp"`           // Classic personal access tokens (ghp_)
	GHO          bool `koanf:"gho"`           // OAuth access tokens (gho_)
	GHU          bool `koanf:"ghu"`           // GitHub user-to-server tokens (ghu_)
	GHS          bool `koanf:"ghs"`           // GitHub server-to-server tokens (ghs_)
	GHR          bool `koanf:"ghr"`           // Refresh tokens (ghr_)
	GithubPat    bool `koanf:"github_pat"`    // Fine-grained personal access tokens (github_pat_)
	AnonymousGit bool `koanf:"anonymous_git"` // Block anonymous git smart HTTP requests (identified by Git-Protocol header + no auth)
}

// ReleasesConfig controls how github.com release download requests are handled.
// When Mode is "block", requests to /{org}/{repo}/releases/download/** are
// rejected with 403 unless the org or org/repo appears in Allow.
// When Mode is "redirect", matched requests are redirected to RedirectTo + the
// original path. Mode "" (the default) disables the feature entirely.
type ReleasesConfig struct {
	// Mode is the enforcement policy: "block" or "redirect".
	// Empty string means the feature is disabled (default).
	Mode string `koanf:"mode"`
	// RedirectTo is the base URL prepended to the original path in redirect mode.
	// Example: "https://releases.example.com/"
	RedirectTo string `koanf:"redirect_to"`
	// RedirectHeadCheck, when true, causes the proxy to issue a HEAD request to
	// the redirect target URL before responding with a 302. If the HEAD response
	// is 404, the proxy returns a friendly 404 page instead of redirecting the
	// client to a URL that would itself 404. This is useful when the redirect
	// target is a selective mirror that only hosts a subset of releases.
	RedirectHeadCheck bool `koanf:"redirect_head_check"`
	// RedirectHeadCheckNetrc is the path to a netrc file whose credentials are
	// sent as Basic auth on HEAD availability probes over HTTPS. Credentials
	// are never injected for plain http:// URLs (to prevent cleartext leakage)
	// and existing Authorization headers are never overwritten. Because GHP
	// typically runs as a DynamicUser (no home directory), this should normally
	// be an absolute path to a file the service can read — e.g. /etc/ghp/netrc.
	// When empty, HEAD requests are sent without authentication.
	RedirectHeadCheckNetrc string `koanf:"redirect_head_check_netrc"`
	// RedirectNotFoundTemplate is the path to a custom HTML template file rendered
	// when RedirectHeadCheck detects a 404 from the redirect target. The template
	// is executed with html/template and receives a struct with fields Owner, Repo,
	// Tag, Asset, and URL. If empty, a built-in default template is used.
	RedirectNotFoundTemplate string `koanf:"redirect_not_found_template"`
	// Allow is a list of org or org/repo entries that are exempt from the policy.
	// Entries may be bare org names (e.g. "goodtune") or org/repo pairs
	// (e.g. "goodtune/ghp"). Matching is case-insensitive.
	Allow []string `koanf:"allow"`
}

// CodeloadConfig controls how codeload.github.com archive download requests
// are handled. The codeload service serves repository archives at paths of the
// form /{owner}/{repo}/(tar.gz|zip|legacy.tar.gz|legacy.zip)/{ref} — these are
// highly cacheable (the (org, repo, sha) tuple is immutable) and a common
// hotspot for build agents that resolve actions like actions/checkout@v4.
//
// When RedirectTo is set, matching archive requests are redirected with a 302
// to RedirectTo + the original path, allowing an internal caching mirror to
// serve the archive. When RedirectTo is empty, all codeload.github.com traffic
// is forwarded transparently to the upstream service.
type CodeloadConfig struct {
	// RedirectTo is the base URL prepended to the original path when
	// redirecting archive requests. Must be an absolute URL with scheme + host
	// (e.g. "https://codeload.cache.example.com/"). When empty, the codeload
	// handler simply proxies requests through to upstream codeload.github.com.
	RedirectTo string `koanf:"redirect_to"`
	// Allow is a list of org or org/repo entries that are exempt from the
	// redirect (passed through to upstream). Entries may be bare org names
	// (e.g. "goodtune") or org/repo pairs (e.g. "goodtune/ghp"). Matching is
	// case-insensitive.
	Allow []string `koanf:"allow"`
}

type TLSConfig struct {
	Certificates []CertificateConfig `koanf:"certificates"`
	// MinVersion sets the minimum TLS version accepted by the server.
	// Allowed values: "1.2" (default), "1.3".
	MinVersion string `koanf:"min_version"`
}

type CertificateConfig struct {
	CertFile string `koanf:"cert_file"`
	KeyFile  string `koanf:"key_file"`
}

type GitHubConfig struct {
	AppID          int64  `koanf:"app_id"`
	ClientID       string `koanf:"client_id"`
	ClientSecret   string `koanf:"client_secret"`
	PrivateKey     string `koanf:"private_key"`      // PEM contents directly (GHP_GITHUB_PRIVATE_KEY)
	PrivateKeyFile string `koanf:"private_key_file"` // Path to PEM file (GHP_GITHUB_PRIVATE_KEY_FILE)
	BaseURL        string `koanf:"base_url"`         // GitHub API base URL for GHES (default: https://api.github.com)
	EnterpriseSlug string `koanf:"enterprise_slug"`
	// EnterpriseExceptions lists targets that are exempt from the enterprise
	// access restriction header (sec-GitHub-allowed-enterprise) injected when
	// EnterpriseSlug is set. GitHub provides no server-side exception
	// mechanism for this feature — its documentation directs proxies to
	// inject the header only for traffic that should be restricted — so the
	// exemption is implemented here by omitting the header for matching
	// requests. At least one valid exception also enables the narrow CLI
	// login identity/scope checks needed to authenticate external accounts.
	// Only meaningful when EnterpriseSlug is non-empty. Because
	// entries are nested structures, this field can only be configured via
	// YAML, not environment variables.
	EnterpriseExceptions []EnterpriseException `koanf:"enterprise_exceptions"`
}

// EnterpriseException exempts requests targeting the listed owners or
// repositories from the enterprise access restriction header, optionally
// gated on team membership and optionally substituting a managed identity.
type EnterpriseException struct {
	// Match lists the targets covered by this exception. Entries are either a
	// bare account name ("torvalds", "kubernetes") — matching every repository
	// owned by that user or organization — or an owner/repo pair
	// ("kubernetes/website") matching a single repository. Matching is
	// case-insensitive.
	Match []string `koanf:"match"`
	// Teams optionally restricts who may exercise this exception. Entries are
	// "org/team-slug" pairs. When non-empty, the requesting user's GitHub
	// username must be an active member of at least one listed team; requests
	// from anyone else (or whose identity cannot be resolved) are treated as
	// if the exception did not match, i.e. the restriction header stays on.
	// Membership is checked via the GitHub API using the default GitHub App,
	// which must be installed on the team's organization with members:read.
	Teams []string `koanf:"teams"`
	// Identity optionally substitutes a managed credential for the caller's
	// own when the exception applies (e.g. so a push to an off-enterprise
	// repository is performed by a dedicated integration identity).
	Identity EnterpriseExceptionIdentity `koanf:"identity"`
}

// EnterpriseExceptionIdentity selects the managed credential substituted for
// requests covered by an EnterpriseException.
type EnterpriseExceptionIdentity struct {
	// AppRecordID is the database record ID (UUID) of a GitHub App registered
	// via the admin UI/API. When set, requests covered by the exception have
	// their Authorization header replaced with an installation token minted
	// from this app's installation on the target owner. When empty, the
	// caller's own credential is forwarded (with the restriction header
	// omitted). If token minting fails, the exception is treated as not
	// matching (fail closed: the restriction header stays on).
	AppRecordID string `koanf:"app_record_id"`
}

type DatabaseConfig struct {
	Driver        string `koanf:"driver"`
	DSN           string `koanf:"dsn"`
	VaultAddr     string `koanf:"vault_addr"`
	VaultMount    string `koanf:"vault_mount"`
	VaultPath     string `koanf:"vault_path"`
	VaultRoleID   string `koanf:"vault_role_id"`
	VaultSecretID string `koanf:"vault_secret_id"`

	// VaultAuthMethod selects how ghp authenticates to Vault.
	// Supported values: "approle" (default) and "kubernetes".
	VaultAuthMethod string `koanf:"vault_auth_method"`
	// VaultK8sRole is the Vault role to authenticate as when
	// VaultAuthMethod is "kubernetes". Required for that method.
	VaultK8sRole string `koanf:"vault_k8s_role"`
	// VaultK8sMount is the Vault auth mount path for the kubernetes
	// auth backend (e.g. "kubernetes" or "kubernetes/cluster-name").
	// Defaults to "kubernetes" when empty.
	VaultK8sMount string `koanf:"vault_k8s_mount"`
	// VaultK8sTokenPath is the path on disk to the projected service
	// account token. The file is re-read on each (re-)authentication so
	// rotated tokens are picked up automatically. Defaults to the
	// in-cluster path when empty.
	VaultK8sTokenPath string `koanf:"vault_k8s_token_path"`
}

type ServerConfig struct {
	Listen                  string `koanf:"listen"`
	HTTPSListen             string `koanf:"https_listen"`
	HTTPListen              string `koanf:"http_listen"`
	ManagementHost          string `koanf:"management_host"`
	SystemdSocketActivation bool   `koanf:"systemd_socket_activation"`
	BaseURL                 string `koanf:"base_url"`
	// TrustProxyHeaders controls whether ghp honours the standardised
	// Forwarded (RFC 7239) and X-Forwarded-Proto/X-Forwarded-Host headers
	// when constructing absolute URLs (e.g. the device-auth verification
	// URI and OAuth callback URLs) and base_url is unset. Set to true only
	// when ghp sits behind a trusted reverse proxy/L7 LB that strips and
	// rewrites these headers. Default false: an internet-reachable instance
	// would otherwise allow a client to spoof scheme/host via these
	// headers and influence generated URLs (host-header injection). The
	// preferred deployment pattern is to set base_url explicitly so the
	// fallback path is never exercised.
	TrustProxyHeaders bool   `koanf:"trust_proxy_headers"`
	ClientIPHeader    string `koanf:"client_ip_header"`
}

type TokensConfig struct {
	DefaultDuration              time.Duration `koanf:"default_duration"`
	MaxDuration                  time.Duration `koanf:"max_duration"`
	AllowNoExpiry                bool          `koanf:"allow_no_expiry"`
	// ExpiredTokenRetentionPeriod is how long after a token expires or is
	// revoked before it is hard-deleted from the database.  Defaults to
	// 30 days.  Set to 0 to disable automatic cleanup.
	ExpiredTokenRetentionPeriod time.Duration `koanf:"expired_token_retention_period"`
}

type LoggingConfig struct {
	Output string        `koanf:"output"`
	Level  string        `koanf:"level"`
	File   LogFileConfig `koanf:"file"`
}

type LogFileConfig struct {
	Path string `koanf:"path"`
}

type MetricsConfig struct {
	Enabled bool   `koanf:"enabled"`
	Listen  string `koanf:"listen"`
}

type OTELConfig struct {
	Enabled  bool   `koanf:"enabled"`
	Endpoint string `koanf:"endpoint"`
	Protocol string `koanf:"protocol"`
}

// CacheConfig holds settings for the Git clone/fetch caching feature.
// When enabled, repositories listed in the database as cached will have
// their git objects stored locally and served from cache on subsequent
// fetch requests, reducing load on GitHub and improving clone performance.
type CacheConfig struct {
	// Enabled activates the git cache feature. When false, all git operations
	// pass through to GitHub as normal.
	Enabled bool `koanf:"enabled"`
	// StoragePath is the local filesystem path where cached bare repos are stored.
	// Defaults to "cache" in the current working directory.
	StoragePath string `koanf:"storage_path"`
	// S3Bucket, when set, uses S3-compatible object storage instead of local
	// filesystem. The StoragePath is used as the key prefix within the bucket.
	S3Bucket string `koanf:"s3_bucket"`
	// S3Region is the AWS region for the S3 bucket.
	S3Region string `koanf:"s3_region"`
	// S3Endpoint is a custom S3-compatible endpoint URL (for MinIO, etc).
	S3Endpoint string `koanf:"s3_endpoint"`
}

// AuthConfig holds settings for the OAuth broker feature.
type AuthConfig struct {
	// JWTPrivateKey is the PEM-encoded RSA private key used to sign broker JWTs
	// with RS256 (asymmetric signing). When set, it takes precedence over
	// JWTPrivateKeyFile and the broker endpoints are enabled. Downstream services
	// can verify tokens using the corresponding public key (via /.well-known/jwks.json)
	// without being able to forge them.
	JWTPrivateKey string `koanf:"jwt_private_key"`
	// JWTPrivateKeyFile is the path to a PEM-encoded RSA private key file.
	// Used when JWTPrivateKey is not set directly.
	JWTPrivateKeyFile string `koanf:"jwt_private_key_file"`
	// AllowedRedirects is a list of permitted redirect_uri values or wildcard
	// domain patterns (e.g. "*.example.com") for the OAuth broker flow.
	AllowedRedirects []string `koanf:"allowed_redirects"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Database: DatabaseConfig{
			Driver:            "sqlite",
			DSN:               "ghp.db",
			VaultAuthMethod:   "approle",
			VaultK8sMount:     "kubernetes",
			VaultK8sTokenPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		Server: ServerConfig{
			Listen: ":8080",
		},
		Tokens: TokensConfig{
			DefaultDuration:             24 * time.Hour,
			MaxDuration:                 7 * 24 * time.Hour,
			ExpiredTokenRetentionPeriod: 30 * 24 * time.Hour,
		},
		Logging: LoggingConfig{
			Output: "stdout",
			Level:  "info",
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Listen:  ":9136",
		},
		OTEL: OTELConfig{
			Protocol: "grpc",
		},
		Cache: CacheConfig{
			StoragePath: "cache",
		},
	}
}

// Load reads configuration from a YAML file and applies environment variable overrides.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	cfg := Defaults()

	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file %s: %w", path, err)
		}
	}

	// Environment variable overrides: GHP_GITHUB_CLIENT_ID -> github.client_id
	// Only the first underscore separates the section from the field name;
	// subsequent underscores are preserved as literal characters in field names
	// (e.g. GHP_GITHUB_CLIENT_ID -> github.client_id, GHP_DEV_MODE -> dev_mode).
	if err := k.Load(env.Provider(".", env.Opt{
		Prefix: "GHP_",
		TransformFunc: func(s string, v string) (string, any) {
			s = strings.TrimPrefix(s, "GHP_")
			s = strings.ToLower(s)
			if i := strings.Index(s, "_"); i > 0 {
				section, field := s[:i], s[i+1:]
				switch section {
				case "github", "database", "server", "tls", "tokens", "logging", "metrics", "otel", "auth", "block", "releases", "codeload", "cache":
					// Handle 3-level nesting for logging.file.*
					if section == "logging" && strings.HasPrefix(field, "file_") {
						return "logging.file." + field[len("file_"):], v
					}
					return section + "." + field, v
				}
			}
			return s, v
		},
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	clientIPHeader, err := netutil.ParseIPHeader(cfg.Server.ClientIPHeader)
	if err != nil {
		return nil, fmt.Errorf("server.client_ip_header: %w", err)
	}
	cfg.Server.ClientIPHeader = string(clientIPHeader)

	// Comma-separated list env vars for slice fields. koanf unmarshals
	// a single env var string into a one-element slice, so we split on
	// commas to support e.g. GHP_ADMINS="alice,bob".
	cfg.Admins = splitCommaSlice(cfg.Admins)
	cfg.Auth.AllowedRedirects = splitCommaSlice(cfg.Auth.AllowedRedirects)
	cfg.Releases.Allow = splitCommaSlice(cfg.Releases.Allow)
	cfg.Codeload.Allow = splitCommaSlice(cfg.Codeload.Allow)

	// GHP_RELEASES_ALLOW_COUNT + GHP_RELEASES_ALLOW_N support indexed allow
	// lists that cannot be expressed as comma-separated values. When set, the
	// indexed entries replace any allow list loaded from YAML or other env vars.
	if countStr := os.Getenv("GHP_RELEASES_ALLOW_COUNT"); countStr != "" {
		count, err := strconv.Atoi(countStr)
		if err != nil {
			return nil, fmt.Errorf("invalid GHP_RELEASES_ALLOW_COUNT %q: %w", countStr, err)
		}
		if count < 0 {
			return nil, fmt.Errorf("invalid GHP_RELEASES_ALLOW_COUNT %q: must be non-negative", countStr)
		}
		entries := make([]string, 0, count)
		for i := 0; i < count; i++ {
			key := fmt.Sprintf("GHP_RELEASES_ALLOW_%d", i)
			v := strings.TrimSpace(os.Getenv(key))
			if v == "" {
				return nil, fmt.Errorf("%s not set or empty (GHP_RELEASES_ALLOW_COUNT=%d)", key, count)
			}
			entries = append(entries, v)
		}
		cfg.Releases.Allow = entries
	}

	// GHP_CODELOAD_ALLOW_COUNT + GHP_CODELOAD_ALLOW_N support indexed allow
	// lists that cannot be expressed as comma-separated values. When set, the
	// indexed entries replace any allow list loaded from YAML or other env vars.
	if countStr := os.Getenv("GHP_CODELOAD_ALLOW_COUNT"); countStr != "" {
		count, err := strconv.Atoi(countStr)
		if err != nil {
			return nil, fmt.Errorf("invalid GHP_CODELOAD_ALLOW_COUNT %q: %w", countStr, err)
		}
		if count < 0 {
			return nil, fmt.Errorf("invalid GHP_CODELOAD_ALLOW_COUNT %q: must be non-negative", countStr)
		}
		entries := make([]string, 0, count)
		for i := 0; i < count; i++ {
			key := fmt.Sprintf("GHP_CODELOAD_ALLOW_%d", i)
			v := strings.TrimSpace(os.Getenv(key))
			if v == "" {
				return nil, fmt.Errorf("%s not set or empty (GHP_CODELOAD_ALLOW_COUNT=%d)", key, count)
			}
			entries = append(entries, v)
		}
		cfg.Codeload.Allow = entries
	}

	// Convenience env vars for the common single-certificate case.
	// GHP_TLS_CERT_FILE / GHP_TLS_KEY_FILE populate Certificates[0]
	// when the slice is empty (the koanf env mapper cannot address
	// array elements).
	if len(cfg.TLS.Certificates) == 0 {
		certFile := os.Getenv("GHP_TLS_CERT_FILE")
		keyFile := os.Getenv("GHP_TLS_KEY_FILE")
		if certFile != "" && keyFile != "" {
			cfg.TLS.Certificates = []CertificateConfig{
				{CertFile: certFile, KeyFile: keyFile},
			}
		}
	}

	return cfg, nil
}

// ReloadFrom re-reads a YAML config file and updates hot-reloadable fields
// in-place. Fields that require a restart (database, server listen addresses,
// TLS certificates) are not updated.
//
// The hot-reloadable field updates are serialised with the read locks held by
// the accessor methods (IsAdmin, IsTokenBlocked, IsReleaseAllowed,
// IsCodeloadAllowed, CodeloadRedirectTo). The guarantee is per accessor call:
// any single accessor invocation observes either the pre-reload or
// post-reload value of the field it reads — never a torn read of a slice or
// string. The guarantee does NOT extend across multiple accessor calls;
// e.g. CodeloadRedirectTo() followed by IsCodeloadAllowed(...) may interleave
// with a reload between them, so a handler that needs cross-field consistency
// must add a snapshot accessor that takes the lock once and copies the
// related fields together.
func (c *Config) ReloadFrom(path string) error {
	fresh, err := Load(path)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Admins = fresh.Admins
	c.Tokens = fresh.Tokens
	c.Logging = fresh.Logging
	c.Metrics = fresh.Metrics
	c.Auth = fresh.Auth
	c.Block = fresh.Block
	c.Releases = fresh.Releases
	c.Codeload = fresh.Codeload
	c.Cache = fresh.Cache
	return nil
}

// splitCommaSlice re-splits a string slice so that any element containing
// commas is expanded. This lets env vars like GHP_ADMINS="a,b" work even
// though koanf treats the value as a single string.
func splitCommaSlice(ss []string) []string {
	var out []string
	for _, s := range ss {
		for _, part := range strings.Split(s, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// IsAdmin returns true if the given GitHub username is in the admin list.
//
// Safe to call concurrently with ReloadFrom: the read lock is held for the
// duration of the lookup, so an in-flight reload either fully precedes or
// fully follows this call.
func (c *Config) IsAdmin(username string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, admin := range c.Admins {
		if strings.EqualFold(admin, username) {
			return true
		}
	}
	return false
}

// IsTokenBlocked returns true when the token string's type prefix is blocked by
// the border policy. Only the standard GitHub token prefixes are evaluated;
// ghp's own managed token types (ghx_, gha_) are never considered here.
//
// Safe to call concurrently with ReloadFrom.
func (c *Config) IsTokenBlocked(token string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	switch {
	case strings.HasPrefix(token, "ghp_"):
		return c.Block.GHP
	case strings.HasPrefix(token, "gho_"):
		return c.Block.GHO
	case strings.HasPrefix(token, "ghu_"):
		return c.Block.GHU
	case strings.HasPrefix(token, "ghs_"):
		return c.Block.GHS
	case strings.HasPrefix(token, "ghr_"):
		return c.Block.GHR
	case strings.HasPrefix(token, "github_pat_"):
		return c.Block.GithubPat
	}
	return false
}

// IsReleaseAllowed returns true when the given org or org/repo combination
// appears in the releases allow list, meaning it is exempt from the releases
// policy (block or redirect). Matching is case-insensitive. An org-only entry
// (e.g. "goodtune") permits any repository under that org.
//
// Safe to call concurrently with ReloadFrom.
func (c *Config) IsReleaseAllowed(org, repo string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	orgRepo := org + "/" + repo
	for _, entry := range c.Releases.Allow {
		if strings.EqualFold(entry, org) || strings.EqualFold(entry, orgRepo) {
			return true
		}
	}
	return false
}

// IsCodeloadAllowed returns true when the given org or org/repo combination
// appears in the codeload allow list, meaning archive download requests for it
// are passed through to upstream rather than redirected to the configured
// caching mirror. Matching is case-insensitive. An org-only entry (e.g.
// "goodtune") exempts every repository under that org.
//
// Safe to call concurrently with ReloadFrom.
func (c *Config) IsCodeloadAllowed(org, repo string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	orgRepo := org + "/" + repo
	for _, entry := range c.Codeload.Allow {
		if strings.EqualFold(entry, org) || strings.EqualFold(entry, orgRepo) {
			return true
		}
	}
	return false
}

// CodeloadRedirectTo returns the configured codeload redirect base URL. It
// takes the read lock so callers on the request hot path can read it without
// racing against ReloadFrom. Returning a string (rather than a snapshot
// struct) keeps the per-request cost to a single lock + field copy with no
// allocation, even when codeload.allow is set — the allow check has its own
// race-free accessor in IsCodeloadAllowed.
func (c *Config) CodeloadRedirectTo() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Codeload.RedirectTo
}

// WarnInvalidBlockTargets logs a warning for any block configuration targeting
// token types that are managed internally by ghp (ghx_, gha_, ghpr_). Those
// tokens are intercepted by the proxy before the passthrough path and cannot be
// blocked via the border policy. The check covers GHP_BLOCK_GHX, GHP_BLOCK_GHA,
// and GHP_BLOCK_GHPR environment variables which a configuration mistake might
// introduce. Note: GHP_BLOCK_GHPR targets ghp's own session token prefix (ghpr_),
// which is distinct from GitHub's refresh token prefix (ghr_) handled by GHP_BLOCK_GHR.
func (c *Config) WarnMissingClientIPHeader(logger interface {
	Warn(msg string, args ...any)
}) {
	if c.Server.TrustProxyHeaders && c.Server.ClientIPHeader == "" {
		logger.Warn("server.trust_proxy_headers is set but server.client_ip_header is not: client attribution and per-IP rate limits will key on the proxy address, so all clients behind the proxy share one rate-limit bucket; set server.client_ip_header to the forwarded header your proxy sets")
	}
}

func (c *Config) WarnInvalidBlockTargets(logger interface {
	Warn(msg string, args ...any)
}) {
	for _, envKey := range []string{"GHP_BLOCK_GHX", "GHP_BLOCK_GHA", "GHP_BLOCK_GHPR"} {
		if v := os.Getenv(envKey); v != "" {
			logger.Warn("unsupported block target: ghp manages this token type internally; blocking has no effect",
				"env", envKey)
		}
	}
}
