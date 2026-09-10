// Package github implements GitHub App authentication for agent tokens (gha_).
// It handles JWT signing with the App's private key, installation token
// generation via the GitHub API, and token caching with automatic renewal.
// This is the credential backend for agent tokens — when an agent uses a gha_
// token, the proxy resolves it to a GitHub App installation token obtained
// through this package.
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goodtune/ghp/internal/crypto"
	ghub "github.com/google/go-github/v91/github"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// userAgent identifies this proxy in outbound GitHub API requests. GitHub
// requires a User-Agent on all REST API calls; the go-github SDK sets one
// automatically, but raw HTTP paths (e.g. ListInstallations) must set it
// explicitly.
const userAgent = "ghp-proxy"

// InstallationTokenError represents a failed installation token request,
// carrying the upstream HTTP status code, GitHub's error message, and
// permission diagnostics.
type InstallationTokenError struct {
	StatusCode           int
	Message              string
	RequestedPermissions map[string]string
	GrantedPermissions   map[string]string
}

func (e *InstallationTokenError) Error() string {
	missing := e.MissingPermissions()
	if len(missing) == 0 {
		return fmt.Sprintf("installation token request failed (%d): %s", e.StatusCode, e.Message)
	}

	parts := make([]string, 0, len(missing))
	for perm, level := range missing {
		parts = append(parts, perm+":"+level)
	}
	sort.Strings(parts)
	return fmt.Sprintf("installation token request failed (%d): %s (missing permissions: %s)",
		e.StatusCode, e.Message, strings.Join(parts, ", "))
}

// MissingPermissions returns the permissions that were requested but not
// granted (or granted at a lower level than requested).
func (e *InstallationTokenError) MissingPermissions() map[string]string {
	missing := make(map[string]string)
	for perm, reqLevel := range e.RequestedPermissions {
		grantedLevel, ok := e.GrantedPermissions[perm]
		if !ok || !permissionSatisfies(grantedLevel, reqLevel) {
			missing[perm] = reqLevel
		}
	}
	return missing
}

// permissionSatisfies returns true if granted >= requested.
// GitHub permission levels: "read" < "write" < "admin".
func permissionSatisfies(granted, requested string) bool {
	levels := map[string]int{"read": 1, "write": 2, "admin": 3}
	return levels[granted] >= levels[requested]
}

// AppConfig holds configuration for GitHub App authentication.
type AppConfig struct {
	AppID      int64
	PrivateKey string // PEM-encoded RSA private key
	BaseURL    string // GitHub API base URL, defaults to https://api.github.com
}

// installationTokenTTL is the duration used for the LRU TTL on cached
// installation tokens. GitHub issues tokens with a 1-hour validity, so we
// evict cached entries 5 minutes early to avoid using near-expired tokens.
const installationTokenTTL = 55 * time.Minute

// maxCachedInstallationTokens is the maximum number of installation tokens
// held in memory simultaneously.
const maxCachedInstallationTokens = 1_000

// installationIDCacheTTL is the duration owner→installation-ID lookups are
// cached. Installation IDs are stable for the lifetime of an installation, so
// a longer TTL would also be safe; one hour bounds the window during which an
// uninstall/reinstall cycle could serve a stale ID.
const installationIDCacheTTL = time.Hour

// maxCachedInstallationIDs is the maximum number of owner→installation-ID
// entries held in memory simultaneously.
const maxCachedInstallationIDs = 1_000

// AppTokenProvider generates GitHub App installation tokens.
type AppTokenProvider struct {
	appID   int64
	key     *rsa.PrivateKey
	baseURL string
	client  *http.Client
	// cache maps a composite key (installationID + repos + permissions) to a
	// raw token string. Entries are automatically evicted after
	// installationTokenTTL via the expirable.LRU TTL mechanism.
	cache *expirable.LRU[string, string]
	// installationIDCache maps a lowercase owner login to the installation ID
	// of this app on that account. Entries are evicted after
	// installationIDCacheTTL.
	installationIDCache *expirable.LRU[string, int64]
}

// SetTransport sets outbound transport before the component is used.
func (p *AppTokenProvider) SetTransport(transport http.RoundTripper) {
	p.client.Transport = transport
}

// NewAppTokenProvider creates a provider from the given config.
func NewAppTokenProvider(cfg AppConfig) (*AppTokenProvider, error) {
	key, err := crypto.ParseRSAPrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &AppTokenProvider{
		appID:               cfg.AppID,
		key:                 key,
		baseURL:             baseURL,
		client:              &http.Client{Timeout: 30 * time.Second},
		cache:               expirable.NewLRU[string, string](maxCachedInstallationTokens, nil, installationTokenTTL),
		installationIDCache: expirable.NewLRU[string, int64](maxCachedInstallationIDs, nil, installationIDCacheTTL),
	}, nil
}

// installationCacheKey returns a stable cache key that uniquely identifies a
// (installationID, repos, permissions) tuple. The repos and permissions are
// sorted before hashing so that call-site ordering does not affect the key.
func installationCacheKey(installationID int64, repos []string, permissions map[string]string) string {
	sortedRepos := make([]string, len(repos))
	copy(sortedRepos, repos)
	sort.Strings(sortedRepos)

	permKeys := make([]string, 0, len(permissions))
	for k := range permissions {
		permKeys = append(permKeys, k)
	}
	sort.Strings(permKeys)
	permParts := make([]string, 0, len(permissions))
	for _, k := range permKeys {
		permParts = append(permParts, k+"="+permissions[k])
	}

	raw := fmt.Sprintf("%d\x00%s\x00%s",
		installationID,
		strings.Join(sortedRepos, "\x1f"),
		strings.Join(permParts, "\x1f"),
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GetInstallationToken returns a GitHub installation token for the given
// installation, scoped to the specified repositories and permissions.
// Results are cached, keyed by installation ID plus the requested repos and
// permissions, and evicted automatically after installationTokenTTL.
func (p *AppTokenProvider) GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error) {
	cacheKey := installationCacheKey(installationID, repos, permissions)
	if tok, ok := p.cache.Get(cacheKey); ok {
		return tok, nil
	}

	// Generate JWT.
	signed, err := p.signJWT()
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	// Request installation token.
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.baseURL, installationID)

	body := map[string]interface{}{}
	if repos != nil {
		body["repositories"] = repos
	}
	if permissions != nil {
		body["permissions"] = permissions
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)

		// Parse GitHub's error message.
		var ghErr struct {
			Message string `json:"message"`
		}
		msg := string(respBody)
		if json.Unmarshal(respBody, &ghErr) == nil && ghErr.Message != "" {
			msg = ghErr.Message
		}

		// Optionally fetch granted permissions to provide diagnostics.
		var grantedPerms map[string]string
		if resp.StatusCode == http.StatusUnprocessableEntity {
			if granted, err := p.getInstallationPermissions(ctx, signed, installationID); err == nil {
				grantedPerms = granted
			}
		}

		return "", &InstallationTokenError{
			StatusCode:           resp.StatusCode,
			Message:              msg,
			RequestedPermissions: permissions,
			GrantedPermissions:   grantedPerms,
		}
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	if result.Token == "" {
		// Never return (or cache) an empty credential from a 201 response —
		// callers treat a nil error as a usable token.
		return "", fmt.Errorf("installation token response missing token")
	}

	// Cache the token. The LRU TTL handles expiry; we rely on installationTokenTTL
	// being shorter than GitHub's 1-hour token validity.
	p.cache.Add(cacheKey, result.Token)

	return result.Token, nil
}

// getInstallationPermissions queries the GitHub API for the permissions
// granted to the given installation. The jwtToken must be a valid App JWT.
func (p *AppTokenProvider) getInstallationPermissions(ctx context.Context, jwtToken string, installationID int64) (map[string]string, error) {
	url := fmt.Sprintf("%s/app/installations/%d", p.baseURL, installationID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating installation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching installation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("installation request failed (%d)", resp.StatusCode)
	}

	var result struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding installation response: %w", err)
	}

	return result.Permissions, nil
}

// GetInstallationIDForOwner resolves the installation ID of this app on the
// given user or organization account. The org endpoint is tried first, then
// the user endpoint (GitHub returns 404 from the org endpoint for user
// accounts). Results are cached for installationIDCacheTTL, keyed by the
// lowercase owner login.
func (p *AppTokenProvider) GetInstallationIDForOwner(ctx context.Context, owner string) (int64, error) {
	key := strings.ToLower(owner)
	if id, ok := p.installationIDCache.Get(key); ok {
		return id, nil
	}

	signed, err := p.signJWT()
	if err != nil {
		return 0, fmt.Errorf("signing JWT: %w", err)
	}

	var lastErr error
	for _, path := range []string{
		fmt.Sprintf("%s/orgs/%s/installation", p.baseURL, owner),
		fmt.Sprintf("%s/users/%s/installation", p.baseURL, owner),
	} {
		id, err := p.fetchInstallationID(ctx, signed, path)
		if err == nil {
			p.installationIDCache.Add(key, id)
			return id, nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("no installation of app %d found on %q: %w", p.appID, owner, lastErr)
}

// fetchInstallationID performs a single installation lookup against the given
// URL using the provided app JWT.
func (p *AppTokenProvider) fetchInstallationID(ctx context.Context, jwtToken, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, fmt.Errorf("creating installation lookup request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetching installation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("installation lookup failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decoding installation response: %w", err)
	}
	if result.ID == 0 {
		return 0, fmt.Errorf("installation response missing id")
	}
	return result.ID, nil
}

// Installation represents a GitHub App installation (API response DTO).
type Installation struct {
	ID                  int64               `json:"id"`
	Account             InstallationAccount `json:"account"`
	Permissions         map[string]string   `json:"permissions"`
	RepositorySelection string              `json:"repository_selection"`
}

// InstallationAccount is the GitHub account (user or org) associated with an installation.
type InstallationAccount struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
}

// InstallationRepository represents a repository accessible to an installation (API response DTO).
type InstallationRepository struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Private  bool   `json:"private"`
}

// newAppClient returns a go-github client authenticated as the GitHub App (JWT).
func (p *AppTokenProvider) newAppClient() (*ghub.Client, error) {
	signed, err := p.signJWT()
	if err != nil {
		return nil, err
	}
	opts := []ghub.ClientOptionsFunc{ghub.WithAuthToken(signed)}
	if p.client.Transport != nil {
		opts = append(opts, ghub.WithTransport(p.client.Transport))
	}
	if p.baseURL != "https://api.github.com" {
		opts = append(opts, ghub.WithEnterpriseURLs(p.baseURL, p.baseURL))
	}
	client, err := ghub.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub app client: %w", err)
	}
	return client, nil
}

// ListInstallations returns all installations for this GitHub App.
// Raw HTTP is used instead of the go-github SDK so that the full permissions
// map from the API is preserved — the SDK's typed InstallationPermissions
// struct only exposes a subset of the permission fields GitHub supports.
func (p *AppTokenProvider) ListInstallations(ctx context.Context) ([]Installation, error) {
	type rawInstallation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
			ID    int64  `json:"id"`
			Type  string `json:"type"`
		} `json:"account"`
		Permissions         map[string]string `json:"permissions"`
		RepositorySelection string            `json:"repository_selection"`
	}

	var all []Installation
	nextURL := fmt.Sprintf("%s/app/installations?per_page=100", p.baseURL)
	for nextURL != "" {
		// Sign per request so a slow paginated walk cannot outlive the JWT
		// (signJWT sets a 10-minute expiry).
		signed, err := p.signJWT()
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, "GET", nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating installations request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+signed)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", userAgent)

		installs, linkHeader, err := func() ([]rawInstallation, string, error) {
			resp, err := p.client.Do(req)
			if err != nil {
				return nil, "", fmt.Errorf("fetching installations: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				return nil, "", fmt.Errorf("listing installations: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}

			var installs []rawInstallation
			if err := json.NewDecoder(resp.Body).Decode(&installs); err != nil {
				return nil, "", fmt.Errorf("decoding installations: %w", err)
			}
			return installs, resp.Header.Get("Link"), nil
		}()
		if err != nil {
			return nil, err
		}

		for _, inst := range installs {
			all = append(all, Installation{
				ID: inst.ID,
				Account: InstallationAccount{
					Login: inst.Account.Login,
					ID:    inst.Account.ID,
					Type:  inst.Account.Type,
				},
				Permissions:         inst.Permissions,
				RepositorySelection: inst.RepositorySelection,
			})
		}
		nextURL = extractLinkNext(linkHeader)
	}
	return all, nil
}

// extractLinkNext parses a GitHub Link header and returns the URL for the
// next page, or an empty string if there is no next page. Per RFC 5988,
// link parameters can appear in any order, so all `;`-separated parameters
// after the URL are scanned for `rel="next"`.
func extractLinkNext(link string) string {
	// Format: <url>; rel="next"; type="application/json", <url>; rel="last"
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		segments := strings.Split(part, ";")
		if len(segments) < 2 {
			continue
		}
		isNext := false
		for _, p := range segments[1:] {
			if strings.TrimSpace(p) == `rel="next"` {
				isNext = true
				break
			}
		}
		if !isNext {
			continue
		}
		url := strings.TrimSpace(segments[0])
		return strings.Trim(url, "<>")
	}
	return ""
}

// ListInstallationRepositories returns repositories accessible to the given installation.
func (p *AppTokenProvider) ListInstallationRepositories(ctx context.Context, installationID int64) ([]InstallationRepository, error) {
	// Create an unscoped installation token via the App JWT client.
	appClient, err := p.newAppClient()
	if err != nil {
		return nil, err
	}
	tok, _, err := appClient.Apps.CreateInstallationToken(ctx, installationID, nil)
	if err != nil {
		return nil, fmt.Errorf("creating installation token: %w", err)
	}

	// Create a client authenticated as the installation.
	instOpts := []ghub.ClientOptionsFunc{ghub.WithAuthToken(tok.GetToken())}
	if p.client.Transport != nil {
		instOpts = append(instOpts, ghub.WithTransport(p.client.Transport))
	}
	if p.baseURL != "https://api.github.com" {
		instOpts = append(instOpts, ghub.WithEnterpriseURLs(p.baseURL, p.baseURL))
	}
	instClient, err := ghub.NewClient(instOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub installation client: %w", err)
	}

	var all []InstallationRepository
	opts := &ghub.ListOptions{PerPage: 100}
	for {
		result, resp, err := instClient.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("listing installation repos: %w", err)
		}
		for _, r := range result.Repositories {
			all = append(all, InstallationRepository{
				FullName: r.GetFullName(),
				Name:     r.GetName(),
				Private:  r.GetPrivate(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}

// signJWT creates a signed JWT for GitHub App authentication.
func (p *AppTokenProvider) signJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", p.appID),
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return jwtToken.SignedString(p.key)
}
