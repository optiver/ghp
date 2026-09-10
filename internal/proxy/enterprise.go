package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// enterpriseHeader is the request header GitHub Enterprise Cloud inspects to
// enforce enterprise access restrictions. When present, requests authenticated
// by accounts outside the listed enterprise(s) are rejected by GitHub with 403.
// GitHub offers no server-side exception mechanism; its documentation directs
// the proxy to inject the header only for traffic that should be restricted,
// which is what EnterprisePolicy implements.
const enterpriseHeader = "sec-GitHub-allowed-enterprise"

// teamMembershipCacheTTL bounds how long a team membership verdict (positive
// or negative) is reused before re-checking against the GitHub API.
const teamMembershipCacheTTL = 5 * time.Minute

// maxCachedTeamMemberships is the upper bound on cached (org, team, username)
// membership verdicts.
const maxCachedTeamMemberships = 10_000

// ExceptionIdentitySource mints a GitHub App installation token for an app's
// installation on a target account. Implemented by *github.AppRegistry. An
// empty appRecordID selects the default app.
type ExceptionIdentitySource interface {
	InstallationTokenForOwner(ctx context.Context, appRecordID, owner string, repos []string, permissions map[string]string) (string, error)
}

// enterpriseException is the compiled, lookup-optimised form of a
// config.EnterpriseException.
type enterpriseException struct {
	owners      map[string]struct{} // lowercase account names
	repos       map[string]struct{} // lowercase "owner/repo" pairs
	teams       [][2]string         // parsed {org, team-slug} requirements
	appRecordID string              // managed identity; "" = forward caller's credential
	hasIdentity bool
}

// EnterprisePolicy decides, per outbound request, whether the enterprise
// access restriction header is injected and whether a managed identity is
// substituted for the caller's credential. A nil *EnterprisePolicy is valid
// and means the feature is disabled (no header, no substitution).
type EnterprisePolicy struct {
	slug       string
	exceptions []enterpriseException
	identity   ExceptionIdentitySource // may be nil: identity substitution disabled
	teams      *teamChecker            // may be nil: team-gated exceptions never apply
	logger     *slog.Logger
}

// WithEnterpriseTransport supplies the team lookup transport at construction.
func WithEnterpriseTransport(transport http.RoundTripper) func(*EnterprisePolicy) {
	return func(p *EnterprisePolicy) {
		if p.teams != nil {
			p.teams.client.Transport = transport
		}
	}
}

// NewEnterprisePolicy compiles the enterprise restriction configuration into a
// policy. Returns nil when gh.EnterpriseSlug is empty (feature disabled).
// identity provides installation tokens for identity substitution and team
// membership checks; pass nil to disable both (matching exceptions then only
// omit the header, and team-gated exceptions fail closed and never apply).
// Malformed match/team entries are logged and skipped.
func NewEnterprisePolicy(gh config.GitHubConfig, identity ExceptionIdentitySource, logger *slog.Logger, opts ...func(*EnterprisePolicy)) *EnterprisePolicy {
	if logger == nil {
		logger = slog.Default()
	}
	if gh.EnterpriseSlug == "" {
		if len(gh.EnterpriseExceptions) > 0 {
			logger.Warn("github.enterprise_exceptions is set but github.enterprise_slug is empty; exceptions have no effect")
		}
		return nil
	}

	p := &EnterprisePolicy{
		slug:     gh.EnterpriseSlug,
		identity: identity,
		logger:   logger,
	}
	if identity != nil {
		p.teams = newTeamChecker(identity, logger)
	}

	for i, exc := range gh.EnterpriseExceptions {
		compiled := enterpriseException{
			owners:      make(map[string]struct{}),
			repos:       make(map[string]struct{}),
			appRecordID: exc.Identity.AppRecordID,
			hasIdentity: exc.Identity.AppRecordID != "",
		}
		for _, m := range exc.Match {
			m = strings.ToLower(strings.TrimSpace(m))
			switch strings.Count(m, "/") {
			case 0:
				if m != "" {
					compiled.owners[m] = struct{}{}
					continue
				}
			case 1:
				owner, repo, _ := strings.Cut(m, "/")
				if owner != "" && repo != "" {
					compiled.repos[m] = struct{}{}
					continue
				}
			}
			logger.Warn("skipping malformed enterprise exception match entry; expected \"owner\" or \"owner/repo\"",
				"exception_index", i, "entry", m)
		}
		for _, t := range exc.Teams {
			t = strings.TrimSpace(t)
			org, team, ok := strings.Cut(t, "/")
			if !ok || org == "" || team == "" {
				logger.Warn("skipping malformed enterprise exception team entry; expected \"org/team-slug\"",
					"exception_index", i, "entry", t)
				continue
			}
			compiled.teams = append(compiled.teams, [2]string{org, team})
		}
		if len(compiled.owners) == 0 && len(compiled.repos) == 0 {
			logger.Warn("skipping enterprise exception with no valid match entries", "exception_index", i)
			continue
		}
		if len(exc.Teams) > 0 && len(compiled.teams) == 0 {
			// All team entries were malformed. Applying the exception without
			// the intended gate would silently widen access — drop it instead.
			logger.Warn("skipping enterprise exception: teams configured but none parse as org/team-slug", "exception_index", i)
			continue
		}
		p.exceptions = append(p.exceptions, compiled)
	}

	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithTeamAPIBaseURL overrides the GitHub API base URL used for team
// membership lookups. Intended for tests.
func WithTeamAPIBaseURL(url string) func(*EnterprisePolicy) {
	return func(p *EnterprisePolicy) {
		if p.teams != nil {
			p.teams.baseURL = strings.TrimRight(url, "/")
		}
	}
}

// UsernameFunc lazily resolves the requesting user's GitHub username. It is
// only invoked when a team-gated exception matches the request target, so
// callers may back it with a blocking lookup.
type UsernameFunc func(ctx context.Context) string

// Apply evaluates the policy for a request targeting owner (and optionally
// repo) and sets or removes the enterprise restriction header on hdr
// accordingly. It returns a managed installation token when the matching
// exception configures identity substitution, or "" when the caller's own
// credential should be forwarded. Callers must replace the outbound
// Authorization header when a non-empty token is returned.
//
// tokenType labels the stage-duration metric and follows the decision
// pipeline vocabulary: "proxy" (ghx_), "agent" (gha_), or "" for raw and
// anonymous credentials (normalised to "unknown").
//
// A nil policy leaves hdr untouched and returns "".
func (p *EnterprisePolicy) Apply(ctx context.Context, hdr http.Header, owner, repo string, username UsernameFunc, tokenType string) string {
	if p == nil {
		return ""
	}
	start := time.Now()
	token, omit := p.evaluate(ctx, owner, repo, username)
	if omit {
		hdr.Del(enterpriseHeader)
	} else {
		hdr.Set(enterpriseHeader, p.slug)
	}
	metrics.ObserveDecision(metrics.StageEnterpriseException, tokenType, time.Since(start))
	return token
}

// evaluate returns the identity token to substitute (may be "") and whether
// the restriction header should be omitted.
func (p *EnterprisePolicy) evaluate(ctx context.Context, owner, repo string, username UsernameFunc) (string, bool) {
	exc := p.match(owner, repo)
	if exc == nil {
		return "", false
	}

	// Resolve the caller's identity once when any gate needs it: team gating
	// always does, and identity substitution requires a verifiable caller so
	// that anonymous (or fabricated-credential) requests cannot be escalated
	// to the managed identity.
	login := ""
	if (len(exc.teams) > 0 || exc.hasIdentity) && username != nil {
		login = username(ctx)
	}

	if len(exc.teams) > 0 {
		if login == "" || !p.callerInTeams(ctx, exc, login) {
			metrics.EnterpriseExceptionTotal.WithLabelValues("team_denied").Inc()
			return "", false
		}
	}

	if exc.hasIdentity {
		if login == "" {
			// Fail closed: substituting the managed credential for a caller
			// GHP cannot identify would let unauthenticated clients act as
			// the App on the excepted target (privilege escalation).
			p.logger.Warn("enterprise exception identity substitution denied: caller identity could not be resolved; keeping restriction header",
				"owner", owner, "repo", repo)
			metrics.EnterpriseExceptionTotal.WithLabelValues("unauthenticated_denied").Inc()
			return "", false
		}
		if p.identity == nil {
			p.logger.Error("enterprise exception configures identity substitution but no app registry is available; keeping restriction header",
				"owner", owner, "repo", repo)
			metrics.EnterpriseExceptionTotal.WithLabelValues("identity_error").Inc()
			return "", false
		}
		var repos []string
		if repo != "" {
			repos = []string{repo}
		}
		token, err := p.identity.InstallationTokenForOwner(ctx, exc.appRecordID, owner, repos, nil)
		if err == nil && token == "" {
			// An empty token with a nil error must not count as a successful
			// substitution: omitting the header while forwarding the caller's
			// own credential would violate the documented fail-closed
			// behaviour for identity-substituting exceptions.
			err = fmt.Errorf("identity source returned an empty token")
		}
		if err != nil {
			// Fail closed: the operator asked for a managed identity on this
			// target; forwarding the caller's own credential with the header
			// omitted would bypass that arrangement.
			p.logger.Error("enterprise exception identity substitution failed; keeping restriction header",
				"owner", owner, "repo", repo, "app_record_id", exc.appRecordID, "error", err)
			metrics.EnterpriseExceptionTotal.WithLabelValues("identity_error").Inc()
			return "", false
		}
		metrics.EnterpriseExceptionTotal.WithLabelValues("identity_substituted").Inc()
		return token, true
	}

	metrics.EnterpriseExceptionTotal.WithLabelValues("header_omitted").Inc()
	return "", true
}

// match returns the exception covering owner (and optionally owner/repo), or
// nil. Matching is case-insensitive; an owner entry covers every repository
// under that account. Exact owner/repo entries take precedence over owner-wide
// entries regardless of configuration order, so a stricter repository rule
// (e.g. team-gated or identity-substituting) cannot be shadowed by an earlier
// broad owner rule. Within the same specificity, the first configured
// exception wins.
func (p *EnterprisePolicy) match(owner, repo string) *enterpriseException {
	if owner == "" {
		return nil
	}
	owner = strings.ToLower(owner)
	if repo != "" {
		ownerRepo := owner + "/" + strings.ToLower(repo)
		for i := range p.exceptions {
			if _, ok := p.exceptions[i].repos[ownerRepo]; ok {
				return &p.exceptions[i]
			}
		}
	}
	for i := range p.exceptions {
		if _, ok := p.exceptions[i].owners[owner]; ok {
			return &p.exceptions[i]
		}
	}
	return nil
}

// callerInTeams reports whether login is an active member of at least one of
// the exception's required teams. Callers must pass a non-empty login.
func (p *EnterprisePolicy) callerInTeams(ctx context.Context, exc *enterpriseException, login string) bool {
	if p.teams == nil {
		return false
	}
	for _, t := range exc.teams {
		if p.teams.isMember(ctx, t[0], t[1], login) {
			return true
		}
	}
	return false
}

// teamChecker verifies GitHub org team membership via the REST API, using an
// installation token minted from the default GitHub App. The default app must
// be installed on the team's organization with the members:read permission.
// Verdicts (positive and negative) are cached for teamMembershipCacheTTL.
type teamChecker struct {
	identity ExceptionIdentitySource
	baseURL  string
	client   *http.Client
	cache    *expirable.LRU[string, bool]
	// flights maps a membership cache key to the *membershipFlight
	// coordinating the lookup currently in progress for it, so concurrent
	// cache misses for the same (org, team, user) trigger exactly one
	// installation-token mint and membership request.
	flights sync.Map
	logger  *slog.Logger
}

// membershipFlight is a single in-progress membership lookup that concurrent
// callers can wait on. The leader stores the verdict in member before closing
// done; waiters must only read member after done is closed.
type membershipFlight struct {
	done   chan struct{}
	member bool
}

func newTeamChecker(identity ExceptionIdentitySource, logger *slog.Logger) *teamChecker {
	return &teamChecker{
		identity: identity,
		baseURL:  githubAPIBase,
		client:   &http.Client{Timeout: 10 * time.Second},
		cache:    expirable.NewLRU[string, bool](maxCachedTeamMemberships, nil, teamMembershipCacheTTL),
		logger:   logger,
	}
}

// isMember reports whether username is an active member of org/teamSlug.
// Any error (token minting, network, non-200) fails closed and is cached as a
// negative verdict so a misconfigured team does not add API latency to every
// request. Concurrent cache misses for the same key are coalesced: the first
// caller performs the lookup and everyone else waits on its verdict, bounded
// by their own context (fail closed on cancellation).
func (c *teamChecker) isMember(ctx context.Context, org, teamSlug, username string) bool {
	key := strings.ToLower(org) + "/" + strings.ToLower(teamSlug) + "/" + strings.ToLower(username)
	if member, ok := c.cache.Get(key); ok {
		return member
	}

	f := &membershipFlight{done: make(chan struct{})}
	if existing, loaded := c.flights.LoadOrStore(key, f); loaded {
		ef := existing.(*membershipFlight)
		select {
		case <-ef.done:
			return ef.member
		case <-ctx.Done():
			return false
		}
	}
	member := c.lookupMembership(ctx, org, teamSlug, username)
	c.cache.Add(key, member)
	f.member = member
	close(f.done)
	c.flights.Delete(key)
	return member
}

func (c *teamChecker) lookupMembership(ctx context.Context, org, teamSlug, username string) bool {
	// Team membership lookups always use the default app (empty appRecordID):
	// the team gate belongs to the operator's enterprise org, which may be a
	// different account than the exception's target owner or identity app.
	token, err := c.identity.InstallationTokenForOwner(ctx, "", org, nil, map[string]string{"members": "read"})
	if err != nil {
		c.logger.Warn("enterprise exception team check: failed to mint members:read token; treating as non-member",
			"org", org, "team", teamSlug, "error", err)
		return false
	}

	url := fmt.Sprintf("%s/orgs/%s/teams/%s/memberships/%s", c.baseURL, org, teamSlug, username)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		c.logger.Warn("enterprise exception team check: failed to create request", "error", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ghp-proxy")

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Warn("enterprise exception team check: request failed; treating as non-member",
			"org", org, "team", teamSlug, "error", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 404 is the expected "not a member" answer; anything else is logged.
		if resp.StatusCode != http.StatusNotFound {
			c.logger.Warn("enterprise exception team check: unexpected status; treating as non-member",
				"org", org, "team", teamSlug, "status", resp.StatusCode)
		}
		return false
	}

	var result struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.logger.Warn("enterprise exception team check: failed to decode response", "error", err)
		return false
	}
	return result.State == "active"
}

// enterpriseTargetFromAPIPath extracts the owner (user or org) and repository
// an api.github.com REST path addresses. Recognised shapes:
//
//	/repos/{owner}/{repo}[/...] → owner, repo
//	/users/{username}[/...]     → owner, ""
//	/orgs/{org}[/...]           → owner, ""
//
// Every other path — including /graphql, /search, and viewer-relative
// endpoints — returns ("", ""), meaning no exception can apply and the
// restriction header stays on.
func enterpriseTargetFromAPIPath(path string) (owner, repo string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch parts[0] {
	case "repos":
		if len(parts) >= 3 && parts[1] != "" && parts[2] != "" {
			return parts[1], parts[2]
		}
	case "users", "orgs":
		if len(parts) >= 2 && parts[1] != "" {
			return parts[1], ""
		}
	}
	return "", ""
}

// enterpriseTargetFromWebPath extracts the owner and repository a github.com
// path addresses. The first segment is the account, the second (with any .git
// suffix stripped) the repository:
//
//	/{owner}                     → owner, ""
//	/{owner}/{repo}[.git][/...]  → owner, repo
//
// Reserved github.com paths (e.g. /login, /notifications) parse as an owner
// name, which is harmless: they only take effect if the operator lists that
// name as an exception.
func enterpriseTargetFromWebPath(path string) (owner, repo string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	owner = parts[0]
	if len(parts) >= 2 && parts[1] != "" {
		repo = strings.TrimSuffix(parts[1], ".git")
	}
	return owner, repo
}

// basicAuthIdentityHeader renders an Authorization header value carrying the
// managed identity token in the scheme git clients expect for GitHub App
// credentials.
func basicAuthIdentityHeader(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
}

// substituteAuthHeader rewrites an Authorization header value to carry the
// managed identity token, preserving the original scheme so the substitution
// is transparent to the client and upstream. An empty or schemeless original
// defaults to Bearer; Basic credentials are re-encoded as
// x-access-token:<token>.
func substituteAuthHeader(original, token string) string {
	scheme, _, ok := strings.Cut(original, " ")
	if !ok || scheme == "" {
		return "Bearer " + token
	}
	if strings.EqualFold(scheme, "basic") {
		return basicAuthIdentityHeader(token)
	}
	return scheme + " " + token
}

// rawTokenFromAuthValue extracts a resolvable GitHub token (gho_, ghp_, ghu_,
// ghs_) from an Authorization header value. It recognises Bearer/token schemes
// and Basic auth with any username, extracting the password field when it is
// a resolvable GitHub token. All other values yield "".
func rawTokenFromAuthValue(v string) string {
	parts := strings.SplitN(v, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	scheme, credential := strings.ToLower(parts[0]), parts[1]
	switch scheme {
	case "bearer", "token":
		if isResolvableGitHubToken(credential) {
			return credential
		}
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return ""
		}
		_, pass, ok := strings.Cut(string(decoded), ":")
		if ok && isResolvableGitHubToken(pass) {
			return pass
		}
	}
	return ""
}
