// Package gitcache implements a Git protocol v2 caching proxy.
//
// NOTE: This package uses the global slog logger rather than accepting an
// injected *slog.Logger. The server configures the default slog handler at
// startup, so package-level slog calls inherit that configuration. This is
// idiomatic Go for packages that don't need per-instance log routing.
package gitcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gitprotocolio"

	"github.com/goodtune/ghp/internal/egress"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
)

// CacheResult describes the outcome of a cache operation for logging and
// metrics.
type CacheResult string

const (
	CacheHit         CacheResult = "hit"
	CacheMiss        CacheResult = "miss"
	CacheRejected    CacheResult = "rejected"
	CacheError       CacheResult = "error"
	CachePassthrough CacheResult = "passthrough" // delegate to inner handler
)

// upstreamError indicates an HTTP error response from upstream GitHub.
type upstreamError struct {
	StatusCode int
}

func (e *upstreamError) Error() string {
	return fmt.Sprintf("upstream returned %d", e.StatusCode)
}

// isUpstreamRejection returns true if the error represents an access-denied
// response (401, 403, 404) from upstream, as opposed to a server/network error.
func isUpstreamRejection(err error) bool {
	var ue *upstreamError
	if errors.As(err, &ue) {
		return ue.StatusCode == 401 || ue.StatusCode == 403 || ue.StatusCode == 404
	}
	return false
}

// ServiceTokenFunc returns a GitHub App installation token for async
// cache warming. Unlike per-request tokens, this is not tied to a specific
// user's credential. May be nil if async warming is not configured.
type ServiceTokenFunc func(ctx context.Context) (string, error)

// Handler implements the Git protocol v2 caching proxy.
//
// Request flow: the Handler sits inside a middleware chain where token
// resolution has already occurred before the request arrives here:
//
//	ScopedPassthroughHandler (resolves ghx_/gha_ proxy tokens → real GitHub tokens)
//	  → CacheLookup middleware (checks if repo is cache-enabled)
//	    → Handler (this code)
//
// By the time a request reaches Handler, the Authorization header contains
// a resolved GitHub credential (e.g. ghs_*, gho_*), not the original proxy
// token. Methods like handleLsRefs and handleFetch forward this header
// verbatim to upstream GitHub.
//
// Access verification: for bundled requests (ls-refs + fetch), handleLsRefs
// runs first and verifies access via upstream GitHub before any cached data
// is served — the fetch command only executes after ls-refs succeeds
// (enforced by the lsRefsSucceeded gate in ServeUploadPack). For standalone
// fetch requests, the ScopedPassthroughHandler has already validated the
// token and enforced scope before the request reaches this handler.
//
type Handler struct {
	registry         *Registry
	serviceTokenFn   ServiceTokenFunc
	upstreamBaseURL  string // e.g. "https://github.com"
	httpClient       *http.Client
	responseCacheDir string // directory for cached upstream protocol responses
}

// NewHandler creates a cache handler.
//
//   - registry: manages local bare repo mirrors
//   - serviceTokenFn: returns a service-level token for async cache warming
//     (may be nil to disable async warming)
//   - upstreamBaseURL: the upstream Git server (e.g. "https://github.com")
//
// defaultUpstreamTimeout is the timeout applied to upstream HTTP requests when
// the cached repository has no per-repo timeout configured.
const defaultUpstreamTimeout = 30 * time.Second

func NewHandler(registry *Registry, serviceTokenFn ServiceTokenFunc, upstreamBaseURL, responseCacheDir string) *Handler {
	return &Handler{
		registry:         registry,
		serviceTokenFn:   serviceTokenFn,
		upstreamBaseURL:  upstreamBaseURL,
		httpClient:       &http.Client{}, // no client-level timeout; per-request context controls it
		responseCacheDir: responseCacheDir,
	}
}

// SetTransport sets outbound transport before the component is used.
func (h *Handler) SetTransport(transport http.RoundTripper) {
	h.httpClient.Transport = transport
}

// ServeInfoRefs handles GET /owner/repo.git/info/refs?service=git-upload-pack
// by returning synthetic protocol v2 capabilities.
func (h *Handler) ServeInfoRefs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("service") != "git-upload-pack" {
		http.Error(w, "only git-upload-pack is supported", http.StatusBadRequest)
		return
	}
	if proto := r.Header.Get("Git-Protocol"); proto != "version=2" {
		http.Error(w, "only Git protocol v2 is supported", http.StatusBadRequest)
		return
	}
	WriteInfoRefsResponse(w)
}

// ServeUploadPack handles POST /owner/repo.git/git-upload-pack by parsing
// protocol v2 commands and serving from cache where possible.
//
// Security invariant: fetch commands are only served after a successful
// ls-refs (which verifies the user's GitHub access via upstream).
func (h *Handler) ServeUploadPack(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if proto := r.Header.Get("Git-Protocol"); proto != "version=2" {
		http.Error(w, "only Git protocol v2 is supported", http.StatusBadRequest)
		return
	}

	body, err := MaybeGunzip(r)
	if err != nil {
		http.Error(w, "cannot decompress request", http.StatusBadRequest)
		return
	}
	defer body.Close()

	commands, err := ParseCommands(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse request: %v", err), http.StatusBadRequest)
		return
	}

	managed, err := h.registry.Get(owner, repo)
	if err != nil {
		slog.Error("open cached repo", "repo", owner+"/"+repo, "err", err)
		http.Error(w, "cache error", http.StatusInternalServerError)
		return
	}

	// In protocol v2 over HTTP, git may send ls-refs + fetch bundled in a
	// single POST, or send a standalone fetch in a subsequent POST (e.g., for
	// additional objects after the initial clone negotiation). Standalone
	// fetch requests are safe because the scoped passthrough handler has
	// already verified the user's token and enforced scope — the Authorization
	// header contains a resolved GitHub credential by this point.
	hasLsRefs := false
	for _, cmd := range commands {
		if cmd.Name == "ls-refs" {
			hasLsRefs = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")

	lsRefsSucceeded := false
	for _, cmd := range commands {
		switch cmd.Name {
		case "ls-refs":
			metrics.CacheLsRefsTotal.Inc()
			if err := h.handleLsRefs(r, managed, cmd, w); err != nil {
				if isUpstreamRejection(err) {
					slog.Info("ls-refs rejected", "repo", owner+"/"+repo, "err", err)
					proxy.SetCacheState(r, string(CacheRejected))
				} else {
					slog.Error("ls-refs failed", "repo", owner+"/"+repo, "err", err)
					proxy.SetCacheState(r, string(CacheError))
				}
				return // stop — no cached data exposed
			}
			lsRefsSucceeded = true

		case "fetch":
			if hasLsRefs && !lsRefsSucceeded {
				// Request contains both ls-refs and fetch, but ls-refs
				// hasn't succeeded yet — reject.
				WriteError(w, "ERR fetch requires ls-refs first for access verification")
				proxy.SetCacheState(r, string(CacheRejected))
				metrics.CacheFetchTotal.WithLabelValues(string(CacheRejected)).Inc()
				return
			}
			result, err := h.handleFetch(r, managed, cmd, w)
			proxy.SetCacheState(r, string(result))
			metrics.CacheFetchTotal.WithLabelValues(string(result)).Inc()
			if err != nil {
				slog.Error("fetch failed", "repo", owner+"/"+repo, "result", result, "err", err)
				return
			}
			slog.Info("fetch served", "repo", owner+"/"+repo, "result", result)
		}
	}
}

// responseCacheKey computes a cache key from the repo identity and request body.
func responseCacheKey(owner, repo string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(owner + "/" + repo + "\x00"))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// handleLsRefs forwards the ls-refs command to upstream GitHub and returns
// the response to the client. This serves as the access verification gate
// and also triggers async cache warming if refs have changed.
//
// The upstream Authorization header is propagated as-is from the incoming
// request (which has already been resolved by the scoped passthrough handler),
// preserving the original auth scheme (Bearer, Basic, etc.).
func (h *Handler) handleLsRefs(r *http.Request, repo *ManagedRepository, cmd Command, w io.Writer) error {
	authHeader := r.Header.Get("Authorization")
	upstreamURL := h.upstreamBaseURL + "/" + repo.owner + "/" + repo.name + ".git/git-upload-pack"

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout(r.Context(), defaultUpstreamTimeout))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, EncodeCommandsToReader(cmd))
	if err != nil {
		WriteError(w, "ERR internal error")
		return fmt.Errorf("create upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")
	// Forward the resolved GitHub credential — see Handler doc comment.
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		WriteError(w, "ERR upstream unavailable")
		return fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Forward the upstream error to the client.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		WriteError(w, fmt.Sprintf("ERR upstream: %d %s", resp.StatusCode, string(body)))
		return &upstreamError{StatusCode: resp.StatusCode}
	}

	// Parse response to check for ref changes.
	var chunks []*gitprotocolio.ProtocolV2ResponseChunk
	scanner := gitprotocolio.NewProtocolV2Response(resp.Body)
	for scanner.Scan() {
		chunks = append(chunks, copyResponseChunk(scanner.Chunk()))
	}
	if err := scanner.Err(); err != nil {
		WriteError(w, "ERR cannot parse upstream response")
		return fmt.Errorf("parse upstream response: %w", err)
	}

	// Check if any refs have changed and trigger async fetch if a service
	// token function is available.
	if h.serviceTokenFn != nil {
		refs, parseErr := ParseLsRefsResponse(chunks)
		if parseErr == nil {
			if hasUpdate, checkErr := repo.HasAnyUpdate(refs); checkErr == nil && hasUpdate {
				go func() {
					warmCtx, cancel := context.WithTimeout(egress.Background(r.Context()), 60*time.Second)
					defer cancel()
					svcToken, tokenErr := h.serviceTokenFn(warmCtx)
					if tokenErr != nil {
						slog.Error("get service token for cache warming", "repo", repo.owner+"/"+repo.name, "err", tokenErr)
						metrics.CacheWarmTotal.WithLabelValues("error").Inc()
						return
					}
					if fetchErr := repo.FetchUpstream(warmCtx, svcToken); fetchErr != nil {
						slog.Error("async cache warming failed", "repo", repo.owner+"/"+repo.name, "err", fetchErr)
						metrics.CacheWarmTotal.WithLabelValues("error").Inc()
					} else {
						metrics.CacheWarmTotal.WithLabelValues("success").Inc()
					}
				}()
			}
		}
	}

	// Forward the upstream response verbatim to the client.
	return WriteResponseChunks(w, chunks)
}

// handleFetch processes a fetch command by checking the response cache first,
// then proxying to upstream GitHub on cache miss. The upstream response is
// tee'd to disk so subsequent identical requests are served locally without
// any go-git pack generation or upstream round-trip.
//
// This is an optimistic cache: on miss, the cost is identical to the uncached
// path (proxy to upstream). On hit, the response is served from disk at
// near-zero CPU cost.
func (h *Handler) handleFetch(r *http.Request, repo *ManagedRepository, cmd Command, w io.Writer) (CacheResult, error) {
	// Re-encode the fetch command for cache key computation and upstream proxy.
	var cmdBuf bytes.Buffer
	for _, c := range cmd.Chunks {
		cmdBuf.Write(c.EncodeToPktLine())
	}
	cmdBytes := cmdBuf.Bytes()

	cacheKey := responseCacheKey(repo.owner, repo.name, cmdBytes)
	cacheDir := filepath.Join(h.responseCacheDir, "_protocol_responses", repo.owner, repo.name)
	cachePath := filepath.Join(cacheDir, cacheKey)

	// Resolve the GitHub username for metric labels. May be empty for
	// anonymous requests; normalise to "anonymous" for metric consistency.
	user := proxy.GetUsername(r)
	if user == "" {
		user = "anonymous"
	}

	// Try serving from response cache.
	if f, err := os.Open(cachePath); err == nil {
		// Touch mtime so the size-limit cleanup evicts least-recently-used files first.
		now := time.Now()
		if err := os.Chtimes(cachePath, now, now); err != nil {
			slog.Warn("failed to update cache file mtime; LRU eviction may evict hot entries", "path", cachePath, "error", err)
		}
		defer f.Close()
		n, copyErr := io.Copy(w, f)
		if copyErr != nil {
			return CacheError, fmt.Errorf("serve cached fetch response: %w", copyErr)
		}
		metrics.CachePackfileTotal.WithLabelValues(repo.owner, repo.name, user, "hit").Inc()
		metrics.CachePackfileBytesTotal.WithLabelValues(repo.owner, repo.name, user, "hit").Add(float64(n))
		slog.Info("fetch served from response cache", "repo", repo.owner+"/"+repo.name, "bytes", n)
		return CacheHit, nil
	}

	// Cache miss — proxy fetch command to upstream and tee response to disk.
	upstreamURL := h.upstreamBaseURL + "/" + repo.owner + "/" + repo.name + ".git/git-upload-pack"

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout(r.Context(), defaultUpstreamTimeout))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", upstreamURL, bytes.NewReader(cmdBytes))
	if err != nil {
		WriteError(w, "ERR internal error")
		return CacheError, fmt.Errorf("create upstream fetch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")
	// Forward the resolved GitHub credential. By this point in the middleware
	// chain the Authorization header contains a real GitHub token (ghs_*, gho_*),
	// not the client's proxy token — see Handler doc comment for the full flow.
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		WriteError(w, "ERR upstream unavailable")
		return CacheError, fmt.Errorf("upstream fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		WriteError(w, fmt.Sprintf("ERR upstream: %d %s", resp.StatusCode, string(body)))
		ue := &upstreamError{StatusCode: resp.StatusCode}
		if isUpstreamRejection(ue) {
			return CacheRejected, ue
		}
		return CacheError, ue
	}

	// Stream upstream response to client and cache to disk.
	if mkErr := os.MkdirAll(cacheDir, 0o750); mkErr == nil {
		tmpFile, tmpErr := os.CreateTemp(cacheDir, ".tmp-*")
		if tmpErr == nil {
			tee := io.TeeReader(resp.Body, tmpFile)
			n, copyErr := io.Copy(w, tee)
			tmpFile.Close()
			if copyErr != nil {
				slog.Error("failed to stream and cache fetch response", "repo", repo.owner+"/"+repo.name, "err", copyErr)
				os.Remove(tmpFile.Name())
				return CacheError, copyErr
			}
			if renameErr := os.Rename(tmpFile.Name(), cachePath); renameErr != nil {
				slog.Error("failed to finalize cached fetch response", "repo", repo.owner+"/"+repo.name, "err", renameErr)
				os.Remove(tmpFile.Name())
				// Served from upstream but not cached — count as passthrough.
				metrics.CachePackfileTotal.WithLabelValues(repo.owner, repo.name, user, "passthrough").Inc()
				metrics.CachePackfileBytesTotal.WithLabelValues(repo.owner, repo.name, user, "passthrough").Add(float64(n))
			} else {
				slog.Info("cached fetch response", "repo", repo.owner+"/"+repo.name, "path", cachePath)
				metrics.CachePackfileTotal.WithLabelValues(repo.owner, repo.name, user, "miss").Inc()
				metrics.CachePackfileBytesTotal.WithLabelValues(repo.owner, repo.name, user, "miss").Add(float64(n))
			}
			return CacheMiss, nil
		}
	}

	// Fallback: stream without caching (mkdir or tmpfile creation failed).
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return CacheError, err
	}
	metrics.CachePackfileTotal.WithLabelValues(repo.owner, repo.name, user, "passthrough").Inc()
	metrics.CachePackfileBytesTotal.WithLabelValues(repo.owner, repo.name, user, "passthrough").Add(float64(n))
	return CacheMiss, nil
}
