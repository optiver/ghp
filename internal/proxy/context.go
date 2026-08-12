package proxy

import (
	"context"
	"net/http"
)

// contextKey is an unexported type used for context keys in this package
// to avoid collisions with keys from other packages.
type contextKey struct{ name string }

var usernameCtxKey = &contextKey{"github-username"}
var userIDCtxKey = &contextKey{"user-id"}
var cacheStateCtxKey = &contextKey{"cache-state"}
var cacheRepoCtxKey = &contextKey{"cache-repo"}
var tokenTypeCtxKey = &contextKey{"token-type"}

// AccessLogSlots holds the mutable string slots that downstream handlers
// populate so the access-log middleware can read them after the request.
type AccessLogSlots struct {
	Username   *string
	UserID     *string
	CacheState *string // "hit", "miss", "rejected", "error", or "" for non-cached
	CacheRepo  *string // "owner/repo" if request hit a cached repository
	TokenType  *string // "proxy", "agent", native prefix (e.g. "gho"), or "" if unresolved
}

// PrepareAccessLogSlots returns a new request whose context carries mutable
// string slots for both the GitHub username and the internal user ID. Inner
// handlers call SetUsername / SetUserID to populate them; the access-log
// middleware reads the results after the request completes.
func PrepareAccessLogSlots(r *http.Request) (*http.Request, *AccessLogSlots) {
	usernameSlot := new(string)
	userIDSlot := new(string)
	cacheStateSlot := new(string)
	cacheRepoSlot := new(string)
	tokenTypeSlot := new(string)
	ctx := context.WithValue(r.Context(), usernameCtxKey, usernameSlot)
	ctx = context.WithValue(ctx, userIDCtxKey, userIDSlot)
	ctx = context.WithValue(ctx, cacheStateCtxKey, cacheStateSlot)
	ctx = context.WithValue(ctx, cacheRepoCtxKey, cacheRepoSlot)
	ctx = context.WithValue(ctx, tokenTypeCtxKey, tokenTypeSlot)
	return r.WithContext(ctx), &AccessLogSlots{
		Username:   usernameSlot,
		UserID:     userIDSlot,
		CacheState: cacheStateSlot,
		CacheRepo:  cacheRepoSlot,
		TokenType:  tokenTypeSlot,
	}
}

// PrepareUsernameSlot returns a new request whose context carries a mutable
// string slot. Inner handlers call SetUsername to populate it; outer handlers
// call GetUsername to read the result. This pattern allows the access-log
// middleware to learn the username that a downstream handler resolved.
//
// Deprecated: use PrepareAccessLogSlots for new code.
func PrepareUsernameSlot(r *http.Request) (*http.Request, *string) {
	slot := new(string)
	ctx := context.WithValue(r.Context(), usernameCtxKey, slot)
	return r.WithContext(ctx), slot
}

// SetUsername stores the resolved GitHub username in the request's context
// slot. It is a no-op if no slot was prepared.
func SetUsername(r *http.Request, username string) {
	if slot, ok := r.Context().Value(usernameCtxKey).(*string); ok {
		*slot = username
	}
}

// SetUserID stores the internal user ID in the request's context slot.
// It is a no-op if no slot was prepared.
func SetUserID(r *http.Request, userID string) {
	if slot, ok := r.Context().Value(userIDCtxKey).(*string); ok {
		*slot = userID
	}
}

// GetUsername returns the GitHub username stored in the request context, or ""
// if none has been set.
func GetUsername(r *http.Request) string {
	if slot, ok := r.Context().Value(usernameCtxKey).(*string); ok {
		return *slot
	}
	return ""
}

// GetUserID returns the internal user ID stored in the request context, or ""
// if none has been set.
func GetUserID(r *http.Request) string {
	if slot, ok := r.Context().Value(userIDCtxKey).(*string); ok {
		return *slot
	}
	return ""
}

// SetCacheState stores the cache result state in the request's context slot.
// Valid values: "hit", "miss", "rejected", "error". It is a no-op if no slot
// was prepared.
func SetCacheState(r *http.Request, state string) {
	if slot, ok := r.Context().Value(cacheStateCtxKey).(*string); ok {
		*slot = state
	}
}

// GetCacheState returns the cache result state from the request's context slot,
// or "" if no state was set.
func GetCacheState(r *http.Request) string {
	if slot, ok := r.Context().Value(cacheStateCtxKey).(*string); ok {
		return *slot
	}
	return ""
}

// SetCacheRepo stores the cached repository identifier (owner/repo) in the
// request's context slot. It is a no-op if no slot was prepared.
func SetCacheRepo(r *http.Request, repo string) {
	if slot, ok := r.Context().Value(cacheRepoCtxKey).(*string); ok {
		*slot = repo
	}
}

func SetTokenType(r *http.Request, tokenType string) {
	if slot, ok := r.Context().Value(tokenTypeCtxKey).(*string); ok {
		*slot = tokenType
	}
}
