package github

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

// AppRegistry manages multiple AppTokenProviders, one per configured GitHub App.
type AppRegistry struct {
	transport http.RoundTripper // configured before LoadAll; retained across Reload
	mu        sync.RWMutex
	providers map[string]*AppTokenProvider // keyed by App.ID (database UUID)
	defaultID string                       // ID of the default app
	totalApps int                          // total App records from last load (may differ from len(providers) if some failed)
	store     database.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger
}

// NewAppRegistry creates a new registry. Call LoadAll to populate it.
func NewAppRegistry(store database.Store, enc *crypto.Encryptor, logger *slog.Logger) *AppRegistry {
	return &AppRegistry{
		providers: make(map[string]*AppTokenProvider),
		store:     store,
		encryptor: enc,
		logger:    logger,
	}
}

// SetTransport configures outbound transport before loading or using the registry.
func (r *AppRegistry) SetTransport(transport http.RoundTripper) {
	r.transport = transport
}

// LoadAll reads all App records from the store and creates an AppTokenProvider
// for each one that has a valid private key.
func (r *AppRegistry) LoadAll(ctx context.Context) error {
	apps, err := r.store.ListApps(ctx)
	if err != nil {
		return fmt.Errorf("listing apps: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset all state so that a second LoadAll call (e.g. in tests) does not
	// accumulate stale providers or a stale defaultID from a previous load.
	r.providers = make(map[string]*AppTokenProvider)
	r.defaultID = ""
	r.totalApps = len(apps)

	// Sort by CreatedAt so default selection is deterministic across backends
	// (Vault list order is not guaranteed stable across restarts).
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].CreatedAt.Before(apps[j].CreatedAt)
	})

	for _, app := range apps {
		if err := r.loadAppLocked(app); err != nil {
			r.logger.Warn("skipping app", "app_id", app.ID, "name", app.Name, "error", err)
			continue
		}
		if app.IsDefault {
			if r.defaultID != "" {
				r.logger.Warn("multiple apps marked as default; using earliest created one — fix via admin UI",
					"previous_default", r.defaultID, "new_default", app.ID)
			}
			r.defaultID = app.ID
		}
	}
	r.logger.Info("app registry loaded", "count", len(r.providers), "total_apps", len(apps))
	return nil
}

// TotalApps returns the number of App records in the store as of the last
// LoadAll or Reload call. This may differ from Count() when apps exist in
// the store but fail to load (e.g. bad private keys). Use this to
// distinguish "no apps in store" from "apps present but none loaded".
func (r *AppRegistry) TotalApps() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totalApps
}

// loadAppLocked creates a provider for the given app. Caller must hold r.mu.
func (r *AppRegistry) loadAppLocked(app *database.App) error {
	privateKey := app.PrivateKey
	if r.encryptor != nil && privateKey != "" {
		decrypted, err := r.encryptor.Decrypt(privateKey)
		if err != nil {
			// If decryption fails, try using the key as-is (may be plaintext in dev).
			r.logger.Debug("private key decryption failed, using as-is", "app_id", app.ID)
			decrypted = privateKey
		}
		privateKey = decrypted
	}

	if privateKey == "" {
		return fmt.Errorf("no private key configured")
	}

	provider, err := NewAppTokenProvider(AppConfig{
		AppID:      app.AppID,
		PrivateKey: privateKey,
		BaseURL:    app.BaseURL,
	})
	if err != nil {
		return fmt.Errorf("creating provider: %w", err)
	}

	provider.SetTransport(r.transport)
	r.providers[app.ID] = provider
	r.logger.Info("app provider loaded", "app_id", app.ID, "name", app.Name, "github_app_id", app.AppID)
	return nil
}

// Get returns the AppTokenProvider for the given app ID.
func (r *AppRegistry) Get(appID string) (*AppTokenProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[appID]
	if !ok {
		return nil, fmt.Errorf("no provider for app %s", appID)
	}
	if provider == nil {
		return nil, fmt.Errorf("provider for app %s is not initialized", appID)
	}
	return provider, nil
}

// GetDefault returns the AppTokenProvider for the default app.
func (r *AppRegistry) GetDefault() (*AppTokenProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.defaultID == "" {
		// If no explicit default, return the first provider if there's only one.
		if len(r.providers) == 1 {
			for _, p := range r.providers {
				if p == nil {
					return nil, fmt.Errorf("sole app provider is not initialized")
				}
				return p, nil
			}
		}
		return nil, fmt.Errorf("no default app configured")
	}
	provider, ok := r.providers[r.defaultID]
	if !ok {
		return nil, fmt.Errorf("default app provider not found")
	}
	if provider == nil {
		return nil, fmt.Errorf("default app provider is not initialized")
	}
	return provider, nil
}

// GetDefaultID returns the database ID of the default app, or empty string if none.
func (r *AppRegistry) GetDefaultID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultID
}

// DefaultOrOnlyID returns the default app ID, or if no default is set and
// exactly one app is loaded, returns that app's ID. Returns empty string
// only when there are zero or 2+ apps with no explicit default.
func (r *AppRegistry) DefaultOrOnlyID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defaultID != "" {
		return r.defaultID
	}
	if len(r.providers) == 1 {
		for id := range r.providers {
			return id
		}
	}
	return ""
}

// Reload re-reads apps from the store and updates providers. It rebuilds
// every provider so that changes to an existing app (rotated private key,
// base_url change, etc.) take effect immediately without a restart.
func (r *AppRegistry) Reload(ctx context.Context) error {
	apps, err := r.store.ListApps(ctx)
	if err != nil {
		return fmt.Errorf("listing apps: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset defaultID before recomputing; if no app is marked default after
	// the reload, GetDefault() should reflect that rather than return stale state.
	r.defaultID = ""
	r.totalApps = len(apps)

	// Sort by CreatedAt so default selection is deterministic (see LoadAll).
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].CreatedAt.Before(apps[j].CreatedAt)
	})

	// Track which IDs are still valid.
	seen := make(map[string]bool)
	for _, app := range apps {
		seen[app.ID] = true
		// Always reload the provider so key/config changes take effect.
		if err := r.loadAppLocked(app); err != nil {
			r.logger.Warn("skipping app on reload", "app_id", app.ID, "name", app.Name, "error", err)
			// Remove any stale provider so the registry doesn't serve
			// an invalidated credential after a key rotation failure.
			delete(r.providers, app.ID)
			continue
		}
		if app.IsDefault {
			if r.defaultID != "" {
				r.logger.Warn("multiple apps marked as default on reload; using earliest created one — fix via admin UI",
					"previous_default", r.defaultID, "new_default", app.ID)
			}
			r.defaultID = app.ID
		}
	}

	// Remove providers for deleted apps.
	for id := range r.providers {
		if !seen[id] {
			delete(r.providers, id)
		}
	}

	r.logger.Info("app registry reloaded", "count", len(r.providers))
	return nil
}

// Count returns the number of loaded providers.
func (r *AppRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// GetInstallationToken resolves an installation token using the default app provider.
// Satisfies the proxy.AppTokenProvider interface.
func (r *AppRegistry) GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error) {
	provider, err := r.GetDefault()
	if err != nil {
		return "", err
	}
	return provider.GetInstallationToken(ctx, installationID, repos, permissions)
}

// GetInstallationTokenForApp resolves an installation token using a specific app's provider.
// If appID is empty, falls back to the default provider.
// Satisfies the proxy.MultiAppTokenProvider interface.
func (r *AppRegistry) GetInstallationTokenForApp(ctx context.Context, appID string, installationID int64, repos []string, permissions map[string]string) (string, error) {
	var provider *AppTokenProvider
	var err error
	if appID != "" {
		provider, err = r.Get(appID)
	} else {
		provider, err = r.GetDefault()
	}
	if err != nil {
		return "", err
	}
	return provider.GetInstallationToken(ctx, installationID, repos, permissions)
}

// InstallationTokenForOwner mints an installation token for the given app's
// installation on the target owner (user or organization), discovering the
// installation ID via the app JWT. An empty appRecordID selects the default
// app. Satisfies the proxy.ExceptionIdentitySource interface used by
// enterprise access restriction exceptions.
func (r *AppRegistry) InstallationTokenForOwner(ctx context.Context, appRecordID, owner string, repos []string, permissions map[string]string) (string, error) {
	var provider *AppTokenProvider
	var err error
	if appRecordID != "" {
		provider, err = r.Get(appRecordID)
	} else {
		provider, err = r.GetDefault()
	}
	if err != nil {
		return "", err
	}
	installationID, err := provider.GetInstallationIDForOwner(ctx, owner)
	if err != nil {
		return "", err
	}
	return provider.GetInstallationToken(ctx, installationID, repos, permissions)
}

// NewRegistryWithState constructs an AppRegistry with pre-populated provider
// slot IDs and an optional default ID. Provider values are nil — Get()
// returns a clear error ("not initialized") instead of a nil pointer, so
// calling GetInstallationToken on a test registry safely fails.
//
// This helper exists in production code (not a _test.go file) because it is
// called cross-package from internal/server/api_test.go and Go does not
// support cross-package test-only exports.
func NewRegistryWithState(providerIDs []string, defaultID string) *AppRegistry {
	r := &AppRegistry{
		providers: make(map[string]*AppTokenProvider),
		defaultID: defaultID,
		totalApps: len(providerIDs),
	}
	for _, id := range providerIDs {
		r.providers[id] = nil
	}
	return r
}
