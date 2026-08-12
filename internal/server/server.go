// Package server wires together all ghp components and runs the HTTP server(s).
// It is responsible for:
//
//   - Opening the database and running/checking migrations
//   - Initializing encryption, token services, and the GitHub App provider
//   - Building the host-dispatch handler that routes requests by Host header
//     to the appropriate backend (API proxy, github.com passthrough,
//     codeload.github.com redirect/passthrough, Copilot passthrough, or
//     management UI)
//   - Starting TLS and/or plain HTTP listeners (including systemd socket
//     activation support)
//   - Running the dedicated Prometheus metrics server on a separate port
//   - Handling graceful shutdown (SIGINT/SIGTERM) and configuration hot-reload
//     (SIGUSR1)
//   - Applying cross-cutting middleware: access logging, security headers, and
//     the Server response header
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/noop"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/docs"
	"github.com/goodtune/ghp/internal/gitcache"
	"github.com/goodtune/ghp/internal/github"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
	"github.com/goodtune/ghp/internal/token"
	"github.com/goodtune/ghp/internal/web"
)

// Server is the main ghp server.
type Server struct {
	cfg         *config.Config
	configPath  string
	version     string
	logger      *slog.Logger
	logProvider otellog.LoggerProvider
	store       database.Store
	migrate     bool
}

// New creates a new Server. logProvider is the OpenTelemetry LoggerProvider
// used to emit the access and audit log streams; a nil provider falls back to a
// no-op provider so the server is safe to construct in tests.
func New(cfg *config.Config, configPath string, version string, logger *slog.Logger, logProvider otellog.LoggerProvider, migrate bool) *Server {
	if logProvider == nil {
		logProvider = noop.NewLoggerProvider()
	}
	return &Server{cfg: cfg, configPath: configPath, version: version, logger: logger, logProvider: logProvider, migrate: migrate}
}

// mustParseURL parses a URL and panics on failure. Only for compile-time constants.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("invalid URL %q: %v", rawURL, err))
	}
	return u
}

// syncBlockMetrics updates Prometheus gauges for block.* feature flags
// to reflect the current config. Called at startup and on config reload.
// Currently covers: block.anonymous_git.
func (s *Server) syncBlockMetrics() {
	if s.cfg.Block.AnonymousGit {
		metrics.BlockAnonymousGitEnabled.Set(1)
	} else {
		metrics.BlockAnonymousGitEnabled.Set(0)
	}
}

// reloadConfig re-reads the configuration file and updates hot-reloadable
// fields in-place. All components holding a pointer to the Config struct
// will see the updated values.
func (s *Server) reloadConfig() {
	if s.configPath == "" {
		s.logger.Warn("config_reload_skipped", "msg", "no config file path, cannot reload")
		return
	}
	if err := s.cfg.ReloadFrom(s.configPath); err != nil {
		s.logger.Error("config_reload_failed", "error", err)
		return
	}
	s.logger.Info("config_reloaded", "path", s.configPath)

	s.syncBlockMetrics()

	// Sync admin roles from the updated config.
	if s.store != nil {
		if err := s.store.SyncAdminRoles(context.Background(), s.cfg.Admins); err != nil {
			s.logger.Error("admin_role_sync_failed", "error", err)
		} else {
			s.logger.Info("admin_roles_synced")
		}
	}
}

// seedDefaultApp creates a default App record from the config if no apps exist
// in the store and the config has a GitHub App configured.
func (s *Server) seedDefaultApp(ctx context.Context, store database.Store, enc *crypto.Encryptor) error {
	if s.cfg.GitHub.AppID == 0 {
		return nil
	}

	apps, err := store.ListApps(ctx)
	if err != nil {
		return fmt.Errorf("listing apps: %w", err)
	}
	if len(apps) > 0 {
		return nil // Apps already exist.
	}

	privateKey := s.cfg.GitHub.PrivateKey
	if privateKey == "" && s.cfg.GitHub.PrivateKeyFile != "" {
		keyData, err := os.ReadFile(s.cfg.GitHub.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("reading private key file: %w", err)
		}
		privateKey = string(keyData)
	}

	// A private key is required to create a usable app record. If none is
	// configured the app would be stored but AppRegistry would fail to load
	// it, resulting in confusing UI/API behaviour with no provider available.
	if privateKey == "" {
		s.logger.Info("skipping default app seeding: no private key configured")
		return nil
	}

	// Encrypt secrets before storing.
	encClientSecret, err := encryptIfPresent(enc, s.cfg.GitHub.ClientSecret)
	if err != nil {
		return fmt.Errorf("encrypting client secret: %w", err)
	}
	encPrivateKey, err := encryptIfPresent(enc, privateKey)
	if err != nil {
		return fmt.Errorf("encrypting private key: %w", err)
	}

	app := &database.App{
		Name:         "Default",
		AppID:        s.cfg.GitHub.AppID,
		ClientID:     s.cfg.GitHub.ClientID,
		ClientSecret: encClientSecret,
		PrivateKey:   encPrivateKey,
		BaseURL:      s.cfg.GitHub.BaseURL,
		IsDefault:    true,
	}

	if err := store.CreateApp(ctx, app); err != nil {
		return fmt.Errorf("creating default app: %w", err)
	}

	s.logger.Info("default app seeded from config", "app_id", app.ID, "github_app_id", app.AppID)

	// Backfill existing agent tokens with the default app_id.
	if _, err := s.backfillTokenAppID(ctx, store, app.ID); err != nil {
		s.logger.Warn("token backfill failed", "error", err)
	}

	return nil
}

// backfillTokenAppID assigns the given appID to all agent proxy_tokens that have
// no app_id set. Returns the number of tokens updated.
func (s *Server) backfillTokenAppID(ctx context.Context, store database.Store, appID string) (int, error) {
	tokens, err := store.ListAllProxyTokens(ctx)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, t := range tokens {
		if t.AppID == nil && t.InstallationID != nil {
			if err := store.UpdateProxyTokenAppID(ctx, t.ID, appID); err != nil {
				s.logger.Warn("backfill token failed", "token_id", t.ID, "error", err)
				continue
			}
			count++
		}
	}
	return count, nil
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	metrics.SetBuildInfo(s.version)

	// Open database.
	var store database.Store
	var err error
	if s.cfg.Database.Driver == "vault" {
		store, err = database.OpenVault(ctx, database.VaultConfig{
			Addr:         s.cfg.Database.VaultAddr,
			MountPath:    s.cfg.Database.VaultMount,
			BasePath:     s.cfg.Database.VaultPath,
			AuthMethod:   s.cfg.Database.VaultAuthMethod,
			RoleID:       s.cfg.Database.VaultRoleID,
			SecretID:     s.cfg.Database.VaultSecretID,
			K8sRole:      s.cfg.Database.VaultK8sRole,
			K8sMount:     s.cfg.Database.VaultK8sMount,
			K8sTokenPath: s.cfg.Database.VaultK8sTokenPath,
		})
	} else {
		store, err = database.Open(s.cfg.Database.Driver, s.cfg.Database.DSN)
	}
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()
	s.store = store

	// Run or check migrations (not applicable for Vault backend).
	if s.cfg.Database.Driver != "vault" {
		migrator := database.NewMigrator(store, s.cfg.Database.Driver)
		if s.migrate {
			s.logger.Info("running database migrations before startup")
			if err := migrator.Migrate(ctx); err != nil {
				return fmt.Errorf("pre-startup migration: %w", err)
			}
			s.logger.Info("database migrations complete")
		} else {
			pending, err := migrator.PendingMigrations(ctx)
			if err != nil {
				s.logger.Warn("could not check migrations", "error", err)
			} else if len(pending) > 0 {
				return fmt.Errorf("database has %d pending migration(s): run 'ghp migrate' first", len(pending))
			}
		}
	}

	// Sync admin roles from config on startup.
	if err := store.SyncAdminRoles(ctx, s.cfg.Admins); err != nil {
		s.logger.Warn("admin_role_sync_failed", "error", err)
	} else {
		s.logger.Info("admin_roles_synced")
	}

	// Warn if the operator has set environment variables for token types
	// that ghp manages internally and cannot be blocked via border policy.
	s.cfg.WarnInvalidBlockTargets(s.logger)

	// Initialise the anonymous git blocking gauge to reflect the startup config.
	s.syncBlockMetrics()

	// Set up encryption. Vault provides encryption at rest, so a
	// passthrough encryptor is used when the backend is Vault.
	var enc *crypto.Encryptor
	if s.cfg.Database.Driver == "vault" {
		enc = crypto.NewPassthroughEncryptor()
	} else {
		encKey := s.cfg.EncryptionKey
		if encKey == "" {
			encKey = os.Getenv("GHP_ENCRYPTION_KEY")
		}
		if encKey == "" {
			return fmt.Errorf("encryption key not configured (set encryption_key in config or GHP_ENCRYPTION_KEY env var)")
		}
		var err error
		enc, err = crypto.NewEncryptor(encKey)
		if err != nil {
			return fmt.Errorf("initializing encryption: %w", err)
		}
	}

	// Create services.
	tokenSvc := token.NewService(store, s.cfg.Tokens.MaxDuration, s.cfg.Tokens.AllowNoExpiry)
	tokenSvc.WarmTokenCache(ctx, s.logger)

	// Seed the default app from config if no apps exist in the store.
	if err := s.seedDefaultApp(ctx, store, enc); err != nil {
		s.logger.Warn("default app seeding failed", "error", err)
	}

	// Build the AppRegistry with all apps from the store.
	appRegistry := github.NewAppRegistry(store, enc, s.logger)
	loadAllFailed := false
	if err := appRegistry.LoadAll(ctx); err != nil {
		s.logger.Warn("failed to load app registry", "error", err)
		loadAllFailed = true
	}

	// Always wire the registry as the app token provider so that apps
	// created via the admin UI/API take effect without a restart. The
	// registry consults the store dynamically on Reload(). Even when
	// zero apps exist at startup, the registry is wired so that apps
	// created later via the admin API become usable immediately.
	//
	// Config-based fallback is only used when LoadAll succeeded and
	// confirmed zero apps exist in the store AND a legacy config-based
	// app ID is set (fresh deployment with config-only setup).
	var appTokenProvider proxy.AppTokenProvider
	if appRegistry.TotalApps() > 0 || loadAllFailed {
		// Apps exist (or may exist — load failed). Always use the registry
		// so newly created/fixed apps take effect after Reload().
		appTokenProvider = appRegistry
		if appRegistry.TotalApps() > 0 && appRegistry.Count() == 0 {
			s.logger.Error("apps exist in store but none loaded successfully; fix app private keys via admin UI",
				"total_apps", appRegistry.TotalApps())
		}
		if loadAllFailed {
			s.logger.Error("app registry load failed; app provider will retry on next Reload()")
		}
	} else if s.cfg.GitHub.AppID != 0 {
		// Fallback: use config-based single app only when a successful
		// LoadAll confirmed zero apps exist in the store.
		privateKey := s.cfg.GitHub.PrivateKey
		if privateKey == "" && s.cfg.GitHub.PrivateKeyFile != "" {
			keyData, err := os.ReadFile(s.cfg.GitHub.PrivateKeyFile)
			if err != nil {
				return fmt.Errorf("reading GitHub App private key file: %w", err)
			}
			privateKey = string(keyData)
		}
		if privateKey != "" {
			atp, err := github.NewAppTokenProvider(github.AppConfig{
				AppID:      s.cfg.GitHub.AppID,
				PrivateKey: privateKey,
			})
			if err != nil {
				return fmt.Errorf("initializing GitHub App token provider: %w", err)
			}
			appTokenProvider = atp
			s.logger.Info("github app token provider initialized (config fallback)", "app_id", s.cfg.GitHub.AppID)
		}
	} else {
		// No apps in store and no config-based app. Wire the empty
		// registry so apps created via the admin API take effect after
		// Reload() without requiring a server restart.
		appTokenProvider = appRegistry
	}

	// Create a server-lifecycle context tied to shutdown signals so that all
	// background work (cache warming, token-warm goroutines) is reliably
	// cancelled when the process receives SIGTERM/SIGINT or when Run returns.
	// This single context is shared with the serve functions below so that
	// only one signal registration is needed for the whole server.
	lifecycleCtx, lifecycleCancel := signal.NotifyContext(ctx, shutdownSignals()...)
	defer lifecycleCancel()

	authHandler := auth.NewHandler(s.cfg, store, enc, s.logger)
	// Periodically purge expired sessions, oauth_states, and
	// cli_device_authorizations rows so the tables don't grow unbounded.
	authHandler.StartCleanup(lifecycleCtx)
	usernameResolver := proxy.NewUsernameResolver(store, s.logger)
	proxyTokenResolver := proxy.NewProxyTokenResolver(tokenSvc, store, enc, appTokenProvider)
	usernameResolver.WarmCache(lifecycleCtx, proxyTokenResolver)
	proxyHandler := proxy.NewHandler(s.cfg, tokenSvc, store, enc, appTokenProvider, usernameResolver, s.logger)

	// Build the enterprise access restriction policy with the app registry as
	// the identity source so exceptions can substitute managed installation
	// tokens and verify team membership. NewHandler installed a baseline
	// policy (matching only); this replaces it with the full-featured one.
	enterprisePolicy := proxy.NewEnterprisePolicy(s.cfg.GitHub, appRegistry, s.logger)
	proxyHandler.SetEnterprisePolicy(enterprisePolicy)

	// Build audit log writer for OpenTelemetry audit log records.
	auditWriter := newAuditLogWriter(s.logProvider.Logger(auditLogScope))
	proxyHandler.SetAuditLogWriter(auditWriter)

	// Recover the concrete *github.AppTokenProvider for legacy admin API
	// endpoints (/api/github/installations). In multi-app mode the registry
	// is used instead; we fall back to the default registry provider here so
	// those endpoints remain functional when no specific app is selected.
	var concreteATP *github.AppTokenProvider
	if atp, ok := appTokenProvider.(*github.AppTokenProvider); ok {
		concreteATP = atp
	} else if appRegistry != nil && appRegistry.Count() > 0 {
		// In multi-app mode, use the default app provider for the legacy endpoints.
		if defaultProvider, err := appRegistry.GetDefault(); err == nil {
			concreteATP = defaultProvider
		}
	}
	api := NewAPI(lifecycleCtx, s.cfg, store, tokenSvc, authHandler, enc, concreteATP, appRegistry, proxyTokenResolver, usernameResolver, s.logger, auditWriter)
	webUI := web.NewHandler(authHandler, store, s.cfg.DevMode, s.version, s.logger)

	// Build HTTP mux.
	mux := http.NewServeMux()

	// Auth routes.
	authHandler.RegisterRoutes(mux)

	// API routes.
	api.RegisterRoutes(mux)

	// Web UI routes.
	webUI.RegisterRoutes(mux)

	// Documentation site (embedded mkdocs output).
	mux.Handle("/docs/", http.StripPrefix("/docs/", docs.Handler()))
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	})

	// Proxy routes — these catch /api/v3/* and /api/graphql.
	mux.Handle("/api/v3/", proxyHandler)
	mux.Handle("/api/graphql", proxyHandler)

	// Create passthrough handlers for github.com and *.githubcopilot.com.
	// Reuse proxyTokenResolver created above for cache warming to avoid duplication.
	githubInner := proxy.NewPassthroughHandler(
		"https://github.com", proxyTokenResolver, s.logger, nil)

	// Wrap with git cache handler if enabled. The cache middleware wraps
	// githubInner (the raw passthrough). The resulting handler is then wrapped
	// by NewScopedPassthroughHandler below, which resolves ghx_/gha_ proxy
	// tokens to real GitHub credentials before the request reaches the cache.
	// The full chain is:
	//   ScopedPassthroughHandler → CacheLookup → (cache handler | raw passthrough)
	// CacheLookup routes to the cache handler for cache-enabled repos, or
	// falls through to the raw passthrough for everything else. By the time
	// the cache handler sees a request, any ghx_/gha_ proxy tokens have
	// already been resolved; if present, the Authorization header contains
	// the resolved GitHub credential (ghs_*, gho_*). Anonymous requests
	// and raw GitHub tokens pass through without resolution.
	if s.cfg.Cache.Enabled {
		if s.cfg.Cache.S3Bucket != "" {
			return fmt.Errorf("S3 cache storage backend is not yet implemented; remove cache.s3_bucket from config and use local filesystem storage (cache.storage_path) instead")
		}
		storageFactory, fsErr := gitcache.NewFilesystemStorageFactory(s.cfg.Cache.StoragePath)
		if fsErr != nil {
			return fmt.Errorf("create filesystem cache storage: %w", fsErr)
		}
		cacheRegistry := gitcache.NewRegistry(storageFactory, mustParseURL("https://github.com"))
		cacheHandler := gitcache.NewHandler(
			cacheRegistry,
			nil, // Service token is optional for initial implementation.
			"https://github.com",
			s.cfg.Cache.StoragePath,
		)
		githubInner = gitcache.NewCacheLookup(githubInner, cacheHandler, store, s.logger)
		gitcache.SyncCacheReposMetric(lifecycleCtx, store)
		gitcache.StartCleanup(lifecycleCtx, s.cfg.Cache.StoragePath, store, 10*time.Minute)
		s.logger.Info("git cache enabled", "storage_path", s.cfg.Cache.StoragePath)
	}

	// Start periodic cleanup of expired/revoked proxy tokens.
	token.StartCleanup(lifecycleCtx, store, s.cfg)

	githubPassthrough := proxy.NewScopedPassthroughHandler(
		githubInner, tokenSvc, proxyTokenResolver, usernameResolver, enterprisePolicy, s.logger, s.cfg)
	githubPassthrough = proxy.NewReleasesHandler(githubPassthrough, s.cfg, s.logger)

	codeloadHandler := proxy.NewCodeloadHandler(s.cfg, s.logger, nil)

	copilotPassthrough := proxy.NewCopilotPassthroughHandler(
		"https://copilot-proxy.githubusercontent.com", s.cfg.GitHub.EnterpriseSlug, s.logger, nil)

	// Build access log writer for OpenTelemetry access log records.
	aw := newAccessLogWriter(s.logProvider.Logger(accessLogScope))

	// Build host dispatch with access logging on all handlers.
	trustProxyHeaders := s.cfg.Server.TrustProxyHeaders
	dispatch := newHostDispatch(hostDispatchConfig{
		apiHandler:      accessLogHandler(backend.API, proxyHandler, aw, trustProxyHeaders),
		githubHandler:   accessLogHandler(backend.GitHub, githubPassthrough, aw, trustProxyHeaders),
		codeloadHandler: accessLogHandler(backend.Codeload, codeloadHandler, aw, trustProxyHeaders),
		copilotHandler:  accessLogHandler(backend.Copilot, copilotPassthrough, aw, trustProxyHeaders),
		mgmtHandler:     accessLogHandler(backend.Mgmt, web.SessionUsernameMiddleware(authHandler)(web.SecurityHeadersMiddleware(mux)), aw, trustProxyHeaders),
		managementHost:  s.cfg.Server.ManagementHost,
	})

	// Wrap dispatch with the Server response header middleware so that every
	// response across all backends carries the "Server: GitHub Proxy <version>"
	// header.
	handler := web.ServerHeaderMiddleware(s.version)(dispatch)

	// Platform-specific signal handling (e.g. SIGUSR1 on Unix for config reload).
	setupPlatformSignals(s.logger, s.reloadConfig)

	// TLS mode: https_listen configured, or socket activation with TLS certificates.
	hasTLS := s.cfg.Server.HTTPSListen != "" ||
		(s.cfg.Server.SystemdSocketActivation && len(s.cfg.TLS.Certificates) > 0)

	// Start standalone metrics server if enabled.
	if s.cfg.Metrics.Enabled {
		var metricsTLS *tls.Config
		if hasTLS {
			var tlsErr error
			metricsTLS, tlsErr = loadTLSConfig(&s.cfg.TLS)
			if tlsErr != nil {
				return fmt.Errorf("loading TLS config for metrics server: %w", tlsErr)
			}
		}
		metricsLn, listenErr := net.Listen("tcp", s.cfg.Metrics.Listen)
		if listenErr != nil {
			return fmt.Errorf("metrics server listen %s: %w", s.cfg.Metrics.Listen, listenErr)
		}
		if metricsTLS != nil {
			metricsLn = tls.NewListener(metricsLn, metricsTLS)
		}
		go s.serveMetrics(lifecycleCtx, metricsLn, metricsTLS)
	}

	if hasTLS {
		return s.serveTLS(lifecycleCtx, handler)
	}

	// Plain HTTP mode (single port, no TLS).
	return s.servePlain(lifecycleCtx, handler)
}

// serveTLS starts an HTTPS server with TLS termination and an optional
// HTTP redirect server. It blocks until shutdown.
//
// With systemd socket activation, file descriptors are inherited from the
// socket unit. Two FDs means fd3=HTTP(80) and fd4=HTTPS(443); a single FD
// is used for HTTPS only.
func (s *Server) serveTLS(ctx context.Context, handler http.Handler) error {
	tlsCfg, err := loadTLSConfig(&s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("loading TLS config: %w", err)
	}
	if tlsCfg == nil {
		return fmt.Errorf("TLS mode enabled but no certificates configured")
	}

	var httpsLn net.Listener
	var httpLn net.Listener // optional HTTP redirect listener

	if s.cfg.Server.SystemdSocketActivation {
		listeners, sdErr := systemdListeners()
		if sdErr != nil {
			s.logger.Warn("systemd_socket_fallback",
				"error", sdErr,
				"msg", "falling back to configured addresses")
		} else {
			switch len(listeners) {
			case 1:
				httpsLn = listeners[0]
			case 2:
				httpLn = listeners[0]  // fd 3 = port 80
				httpsLn = listeners[1] // fd 4 = port 443
			default:
				for _, ln := range listeners {
					ln.Close()
				}
				return fmt.Errorf("expected 1-2 systemd sockets for TLS mode, got %d", len(listeners))
			}
		}
	}

	// Fall back to configured addresses when systemd sockets are unavailable.
	if httpsLn == nil {
		if s.cfg.Server.HTTPSListen == "" {
			return fmt.Errorf("https_listen not configured and no systemd socket available")
		}
		httpsLn, err = net.Listen("tcp", s.cfg.Server.HTTPSListen)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPSListen, err)
		}
	}

	tlsLn := tls.NewListener(httpsLn, tlsCfg)

	// Set TLSConfig so HTTP/2 is auto-configured by net/http.
	httpsServer := &http.Server{Handler: handler, TLSConfig: tlsCfg}

	// Start HTTP redirect server from systemd socket or configured address.
	var httpServer *http.Server
	if httpLn != nil {
		httpServer = &http.Server{Handler: httpsRedirectHandler()}
		go func() {
			if err := httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
				s.logger.Error("http_redirect_server_error", "err", err)
			}
		}()
	} else if s.cfg.Server.HTTPListen != "" {
		cfgLn, err := net.Listen("tcp", s.cfg.Server.HTTPListen)
		if err != nil {
			tlsLn.Close()
			return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPListen, err)
		}
		httpServer = &http.Server{Handler: httpsRedirectHandler()}
		go func() {
			if err := httpServer.Serve(cfgLn); err != nil && err != http.ErrServerClosed {
				s.logger.Error("http_redirect_server_error",
					"listen_addr", s.cfg.Server.HTTPListen,
					"err", err)
			}
		}()
	}

	// Graceful shutdown for both servers. ctx is already lifecycle-aware
	// (signal.NotifyContext created in Run), so we use it directly.
	go func() {
		<-ctx.Done()
		s.logger.Info("server_shutdown", "msg", "shutting down")
		timeout, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tcancel()
		httpsServer.Shutdown(timeout)
		if httpServer != nil {
			httpServer.Shutdown(timeout)
		}
	}()

	s.logger.Info("server_ready",
		"mode", "tls",
		"systemd", s.cfg.Server.SystemdSocketActivation,
		"msg", "ready to accept connections")
	notifySystemd("READY=1")

	if err := httpsServer.Serve(tlsLn); err != http.ErrServerClosed {
		if httpServer != nil {
			httpServer.Close()
		}
		return fmt.Errorf("server error: %w", err)
	}
	notifySystemd("STOPPING=1")
	return nil
}

// servePlain starts a plain HTTP server (legacy mode, no TLS). It blocks
// until shutdown.
func (s *Server) servePlain(ctx context.Context, handler http.Handler) error {
	ln, err := s.createListener()
	if err != nil {
		return fmt.Errorf("creating listener: %w", err)
	}

	httpServer := &http.Server{Handler: handler}

	// ctx is already lifecycle-aware (signal.NotifyContext created in Run).
	go func() {
		<-ctx.Done()
		s.logger.Info("server_shutdown", "msg", "shutting down")
		timeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		httpServer.Shutdown(timeout)
	}()

	s.logger.Info("server_ready", "listen", s.cfg.Server.Listen, "msg", "ready to accept connections")
	notifySystemd("READY=1")

	if err := httpServer.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	notifySystemd("STOPPING=1")
	return nil
}

func (s *Server) createListener() (net.Listener, error) {
	addr := s.cfg.Server.Listen

	// Check for systemd socket activation.
	if s.cfg.Server.SystemdSocketActivation {
		listeners, err := systemdListeners()
		if err != nil {
			s.logger.Warn("systemd_socket_fallback",
				"error", err,
				"msg", "falling back to configured address")
		} else if len(listeners) >= 1 {
			// Use the first listener; close any extras (plain mode needs one).
			for _, ln := range listeners[1:] {
				ln.Close()
			}
			return listeners[0], nil
		}
	}

	// Unix socket.
	if strings.HasPrefix(addr, "unix://") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		os.Remove(sockPath) // Clean up stale socket.
		return net.Listen("unix", sockPath)
	}

	// TCP.
	return net.Listen("tcp", addr)
}

// serveMetrics starts a dedicated HTTP (or HTTPS when tlsCfg is non-nil) server
// on the given listener, exposing only the Prometheus /metrics endpoint. It
// runs until ctx is cancelled or a shutdown signal is received, then drains
// with a 30-second timeout.
func (s *Server) serveMetrics(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.Handler())

	srv := &http.Server{Handler: mux, TLSConfig: tlsCfg}

	// ctx is already lifecycle-aware (signal.NotifyContext created in Run).
	go func() {
		<-ctx.Done()
		timeout, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tcancel()
		_ = srv.Shutdown(timeout)
	}()

	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}
	s.logger.Info("metrics_server_ready", "listen", ln.Addr().String(), "scheme", scheme)

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		s.logger.Error("metrics_server_error", "error", err)
	}
}

// systemdListeners returns net.Listeners for each file descriptor passed
// by the systemd socket activation protocol (LISTEN_FDS).
func systemdListeners() ([]net.Listener, error) {
	fdsStr := os.Getenv("LISTEN_FDS")
	if fdsStr == "" {
		return nil, fmt.Errorf("LISTEN_FDS not set")
	}
	nfds, err := strconv.Atoi(fdsStr)
	if err != nil || nfds <= 0 {
		return nil, fmt.Errorf("invalid LISTEN_FDS value: %s", fdsStr)
	}
	listeners := make([]net.Listener, 0, nfds)
	for i := 0; i < nfds; i++ {
		fd := 3 + i
		f := os.NewFile(uintptr(fd), fmt.Sprintf("systemd-socket-%d", i))
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			for _, prev := range listeners {
				prev.Close()
			}
			return nil, fmt.Errorf("creating listener from fd %d: %w", fd, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

type hostDispatchConfig struct {
	apiHandler      http.Handler
	githubHandler   http.Handler
	codeloadHandler http.Handler
	copilotHandler  http.Handler
	mgmtHandler     http.Handler
	managementHost  string
}

// newHostDispatch creates a handler that routes requests by Host header.
//
// The Host header is normalised to lowercase before comparison: hostnames are
// case-insensitive (RFC 1035 §2.3.3) and net/http does not lowercase r.Host
// for us, so without this a client sending "API.GitHub.com" would 404 even
// though it resolves to the same backend as "api.github.com".
func newHostDispatch(cfg hostDispatchConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)

		switch {
		case host == backend.API:
			cfg.apiHandler.ServeHTTP(w, r)
		case host == backend.GitHub:
			cfg.githubHandler.ServeHTTP(w, r)
		case host == backend.Codeload:
			cfg.codeloadHandler.ServeHTTP(w, r)
		case host == "githubcopilot.com" || strings.HasSuffix(host, ".githubcopilot.com"):
			cfg.copilotHandler.ServeHTTP(w, r)
		case cfg.managementHost == "" || strings.EqualFold(host, cfg.managementHost):
			cfg.mgmtHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func notifySystemd(state string) {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return
	}
	conn, err := net.Dial("unixgram", socketPath)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte(state))
}
