# Configuration

Server configuration is loaded from a YAML file (via `--config` flag or
`GHP_CONFIG` env var). Environment variables with the `GHP_` prefix override
values from the config file.

## Environment Variables

### Core

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_ENCRYPTION_KEY` | AES-256-GCM key for encrypting GitHub tokens at rest (required for sqlite/postgres; not needed for vault) | |
| `GHP_DEV_MODE` | Enable test endpoints — never use in production | `false` |
| `GHP_ADMINS` | Comma-separated list of admin GitHub usernames | |

### Database

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_DATABASE_DRIVER` | `sqlite`, `postgres`, or `vault` | `sqlite` |
| `GHP_DATABASE_DSN` | Database connection string (sqlite/postgres only) | `ghp.db` |
| `GHP_DATABASE_VAULT_ADDR` | Vault server address (vault driver only) | |
| `GHP_DATABASE_VAULT_MOUNT` | Vault KV v2 mount path | `secret` |
| `GHP_DATABASE_VAULT_PATH` | Key prefix within the mount | `ghp` |
| `GHP_DATABASE_VAULT_AUTH_METHOD` | Vault auth method: `approle` or `kubernetes` | `approle` |
| `GHP_DATABASE_VAULT_ROLE_ID` | Vault AppRole role ID (when method=`approle`) | |
| `GHP_DATABASE_VAULT_SECRET_ID` | Vault AppRole secret ID (when method=`approle`) | |
| `GHP_DATABASE_VAULT_K8S_ROLE` | Vault role name (when method=`kubernetes`) | |
| `GHP_DATABASE_VAULT_K8S_MOUNT` | Vault auth mount for kubernetes method (e.g. `kubernetes/cluster-name`) | `kubernetes` |
| `GHP_DATABASE_VAULT_K8S_TOKEN_PATH` | Path to the projected service account JWT | `/var/run/secrets/kubernetes.io/serviceaccount/token` |

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_SERVER_LISTEN` | Listen address for plain HTTP mode | `:8080` |
| `GHP_SERVER_HTTPS_LISTEN` | HTTPS listen address (enables TLS mode) | |
| `GHP_SERVER_HTTP_LISTEN` | HTTP listen address for HTTPS redirects | |
| `GHP_SERVER_MANAGEMENT_HOST` | Hostname for the management UI and API | |
| `GHP_SERVER_BASE_URL` | Public base URL for OAuth callbacks and links | |
| `GHP_SERVER_TRUST_PROXY_HEADERS` | Honour `Forwarded` / `X-Forwarded-Proto` / `X-Forwarded-Host` when `base_url` is unset, and `Forwarded` (`for=`) / `X-Real-IP` / `X-Forwarded-For` for client attribution in access logs, `ghp_client_request_total`, and the per-IP auth rate limiter (only enable behind a trusted reverse proxy) | `false` |
| `GHP_SERVER_SYSTEMD_SOCKET_ACTIVATION` | Accept sockets from systemd instead of binding addresses | `false` |

### GitHub

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_GITHUB_CLIENT_ID` | GitHub App client ID (for OAuth login) | |
| `GHP_GITHUB_CLIENT_SECRET` | GitHub App client secret (for OAuth login) | |
| `GHP_GITHUB_APP_ID` | GitHub App ID (enables `gha_` agent tokens) | |
| `GHP_GITHUB_PRIVATE_KEY` | PEM-encoded GitHub App private key content | |
| `GHP_GITHUB_PRIVATE_KEY_FILE` | Path to GitHub App private key PEM file | |
| `GHP_GITHUB_ENTERPRISE_SLUG` | Enterprise slug for access restriction header | |
| — | `github.enterprise_exceptions` (targets exempt from the restriction header) is YAML-only; nested lists cannot be expressed as environment variables | |
| `GHP_GITHUB_BASE_URL` | GitHub API base URL for GHES deployments (must be HTTPS; e.g. `https://ghes.example.com/api/v3`). Omit or leave empty for github.com. Per-app overrides are set via the admin UI. | `https://api.github.com` |

### TLS

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_TLS_CERT_FILE` | Path to TLS certificate file (single-cert convenience) | |
| `GHP_TLS_KEY_FILE` | Path to TLS private key file (single-cert convenience) | |
| `GHP_TLS_MIN_VERSION` | Minimum TLS version: `1.2` or `1.3` | `1.2` |

### Tokens

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_TOKENS_DEFAULT_DURATION` | Default token lifetime | `24h` |
| `GHP_TOKENS_MAX_DURATION` | Maximum token lifetime | `168h` |
| `GHP_TOKENS_ALLOW_NO_EXPIRY` | Allow creating tokens that never expire | `false` |
| `GHP_TOKENS_EXPIRED_TOKEN_RETENTION_PERIOD` | How long after expiry or revocation before a token is hard-deleted. Set to `0` to disable cleanup. | `720h` (30 days) |

### Logging

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_LOGGING_OUTPUT` | Log destination: `stdout` or `file` | `stdout` |
| `GHP_LOGGING_LEVEL` | Log level: `debug`, `info`, `warn`, `error` | `info` |
| `GHP_LOGGING_FILE_PATH` | Path to log file (when output is `file`) | |

### Metrics

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_METRICS_ENABLED` | Enable the dedicated Prometheus metrics server | `true` |
| `GHP_METRICS_LISTEN` | Listen address for the metrics server | `:9136` |

### OpenTelemetry

ghp emits all logs as OpenTelemetry log records. They are always written to the
console (per the [Logging](#logging) settings); enabling `otel` additionally
exports every record to an OTLP collector. See
[Monitoring → Logging](monitoring.md#logging) for the record format.

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_OTEL_ENABLED` | Export log records to an OTLP collector | `false` |
| `GHP_OTEL_ENDPOINT` | OTLP exporter endpoint (e.g. `http://localhost:4317`). An `http://` scheme disables TLS. | |
| `GHP_OTEL_PROTOCOL` | OTLP transport protocol: `grpc` or `http` | `grpc` |

### OAuth Broker

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_AUTH_JWT_PRIVATE_KEY` | PEM-encoded RSA private key for signing broker JWTs (enables broker) | |
| `GHP_AUTH_JWT_PRIVATE_KEY_FILE` | Path to RSA private key PEM file for broker JWTs | |
| `GHP_AUTH_ALLOWED_REDIRECTS` | Comma-separated list of permitted OAuth redirect URIs | |

See [OAuth Broker](../features/oauth-broker.md) for integration details.

### Border Policy

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_BLOCK_GHP` | Block GitHub personal access tokens (`ghp_`) | `false` |
| `GHP_BLOCK_GHO` | Block GitHub OAuth access tokens (`gho_`) | `false` |
| `GHP_BLOCK_GHU` | Block GitHub user-to-server tokens (`ghu_`) | `false` |
| `GHP_BLOCK_GHS` | Block GitHub server-to-server tokens (`ghs_`) | `false` |
| `GHP_BLOCK_GHR` | Block GitHub refresh tokens (`ghr_`) | `false` |
| `GHP_BLOCK_GITHUB_PAT` | Block GitHub fine-grained personal access tokens (`github_pat_`) | `false` |
| `GHP_BLOCK_ANONYMOUS_GIT` | Block unauthenticated git smart HTTP requests | `false` |

See [Token Type Border Policy](../features/border-policy.md) for details.

### Release Controls

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_RELEASES_MODE` | Release download policy: `block`, `redirect`, or empty (disabled) | |
| `GHP_RELEASES_REDIRECT_TO` | Base URL for redirect mode (must be absolute) | |
| `GHP_RELEASES_REDIRECT_HEAD_CHECK` | Issue a HEAD request to the redirect target before redirecting; if the target returns 404, serve a friendly error page instead | `false` |
| `GHP_RELEASES_REDIRECT_HEAD_CHECK_NETRC` | Path to a netrc file whose credentials are sent as Basic auth on HEAD probes (see [Authenticated HEAD Checks](../features/release-controls.md#authenticated-head-checks)) | |
| `GHP_RELEASES_REDIRECT_NOT_FOUND_TEMPLATE` | Path to a custom HTML template for the 404 page (see [HEAD Check](../features/release-controls.md#head-check)); requires a process restart to take effect | |
| `GHP_RELEASES_ALLOW` | Comma-separated org or org/repo entries exempt from the policy | |
| `GHP_RELEASES_ALLOW_COUNT` | Number of indexed allow entries (use with `GHP_RELEASES_ALLOW_0`, `GHP_RELEASES_ALLOW_1`, ...) | |

See [Release Download Controls](../features/release-controls.md) for details.

### Codeload Redirect

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_CODELOAD_REDIRECT_TO` | Base URL to redirect codeload.github.com archive requests to (must be absolute). When unset, requests are forwarded transparently to upstream. | |
| `GHP_CODELOAD_ALLOW` | Comma-separated org or org/repo entries that bypass the redirect (passthrough to upstream) | |
| `GHP_CODELOAD_ALLOW_COUNT` | Number of indexed allow entries (use with `GHP_CODELOAD_ALLOW_0`, `GHP_CODELOAD_ALLOW_1`, ...) | |

See [Codeload Redirect](../features/codeload.md) for details.

### Git Cache

| Variable | Description | Default |
|----------|-------------|---------|
| `GHP_CACHE_ENABLED` | Enable the git clone/fetch caching feature | `false` |
| `GHP_CACHE_STORAGE_PATH` | Local filesystem path for cached bare repos | `cache` |
| `GHP_CACHE_S3_BUCKET` | S3 bucket name for shared cache storage (optional) | |
| `GHP_CACHE_S3_REGION` | AWS region for the S3 bucket | |
| `GHP_CACHE_S3_ENDPOINT` | Custom S3-compatible endpoint URL (for MinIO, etc) | |

See [Git Cache](../features/git-cache.md) for details.

## Full YAML Reference

```yaml
# encryption_key: ""            # WARNING: prefer GHP_ENCRYPTION_KEY env var; never commit this to version control
                                 # Not required when database.driver is "vault" (Vault encrypts at rest)

github:
  client_id: ""
  client_secret: ""
  app_id: 0                    # GitHub App ID (enables gha_ agent tokens)
  private_key_file: ""         # path to PEM file for GitHub App authentication
  # private_key: ""            # or inline PEM content (useful in containers)
  enterprise_slug: ""
  # base_url: ""               # GHES API base URL (e.g. https://ghes.example.com/api/v3); omit for github.com
  # enterprise_exceptions:     # exempt targets from the enterprise access restriction header
  #                            # (YAML only — nested lists cannot be set via environment variables)
  #   - match:                 # account names ("torvalds", "kubernetes") or owner/repo pairs
  #       - torvalds
  #       - kubernetes/website
  #     teams:                 # optional: restrict who may use this exception (org/team-slug);
  #       - my-org/oss-team    #   requires the default app installed on the org with members:read
  #     identity:              # optional: substitute a managed credential for matching requests
  #       app_record_id: ""    #   database record ID of a GitHub App (see admin UI)

database:
  driver: "sqlite"             # "sqlite", "postgres", or "vault"
  dsn: "ghp.db"
  # vault_addr: ""             # Vault server address (vault driver only)
  # vault_mount: "secret"      # KV v2 mount path
  # vault_path: "ghp"          # key prefix within the mount
  # vault_auth_method: "approle"  # "approle" (default) or "kubernetes"
  # vault_role_id: ""          # AppRole role ID (auth_method=approle)
  # vault_secret_id: ""        # AppRole secret ID (auth_method=approle)
  # vault_k8s_role: ""         # Vault role to authenticate as (auth_method=kubernetes)
  # vault_k8s_mount: "kubernetes"  # auth mount path (auth_method=kubernetes)
  # vault_k8s_token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"

server:
  listen: ":8080"              # plain HTTP mode (development or behind reverse proxy)
  https_listen: ":443"         # TLS mode (recommended for production)
  http_listen: ":80"           # HTTP-to-HTTPS redirect server
  management_host: ""          # hostname for management UI (e.g. ghp.example.com)
  base_url: ""                 # public base URL (e.g. https://ghp.example.com)
  # trust_proxy_headers: false # honour Forwarded / X-Forwarded-Proto / X-Forwarded-Host
                                #   when base_url is unset, and Forwarded (for=) /
                                #   X-Real-IP / X-Forwarded-For for client attribution in
                                #   access logs, the ghp_client_request_total metric, and
                                #   the per-IP auth rate limiter. Set true only behind a
                                #   trusted reverse proxy that strips and rewrites these
                                #   headers. Prefer setting base_url for URL construction.
  # systemd_socket_activation: false  # accept sockets from systemd

tls:
  certificates:
    - cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
  min_version: "1.2"           # minimum TLS version: "1.2" (default) or "1.3"

tokens:
  default_duration: "24h"
  max_duration: "168h"         # 7 days
  allow_no_expiry: false       # set true to allow tokens with no expiry (duration: "never")
  expired_token_retention_period: "720h"  # hard-delete expired/revoked tokens after 30 days (set to 0 to disable)

logging:
  output: "stdout"             # "stdout" or "file"
  level: "info"                # "debug", "info", "warn", "error"
  file:
    path: "/var/log/ghp/ghp.log"

metrics:
  enabled: true                # set to false to disable
  listen: ":9136"              # dedicated metrics server port

# otel:                        # Export OpenTelemetry log records to an OTLP collector
#   enabled: false             # logs are always written to the console regardless
#   endpoint: ""               # OTLP exporter endpoint (e.g. http://localhost:4317); http:// disables TLS
#   protocol: "grpc"           # "grpc" or "http"

auth:
  jwt_private_key_file: ""     # RSA private key for OAuth broker JWT signing (RS256)
  # jwt_private_key: ""        # or inline PEM content
  allowed_redirects:            # permitted redirect_uri values for broker flow
    - "https://app.example.com/auth/callback"
    - "*.internal.example.com"  # wildcard domain patterns supported

block:
  ghp: false                   # block GitHub personal access tokens (ghp_)
  gho: false                   # block GitHub OAuth access tokens (gho_)
  ghu: false                   # block GitHub user-to-server tokens (ghu_)
  ghs: false                   # block GitHub server-to-server tokens (ghs_)
  ghr: false                   # block GitHub refresh tokens (ghr_)
  anonymous_git: false         # block unauthenticated git smart HTTP traffic

releases:
  mode: ""                     # "block", "redirect", or "" (disabled)
  redirect_to: ""              # absolute URL base for redirect mode
  redirect_head_check: false   # HEAD-check redirect target; serve 404 page if target returns 404
  redirect_head_check_netrc: ""  # path to netrc file for HEAD check auth (optional)
  redirect_not_found_template: ""  # path to custom 404 HTML template (optional)
  allow:                       # org or org/repo entries exempt from policy
    - "myorg"
    - "trusted/tool"

codeload:
  redirect_to: ""              # absolute URL base for redirecting codeload archive requests; passthrough when empty
  allow:                       # org or org/repo entries that pass through to upstream codeload
    - "myorg"

cache:
  enabled: false               # enable git clone/fetch caching
  storage_path: "cache"        # local path for cached bare repos
  # s3_bucket: ""              # S3 bucket for shared cache storage (optional)
  # s3_region: ""              # AWS region
  # s3_endpoint: ""            # custom S3-compatible endpoint (MinIO, etc)

admins:
  - "alice"
  - "bob"

dev_mode: false                # enable test endpoints (never use in production)
```

## Encryption Key

Generate an encryption key:

```bash
export GHP_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

This key encrypts GitHub tokens at rest. Store it securely — if lost, stored
tokens cannot be decrypted. Use an environment variable or secrets manager
rather than putting it in the config file.

!!! note "Not required for Vault backend"
    When using `driver: vault`, the encryption key is not needed. Vault
    provides encryption at rest natively, so GHP uses a passthrough encryptor
    and the `GHP_ENCRYPTION_KEY` setting is ignored.

## Hot Reloading

The following settings can be changed without restarting the server by sending
`SIGUSR1` to the ghp process:

- `admins` — admin user list (roles are re-synced immediately)
- `tokens.default_duration` — default token lifetime applied to new tokens
- `auth.allowed_redirects` — OAuth broker allowed redirects
- `block` — border policy settings (anonymous git, token type blocking)
- `releases` — release download policy and allow list (`mode`, `redirect_to`, `redirect_head_check`, `allow`); note that `redirect_head_check_netrc` and `redirect_not_found_template` are loaded once at startup and require a restart to change
Settings that require a restart: database driver/DSN, server listen addresses,
`cache` (enable/disable, storage path),
TLS certificates, the encryption key, logging configuration, metrics
enable/disable, OAuth broker enable/disable and signing key
(`auth.jwt_private_key` / `auth.jwt_private_key_file`), `tokens.max_duration`,
and `tokens.allow_no_expiry` (both captured at server startup).

!!! note "App changes are live without reload"
    GitHub Apps created, updated, or deleted via the admin UI or API take effect
    immediately — the app registry is reloaded automatically after each change.
    No `SIGUSR1` or restart is required.

```bash
# Reload configuration
kill -USR1 $(pidof ghp)
```

!!! note "Admin role is re-evaluated on login and reload"
    The `admins` list is the source of truth for admin privileges. When the
    configuration is reloaded, admin roles are immediately re-synced with the
    database. Users also have their role re-evaluated each time they log in
    via GitHub OAuth.
