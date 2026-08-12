package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	code := isolateTestsFromHostSystemConfig(m)
	os.Exit(code)
}

func isolateTestsFromHostSystemConfig(m *testing.M) int {
	dir, err := os.MkdirTemp("", "ghp-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	systemConfigPathOverride = filepath.Join(dir, "absent-system-config.yaml")
	return m.Run()
}

// TestHelpOutput_Root verifies that the root help text mentions all subcommands and flags.
func TestHelpOutput_Root(t *testing.T) {
	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})
	_ = rootCmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"serve",
		"migrate",
		"auth",
		"token",
		"apptoken",
		"version",
		"--config",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("root help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Serve verifies that "ghp serve --help" mentions all its flags.
func TestHelpOutput_Serve(t *testing.T) {
	cmd := newServeCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"--migrate"} {
		if !strings.Contains(output, want) {
			t.Errorf("serve help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Migrate verifies that "ghp migrate --help" mentions the status subcommand.
func TestHelpOutput_Migrate(t *testing.T) {
	cmd := newMigrateCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"status"} {
		if !strings.Contains(output, want) {
			t.Errorf("migrate help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Auth verifies that "ghp auth --help" mentions all subcommands.
func TestHelpOutput_Auth(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"login", "set-token", "status"} {
		if !strings.Contains(output, want) {
			t.Errorf("auth help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_AuthLogin verifies that "ghp auth login --help" describes the command correctly.
func TestHelpOutput_AuthLogin(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"device-authorization",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("auth login help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_AuthStatus verifies that "ghp auth status --help" describes the command correctly.
func TestHelpOutput_AuthStatus(t *testing.T) {
	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"authentication status",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("auth status help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_Token verifies that "ghp token --help" mentions create, list, and revoke subcommands.
func TestHelpOutput_Token(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{"create", "list", "revoke"} {
		if !strings.Contains(output, want) {
			t.Errorf("token help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_TokenCreate verifies that "ghp token create --help" mentions all its flags.
func TestHelpOutput_TokenCreate(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"--type",
		"--app",
		"--app-id",
		"--repo",
		"--repos",
		"--installation",
		"--installation-id",
		"--scope",
		"--duration",
		"--session",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("token create help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_TokenList verifies that "ghp token list --help" describes the command correctly.
func TestHelpOutput_TokenList(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"active tokens",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("token list help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestHelpOutput_TokenRevoke verifies that "ghp token revoke --help" mentions the token-id argument.
func TestHelpOutput_TokenRevoke(t *testing.T) {
	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"revoke", "--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"token-id",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("token revoke help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestVersionCmd verifies that "ghp version" prints the version string.
func TestVersionCmd(t *testing.T) {
	cmd := newVersionCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version cmd error: %v", err)
	}
	// Version is set via ldflags at build time; in tests it defaults to "dev".
	if !strings.Contains(buf.String(), "ghp version") {
		t.Errorf("expected 'ghp version' in output, got %q", buf.String())
	}
}

// TestAuthLoginCmd_NoServerURL verifies that auth login returns an error when no server URL is configured.
func TestAuthLoginCmd_NoServerURL(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no server URL is configured")
	}
	if !strings.Contains(err.Error(), "server URL not configured") {
		t.Errorf("expected 'server URL not configured' in error, got: %v", err)
	}
}

// TestAuthLoginCmd_DeviceFlow verifies that "ghp auth login" runs the device
// authorization flow against the server, displays the verification URL and
// user code, polls until the request is approved, and saves the issued token
// to the local config file.
func TestAuthLoginCmd_DeviceFlow(t *testing.T) {
	const userCode = "ABCD-EFGH"
	const deviceCode = "device-code-xyz"
	const issuedToken = "ghpr_devicetoken123"

	pollCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/cli/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":               deviceCode,
				"user_code":                 userCode,
				"verification_uri":          "http://server.example/cli/auth",
				"verification_uri_complete": "http://server.example/cli/auth?user_code=" + userCode,
				"expires_in":                600,
				"interval":                  1,
			})
		case r.Method == "POST" && r.URL.Path == "/cli/auth/device/token":
			pollCount++
			w.Header().Set("Content-Type", "application/json")
			if pollCount < 2 {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{
				"session_token": issuedToken,
				"username":      "alice",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", home)
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth login error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, userCode) {
		t.Errorf("expected user code %q in output, got: %q", userCode, output)
	}
	if !strings.Contains(output, "/cli/auth?user_code="+userCode) {
		t.Errorf("expected verification URL in output, got: %q", output)
	}

	// Token should be saved to ~/.config/ghp/config.yaml.
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.UserToken != issuedToken {
		t.Errorf("UserToken = %q, want %q", cfg.UserToken, issuedToken)
	}

	if pollCount < 2 {
		t.Errorf("expected at least 2 polls, got %d", pollCount)
	}
}

// TestAuthLoginCmd_DeviceFlowDenied verifies that the CLI surfaces an
// access_denied response from the server as a clean error.
func TestAuthLoginCmd_DeviceFlowDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cli/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "dc",
				"user_code":        "AAAA-BBBB",
				"verification_uri": "http://server.example/cli/auth",
				"expires_in":       600,
				"interval":         1,
			})
		case r.URL.Path == "/cli/auth/device/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when device flow is denied")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected 'denied' in error, got: %v", err)
	}
}

// TestAuthLoginCmd_ServerError verifies that auth login reports an error when
// the device-start endpoint returns a non-200 status.
func TestAuthLoginCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when server returns 500")
	}
}

// TestAuthLoginCmd_DeviceFlowServerError verifies that an RFC-8628
// `server_error` from the polling endpoint surfaces as a clear,
// actionable error instead of "unexpected error from server".
func TestAuthLoginCmd_DeviceFlowServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "dc",
				"user_code":        "AAAA-BBBB",
				"verification_uri": "http://server.example/cli/auth",
				"expires_in":       600,
				"interval":         1,
			})
		case "/cli/auth/device/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "server_error"})
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when poll returns server_error")
	}
	if !strings.Contains(err.Error(), "server_error") || !strings.Contains(err.Error(), "ghp server") {
		t.Errorf("expected friendly server_error message, got: %v", err)
	}
}

// TestAuthLoginCmd_DeviceFlowRateLimit verifies that the CLI honours an
// HTTP 429 response with Retry-After by sleeping briefly and resuming the
// poll instead of aborting. The rate-limit response is followed by a
// successful approval so the test completes without timing out.
func TestAuthLoginCmd_DeviceFlowRateLimit(t *testing.T) {
	const issuedToken = "ghpr_ratelimit_token_aaaaaaaa"
	pollCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli/auth/device":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "dc",
				"user_code":        "AAAA-BBBB",
				"verification_uri": "http://server.example/cli/auth",
				"expires_in":       600,
				"interval":         1,
			})
		case "/cli/auth/device/token":
			pollCount++
			w.Header().Set("Content-Type", "application/json")
			if pollCount == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{"message": "Rate limit exceeded"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{
				"session_token": issuedToken,
				"username":      "alice",
			})
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GHP_NO_BROWSER", "1")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"login"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected success after backing off on 429, got: %v", err)
	}
	if pollCount < 2 {
		t.Errorf("expected at least 2 polls (one rate-limited + one successful), got %d", pollCount)
	}
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.UserToken != issuedToken {
		t.Errorf("UserToken = %q, want %q", cfg.UserToken, issuedToken)
	}
}

// TestParseRetryAfter covers the CLI's interpretation of the Retry-After
// header (delta-seconds, HTTP-date, and malformed/empty cases).
func TestParseRetryAfter(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{"  10  ", 10 * time.Second},
		{"-1", 0},
		{"not a number", 0},
		// HTTP-date in the future yields a positive duration; we don't
		// pin to an exact value because parseRetryAfter computes
		// time.Until(t), which races with wall-clock at sub-second
		// granularity. Just assert it's roughly within a 30s window.
		{now.Add(20 * time.Second).Format(http.TimeFormat), 20 * time.Second},
	}
	for _, tt := range tests {
		got := parseRetryAfter(tt.in)
		if tt.want == 0 {
			if got != 0 {
				t.Errorf("parseRetryAfter(%q) = %v, want 0", tt.in, got)
			}
			continue
		}
		// Allow ±5s slack for the HTTP-date variant.
		diff := got - tt.want
		if diff < -5*time.Second || diff > 5*time.Second {
			t.Errorf("parseRetryAfter(%q) = %v, want ~%v", tt.in, got, tt.want)
		}
	}
}

// TestAuthSetTokenCmd_Valid verifies that set-token saves a ghpr_ token to config.
func TestAuthSetTokenCmd_Valid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "http://localhost:8080")
	t.Setenv("GHP_USER_TOKEN", "")

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"set-token", "ghpr_abc123def456"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("set-token error: %v", err)
	}
	if !strings.Contains(buf.String(), "saved") {
		t.Errorf("expected 'saved' confirmation in output, got: %q", buf.String())
	}

	// Verify the token was written to the config file.
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg.UserToken != "ghpr_abc123def456" {
		t.Errorf("UserToken = %q, want %q", cfg.UserToken, "ghpr_abc123def456")
	}
}

// TestAuthSetTokenCmd_InvalidPrefix verifies that set-token rejects tokens without the ghpr_ prefix.
func TestAuthSetTokenCmd_InvalidPrefix(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"set-token", "notavalidtoken"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for token without ghpr_ prefix")
	}
}

// TestAuthStatusCmd_NoToken verifies that auth status reports unauthenticated when no token is set.
func TestAuthStatusCmd_NoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to stub server: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth status error: %v", err)
	}
	if !strings.Contains(buf.String(), "Not authenticated") {
		t.Errorf("expected 'Not authenticated' in output, got: %q", buf.String())
	}
}

// TestAuthStatusCmd_Authenticated verifies that auth status calls the stub server and reports the user.
func TestAuthStatusCmd_Authenticated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer testtoken" {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"username":      "alice",
			"role":          "admin",
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("auth status error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "alice") {
		t.Errorf("expected username 'alice' in output, got: %q", output)
	}
	if !strings.Contains(output, "admin") {
		t.Errorf("expected role 'admin' in output, got: %q", output)
	}
}

// TestAuthStatusCmd_NoServerURL verifies that auth status returns an error when no server URL is configured.
func TestAuthStatusCmd_NoServerURL(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newAuthCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"status"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no server URL is configured")
	}
	if !strings.Contains(err.Error(), "server URL not configured") {
		t.Errorf("expected 'server URL not configured' in error, got: %v", err)
	}
}

// TestTokenCreateCmd_NoConfig verifies that token create returns an error when not configured.
func TestTokenCreateCmd_NoConfig(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--scope", "contents:read", "--repo", "owner/repo"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected 'not configured' in error, got: %v", err)
	}
}

// TestTokenCreateCmd_ProxyToken verifies that token create sends correct body and prints the token.
func TestTokenCreateCmd_ProxyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/tokens" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "proxy" {
			t.Errorf("expected type 'proxy', got %v", body["type"])
		}
		if body["repository"] != "owner/repo" {
			t.Errorf("expected repository 'owner/repo', got %v", body["repository"])
		}
		if body["scopes"] != "contents:read" {
			t.Errorf("expected scopes 'contents:read', got %v", body["scopes"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghx_testproxy",
			"type":       "proxy",
			"expires_at": "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--scope", "contents:read", "--repo", "owner/repo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "ghx_testproxy") {
		t.Errorf("expected token in output, got: %q", output)
	}
}

// TestTokenCreateCmd_AgentTokenMissingInstallation verifies that agent token creation requires --installation or --installation-id.
func TestTokenCreateCmd_AgentTokenMissingInstallation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to stub server: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--type", "agent", "--scope", "contents:read"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --installation is missing for agent token")
	}
	if !strings.Contains(err.Error(), "--installation") {
		t.Errorf("expected '--installation' in error, got: %v", err)
	}
}

// TestTokenCreateCmd_AgentToken verifies that a complete agent token request is sent to the server.
func TestTokenCreateCmd_AgentToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["type"] != "agent" {
			t.Errorf("expected type 'agent', got %v", body["type"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":        "gha_testagent",
			"type":         "agent",
			"repositories": []string{"owner/repo1", "owner/repo2"},
			"expires_at":   "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{
		"create",
		"--type", "agent",
		"--scope", "contents:read",
		"--repos", "owner/repo1,owner/repo2",
		"--installation-id", "12345",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create agent error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "gha_testagent") {
		t.Errorf("expected token in output, got: %q", output)
	}
}

// TestTokenCreateCmd_AppAndInstallationByName verifies end-to-end name-based resolution.
func TestTokenCreateCmd_AppAndInstallationByName(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/apps":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "app-uuid-1", "name": "mybot", "is_default": false},
				{"id": "app-uuid-2", "name": "otherbot", "is_default": true},
			})
		case r.Method == "GET" && r.URL.Path == "/api/apps/app-uuid-1/installations":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 100, "account": map[string]string{"login": "alpha-org"}},
				{"id": 200, "account": map[string]string{"login": "beta-org"}},
			})
		case r.Method == "POST" && r.URL.Path == "/api/tokens":
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "gha_resolved",
				"type":       "agent",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--app", "mybot", "--installation", "beta-org"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "gha_resolved") {
		t.Errorf("expected token in output, got: %q", output)
	}
	if gotBody["type"] != "agent" {
		t.Errorf("expected type 'agent', got %v", gotBody["type"])
	}
	if gotBody["app_record_id"] != "app-uuid-1" {
		t.Errorf("expected app_record_id 'app-uuid-1', got %v", gotBody["app_record_id"])
	}
	if instID, ok := gotBody["installation_id"].(float64); !ok || int64(instID) != 200 {
		t.Errorf("expected installation_id 200, got %v", gotBody["installation_id"])
	}
}

// TestTokenCreateCmd_InstallationOnlyDefaultApp verifies --installation auto-resolves the default app.
func TestTokenCreateCmd_InstallationOnlyDefaultApp(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/apps":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "app-uuid-1", "name": "mybot", "is_default": true},
				{"id": "app-uuid-2", "name": "otherbot", "is_default": false},
			})
		case r.Method == "GET" && r.URL.Path == "/api/apps/app-uuid-1/installations":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 42, "account": map[string]string{"login": "myorg"}},
			})
		case r.Method == "POST" && r.URL.Path == "/api/tokens":
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "gha_autoapp",
				"type":       "agent",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--installation", "myorg"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	if gotBody["type"] != "agent" {
		t.Errorf("expected type auto-inferred as 'agent', got %v", gotBody["type"])
	}
	if instID, ok := gotBody["installation_id"].(float64); !ok || int64(instID) != 42 {
		t.Errorf("expected installation_id 42, got %v", gotBody["installation_id"])
	}
}

// TestTokenCreateCmd_InstallationOnlySingleApp verifies --installation auto-resolves when only one app exists.
func TestTokenCreateCmd_InstallationOnlySingleApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/apps":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "sole-app", "name": "onlybot", "is_default": false},
			})
		case r.Method == "GET" && r.URL.Path == "/api/apps/sole-app/installations":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 99, "account": map[string]string{"login": "soleorg"}},
			})
		case r.Method == "POST" && r.URL.Path == "/api/tokens":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "gha_soleapp",
				"type":       "agent",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--installation", "soleorg"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	if !strings.Contains(buf.String(), "gha_soleapp") {
		t.Errorf("expected token in output, got: %q", buf.String())
	}
}

// TestTokenCreateCmd_AppNotFound verifies error message when app name doesn't match.
func TestTokenCreateCmd_AppNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/apps" {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "app-1", "name": "mybot", "is_default": true},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--app", "nonexistent", "--installation-id", "42"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when app name not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "mybot") {
		t.Errorf("expected available app names in error, got: %v", err)
	}
}

// TestTokenCreateCmd_InstallationNotFound verifies error message when installation login doesn't match.
func TestTokenCreateCmd_InstallationNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/apps":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "app-1", "name": "mybot", "is_default": true},
			})
		case r.URL.Path == "/api/apps/app-1/installations":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]string{"login": "alpha"}},
				{"id": 20, "account": map[string]string{"login": "beta"}},
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--installation", "nonexistent"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when installation not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "alpha") {
		t.Errorf("expected available installations in error, got: %v", err)
	}
}

// TestTokenCreateCmd_MutuallyExclusiveFlags verifies mutual exclusivity of name/ID flags.
func TestTokenCreateCmd_MutuallyExclusiveFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "app and app-id",
			args: []string{"create", "--app", "mybot", "--app-id", "some-uuid", "--installation-id", "42"},
			want: "--app and --app-id are mutually exclusive",
		},
		{
			name: "installation and installation-id",
			args: []string{"create", "--app", "mybot", "--installation", "myorg", "--installation-id", "42"},
			want: "--installation and --installation-id are mutually exclusive",
		},
		{
			name: "app with explicit proxy type",
			args: []string{"create", "--type", "proxy", "--app", "mybot", "--installation-id", "42"},
			want: "only valid for agent tokens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newTokenCmd()
			buf := &bytes.Buffer{}
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected %q in error, got: %v", tt.want, err)
			}
		})
	}
}

// TestTokenCreateCmd_AppWithDurationNever verifies creating a no-expiry app token via name flags.
func TestTokenCreateCmd_AppWithDurationNever(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/apps":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "app-1", "name": "mybot", "is_default": true},
			})
		case r.Method == "GET" && r.URL.Path == "/api/apps/app-1/installations":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 42, "account": map[string]string{"login": "myorg"}},
			})
		case r.Method == "POST" && r.URL.Path == "/api/tokens":
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "gha_neverexpires",
				"type":       "agent",
				"expires_at": nil,
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--app", "mybot", "--installation", "myorg", "--duration", "never"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	if gotBody["duration"] != "never" {
		t.Errorf("expected duration 'never', got %v", gotBody["duration"])
	}
	if !strings.Contains(buf.String(), "gha_neverexpires") {
		t.Errorf("expected token in output, got: %q", buf.String())
	}
}

// TestTokenCreateCmd_CaseInsensitiveAppMatch verifies that app name matching is case-insensitive.
func TestTokenCreateCmd_CaseInsensitiveAppMatch(t *testing.T) {
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/apps":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "app-1", "name": "MyBot", "is_default": true},
			})
		case r.Method == "GET" && r.URL.Path == "/api/apps/app-1/installations":
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 42, "account": map[string]string{"login": "MyOrg"}},
			})
		case r.Method == "POST" && r.URL.Path == "/api/tokens":
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "gha_casetest",
				"type":       "agent",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"create", "--app", "mybot", "--installation", "myorg"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token create error: %v", err)
	}
	if gotBody["app_record_id"] != "app-1" {
		t.Errorf("expected app_record_id 'app-1', got %v", gotBody["app_record_id"])
	}
}

// TestTokenListCmd verifies that token list calls the stub server and prints tokens.
func TestTokenListCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/tokens" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":           "11111111-1111-1111-1111-111111111111",
				"token_prefix": "ghx_abcd",
				"token_type":   "proxy",
				"repositories": []interface{}{"owner/repo"},
				"session_id":   "sess1",
				"expires_at":   "2099-01-01T00:00:00Z",
			},
		})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token list error: %v", err)
	}
	output := buf.String()
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected a header line and one data line, got: %q", output)
	}
	wantHeader := []string{"ID", "TYPE", "REPOS", "SCOPES", "SESSION", "EXPIRES"}
	if gotHeader := strings.Fields(lines[0]); !slices.Equal(gotHeader, wantHeader) {
		t.Errorf("expected header %v, got: %v", wantHeader, gotHeader)
	}
	fields := strings.Fields(lines[1])
	if len(fields) == 0 || fields[0] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("expected ID column to be the token id, got row: %q", lines[1])
	}
	if strings.Contains(output, "ghx_abcd") {
		t.Errorf("expected token prefix NOT to appear anywhere in output, got: %q", output)
	}
}

// TestTokenListCmd_Empty verifies that token list handles empty results gracefully.
func TestTokenListCmd_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"list"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token list error: %v", err)
	}
	if !strings.Contains(buf.String(), "No tokens found") {
		t.Errorf("expected 'No tokens found' in output, got: %q", buf.String())
	}
}

// TestTokenRevokeCmd verifies that token revoke calls the stub server and reports success.
func TestTokenRevokeCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/api/tokens/ghx_abcd" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"revoke", "ghx_abcd"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("token revoke error: %v", err)
	}
	if !strings.Contains(buf.String(), "ghx_abcd") {
		t.Errorf("expected token ID in output, got: %q", buf.String())
	}
}

// TestTokenRevokeCmd_ServerError verifies that token revoke reports errors from the server.
func TestTokenRevokeCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "token not found"})
	}))
	defer srv.Close()

	t.Setenv("GHP_SERVER_URL", srv.URL)
	t.Setenv("GHP_USER_TOKEN", "testtoken")
	t.Setenv("HOME", t.TempDir())

	cmd := newTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"revoke", "ghx_notexist"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when server returns non-200 status")
	}
}

// TestLoadCLIConfig_EnvVars verifies that environment variables take priority over the config file.
func TestLoadCLIConfig_EnvVars(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "http://env-server:8080")
	t.Setenv("GHP_USER_TOKEN", "env-token")
	t.Setenv("HOME", t.TempDir())

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://env-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "http://env-server:8080")
	}
	if cfg.UserToken != "env-token" {
		t.Errorf("UserToken: got %q, want %q", cfg.UserToken, "env-token")
	}
}

// TestLoadCLIConfig_Defaults verifies that loadCLIConfig returns empty strings when nothing is set.
func TestLoadCLIConfig_Defaults(t *testing.T) {
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")
	t.Setenv("HOME", t.TempDir())

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "" {
		t.Errorf("ServerURL: expected empty, got %q", cfg.ServerURL)
	}
	if cfg.UserToken != "" {
		t.Errorf("UserToken: expected empty, got %q", cfg.UserToken)
	}
}

// TestLoadCLIConfig_FromFile verifies that values are loaded from the YAML config file when env vars are unset.
func TestLoadCLIConfig_FromFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")

	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := "server_url: http://file-server:8080\nuser_token: file-token\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://file-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "http://file-server:8080")
	}
	if cfg.UserToken != "file-token" {
		t.Errorf("UserToken: got %q, want %q", cfg.UserToken, "file-token")
	}
}

// TestLoadCLIConfig_EnvVarsPriorityOverFile verifies that env vars win when both env vars and file are set.
func TestLoadCLIConfig_EnvVarsPriorityOverFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "http://env-server:8080")
	t.Setenv("GHP_USER_TOKEN", "env-token")

	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := "server_url: http://file-server:9090\nuser_token: file-token\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://env-server:8080" {
		t.Errorf("ServerURL: got %q, want env value %q", cfg.ServerURL, "http://env-server:8080")
	}
	if cfg.UserToken != "env-token" {
		t.Errorf("UserToken: got %q, want env value %q", cfg.UserToken, "env-token")
	}
}

// TestHelpOutput_AppToken verifies that "ghp apptoken --help" describes the command correctly.
func TestHelpOutput_AppToken(t *testing.T) {
	cmd := newAppTokenCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	_ = cmd.Execute()

	output := buf.String()
	for _, want := range []string{
		"installation-name",
		"installation access token",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("apptoken help: expected %q to appear in output:\n%s", want, output)
		}
	}
}

// TestAppTokenCmd_SingleInstallation verifies that apptoken auto-selects when there's one installation.
func TestAppTokenCmd_SingleInstallation(t *testing.T) {
	// Stub GitHub API: ListInstallations + CreateInstallationAccessToken.
	// go-github prepends /api/v3/ for non-api.github.com URLs (enterprise mode).
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/app/installations"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"id": 42,
					"account": map[string]interface{}{
						"login": "myorg",
						"id":    1,
						"type":  "Organization",
					},
					"permissions":          map[string]string{},
					"repository_selection": "all",
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/app/installations/42/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_testtoken123",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	// Write a config file pointing at the stub server.
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("apptoken error: %v", err)
	}
	if !strings.Contains(buf.String(), "ghs_testtoken123") {
		t.Errorf("expected token in output, got: %q", buf.String())
	}
}

// TestAppTokenCmd_ByName verifies that apptoken selects the correct installation by name.
func TestAppTokenCmd_ByName(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/app/installations"):
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]interface{}{"login": "alpha", "id": 1, "type": "Organization"}},
				{"id": 20, "account": map[string]interface{}{"login": "beta", "id": 2, "type": "Organization"}},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/app/installations/20/access_tokens"):
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_betatoken",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken", "beta"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("apptoken error: %v", err)
	}
	if !strings.Contains(buf.String(), "ghs_betatoken") {
		t.Errorf("expected token in output, got: %q", buf.String())
	}
}

// TestAppTokenCmd_MultipleInstallationsNoName verifies that apptoken errors when multiple installations exist and no name is given.
func TestAppTokenCmd_MultipleInstallationsNoName(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/app/installations") {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]interface{}{"login": "alpha", "id": 1, "type": "Organization"}},
				{"id": 20, "account": map[string]interface{}{"login": "beta", "id": 2, "type": "Organization"}},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghSrv.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when multiple installations and no name specified")
	}
	if !strings.Contains(err.Error(), "multiple installations") {
		t.Errorf("expected 'multiple installations' in error, got: %v", err)
	}
}

// TestAppTokenCmd_NotFound verifies that apptoken errors when installation name doesn't match.
func TestAppTokenCmd_NotFound(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/app/installations") {
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 10, "account": map[string]interface{}{"login": "alpha", "id": 1, "type": "Organization"}},
			})
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ghSrv.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "ghp.yaml")
	cfgContent := fmt.Sprintf("github:\n  app_id: 12345\n  private_key: |\n    %s\n  base_url: %s\n",
		strings.ReplaceAll(testRSAKeyForCmd, "\n", "\n    "), ghSrv.URL)
	os.WriteFile(cfgPath, []byte(cfgContent), 0600)

	rootCmd := newRootCmd()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", cfgPath, "apptoken", "nonexistent"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when installation name not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

// testRSAKeyForCmd is the same test-only RSA key used in github/app_test.go.
var testRSAKeyForCmd = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwUAwCT0ycvVRxvwAUe4RYLbAyPk2uEEpUJIb0VNvi9WWjPVl
AfRUGuvgnDSs46BbE+cnYSSG36xMDedASH2oH+p/mJb5vSgLpFjIkv/uX8XOmtZ6
jxOX5O12WtNgU2qpCX19UnDYipjY6YylePJ64eKP9XBGMOlGPHCXmFdDY6O+0uPw
wAd211IwT5PkhN/PixGiYpKAn7LvZ3je4Y1cmxRKw0A0CyTVKvG27PlA2jo+pTeK
St8cDa5L4vA6vkFqPqrFrAKa0te33Cu0Kkz6n3tx2DTeI+4pKQid+ze+125crynq
pvu5FMAkXCmVOLCaeHFMg2R+1qXQNoQ2v7QHdQIDAQABAoIBAE8KBjuZJIuhK4/T
nPvlf4ULaiEo0MkemZvDDo6YbgyG0LsZWPUqLcYPCIBLCRVWjjm/NruEGYfdLAQZ
u5CKmFtpaUOLKFzFxrEywOJiu+e++ygYJetj66Gtv9UZFBI6EyX3Be1UizRwnHM1
W65ymnDN3exYPdUea+QndtFPi5fx+JQGrVRzHDCzwBPvqMAebR+OaZ7p3OIAqlOI
Y+RWs/I3DQFXwdRpU1cSTv18/EEcbyOJN4fJv/jk77ntqkOW2tPoZlgOMvdZPqQC
K0DTZDKmfkZGUHwxaQtPR1jnxcx4rWVEFk2dxP5RBs8zUy8BrMwGVW3A5GfB3d2N
m6FNchcCgYEA4H3boVNV37ifGIZM00LV5F51tzRC4plDgnjznp5AZk/H9bJfC/I4
k+EN4VeGjg4jgfTQyEMHBXY6bpTnth7Xh7Yr44Qyji/j5JQFdAVA2ydFc5G95/Zk
LEhqnsnZ96qSQG8jKGrq5TmZumb13I2t22K+pYPbwl8MXgktB1Ck8ucCgYEA3F/S
fmmZkbJreYyubC/ZDidTxEcuVw0GVPtK2/ITi7R+YVqVg5JczBzlQIKGEJabtUrZ
0scS45b/87iw50mzRw0VvitNk/MQ4OJhMdBk1+RWK4m1udY/SQXEHKegO/LSIZbm
LkxR+eZywXVk50lJAyeuMolybxdej3XKvJaaQ0MCgYEAo6AYrYWoWeCfVajN5k4Y
yNNwyY/2EGPVqQuvxjViizArdxID5Rkv09l93HmHQZNcniRq6Qyx2XFLNb6jBUOF
pQ1LABIjJzAQ01JwhxgtJY+CN7JK0P/uE7jUvdgyXyqcXwqifZswitNpEUxqd89s
oTNf8hQh4ZKV2RSnFWXaVJECgYBVIJ7LPjeYVHe3yGRIXmNWWFK/a0+3SMy9XyUX
uXdbbCm1qaw/2vYF0tOsC7+GAOe9LGDgTw445EeS+jE75vhd5ewUPd4F3MsUU95/
w6Rw0T+IKfYNB3oC1zteZlI7Vh1d5FCeadTw19hUaujDf0e49EcSNo4B4+EfQb1D
BFoqyQKBgAJC8ejath862GxPQB9mpkuxwYR+Odp/Uz46xfyrSJrKb0BQrn9v6Kyd
lEYYwchE0C7L13qVoxEJN9U5XtgNERUpCQi3NCHwD8ADwpyAzQP57UBLS8Bb5ByC
xARUAV0AcnOf8WgFfswT1z7K4sJABdSBhP1URlo9YBW41+FAzQbm
-----END RSA PRIVATE KEY-----`

// TestLoadCLIConfig_InsecurePerms verifies that loadCLIConfig still loads config when file has insecure permissions.
func TestLoadCLIConfig_InsecurePerms(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GHP_SERVER_URL", "")
	t.Setenv("GHP_USER_TOKEN", "")

	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	configContent := "server_url: http://file-server:8080\nuser_token: file-token\n"
	// Write with insecure permissions (world-readable) to trigger the warning path.
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Config should still be loaded despite insecure permissions (the function warns but does not fail).
	cfg, err := loadCLIConfig()
	if err != nil {
		t.Fatalf("loadCLIConfig error: %v", err)
	}
	if cfg.ServerURL != "http://file-server:8080" {
		t.Errorf("ServerURL: got %q, want %q", cfg.ServerURL, "http://file-server:8080")
	}
	if cfg.UserToken != "file-token" {
		t.Errorf("UserToken: got %q, want %q", cfg.UserToken, "file-token")
	}
}
