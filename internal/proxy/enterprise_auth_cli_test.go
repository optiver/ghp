package proxy

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/config"
)

type loginCLITransport struct{}

func (loginCLITransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get(enterpriseHeader) != "" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"enterprise restriction"}`)
	} else if r.URL.Path == "/graphql" {
		fmt.Fprint(w, `{"data":{"viewer":{"login":"external-user"}}}}`)
	} else if r.URL.Path == "/" {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org, gist")
		fmt.Fprint(w, `{}`)
	} else {
		return nil, fmt.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
	}
	return w.Result(), nil
}

// Exercise the installed GitHub CLI when available, using only local servers,
// a fake credential and isolated config. No real account or browser is used.
func TestEnterpriseLogin_GitHubCLI(t *testing.T) {
	gh, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("GitHub CLI is not installed")
	}
	for _, mode := range []string{"--web", "--with-token"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{GitHub: config.GitHubConfig{
				EnterpriseSlug: "enterprise", EnterpriseExceptions: []config.EnterpriseException{{Match: []string{"optiver"}}},
			}}
			h := &Handler{cfg: cfg, logger: slog.Default(), client: &http.Client{Transport: loginCLITransport{}}, enterprise: NewEnterprisePolicy(cfg.GitHub, nil, slog.Default())}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Device-flow endpoints exchange the fixture credential. The
				// API requests go through the production enterprise policy.
				switch r.URL.Path {
				case "/login/device/code":
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"device_code":"fixture","user_code":"FIXTURE","verification_uri":"https://example.test/device","expires_in":60,"interval":1}`)
				case "/login/oauth/access_token":
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, `{"access_token":"gho_fixture","token_type":"bearer","scope":"repo,read:org,gist"}`)
				default:
					h.ServeHTTP(w, r)
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			certPath := filepath.Join(dir, "ca.pem")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			// gh rejects hostnames with ports. Tunnel its fixture hostname to
			// the local TLS listener; unexpected destinations are rejected.
			host := server.Certificate().DNSNames[0]
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.Host != host+":443" {
					http.Error(w, "unexpected proxy target", http.StatusForbidden)
					return
				}
				upstream, err := net.Dial("tcp", server.Listener.Addr().String())
				if err != nil {
					t.Error(err)
					return
				}
				defer upstream.Close()
				client, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer client.Close()
				fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
				rw.Flush()
				go io.Copy(upstream, rw)
				io.Copy(client, upstream)
			}))
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, gh, "auth", "login", "--hostname", host, "--git-protocol", "https", "--insecure-storage", mode)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				switch key {
				case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GH_CONFIG_DIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_CONFIG_GLOBAL", "GH_DEBUG", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy":
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "GH_CONFIG_DIR="+dir, "SSL_CERT_FILE="+certPath, "SSL_CERT_DIR="+dir, "GIT_CONFIG_GLOBAL="+filepath.Join(dir, "gitconfig"), "HTTPS_PROXY="+proxy.URL)
			if mode == "--with-token" {
				cmd.Stdin = strings.NewReader("gho_fixture\n")
			}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("GitHub CLI login failed: %v\n%s", err, output)
			}
			lookup := exec.CommandContext(ctx, gh, "auth", "token", "--hostname", host, "--user", "external-user")
			lookup.Env = cmd.Env
			if output, err := lookup.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "gho_fixture" {
				t.Fatalf("fixture account was not saved: %v\n%s", err, output)
			}
		})
	}
}
