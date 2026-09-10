package github

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/database"
)

type outboundTransport func(*http.Request) (*http.Response, error)

func (f outboundTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegistryTransportSurvivesReloadAndCoversSDK(t *testing.T) {
	r := newTestRegistry([]*database.App{makeApp("app", "Test App", 1, true)})
	counts := map[string]int{}
	transport := outboundTransport(func(req *http.Request) (*http.Response, error) {
		counts[req.URL.Path]++
		if req.Header.Get("Authorization") == "" {
			t.Error("missing GitHub authentication")
		}
		body, status := "", http.StatusOK
		switch req.URL.Path {
		case "/app/installations":
			body = `[]`
		case "/app/installations/1/access_tokens":
			body = `{"token":"ghs_installation","expires_at":"2099-01-01T00:00:00Z"}`
			status = http.StatusCreated
		case "/installation/repositories":
			body = `{"total_count":1,"repositories":[{"full_name":"org/repo","name":"repo"}]}`
		default:
			t.Errorf("unexpected request: %s", req.URL)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	r.SetTransport(transport)
	ctx := context.Background()
	for _, load := range []func(context.Context) error{r.LoadAll, r.Reload} {
		if err := load(ctx); err != nil {
			t.Fatal(err)
		}
		p, err := r.GetDefault()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.ListInstallations(ctx); err != nil {
			t.Fatal(err)
		}
		repos, err := p.ListInstallationRepositories(ctx, 1)
		if err != nil || len(repos) != 1 || repos[0].FullName != "org/repo" {
			t.Fatalf("repos=%v err=%v", repos, err)
		}
	}
	for _, path := range []string{"/app/installations", "/app/installations/1/access_tokens", "/installation/repositories"} {
		if counts[path] != 2 {
			t.Errorf("%s bypassed transport: %d requests", path, counts[path])
		}
	}
}
