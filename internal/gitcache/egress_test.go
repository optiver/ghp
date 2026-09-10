package gitcache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/goodtune/ghp/internal/egress"
)

func TestGoGitFetchUsesSelectedProxy(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("REQUEST_METHOD", "")
	var counts [2]atomic.Int32
	var proxies []egress.Proxy
	for i := range 2 {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counts[i].Add(1)
			if r.URL.Host != "git.example.com" || r.URL.Path != "/org/repo.git/info/refs" {
				t.Errorf("unexpected git destination: %s", r.URL)
			}
			if user, password, ok := r.BasicAuth(); !ok || user != "x-access-token" || password != "ghs_git" {
				t.Error("git authentication lost")
			}
			if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
				t.Error("proxy authentication lost")
			}
			// A protocol failure must still release the complete fetch reservation.
			http.Error(w, "not a repository", http.StatusNotFound)
		}))
		t.Cleanup(s.Close)
		u, _ := url.Parse(s.URL)
		u.User = url.UserPassword("user", "pass")
		proxies = append(proxies, egress.Proxy{Name: []string{"a", "b"}[i], URL: u.String()})
	}
	pool, err := egress.New(egress.Config{Strategy: egress.LeastConnections, Proxies: proxies})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.CloseIdleConnections()
	u, _ := url.Parse("http://git.example.com/org/repo.git")
	m, err := openManagedRepository("org", "repo", u, memory.NewStorage())
	if err != nil {
		t.Fatal(err)
	}
	m.egress = pool
	for range 4 {
		err := m.FetchUpstream(context.Background(), "ghs_git")
		if err == nil || strings.Contains(err.Error(), "pass") {
			t.Fatalf("missing or unsafe error: %v", err)
		}
	}
	if counts[0].Load() != 2 || counts[1].Load() != 2 {
		t.Fatalf("go-git did not balance fetches: %d/%d", counts[0].Load(), counts[1].Load())
	}
}
