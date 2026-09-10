package auth

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/config"
)

type outboundTransport func(*http.Request) (*http.Response, error)

func (f outboundTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOAuthTransportAndContext(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "routing metadata")
	h := NewHandler(config.Defaults(), nil, nil, slog.Default())
	var paths []string
	h.SetTransport(outboundTransport(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		if r.Context().Value(contextKey{}) != "routing metadata" {
			t.Error("OAuth lost caller context")
		}
		body := `{"access_token":"gho_test","expires_in":28800}`
		if r.URL.Path == "/user" {
			body = `{"id":1,"login":"alice"}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}))
	token, _, _, err := h.exchangeCode(ctx, "code", "https://ghp.example.com/callback")
	if err != nil {
		t.Fatal(err)
	}
	user, err := h.getGitHubUser(ctx, token)
	if err != nil || user.Login != "alice" || len(paths) != 2 {
		t.Fatalf("OAuth flow failed: user=%v paths=%v err=%v", user, paths, err)
	}
}
