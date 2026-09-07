package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestEnterpriseLoginQuery(t *testing.T) {
	tests := []struct {
		name, query string
		allow       bool
	}{
		{"gh login", `query UserCurrent{viewer{login}}`, true},
		{"anonymous query", `{ viewer { login } }`, true},
		{"comments", "query UserCurrent { # current account\n viewer { login } }", true},
		{"safe aliases", `{ account: viewer { username: login } }`, true},
		{"repository", `{ repository(owner:"optiver",name:"ghp") { name } }`, false},
		{"mixed repository", `{ viewer { login } repository(owner:"other",name:"repo") { name } }`, false},
		{"viewer repositories", `{ viewer { login repositories(first:1) { nodes { name } } } }`, false},
		{"viewer organizations", `{ viewer { login organizations(first:1) { nodes { login } } } }`, false},
		{"extra profile fields", `{ viewer { login email } }`, false},
		{"aliased other root", `{ viewer: user(login:"someone") { login } }`, false},
		{"aliased other field", `{ viewer { login: email } }`, false},
		{"mutation", `mutation { viewer { login } }`, false},
		{"subscription", `subscription { viewer { login } }`, false},
		{"multiple operations", `query Login { viewer { login } } query Other { viewer { email } }`, false},
		{"fragment", `query { viewer { ...Identity } } fragment Identity on User { login }`, false},
		{"unused fragment", `{ viewer { login } } fragment Extra on User { email }`, false},
		{"inline fragment", `{ viewer { ... on User { login } } }`, false},
		{"directive", `{ viewer @skip(if:true) { login } }`, false},
		{"operation directive", `query Login @skip(if:true) { viewer { login } }`, false},
		{"leaf directive", `{ viewer { login @skip(if:true) } }`, false},
		{"arguments", `{ viewer(login:"someone") { login } }`, false},
		{"leaf arguments", `{ viewer { login(format:"x") } }`, false},
		{"leaf selection", `{ viewer { login { email } } }`, false},
		{"variable definition", `query Login($unused: String) { viewer { login } }`, false},
		{"introspection", `{ __schema { queryType { name } } }`, false},
		{"malformed", `{ viewer { login }`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(graphQLRequestBody{Query: tt.query})
			if err != nil {
				t.Fatal(err)
			}
			if got := isEnterpriseLoginQuery(body); got != tt.allow {
				t.Fatalf("allowed = %v, want %v", got, tt.allow)
			}
		})
	}
}

func TestEnterpriseLoginEnvelope(t *testing.T) {
	for _, body := range []string{
		`{"query":"query Login{viewer{login}}","operationName":"Login","variables":{}}`,
		`{"query":"{viewer{login}}","operationName":null,"variables":null}`,
	} {
		if !isEnterpriseLoginQuery([]byte(body)) {
			t.Errorf("rejected valid envelope %s", body)
		}
	}
	for _, body := range []string{
		`{"query":"{viewer{login}}","query":"{viewer{email}}"}`,
		`{"query":"{viewer{email}}","query":"{viewer{login}}"}`,
		`{"query":"{viewer{login}}","Query":"{viewer{email}}"}`,
		`{"Query":"{viewer{login}}"}`,
		`{"query":"query Login{viewer{login}}","operationName":"Other"}`,
		`{"query":"{viewer{login}}","operationName":7}`,
		`{"query":"{viewer{login}}","extensions":{"persistedQuery":{}}}`,
		`{"query":"{viewer{login}}"} {"query":"{viewer{email}}"}`,
		`[{"query":"{viewer{login}}"}]`,
		`{"query":null}`,
		`{"query":123}`,
		`null`,
		`{}`,
		`{"query":"{viewer{login}}"`,
	} {
		if isEnterpriseLoginQuery([]byte(body)) {
			t.Errorf("accepted ambiguous/unsupported envelope %s", body)
		}
	}
}

func TestServeHTTP_EnterpriseLogin(t *testing.T) {
	const login = `{"query":"query UserCurrent{viewer{login}}"}`
	tests := []struct {
		name, method, path, body string
		noAuth, noExceptions     bool
		contentType, encoding    string
		omit                     bool
	}{
		{name: "browser login", method: "POST", path: "/graphql", body: login, omit: true},
		{name: "GHE route", method: "POST", path: "/api/graphql", body: login, omit: true},
		{name: "scope validation", method: "GET", path: "/", omit: true},
		{name: "GHE scope validation", method: "GET", path: "/api/v3/", omit: true},
		{name: "no exceptions", method: "POST", path: "/graphql", body: login, noExceptions: true},
		{name: "no scope exceptions", method: "GET", path: "/", noExceptions: true},
		{name: "anonymous login", method: "POST", path: "/graphql", body: login, noAuth: true},
		{name: "anonymous root", method: "GET", path: "/", noAuth: true},
		{name: "REST identity remains restricted", method: "GET", path: "/user"},
		{name: "user repos remain restricted", method: "GET", path: "/user/repos"},
		{name: "excepted REST repo", method: "GET", path: "/repos/optiver/ghp", omit: true},
		{name: "other REST repo", method: "GET", path: "/repos/other/repo"},
		{name: "mixed GraphQL query", method: "POST", path: "/graphql", body: `{"query":"{viewer{login email}}"}`},
		{name: "GET GraphQL", method: "GET", path: "/graphql", body: login},
		{name: "wrong content type", method: "POST", path: "/graphql", body: login, contentType: "application/graphql"},
		{name: "JSON charset", method: "POST", path: "/graphql", body: login, contentType: "application/json; charset=utf-8", omit: true},
		{name: "encoded body", method: "POST", path: "/graphql", body: login, encoding: "gzip"},
		{name: "URL query", method: "POST", path: "/graphql?query=other", body: login},
		{name: "root query", method: "GET", path: "/?query=other"},
		{name: "root body", method: "GET", path: "/", body: login},
		{name: "root write", method: "POST", path: "/"},
		{name: "malformed body", method: "POST", path: "/graphql", body: "{"},
		{name: "oversized body preserved", method: "POST", path: "/graphql", body: login + strings.Repeat(" ", maxEnterpriseLoginBodyBytes*2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := config.GitHubConfig{EnterpriseSlug: "my-enterprise"}
			if !tt.noExceptions {
				gh.EnterpriseExceptions = []config.EnterpriseException{{Match: []string{"optiver"}}}
			}
			ct := &captureTransport{responseHeaders: http.Header{"X-Oauth-Scopes": {"repo, read:org"}}}
			h := &Handler{
				cfg: &config.Config{GitHub: gh}, logger: slog.Default(),
				client: &http.Client{Transport: ct}, enterprise: NewEnterprisePolicy(gh, nil, slog.Default()),
			}
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, "http://api.github.com"+tt.path, body)
			req.Header.Set("Content-Type", "application/json")
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			req.Header.Set("Content-Encoding", tt.encoding)
			// Caller-supplied enterprise headers cannot change the decision.
			req.Header.Set(enterpriseHeader, "client-supplied")
			if !tt.noAuth {
				req.Header.Set("Authorization", "Bearer gho_external")
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK || ct.lastReq == nil {
				t.Fatalf("not forwarded: %d %s", rr.Code, rr.Body.String())
			}
			wantHeader := "my-enterprise"
			if tt.omit {
				wantHeader = ""
			}
			if got := ct.lastReq.Header.Get(enterpriseHeader); got != wantHeader {
				t.Errorf("enterprise header = %q, want %q", got, wantHeader)
			}
			if got := ct.lastReq.Header.Get("Authorization"); got != req.Header.Get("Authorization") {
				t.Error("caller credential changed")
			}
			if got := rr.Header().Get("X-OAuth-Scopes"); got != "repo, read:org" {
				t.Errorf("scope validation header lost: %q", got)
			}
			if ct.lastReq.Body != nil {
				got, err := io.ReadAll(ct.lastReq.Body)
				ct.lastReq.Body.Close()
				if err != nil || string(got) != tt.body {
					t.Errorf("forwarded body changed: %q, error: %v", got, err)
				}
			}
		})
	}
}

func TestEnterpriseLogin_PolicyGatesAndMetrics(t *testing.T) {
	for _, tt := range []struct {
		name string
		exc  config.EnterpriseException
		omit bool
	}{
		{"invalid match", config.EnterpriseException{Match: []string{"bad/path/entry"}}, false},
		{"invalid team", config.EnterpriseException{Match: []string{"optiver"}, Teams: []string{"bad"}}, false},
		{"team gated", config.EnterpriseException{Match: []string{"optiver"}, Teams: []string{"org/team"}}, true},
		{"managed identity", config.EnterpriseException{Match: []string{"optiver"}, Identity: config.EnterpriseExceptionIdentity{AppRecordID: "app-1"}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gh := config.GitHubConfig{EnterpriseSlug: "enterprise", EnterpriseExceptions: []config.EnterpriseException{tt.exc}}
			src := &fakeIdentitySource{token: "ghs_managed"}
			p := NewEnterprisePolicy(gh, src, slog.Default())
			r := httptest.NewRequest("POST", "https://api.github.com/graphql", strings.NewReader(`{"query":"{viewer{login}}"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer gho_external")
			labels := prometheus.Labels{"outcome": "auth_header_omitted"}
			before := getCounterValue(t, metrics.EnterpriseExceptionTotal, labels)
			got := p.ApplyAPI(r, func(_ context.Context) string {
				t.Fatal("login must not require an identity lookup or team check")
				return ""
			}, "")
			if got != "" || len(src.calls) != 0 {
				t.Fatal("login must not substitute a managed credential")
			}
			if (r.Header.Get(enterpriseHeader) == "") != tt.omit {
				t.Fatalf("unexpected enterprise header: %q", r.Header.Get(enterpriseHeader))
			}
			wantDelta := float64(0)
			if tt.omit {
				wantDelta = 1
			}
			if delta := getCounterValue(t, metrics.EnterpriseExceptionTotal, labels) - before; delta != wantDelta {
				t.Errorf("auth metric delta = %v, want %v", delta, wantDelta)
			}
		})
	}
}

func TestServeHTTP_EnterpriseLogin_PreservesTokenRestrictions(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(fmt.Sprint("repo scoped=", scoped), func(t *testing.T) {
			repo := ""
			if scoped {
				repo = "optiver/ghp"
			}
			h, tok, ct := newScopedHandlerWithTransport(t, repo, nil)
			h.SetEnterprisePolicy(NewEnterprisePolicy(config.GitHubConfig{
				EnterpriseSlug: "enterprise", EnterpriseExceptions: []config.EnterpriseException{{Match: []string{"optiver"}}},
			}, nil, slog.Default()))
			r := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`{"query":"{viewer{login}}"}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if scoped {
				if rr.Code != http.StatusForbidden || ct.lastReq != nil {
					t.Fatalf("repository scope bypassed: %d", rr.Code)
				}
			} else if rr.Code != http.StatusOK || ct.lastReq.Header.Get(enterpriseHeader) != "" {
				t.Fatalf("resolved credential login failed: %d", rr.Code)
			}
		})
	}
	// Border policy still runs before login exceptions.
	h := &Handler{cfg: &config.Config{Block: config.BlockConfig{GHO: true}}}
	r := httptest.NewRequest("POST", "http://api.github.com/graphql", strings.NewReader(`{"query":"{viewer{login}}"}`))
	r.Header.Set("Authorization", "Bearer gho_external")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("border policy bypassed: %d", rr.Code)
	}
}

type failingLoginBody struct{ closed bool }

func (*failingLoginBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (b *failingLoginBody) Close() error           { b.closed = true; return nil }

func TestEnterpriseLogin_BodyReadError(t *testing.T) {
	body := &failingLoginBody{}
	r := httptest.NewRequest("POST", "https://api.github.com/graphql", nil)
	r.Body = body
	r.Header.Set("Authorization", "Bearer gho_external")
	r.Header.Set("Content-Type", "application/json")
	if isEnterpriseLoginRequest(r) {
		t.Fatal("read failure must not exempt request")
	}
	r.Body.Close()
	if !body.closed {
		t.Fatal("original body was not closed")
	}
}
