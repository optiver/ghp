package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	otellog "go.opentelemetry.io/otel/log"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
)

func TestAccessLog(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("User-Agent", "git/2.40")
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	rec := exp.only(t)

	// Record-level fields.
	if rec.severity != otellog.SeverityInfo {
		t.Errorf("severity: got %v, want Info", rec.severity)
	}
	if rec.body != "handled request" {
		t.Errorf("body: got %q, want %q", rec.body, "handled request")
	}
	if rec.scope != "test" {
		t.Errorf("scope: got %q", rec.scope)
	}

	// HTTP semantic-convention attributes.
	if got := rec.int(t, attrHTTPResponseStatusCode); got != 200 {
		t.Errorf("%s: got %d, want 200", attrHTTPResponseStatusCode, got)
	}
	if got := rec.int(t, attrHTTPResponseBodySize); got != 5 {
		t.Errorf("%s: got %d, want 5", attrHTTPResponseBodySize, got)
	}
	if got := rec.float(t, attrHTTPServerRequestDuration); got <= 0 {
		t.Errorf("%s should be positive, got %v", attrHTTPServerRequestDuration, got)
	}
	if got := rec.str(t, attrHTTPRequestMethod); got != "GET" {
		t.Errorf("%s: got %q, want GET", attrHTTPRequestMethod, got)
	}
	if got := rec.str(t, attrServerAddress); got != "github.com" {
		t.Errorf("%s: got %q, want github.com", attrServerAddress, got)
	}
	if got := rec.str(t, attrURLPath); got != "/org/repo" {
		t.Errorf("%s: got %q, want /org/repo", attrURLPath, got)
	}
	if got := rec.str(t, attrClientAddress); got != "192.168.1.1" {
		t.Errorf("%s: got %q, want 192.168.1.1", attrClientAddress, got)
	}
	if got := rec.int(t, attrClientPort); got != 12345 {
		t.Errorf("%s: got %d, want 12345", attrClientPort, got)
	}
	if got := rec.str(t, attrNetworkProtocolVersion); got != "1.1" {
		t.Errorf("%s: got %q, want 1.1", attrNetworkProtocolVersion, got)
	}
	if got := rec.str(t, attrUserAgentOriginal); got != "git/2.40" {
		t.Errorf("%s: got %q, want git/2.40", attrUserAgentOriginal, got)
	}
	if got := rec.str(t, attrGHPBackend); got != backend.GitHub {
		t.Errorf("%s: got %q, want %q", attrGHPBackend, got, backend.GitHub)
	}

	// Request headers captured under http.request.header.*
	if ua := rec.slice(t, attrHTTPRequestHeaderPrefix+"user-agent"); len(ua) == 0 || ua[0] != "git/2.40" {
		t.Errorf("request user-agent header: got %v, want [git/2.40]", ua)
	}
}

func TestAccessLog_SensitiveHeadersRedacted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	if auth := rec.slice(t, attrHTTPRequestHeaderPrefix+"authorization"); len(auth) == 0 || auth[0] != "REDACTED" {
		t.Errorf("authorization header should be REDACTED, got %v", auth)
	}
	if cookie := rec.slice(t, attrHTTPRequestHeaderPrefix+"cookie"); len(cookie) == 0 || cookie[0] != "REDACTED" {
		t.Errorf("cookie header should be REDACTED, got %v", cookie)
	}
}

func TestAccessLog_ExtendedSensitiveRequestHeadersRedacted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.Header.Set("X-Auth-Token", "secret-auth")
	req.Header.Set("X-Api-Key", "secret-api-key")
	req.Header.Set("X-Access-Token", "secret-access-token")
	req.Header.Set("User-Agent", "git/2.40")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	for _, h := range []string{"x-auth-token", "x-api-key", "x-access-token"} {
		if v := rec.slice(t, attrHTTPRequestHeaderPrefix+h); len(v) == 0 || v[0] != "REDACTED" {
			t.Errorf("%s header should be REDACTED, got %v", h, v)
		}
	}
	// Non-sensitive headers should pass through.
	if ua := rec.slice(t, attrHTTPRequestHeaderPrefix+"user-agent"); len(ua) == 0 || ua[0] != "git/2.40" {
		t.Errorf("user-agent should not be redacted, got %v", ua)
	}
}

func TestAccessLog_SetCookieResponseHeaderRedacted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret; HttpOnly; Secure")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	if v := rec.slice(t, attrHTTPResponseHeaderPrefix+"set-cookie"); len(v) == 0 || v[0] != "REDACTED" {
		t.Errorf("set-cookie response header should be REDACTED, got %v", v)
	}
	// Non-sensitive response headers should pass through.
	if ct := rec.slice(t, attrHTTPResponseHeaderPrefix+"content-type"); len(ct) == 0 || ct[0] != "text/plain" {
		t.Errorf("content-type should not be redacted, got %v", ct)
	}
}

func TestAccessLog_UserIDFromSlot(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.SetUserID(r, "user-uuid-123")
		proxy.SetUsername(r, "alice")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.Mgmt, inner, aw, false)

	req := httptest.NewRequest("GET", "http://ghp.example.com/admin", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	// enduser.id should prefer the GitHub username over the internal UUID.
	if got := rec.str(t, attrEndUserID); got != "alice" {
		t.Errorf("%s: got %q, want alice", attrEndUserID, got)
	}
}

func TestAccessLog_UserIDFallsBackToUUIDWhenUsernameEmpty(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only set user ID (no username) — simulates requests where
		// only the internal UUID is known.
		proxy.SetUserID(r, "user-uuid-456")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.Mgmt, inner, aw, false)

	req := httptest.NewRequest("GET", "http://ghp.example.com/admin", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	// enduser.id should fall back to the internal UUID when no username is set.
	if got := rec.str(t, attrEndUserID); got != "user-uuid-456" {
		t.Errorf("%s: got %q, want user-uuid-456", attrEndUserID, got)
	}
}

func TestAccessLog_UserIDFallsBackToUsername(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only set username (no user ID) — simulates proxy requests
		// where only the GitHub username is resolved.
		proxy.SetUsername(r, "alice")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.API, inner, aw, false)

	req := httptest.NewRequest("GET", "http://api.github.com/repos/org/repo", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	// enduser.id should fall back to the username when no user ID is set.
	if got := rec.str(t, attrEndUserID); got != "alice" {
		t.Errorf("%s: got %q, want alice", attrEndUserID, got)
	}
}

func TestAccessLog_ErrorLevel(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/error", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	rec := exp.only(t)

	if rec.severity != otellog.SeverityError {
		t.Errorf("severity: got %v, want Error for 500 status", rec.severity)
	}
	if got := rec.int(t, attrHTTPResponseStatusCode); got != 500 {
		t.Errorf("%s: got %d, want 500", attrHTTPResponseStatusCode, got)
	}
}

func getClientRequestCount(t *testing.T, labels prometheus.Labels) float64 {
	t.Helper()
	c, err := metrics.ClientRequestTotal.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	var m io_prometheus_client.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestAccessLog_ClientRequestMetric(t *testing.T) {
	logger, _ := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.SetTokenType(r, "proxy")
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.API, inner, aw, false)

	req := httptest.NewRequest("GET", "http://api.github.com/repos/org/repo", nil)
	req.RemoteAddr = "192.168.1.50:33000"
	rr := httptest.NewRecorder()

	labels := prometheus.Labels{
		"client":     "192.168.1.50",
		"backend":    backend.API,
		"token_type": "proxy",
		"status":     "200",
	}
	before := getClientRequestCount(t, labels)
	handler.ServeHTTP(rr, req)
	after := getClientRequestCount(t, labels)

	if after-before != 1 {
		t.Errorf("expected client request counter to increment by 1, got %f", after-before)
	}
}

func TestAccessLog_ClientRequestMetric_UnknownTokenType(t *testing.T) {
	logger, _ := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.RemoteAddr = "192.168.1.51:33001"
	rr := httptest.NewRecorder()

	labels := prometheus.Labels{
		"client":     "192.168.1.51",
		"backend":    backend.GitHub,
		"token_type": "unknown",
		"status":     "404",
	}
	before := getClientRequestCount(t, labels)
	handler.ServeHTTP(rr, req)
	after := getClientRequestCount(t, labels)

	if after-before != 1 {
		t.Errorf("expected client request counter to increment by 1, got %f", after-before)
	}
}

func TestAccessLog_ForwardedHeaderIgnoredWhenUntrusted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, false)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.RemoteAddr = "192.168.1.60:44000"
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	rr := httptest.NewRecorder()

	labels := prometheus.Labels{
		"client":     "192.168.1.60",
		"backend":    backend.GitHub,
		"token_type": "unknown",
		"status":     "200",
	}
	before := getClientRequestCount(t, labels)
	handler.ServeHTTP(rr, req)
	after := getClientRequestCount(t, labels)

	if after-before != 1 {
		t.Errorf("expected client request counter to increment by 1, got %f", after-before)
	}

	rec := exp.only(t)
	if got := rec.str(t, attrClientAddress); got != "192.168.1.60" {
		t.Errorf("%s: got %q, want 192.168.1.60", attrClientAddress, got)
	}
	if got := rec.int(t, attrClientPort); got != 44000 {
		t.Errorf("%s: got %d, want 44000", attrClientPort, got)
	}
}

func TestAccessLog_ForwardedHeaderHonouredWhenTrusted(t *testing.T) {
	logger, exp := newCaptureLogger(t)
	aw := newAccessLogWriter(logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := accessLogHandler(backend.GitHub, inner, aw, true)

	req := httptest.NewRequest("GET", "http://github.com/org/repo", nil)
	req.RemoteAddr = "192.168.1.61:44001"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 10.8.8.8")
	rr := httptest.NewRecorder()

	labels := prometheus.Labels{
		"client":     "10.8.8.8",
		"backend":    backend.GitHub,
		"token_type": "unknown",
		"status":     "200",
	}
	before := getClientRequestCount(t, labels)
	handler.ServeHTTP(rr, req)
	after := getClientRequestCount(t, labels)

	if after-before != 1 {
		t.Errorf("expected client request counter to increment by 1, got %f", after-before)
	}

	rec := exp.only(t)
	if got := rec.str(t, attrClientAddress); got != "10.8.8.8" {
		t.Errorf("%s: got %q, want 10.8.8.8", attrClientAddress, got)
	}
	if rec.has(attrClientPort) {
		t.Errorf("%s should be omitted when client address comes from a forwarded header", attrClientPort)
	}
}
