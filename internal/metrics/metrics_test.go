package metrics

import (
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

func getCounterValue(t *testing.T, counter *prometheus.CounterVec, labels prometheus.Labels) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	c, err := counter.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestObserveProxyRequest_REST(t *testing.T) {
	userID := "testuser"
	pt := &database.ProxyToken{
		TokenType: "ghx",
		UserID:    &userID,
	}

	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "ghx",
		"type":       "rest",
		"user":       "testuser",
		"app":        "",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("api.github.com", pt, "GET", 200, 100*time.Millisecond, "rest", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_GraphQL(t *testing.T) {
	userID := "testuser"
	pt := &database.ProxyToken{
		TokenType: "ghx",
		UserID:    &userID,
	}

	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "POST",
		"status":     "200",
		"token_type": "ghx",
		"type":       "graphql",
		"user":       "testuser",
		"app":        "",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("api.github.com", pt, "POST", 200, 50*time.Millisecond, "graphql", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_Git(t *testing.T) {
	userID := "testuser"
	pt := &database.ProxyToken{
		TokenType: "ghx",
		UserID:    &userID,
	}

	labels := prometheus.Labels{
		"backend":    "github.com",
		"method":     "POST",
		"status":     "200",
		"token_type": "ghx",
		"type":       "git",
		"user":       "testuser",
		"app":        "",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("github.com", pt, "POST", 200, 200*time.Millisecond, "git", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_WithInstallationID(t *testing.T) {
	userID := "testuser"
	installID := int64(12345)
	pt := &database.ProxyToken{
		TokenType:      "gha",
		UserID:         &userID,
		InstallationID: &installID,
	}

	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "gha",
		"type":       "rest",
		"user":       "testuser",
		"app":        "12345",
	}

	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObserveProxyRequest("api.github.com", pt, "GET", 200, 100*time.Millisecond, "rest", "testuser")
	after := getCounterValue(t, ProxyRequestTotal, labels)

	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveProxyRequest_NilPt(t *testing.T) {
	// Should not panic.
	ObserveProxyRequest("api.github.com", nil, "GET", 200, 100*time.Millisecond, "rest", "")
}

func getHistogramCount(t *testing.T, h *prometheus.HistogramVec, labels prometheus.Labels) uint64 {
	t.Helper()
	var m io_prometheus_client.Metric
	obs, err := h.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if err := obs.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

func TestObserveDecision_AllStages(t *testing.T) {
	stages := []string{
		StageTotal,
		StageTokenExtraction,
		StageBorderPolicyCheck,
		StageTokenResolution,
		StageUsernameResolution,
		StageScopeParsing,
		StageScopeEnforcement,
		StageGitHubTokenResolution,
		StageUpstreamRoundtrip,
		StageRedirectHeadCheck,
		StageCacheLookup,
		StageGraphQLAnalysis,
	}

	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			labels := prometheus.Labels{
				"stage":      stage,
				"token_type": "proxy",
			}
			before := getHistogramCount(t, ProxyDecisionDuration, labels)
			ObserveDecision(stage, "proxy", 1*time.Millisecond)
			after := getHistogramCount(t, ProxyDecisionDuration, labels)
			if after-before != 1 {
				t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
			}
		})
	}
}

func TestObserveDecision_EmptyTokenType(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageTokenExtraction,
		"token_type": "unknown",
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(StageTokenExtraction, "", 500*time.Microsecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
	}
}

func getGaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	if err := g.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

func getCounterValueSimple(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m io_prometheus_client.Metric
	if err := c.(prometheus.Metric).Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestBlockAnonymousGitEnabled_Gauge(t *testing.T) {
	BlockAnonymousGitEnabled.Set(1)
	if got := getGaugeValue(t, BlockAnonymousGitEnabled); got != 1 {
		t.Errorf("expected gauge value 1, got %f", got)
	}
	BlockAnonymousGitEnabled.Set(0)
	if got := getGaugeValue(t, BlockAnonymousGitEnabled); got != 0 {
		t.Errorf("expected gauge value 0, got %f", got)
	}
}

func TestBlockAnonymousGitTotal_Counter(t *testing.T) {
	before := getCounterValueSimple(t, BlockAnonymousGitTotal)
	BlockAnonymousGitTotal.Inc()
	after := getCounterValueSimple(t, BlockAnonymousGitTotal)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestReleasesRedirectHeadCheckTotal(t *testing.T) {
	results := []string{"found", "not_found", "error"}
	for _, result := range results {
		t.Run(result, func(t *testing.T) {
			labels := prometheus.Labels{"result": result}
			before := getCounterValue(t, ReleasesRedirectHeadCheckTotal, labels)
			ReleasesRedirectHeadCheckTotal.WithLabelValues(result).Inc()
			after := getCounterValue(t, ReleasesRedirectHeadCheckTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestEnterpriseExceptionTotal(t *testing.T) {
	outcomes := []string{"header_omitted", "identity_substituted", "team_denied", "unauthenticated_denied", "identity_error"}
	for _, outcome := range outcomes {
		t.Run(outcome, func(t *testing.T) {
			labels := prometheus.Labels{"outcome": outcome}
			before := getCounterValue(t, EnterpriseExceptionTotal, labels)
			EnterpriseExceptionTotal.WithLabelValues(outcome).Inc()
			after := getCounterValue(t, EnterpriseExceptionTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestCodeloadRedirectTotal(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		repo    string
		archive string
		result  string
	}{
		{"redirect tar.gz", "actions", "checkout", "tar.gz", "redirect"},
		{"redirect zip", "actions", "checkout", "zip", "redirect"},
		{"passthrough legacy.tar.gz", "goodtune", "ghp", "legacy.tar.gz", "passthrough"},
		{"passthrough legacy.zip", "goodtune", "ghp", "legacy.zip", "passthrough"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := prometheus.Labels{
				"owner":   tt.owner,
				"repo":    tt.repo,
				"archive": tt.archive,
				"result":  tt.result,
			}
			before := getCounterValue(t, CodeloadRedirectTotal, labels)
			CodeloadRedirectTotal.WithLabelValues(tt.owner, tt.repo, tt.archive, tt.result).Inc()
			after := getCounterValue(t, CodeloadRedirectTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestObserveDecision_RedirectHeadCheck(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageRedirectHeadCheck,
		"token_type": "unknown",
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(StageRedirectHeadCheck, "", 10*time.Millisecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
	}
}

func TestObserveClientRequest(t *testing.T) {
	labels := prometheus.Labels{
		"client":     "10.1.2.3",
		"backend":    "api.github.com",
		"token_type": "proxy",
		"status":     "200",
	}
	before := getCounterValue(t, ClientRequestTotal, labels)
	ObserveClientRequest("10.1.2.3", "api.github.com", "proxy", 200)
	after := getCounterValue(t, ClientRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObserveClientRequest_UnknownDefaults(t *testing.T) {
	labels := prometheus.Labels{
		"client":     "unknown",
		"backend":    "github.com",
		"token_type": "unknown",
		"status":     "404",
	}
	before := getCounterValue(t, ClientRequestTotal, labels)
	ObserveClientRequest("", "github.com", "", 404)
	after := getCounterValue(t, ClientRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObservePassthroughRequest(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
		wantType  string
	}{
		{"gho", "gho", "gho"},
		{"ghp", "ghp", "ghp"},
		{"ghu", "ghu", "ghu"},
		{"ghs", "ghs", "ghs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := prometheus.Labels{
				"backend":    "api.github.com",
				"method":     "GET",
				"status":     "200",
				"token_type": tt.wantType,
				"type":       "rest",
				"user":       "testuser",
				"app":        "",
			}
			before := getCounterValue(t, ProxyRequestTotal, labels)
			ObservePassthroughRequest("api.github.com", "GET", 200, 100*time.Millisecond, "rest", tt.tokenType, "testuser")
			after := getCounterValue(t, ProxyRequestTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestObservePassthroughRequest_UnknownUser(t *testing.T) {
	labels := prometheus.Labels{
		"backend":    "github.com",
		"method":     "POST",
		"status":     "200",
		"token_type": "gho",
		"type":       "git",
		"user":       "unknown",
		"app":        "",
	}
	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObservePassthroughRequest("github.com", "POST", 200, 100*time.Millisecond, "git", "gho", "")
	after := getCounterValue(t, ProxyRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestObservePassthroughRequest_UnknownTokenType(t *testing.T) {
	labels := prometheus.Labels{
		"backend":    "api.github.com",
		"method":     "GET",
		"status":     "200",
		"token_type": "unknown",
		"type":       "rest",
		"user":       "unknown",
		"app":        "",
	}
	before := getCounterValue(t, ProxyRequestTotal, labels)
	ObservePassthroughRequest("api.github.com", "GET", 200, 100*time.Millisecond, "rest", "", "")
	after := getCounterValue(t, ProxyRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestCacheFetchTotal(t *testing.T) {
	results := []string{"hit", "miss", "rejected", "error"}
	for _, result := range results {
		t.Run(result, func(t *testing.T) {
			labels := prometheus.Labels{"result": result}
			before := getCounterValue(t, CacheFetchTotal, labels)
			CacheFetchTotal.WithLabelValues(result).Inc()
			after := getCounterValue(t, CacheFetchTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestCacheLsRefsTotal(t *testing.T) {
	before := getCounterValueSimple(t, CacheLsRefsTotal)
	CacheLsRefsTotal.Inc()
	after := getCounterValueSimple(t, CacheLsRefsTotal)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestCacheWarmTotal(t *testing.T) {
	for _, result := range []string{"success", "error"} {
		t.Run(result, func(t *testing.T) {
			labels := prometheus.Labels{"result": result}
			before := getCounterValue(t, CacheWarmTotal, labels)
			CacheWarmTotal.WithLabelValues(result).Inc()
			after := getCounterValue(t, CacheWarmTotal, labels)
			if after-before != 1 {
				t.Errorf("expected counter to increment by 1, got %f", after-before)
			}
		})
	}
}

func TestCacheReposActive(t *testing.T) {
	CacheReposActive.Set(5)
	if got := getGaugeValue(t, CacheReposActive); got != 5 {
		t.Errorf("expected gauge value 5, got %f", got)
	}
	CacheReposActive.Set(0)
	if got := getGaugeValue(t, CacheReposActive); got != 0 {
		t.Errorf("expected gauge value 0, got %f", got)
	}
}

func TestCacheRequestTotal(t *testing.T) {
	labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "result": "nocache"}
	before := getCounterValue(t, CacheRequestTotal, labels)
	CacheRequestTotal.WithLabelValues("testorg", "testrepo", "nocache").Inc()
	after := getCounterValue(t, CacheRequestTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}

	// Verify bypass label works too.
	bypassLabels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "result": "bypass"}
	beforeBypass := getCounterValue(t, CacheRequestTotal, bypassLabels)
	CacheRequestTotal.WithLabelValues("testorg", "testrepo", "bypass").Inc()
	afterBypass := getCounterValue(t, CacheRequestTotal, bypassLabels)
	if afterBypass-beforeBypass != 1 {
		t.Errorf("expected bypass counter to increment by 1, got %f", afterBypass-beforeBypass)
	}
}

func TestCachePackfileTotal(t *testing.T) {
	for _, result := range []string{"hit", "miss", "passthrough"} {
		labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "user": "testuser", "result": result}
		before := getCounterValue(t, CachePackfileTotal, labels)
		CachePackfileTotal.WithLabelValues("testorg", "testrepo", "testuser", result).Inc()
		after := getCounterValue(t, CachePackfileTotal, labels)
		if after-before != 1 {
			t.Errorf("expected %s counter to increment by 1, got %f", result, after-before)
		}
	}
}

func TestCachePackfileBytesTotal(t *testing.T) {
	for _, result := range []string{"hit", "miss", "passthrough"} {
		labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo", "user": "testuser", "result": result}
		before := getCounterValue(t, CachePackfileBytesTotal, labels)
		CachePackfileBytesTotal.WithLabelValues("testorg", "testrepo", "testuser", result).Add(1024)
		after := getCounterValue(t, CachePackfileBytesTotal, labels)
		if after-before != 1024 {
			t.Errorf("expected %s bytes counter to increment by 1024, got %f", result, after-before)
		}
	}
}

func TestObserveDecision_CacheLookup(t *testing.T) {
	labels := prometheus.Labels{
		"stage":      StageCacheLookup,
		"token_type": "proxy",
	}
	before := getHistogramCount(t, ProxyDecisionDuration, labels)
	ObserveDecision(StageCacheLookup, "proxy", 5*time.Millisecond)
	after := getHistogramCount(t, ProxyDecisionDuration, labels)
	if after-before != 1 {
		t.Errorf("expected histogram sample count to increment by 1, got %d", after-before)
	}
}

func getGaugeVecValue(t *testing.T, g *prometheus.GaugeVec, labels prometheus.Labels) float64 {
	t.Helper()
	gauge, err := g.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	return getGaugeValue(t, gauge)
}

func TestCacheEvictionTotal(t *testing.T) {
	labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo"}
	before := getCounterValue(t, CacheEvictionTotal, labels)
	CacheEvictionTotal.WithLabelValues("testorg", "testrepo").Inc()
	after := getCounterValue(t, CacheEvictionTotal, labels)
	if after-before != 1 {
		t.Errorf("expected counter to increment by 1, got %f", after-before)
	}
}

func TestCacheResponseSizeBytes(t *testing.T) {
	labels := prometheus.Labels{"owner": "testorg", "repo": "testrepo"}
	CacheResponseSizeBytes.WithLabelValues("testorg", "testrepo").Set(1048576)
	got := getGaugeVecValue(t, CacheResponseSizeBytes, labels)
	if got != 1048576 {
		t.Errorf("expected gauge value 1048576, got %f", got)
	}
}

func TestSetBuildInfo(t *testing.T) {
	// Inject a fake debug.ReadBuildInfo that returns a known revision.
	orig := runtimeDebugReadBuildInfo
	t.Cleanup(func() { runtimeDebugReadBuildInfo = orig })

	runtimeDebugReadBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc123"},
			},
		}, true
	}

	SetBuildInfo("1.2.3")

	labels := prometheus.Labels{
		"version":   "1.2.3",
		"revision":  "abc123",
		"goversion": runtime.Version(),
		"goos":      runtime.GOOS,
		"goarch":    runtime.GOARCH,
	}

	gauge, err := BuildInfo.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if got := getGaugeValue(t, gauge); got != 1 {
		t.Errorf("expected build_info gauge value 1, got %f", got)
	}
}

func TestSetBuildInfo_NoVCSRevision(t *testing.T) {
	orig := runtimeDebugReadBuildInfo
	t.Cleanup(func() { runtimeDebugReadBuildInfo = orig })

	runtimeDebugReadBuildInfo = func() (*debug.BuildInfo, bool) {
		return nil, false
	}

	SetBuildInfo("dev")

	labels := prometheus.Labels{
		"version":   "dev",
		"revision":  "unknown",
		"goversion": runtime.Version(),
		"goos":      runtime.GOOS,
		"goarch":    runtime.GOARCH,
	}

	gauge, err := BuildInfo.GetMetricWith(labels)
	if err != nil {
		t.Fatalf("GetMetricWith: %v", err)
	}
	if got := getGaugeValue(t, gauge); got != 1 {
		t.Errorf("expected build_info gauge value 1, got %f", got)
	}
}

func TestTokenCleanupDeletedTotal(t *testing.T) {
	before := getCounterValueSimple(t, TokenCleanupDeletedTotal)
	TokenCleanupDeletedTotal.Add(5)
	after := getCounterValueSimple(t, TokenCleanupDeletedTotal)
	if after-before != 5 {
		t.Errorf("expected counter to increment by 5, got %f", after-before)
	}
}
