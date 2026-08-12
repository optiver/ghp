package auth

import (
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/netutil"
)

// visitorTTL is how long an idle visitor entry is kept before being evicted.
const visitorTTL = 3 * time.Minute

// visitor holds the per-IP rate limiter and the last time it was seen.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter is a per-IP token-bucket rate limiter backed by
// golang.org/x/time/rate. A background goroutine evicts idle entries
// so that memory usage is bounded.
type IPRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     rate.Limit
	burst    int

	// endpoint names the protected route; used in log and metric labels.
	endpoint string
	logger   *slog.Logger

	trustProxyHeaders bool
}

// NewIPRateLimiter creates a new IPRateLimiter that allows up to limit requests
// per window duration per IP address. The underlying token bucket refills at
// limit/window tokens per second with a burst equal to limit.
//
// endpoint is included in slog and Prometheus label values so operators can
// distinguish traffic sources in dashboards and alerts.
// logger receives a Warn-level entry for every rejected request.
func NewIPRateLimiter(limit int, window time.Duration, endpoint string, trustProxyHeaders bool, logger *slog.Logger) *IPRateLimiter {
	l := &IPRateLimiter{
		visitors:          make(map[string]*visitor),
		rate:              rate.Limit(float64(limit) / window.Seconds()),
		burst:             limit,
		endpoint:          endpoint,
		logger:            logger,
		trustProxyHeaders: trustProxyHeaders,
	}
	go l.cleanupLoop()
	return l
}

// getVisitor returns the rate.Limiter for ip, creating one if needed.
// Must be called with l.mu held.
func (l *IPRateLimiter) getVisitor(ip string) *rate.Limiter {
	v, ok := l.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v.limiter
}

// Allow reports whether a request from ip is within the rate limit.
func (l *IPRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.getVisitor(ip).Allow()
}

// cleanupLoop evicts visitor entries that have been idle for longer than
// visitorTTL, preventing unbounded memory growth.
func (l *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-visitorTTL)
		for ip, v := range l.visitors {
			if v.lastSeen.Before(cutoff) {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

// Middleware returns an http.Handler that enforces the rate limit before
// delegating to next.
//
// Rejected requests receive:
//   - HTTP 429 Too Many Requests
//   - Content-Type: application/json
//   - Retry-After: 1 (second)
//   - a JSON error body
//
// Each rejection is also:
//   - logged via slog at Warn level with endpoint and IP
//   - counted in the ghp_auth_rate_limit_total{endpoint} Prometheus counter
func (l *IPRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netutil.ClientIP(r, l.trustProxyHeaders)
		if !l.Allow(ip) {
			l.logger.Warn("rate_limit_exceeded",
				"endpoint", l.endpoint,
				"ip", ip,
			)
			metrics.RateLimitTotal.WithLabelValues(l.endpoint).Inc()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(1))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"message":"Rate limit exceeded. Please try again later."}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
