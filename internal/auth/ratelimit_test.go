package auth

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// newTestLimiter creates a limiter with a no-op logger suitable for unit tests.
func newTestLimiter(limit int, window time.Duration) *IPRateLimiter {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewIPRateLimiter(limit, window, "/test", false, logger)
}

func TestIPRateLimiter_Allow(t *testing.T) {
	limiter := newTestLimiter(3, time.Minute)
	ip := "1.2.3.4"

	for i := 0; i < 3; i++ {
		if !limiter.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	if limiter.Allow(ip) {
		t.Error("fourth request should be rate limited")
	}

	if !limiter.Allow("5.6.7.8") {
		t.Error("different IP should be allowed")
	}
}

func TestIPRateLimiter_Middleware(t *testing.T) {
	limiter := newTestLimiter(2, time.Minute)

	called := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
	if called != 2 {
		t.Errorf("inner handler called %d times, want 2", called)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if called != 2 {
		t.Error("inner handler should not be called after rate limit")
	}
}

func TestIPRateLimiter_Middleware_ResponseHeaders(t *testing.T) {
	limiter := newTestLimiter(1, time.Minute)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("Retry-After header missing on 429 response")
	}
}

func TestIPRateLimiter_Middleware_ForwardedHeaderIgnoredWhenUntrusted(t *testing.T) {
	limiter := newTestLimiter(1, time.Minute)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i+1))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("request %d: expected %d, got %d", i+1, want, w.Code)
		}
	}
}

func TestIPRateLimiter_Middleware_ForwardedHeaderHonouredWhenTrusted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	limiter := NewIPRateLimiter(1, time.Minute, "/test", true, logger)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i+1))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for repeated forwarded client, got %d", w.Code)
	}
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	limiter := newTestLimiter(1000, time.Minute)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := limiter.Middleware(inner)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
			for j := 0; j < 10; j++ {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = ip + ":1234"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
			}
		}(i)
	}
	wg.Wait()
}
