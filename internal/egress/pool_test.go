package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testPool(t *testing.T, strategy string, proxies ...Proxy) *Pool {
	t.Helper()
	for _, name := range []string{"NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(name, "")
	}
	p, err := New(Config{Strategy: strategy, Proxies: proxies})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.CloseIdleConnections)
	return p
}

func active(p *Pool) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total int64
	for _, c := range p.candidates {
		total += c.Active
	}
	return total
}

func TestWeightedRoundRobin(t *testing.T) {
	three := 3
	p := testPool(t, WeightedRoundRobin,
		Proxy{Name: "a", URL: "http://a:3128", Weight: &three},
		Proxy{Name: "b", URL: "http://b:3128"})
	u, _ := url.Parse("https://api.github.com")
	counts := map[string]int{}
	for range 400 {
		lease, err := p.Acquire(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		counts[lease.ProxyURL().Hostname()]++
		lease.Release()
	}
	if counts["a"] != 300 || counts["b"] != 100 || active(p) != 0 {
		t.Fatalf("distribution=%v active=%d", counts, active(p))
	}
}

func TestLeastConnectionsReservesAtomically(t *testing.T) {
	two := 2
	p := testPool(t, LeastConnections,
		Proxy{Name: "a", URL: "http://a", Weight: &two}, Proxy{Name: "b", URL: "http://b"})
	u, _ := url.Parse("https://api.github.com")
	var wg sync.WaitGroup
	leases := make(chan *Lease, 120)
	for range 120 {
		wg.Go(func() {
			l, err := p.Acquire(context.Background(), u)
			if err != nil {
				t.Error(err)
				return
			}
			leases <- l
		})
	}
	wg.Wait()
	if p.candidates[0].Active != 80 || p.candidates[1].Active != 40 {
		t.Fatalf("unexpected weighted active load: %+v", p.candidates)
	}
	close(leases)
	for l := range leases {
		wg.Go(func() { l.Release(); l.Release() })
	}
	wg.Wait()
	if active(p) != 0 {
		t.Fatalf("leaked reservations: %d", active(p))
	}
}

func TestIPHashStableAndWeighted(t *testing.T) {
	cs := []Candidate{{Name: "a", Weight: 3}, {Name: "b", Weight: 1}}
	reordered := []Candidate{cs[1], cs[0]}
	expanded := append(append([]Candidate{}, cs...), Candidate{Name: "c", Weight: 1})
	s := &ipHash{}
	counts := map[string]int{}
	for i := range 10000 {
		key := fmt.Sprintf("192.0.%d.%d", i/256, i%256)
		name := cs[s.Select(cs, key)].Name
		counts[name]++
		if reordered[s.Select(reordered, key)].Name != name {
			t.Fatal("list order changed IP affinity")
		}
		newName := expanded[s.Select(expanded, key)].Name
		if newName != "c" && newName != name {
			t.Fatal("adding a member remapped clients between existing members")
		}
	}
	if counts["a"] < 7200 || counts["a"] > 7800 {
		t.Fatalf("unexpected hash distribution: %v", counts)
	}
	// Background operations must spread rather than all hashing an empty key.
	counts = map[string]int{}
	for range 40 {
		counts[cs[s.Select(cs, "")].Name]++
	}
	if counts["a"] != 30 || counts["b"] != 10 {
		t.Fatalf("background distribution: %v", counts)
	}
}

func TestClientIPContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ctx = WithClientIP(ctx, "::ffff:192.0.2.1")
	detached := Background(ctx)
	cancel()
	if detached.Err() != nil || detached.Value(clientIPKey{}) != "192.0.2.1" {
		t.Fatal("detached context lost routing key or inherited cancellation")
	}
	if got := WithClientIP(ctx, "invalid").Value(clientIPKey{}); got != "" {
		t.Fatalf("invalid client IP became a routing key: %v", got)
	}
}

func TestForwardProxyAndStreamingAccounting(t *testing.T) {
	var counts [2]atomic.Int32
	var proxies []Proxy
	for i := range 2 {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			counts[i].Add(1)
			if r.URL.String() != "http://api.example.com/stream?q=1" || r.Host != "api.example.com" {
				t.Errorf("destination changed: URL=%s Host=%s", r.URL, r.Host)
			}
			if r.Header.Get("Authorization") != "Bearer github-token" {
				t.Error("GitHub authorization was lost")
			}
			if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
				t.Errorf("incorrect proxy authentication: %q", r.Header.Get("Proxy-Authorization"))
			}
			w.Header().Set("X-Proxy", fmt.Sprint(i))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		t.Cleanup(s.Close)
		u, _ := url.Parse(s.URL)
		u.User = url.UserPassword("user", "pass")
		proxies = append(proxies, Proxy{Name: fmt.Sprint("proxy-", i), URL: u.String()})
	}
	p := testPool(t, LeastConnections, proxies...)
	client := &http.Client{Transport: p}
	request := func() (*http.Response, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		r, _ := http.NewRequestWithContext(ctx, "GET", "http://api.example.com/stream?q=1", nil)
		r.Header.Set("Authorization", "Bearer github-token")
		r.Header.Set("Proxy-Authorization", "untrusted-client-proxy-auth")
		resp, err := client.Do(r)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); resp.Body.Close() })
		return resp, cancel
	}
	first, _ := request()
	second, cancel := request()
	if first.Header.Get("X-Proxy") == second.Header.Get("X-Proxy") || active(p) != 2 {
		t.Fatalf("open streams were not balanced: active=%d", active(p))
	}
	first.Body.Close()
	third, _ := request()
	if third.Header.Get("X-Proxy") != first.Header.Get("X-Proxy") {
		t.Error("least connections did not reuse the freed member")
	}
	// Cancellation must release the slot even before the caller closes Body.
	cancel()
	deadline := time.Now().Add(time.Second)
	for active(p) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active(p) != 1 {
		t.Fatal("canceled request retained its reservation")
	}
	second.Body.Close()
	third.Body.Close()
	if active(p) != 0 || counts[0].Load()+counts[1].Load() != 3 {
		t.Fatal("incorrect operation accounting")
	}
}

// connectProxy tunnels only to the local test origin, independently of DNS.
func connectProxy(t *testing.T, origin string, secure bool, count *atomic.Int32) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "example.com:443" {
			t.Errorf("unexpected CONNECT: %s %s", r.Method, r.Host)
			http.Error(w, "bad CONNECT", 400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
			t.Error("missing CONNECT authentication")
		}
		count.Add(1)
		upstream, err := net.Dial("tcp", origin)
		if err != nil {
			http.Error(w, "dial failed", 502)
			return
		}
		defer upstream.Close()
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		rw.Flush()
		done := make(chan struct{})
		go func() { io.Copy(upstream, rw); upstream.Close(); close(done) }()
		io.Copy(conn, upstream)
		conn.Close()
		<-done
	})
	var s *httptest.Server
	if secure {
		s = httptest.NewTLSServer(h)
	} else {
		s = httptest.NewServer(h)
	}
	t.Cleanup(s.Close)
	return s
}

func TestHTTPAndHTTPSConnectWithHTTP2Reuse(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint("secure=", secure), func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "copilot.example.com" || r.TLS.ServerName != "example.com" || r.ProtoMajor != 2 {
					t.Errorf("Host/SNI/HTTP2 changed: %s %s %s", r.Host, r.TLS.ServerName, r.Proto)
				}
				if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "Bearer origin-token" {
					t.Error("proxy and origin credentials were mixed")
				}
				io.WriteString(w, "response")
			}))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			t.Cleanup(origin.Close)
			var counts [2]atomic.Int32
			var proxies []Proxy
			for i := range 2 {
				s := connectProxy(t, origin.Listener.Addr().String(), secure, &counts[i])
				u, _ := url.Parse(s.URL)
				u.User = url.UserPassword("user", "pass")
				proxies = append(proxies, Proxy{Name: fmt.Sprint("proxy-", i), URL: u.String()})
			}
			p := testPool(t, "", proxies...)
			for _, tr := range p.transports {
				tr.TLSClientConfig = &tls.Config{RootCAs: origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
			}
			for range 8 {
				req, _ := http.NewRequest("GET", "https://example.com/resource", nil)
				req.Host = "copilot.example.com" // Copilot preserves a different original Host.
				req.Header.Set("Authorization", "Bearer origin-token")
				resp, err := p.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(got) != "response" {
					t.Fatalf("response=%q err=%v", got, err)
				}
			}
			if counts[0].Load() != 1 || counts[1].Load() != 1 || active(p) != 0 {
				t.Fatalf("connections not reused: %d %d, active=%d", counts[0].Load(), counts[1].Load(), active(p))
			}
		})
	}
}

func TestNoProxyBypassesPoolAndEnvironment(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	defer origin.Close()
	p := testPool(t, "", Proxy{Name: "unreachable", URL: "http://127.0.0.1:1"})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	envURL, _ := url.Parse("http://bypass.example.com")
	t.Setenv("NO_PROXY", "bypass.example.com")
	withBypass, err := New(Config{Proxies: []Proxy{{Name: "unreachable", URL: "http://127.0.0.1:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer withBypass.CloseIdleConnections()
	lease, err := withBypass.Acquire(context.Background(), envURL)
	if err != nil || lease.ProxyURL() != nil {
		t.Fatalf("NO_PROXY ignored: %v", err)
	}
	lease.Release()
	// Implicit loopback bypass also must not fall through to HTTP_PROXY.
	resp, err := (&http.Client{Transport: p}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "direct" || active(p) != 0 {
		t.Fatal("did not bypass")
	}
}

func TestFailureDoesNotRetryAndRedactsCredentials(t *testing.T) {
	var attempts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	u.User = url.UserPassword("secret-user", "secret-password")
	p := testPool(t, "", Proxy{Name: "broken", URL: u.String()}, Proxy{Name: "unused", URL: "http://127.0.0.1:1"})
	req, _ := http.NewRequest("POST", "http://api.example.com/mutation", strings.NewReader("body"))
	_, err := p.RoundTrip(req)
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("missing or unsafe error: %v", err)
	}
	if attempts.Load() != 1 || active(p) != 0 {
		t.Fatal("request replayed or reservation leaked")
	}
	lease, _ := p.Acquire(context.Background(), req.URL)
	defer lease.Release()
	if !errors.Is(lease.WrapError(context.Canceled), context.Canceled) {
		t.Fatal("lost cancellation identity")
	}
	timeout := &url.Error{Op: "Get", URL: "https://example.com", Err: lease.WrapError(context.DeadlineExceeded)}
	if !timeout.Timeout() {
		t.Fatal("wrapped transport timeout no longer satisfies url.Error.Timeout")
	}
}

func TestUpgradePreservesBidirectionalBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		fmt.Fprint(rw, line)
		rw.Flush()
		io.Copy(io.Discard, rw)
	}))
	defer s.Close()
	p := testPool(t, "", Proxy{Name: "a", URL: s.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://api.example.com/socket", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")
	resp, err := p.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatal("transport stripped upgraded body's Write method")
	}
	if _, err := io.WriteString(rw, "ping\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rw, buf); err != nil || string(buf) != "ping\n" {
		t.Fatalf("echo=%q err=%v", buf, err)
	}
	if active(p) != 1 {
		t.Fatal("upgrade released early")
	}
	rw.Close()
	if active(p) != 0 {
		t.Fatal("upgrade leaked active request")
	}
}

func TestHTTPResponsesAreNotRetried(t *testing.T) {
	for _, status := range []int{403, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(status)
				io.WriteString(w, "upstream response")
			}))
			defer s.Close()
			p := testPool(t, "", Proxy{Name: "a", URL: s.URL})
			req, _ := http.NewRequest("GET", "http://api.example.com/limited", nil)
			resp, err := p.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != status || resp.Header.Get("Retry-After") != "60" || string(got) != "upstream response" || requests.Load() != 1 || active(p) != 0 {
				t.Fatalf("upstream response changed or replayed: %v", err)
			}
		})
	}
}

func TestLegacyEnvironment(t *testing.T) {
	if os.Getenv("GHP_EGRESS_LEGACY_TEST") == "1" {
		p, err := New(Config{})
		if err != nil || p.Transport() != nil {
			t.Fatal("legacy transport changed")
		}
		resp, err := (&http.Client{Transport: p.Transport()}).Get("http://egress-legacy.invalid/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "legacy" {
			t.Fatal("environment proxy not used")
		}
		return
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "legacy") }))
	defer s.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLegacyEnvironment$")
	for _, v := range os.Environ() {
		name, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "REQUEST_METHOD":
		default:
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "GHP_EGRESS_LEGACY_TEST=1", "HTTP_PROXY="+s.URL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("legacy subprocess: %v\n%s", err, out)
	}
}

func BenchmarkSelection(b *testing.B) {
	for _, strategy := range []string{WeightedRoundRobin, LeastConnections, IPHash} {
		b.Run(strategy, func(b *testing.B) {
			p, err := New(Config{Strategy: strategy, Proxies: []Proxy{{Name: "a", URL: "http://a"}, {Name: "b", URL: "http://b"}}})
			if err != nil {
				b.Fatal(err)
			}
			defer p.CloseIdleConnections()
			ctx := WithClientIP(context.Background(), "192.0.2.1")
			u, _ := url.Parse("https://api.github.com")
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					l, err := p.Acquire(ctx, u)
					if err != nil {
						b.Error(err)
						return
					}
					l.Release()
				}
			})
		})
	}
}
