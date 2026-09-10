package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/http/httpproxy"
)

// Pool selects a reusable forward-proxy transport per request. It does not
// rewrite destinations, retry requests, or modify process-global transports.
type Pool struct {
	mu         sync.Mutex
	candidates []Candidate
	selector   Selector
	urls       []*url.URL
	transports []*http.Transport
	direct     *http.Transport
	bypass     func(*url.URL) (*url.URL, error)
}

// New returns nil for an empty pool, preserving the caller's default transport.
func New(cfg Config) (*Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.Proxies) == 0 {
		return nil, nil
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("egress requires a standard default HTTP transport")
	}
	p := &Pool{direct: base.Clone(), selector: &roundRobin{}}
	p.direct.Proxy = nil
	switch cfg.Strategy {
	case LeastConnections:
		p.selector = &roundRobin{least: true}
	case IPHash:
		p.selector = &ipHash{}
	}
	// Keep Go's NO_PROXY semantics, including implicit localhost bypasses.
	// The placeholder is only used for matching and never dialled.
	env := httpproxy.FromEnvironment()
	env.HTTPProxy, env.HTTPSProxy = "http://egress.invalid", "http://egress.invalid"
	p.bypass = env.ProxyFunc()
	for _, proxy := range cfg.Proxies {
		u, _ := url.Parse(proxy.URL) // validated above
		tr := base.Clone()
		tr.Proxy = http.ProxyURL(u)
		p.urls = append(p.urls, u)
		p.transports = append(p.transports, tr)
		p.candidates = append(p.candidates, Candidate{Name: proxy.Name, Weight: proxy.weight()})
	}
	return p, nil
}

// Transport avoids putting a typed nil *Pool into an http.RoundTripper.
func (p *Pool) Transport() http.RoundTripper {
	if p == nil {
		return nil
	}
	return p
}

// Lease reserves one active operation. Call Release on every exit path.
// It also supports clients such as go-git that accept a proxy URL per operation
// but cannot accept a per-operation HTTP transport.
type Lease struct {
	pool  *Pool
	index int
	once  sync.Once
}

func (p *Pool) Acquire(ctx context.Context, destination *url.URL) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil {
		return &Lease{}, nil
	}
	proxy, err := p.bypass(destination)
	if err != nil {
		return nil, err
	}
	if proxy == nil {
		return &Lease{}, nil
	}
	key, _ := ctx.Value(clientIPKey{}).(string)
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.selector.Select(p.candidates, key)
	if i < 0 || i >= len(p.candidates) {
		return nil, errors.New("egress selector returned no proxy")
	}
	p.candidates[i].Active++
	return &Lease{pool: p, index: i}, nil
}

// ProxyURL returns a copy, or nil when existing/direct routing applies.
func (l *Lease) ProxyURL() *url.URL {
	if l.pool == nil {
		return nil
	}
	u := *l.pool.urls[l.index]
	return &u
}

func (l *Lease) Release() {
	l.once.Do(func() {
		if l.pool != nil {
			l.pool.mu.Lock()
			l.pool.candidates[l.index].Active--
			l.pool.mu.Unlock()
		}
	})
}

// WrapError prevents proxy credentials embedded in library errors from reaching
// logs or clients. Unwrap retains cancellation/timeout checks with errors.Is/As.
func (l *Lease) WrapError(err error) error {
	if err == nil || l.pool == nil {
		return err
	}
	return &proxyError{name: l.pool.candidates[l.index].Name, cause: err}
}

type proxyError struct {
	name  string
	cause error
}

func (e *proxyError) Error() string {
	reason := "request failed"
	if errors.Is(e.cause, context.Canceled) {
		reason = "request canceled"
	} else if e.Timeout() {
		reason = "request timed out"
	}
	return fmt.Sprintf("egress proxy %s: %s", e.name, reason)
}
func (e *proxyError) Unwrap() error { return e.cause }

// Preserve net.Error behavior for clients that inspect url.Error.Timeout.
func (e *proxyError) Timeout() bool {
	var err net.Error
	return errors.As(e.cause, &err) && err.Timeout()
}

func (e *proxyError) Temporary() bool {
	var err net.Error
	return errors.As(e.cause, &err) && err.Temporary()
}

func (p *Pool) RoundTrip(req *http.Request) (*http.Response, error) {
	lease, err := p.Acquire(req.Context(), req.URL)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	tr := p.direct
	if lease.pool != nil {
		tr = p.transports[lease.index]
	}
	stop := context.AfterFunc(req.Context(), lease.Release)
	finish := func() { stop(); lease.Release() }
	// Proxy authentication belongs to the selected transport, not the caller.
	out := req.Clone(req.Context())
	out.Header.Del("Proxy-Authorization")
	resp, err := tr.RoundTrip(out)
	if err != nil {
		finish()
		return nil, lease.WrapError(err)
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		finish()
		return resp, nil
	}
	b := &body{ReadCloser: resp.Body, finish: finish}
	if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
		// Upgrades may continue writing after read EOF. Release on close.
		b.upgraded = true
		resp.Body = &upgradedBody{body: b, Writer: rw}
	} else {
		resp.Body = b
	}
	return resp, nil
}

type body struct {
	io.ReadCloser
	finish   func()
	upgraded bool
}

func (b *body) Read(buf []byte) (int, error) {
	n, err := b.ReadCloser.Read(buf)
	if err != nil && !b.upgraded {
		b.finish()
	}
	return n, err
}

func (b *body) Close() error {
	defer b.finish()
	return b.ReadCloser.Close()
}

type upgradedBody struct {
	*body
	io.Writer
}

func (p *Pool) CloseIdleConnections() {
	if p == nil {
		return
	}
	p.direct.CloseIdleConnections()
	for _, tr := range p.transports {
		tr.CloseIdleConnections()
	}
}
