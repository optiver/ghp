// Package egress provides optional HTTP forward-proxy load balancing.
// Destination routing, authentication, and request policy remain with callers.
package egress

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	WeightedRoundRobin = "weighted_round_robin"
	LeastConnections   = "least_connections"
	IPHash             = "ip_hash"
)

// Config is startup-only. An empty pool preserves environment proxy settings.
type Config struct {
	Strategy string  `koanf:"strategy"`
	Proxies  []Proxy `koanf:"proxies"`
}

type Proxy struct {
	Name   string `koanf:"name"`
	URL    string `koanf:"url"`
	Weight *int   `koanf:"weight"` // nil means 1; explicit zero is invalid
}

func (p Proxy) weight() int64 {
	if p.Weight == nil {
		return 1
	}
	return int64(*p.Weight)
}

var memberName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// Validate never includes a proxy URL in errors: it can contain credentials.
func (c Config) Validate() error {
	switch c.Strategy {
	case "", WeightedRoundRobin, LeastConnections, IPHash:
	default:
		return fmt.Errorf("egress.strategy must be weighted_round_robin, least_connections, or ip_hash")
	}
	if len(c.Proxies) > 256 {
		return fmt.Errorf("egress.proxies supports at most 256 members")
	}
	names, endpoints := map[string]bool{}, map[string]bool{}
	for i, p := range c.Proxies {
		if !memberName.MatchString(p.Name) || names[p.Name] {
			return fmt.Errorf("egress.proxies[%d].name must be unique and contain 1-64 letters, digits, dots, underscores, or hyphens, starting with a letter or digit", i)
		}
		names[p.Name] = true
		if p.weight() < 1 || p.weight() > 10000 {
			return fmt.Errorf("egress.proxies[%d].weight must be between 1 and 10000", i)
		}
		u, err := url.Parse(p.URL)
		if err != nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return fmt.Errorf("egress.proxies[%d].url must be an absolute HTTP(S) proxy URL without a path, query, or fragment", i)
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strings.HasSuffix(u.Host, ":") {
			return fmt.Errorf("egress.proxies[%d].url has an invalid port", i)
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		ip, ipErr := netip.ParseAddr(host)
		if host == "" || (strings.Contains(host, ":") && ipErr != nil) {
			return fmt.Errorf("egress.proxies[%d].url has an invalid host", i)
		}
		if ipErr == nil {
			host = ip.Unmap().String()
		}
		endpoint := u.Scheme + "://" + net.JoinHostPort(host, strconv.Itoa(n))
		if endpoints[endpoint] {
			return fmt.Errorf("egress.proxies[%d].url duplicates another proxy endpoint", i)
		}
		endpoints[endpoint] = true
	}
	return nil
}
