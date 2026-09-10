package egress

import (
	"strings"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	zero, negative, large := 0, -1, 10001
	for _, tt := range []struct {
		name string
		cfg  Config
	}{
		{"strategy", Config{Strategy: "unknown"}},
		{"missing name", Config{Proxies: []Proxy{{URL: "http://proxy"}}}},
		{"invalid name", Config{Proxies: []Proxy{{Name: "a\nb", URL: "http://proxy"}}}},
		{"duplicate name", Config{Proxies: []Proxy{{Name: "a", URL: "http://a"}, {Name: "a", URL: "http://b"}}}},
		{"duplicate endpoint", Config{Proxies: []Proxy{{Name: "a", URL: "http://PROXY.:080"}, {Name: "b", URL: "http://proxy"}}}},
		{"duplicate credentials", Config{Proxies: []Proxy{{Name: "a", URL: "http://alice:password@proxy"}, {Name: "b", URL: "http://bob:password@proxy"}}}},
		{"zero weight", Config{Proxies: []Proxy{{Name: "a", URL: "http://proxy", Weight: &zero}}}},
		{"negative weight", Config{Proxies: []Proxy{{Name: "a", URL: "http://proxy", Weight: &negative}}}},
		{"large weight", Config{Proxies: []Proxy{{Name: "a", URL: "http://proxy", Weight: &large}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	for _, raw := range []string{
		"proxy:3128", "socks5://proxy:1080", "http://", "http://user:secret@proxy/path",
		"http://user:secret@proxy?query", "http://user:secret@proxy#fragment",
		"http://user:secret@proxy:invalid", "http://user:secret@proxy:0", "http://proxy:65536",
		"http://user:%secret@proxy", "http://proxy:", "http://.", "http://::1",
	} {
		cfg := Config{Proxies: []Proxy{{Name: "test", URL: raw}}}
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("accepted invalid proxy URL %q", raw)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user:") {
			t.Fatalf("validation exposed credentials: %s", err)
		}
	}
	for _, raw := range []string{"http://proxy", "https://user:password@proxy:3128/", "http://[::1]:3128"} {
		if err := (Config{Proxies: []Proxy{{Name: "a", URL: raw}}}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
