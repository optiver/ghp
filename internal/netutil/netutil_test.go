package netutil

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		xRealIP    string
		xForwarded string
		trust      bool
		want       string
	}{
		{name: "remote addr only", remoteAddr: "192.168.1.10:54321", want: "192.168.1.10"},
		{name: "remote addr without port", remoteAddr: "192.168.1.10", want: "192.168.1.10"},
		{name: "x-real-ip ignored when untrusted", remoteAddr: "192.168.1.10:54321", xRealIP: "10.0.0.1", want: "192.168.1.10"},
		{name: "x-forwarded-for ignored when untrusted", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1", want: "192.168.1.10"},
		{name: "forwarded ignored when untrusted", remoteAddr: "192.168.1.10:54321", forwarded: "for=10.0.0.1", want: "192.168.1.10"},
		{name: "x-real-ip trusted", remoteAddr: "192.168.1.10:54321", xRealIP: "10.0.0.1", trust: true, want: "10.0.0.1"},
		{name: "x-real-ip trimmed", remoteAddr: "192.168.1.10:54321", xRealIP: "  10.0.0.1  ", trust: true, want: "10.0.0.1"},
		{name: "x-real-ip invalid falls back", remoteAddr: "192.168.1.10:54321", xRealIP: "not-an-ip", trust: true, want: "192.168.1.10"},
		{name: "x-forwarded-for single", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1", trust: true, want: "10.0.0.1"},
		{name: "x-forwarded-for chain uses rightmost", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1, 10.0.0.2, 10.0.0.3", trust: true, want: "10.0.0.3"},
		{name: "x-forwarded-for spoofed prefix ignored", remoteAddr: "192.168.1.10:54321", xForwarded: "1.1.1.1, 172.16.0.5", trust: true, want: "172.16.0.5"},
		{name: "x-forwarded-for with port", remoteAddr: "192.168.1.10:54321", xForwarded: "10.0.0.1:8080", trust: true, want: "10.0.0.1"},
		{name: "x-forwarded-for invalid falls back", remoteAddr: "192.168.1.10:54321", xForwarded: "garbage", trust: true, want: "192.168.1.10"},
		{name: "x-real-ip wins over x-forwarded-for", remoteAddr: "192.168.1.10:54321", xRealIP: "10.0.0.9", xForwarded: "10.0.0.1", trust: true, want: "10.0.0.9"},
		{name: "forwarded single element", remoteAddr: "192.168.1.10:54321", forwarded: "for=10.0.0.1", trust: true, want: "10.0.0.1"},
		{name: "forwarded chain uses rightmost element", remoteAddr: "192.168.1.10:54321", forwarded: "for=1.1.1.1, for=172.16.0.5", trust: true, want: "172.16.0.5"},
		{name: "forwarded with other fields", remoteAddr: "192.168.1.10:54321", forwarded: "by=203.0.113.43;for=10.0.0.1;proto=https", trust: true, want: "10.0.0.1"},
		{name: "forwarded quoted with port", remoteAddr: "192.168.1.10:54321", forwarded: `for="10.0.0.1:8080"`, trust: true, want: "10.0.0.1"},
		{name: "forwarded bracketed ipv6", remoteAddr: "192.168.1.10:54321", forwarded: `for="[2001:db8::1]"`, trust: true, want: "2001:db8::1"},
		{name: "forwarded bracketed ipv6 with port", remoteAddr: "192.168.1.10:54321", forwarded: `for="[2001:db8::1]:443"`, trust: true, want: "2001:db8::1"},
		{name: "forwarded ipv6 canonicalized", remoteAddr: "192.168.1.10:54321", forwarded: `for="[2001:DB8::1]"`, trust: true, want: "2001:db8::1"},
		{name: "forwarded unknown falls through to x-real-ip", remoteAddr: "192.168.1.10:54321", forwarded: "for=unknown", xRealIP: "10.0.0.1", trust: true, want: "10.0.0.1"},
		{name: "forwarded obfuscated falls through to x-forwarded-for", remoteAddr: "192.168.1.10:54321", forwarded: "for=_hidden", xForwarded: "10.0.0.2", trust: true, want: "10.0.0.2"},
		{name: "forwarded wins over x-real-ip", remoteAddr: "192.168.1.10:54321", forwarded: "for=10.0.0.7", xRealIP: "10.0.0.9", trust: true, want: "10.0.0.7"},
		{name: "trusted but no headers falls back", remoteAddr: "192.168.1.10:54321", trust: true, want: "192.168.1.10"},
		{name: "ipv6 remote addr", remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				r.Header.Set("Forwarded", tt.forwarded)
			}
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xForwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.xForwarded)
			}
			if got := ClientIP(r, tt.trust); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
