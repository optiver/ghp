**Upstream proxy load balancing — implementation decisions**

The pool uses standard HTTP(S) forward proxies, including CONNECT for HTTPS,
and covers ghp's server-side GitHub clients. Configuration and operational
examples are in [Outbound Proxy Pool](../features/egress.md).

Following review, the implementation focuses on configurable selection and
transport injection. Health probes, cooldowns, automatic failover/retries,
rate-limit policy, new metrics, and live configuration reload are separate
features. Pool changes require a restart.

The implementation has three boundaries:

1. `internal/egress` validates configuration, selects a member, reuses its HTTP
   transport, and accounts for active response streams. A Selector interface
   separates weighted round robin, weighted least connections, and weighted IP
   hashing from transport and lifecycle management. The pool does not alter
   destination routing, GitHub authentication, or handler response policies.
2. `internal/server` constructs one pool and injects its transport into existing
   clients before starting outbound work. Small startup setters and existing
   constructor options preserve client timeouts and redirect behavior. Trusted
   client-IP metadata is added to request context for IP affinity.
3. go-git's per-fetch ProxyOptions use a pool lease because go-git lacks a
   per-fetch HTTP-client injection point. The complete fetch session counts as
   one operation. The adapter does not replace go-git's global protocol map.

An omitted or empty pool returns no custom transport, preserving environment
proxy settings. Explicit members override HTTP_PROXY/HTTPS_PROXY for the
included clients, while standard NO_PROXY and loopback bypasses still apply.
Proxy credentials are isolated from GitHub Authorization and redacted in pool
errors. Internal mirror probes, databases, telemetry, and CLI connections to
management endpoints retain their existing routing.

Tests cover configuration, distribution and affinity, concurrent reservations,
HTTP/HTTPS CONNECT, HTTP/2 reuse, streaming/cancellation, protocol upgrades,
proxy authentication, environment compatibility, no cross-proxy replay, OAuth
context propagation, App registry reload/SDK requests, and the go-git adapter.
