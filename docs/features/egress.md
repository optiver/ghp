# Outbound Proxy Pool

ghp can distribute GitHub-bound requests across a pool of HTTP or HTTPS forward
proxies. Each request uses one selected proxy for its entire lifetime, including
streaming responses. HTTPS destinations use CONNECT, just as they do with
`HTTPS_PROXY`.

Configure the pool in the server YAML and restart ghp:

```yaml
egress:
  strategy: weighted_round_robin
  proxies:
    - name: egress-a
      url: http://proxy-a.internal:3128
      weight: 3
    - name: egress-b
      url: http://proxy-b.internal:3128
      weight: 1
```

With this configuration, weighted round robin sends approximately three
requests through `egress-a` for each request through `egress-b`.

## Choosing a Strategy

| `strategy` | Selection | Suitable for |
|------------|-----------|--------------|
| `weighted_round_robin` (default) | Smoothly distributes requests in proportion to member weights | General use; equal weights provide ordinary round robin |
| `least_connections` | Chooses the lowest active-operation count divided by weight, with weighted round robin for ties | Mixed short API requests and long downloads or streams |
| `ip_hash` | Weighted rendezvous hashing of client IP and stable member name | Keeping a client's requests on a consistent egress proxy |

`least_connections` measures active requests/streams, including response bodies
that are still being consumed, rather than idle TCP sockets. HTTP/2 can carry
many active requests over one socket. The go-git cache warmer reserves one
member for a complete fetch session, which counts as one active operation.
Load counts are local to each ghp process.

`ip_hash` uses the same client IP policy as access logs and authentication rate
limits. Behind a trusted ingress proxy, configure `server.client_ip_header` to
the header that proxy sets. Otherwise the connection's peer address is used.
IPv4 and IPv6 addresses are normalized and source ports are ignored. Clients
sharing a NAT share affinity, so their traffic may be unevenly distributed.
Reordering members does not change affinity; changing names or weights can.
Background requests without a client IP use weighted round robin. The pool
preserves affinity metadata for lookups triggered by a client request.

## Compatibility and Routing

| Configuration | Behavior |
|---------------|----------|
| No `egress` section, or `proxies: []` | Existing default transport behavior, including `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` |
| One member | All eligible requests use that proxy |
| Multiple members | Requests use the selected strategy |
| Destination matches `NO_PROXY` | Direct connection, bypassing both the pool and environment proxy addresses |

An explicit pool takes precedence over `HTTP_PROXY` and `HTTPS_PROXY` for the
GitHub-facing clients. Standard uppercase/lowercase environment precedence,
`NO_PROXY` matching, and implicit localhost/loopback bypasses still apply.
Without either a pool or an environment proxy, connections remain direct.

To migrate an existing single proxy from `HTTPS_PROXY` into YAML:

```yaml
egress:
  proxies:
    - name: existing-proxy
      url: http://proxy.internal:3128
```

The pool covers API/GraphQL forwarding, Git/web traffic, Copilot, codeload,
OAuth exchanges and refreshes, identity/team lookups, GitHub App requests,
management API GitHub lookups, and git-cache fetches. Configured GitHub
Enterprise Server destinations also use the pool. Existing destination URLs,
Host headers, timeouts, redirect rules, and token/scope checks are retained.

Release-mirror HEAD probes, database/Vault connections, telemetry exports, and
CLI connections to ghp keep their existing routing. Redirects returned to a
client are still followed by that client, outside ghp.

## Configuration Details

Member names must be unique, start with a letter or digit, and contain only
letters, digits, dots, underscores, or hyphens (maximum 64 characters). Use
stable names for IP affinity. URLs must be absolute `http://` or `https://`
proxy endpoints without a path, query, or fragment; a trailing `/` is allowed.
Omitted weights default to 1; explicit weights must be between 1 and 10000.
A pool supports up to 256 members and rejects duplicate normalized endpoints.

Proxy Basic authentication can be supplied as URL userinfo, for example
`https://username:password@proxy.internal:3128`. Percent-encode reserved
characters in credentials. Protect the configuration file as a secret. Proxy
credentials are separate from GitHub Authorization, and pool errors identify
the member by name without printing its URL. TLS certificate verification
remains enabled for HTTPS proxies and HTTPS destinations.

The member list is YAML-only. `GHP_EGRESS_STRATEGY` overrides `egress.strategy`.
Pool membership, weights, strategy, and environment proxy/bypass changes take
effect after a process restart; `SIGUSR1` does not update the pool.

## Errors and Rate Limits

A failed request returns through the existing handler's error path. The pool
does not retry on another member, mark members unhealthy, or fall back to
direct egress after a failure. This avoids replaying writes or consumed request
bodies. All configured members remain eligible; remove an unavailable member
from config and restart ghp if necessary. Standard HTTP transport retries of
safe requests on stale connections remain within the selected member.

The pool leaves GitHub responses to the existing handlers and applies no
rate-limit policy. In particular, a 403 or 429 does not trigger a retry on a
different proxy. Separate public egress IPs can distribute IP-based load;
proxies sharing one NAT do not provide that benefit. GitHub user, credential,
and App-installation quotas continue to apply across pool members.
