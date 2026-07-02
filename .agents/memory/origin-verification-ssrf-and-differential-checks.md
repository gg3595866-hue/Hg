---
name: Origin verification SSRF guard + differential comparison
description: Any "connect directly to a user-supplied IP/port" feature needs SSRF input validation and multi-signal comparison, not single-signal confidence claims.
---

Any endpoint that takes a user-supplied IP/hostname/port and makes a server-side connection to it (e.g. "verify this candidate origin IP") is an SSRF vector and must validate before dialing out:
- IP must parse as IPv4 and be public/routable — reject private (10/8, 172.16/12, 192.168/16), loopback, link-local, CGNAT, TEST-NET, multicast/reserved ranges.
- Port must be checked against an allowlist of expected web ports, not accepted as an arbitrary integer.
- Hostname must match a strict hostname regex before being used in a `Host` header or TLS SNI.
Reject with 400 before any network call is made — validation must happen in the route handler, not just deep in the service function.

**Why:** without this, the endpoint is a generic internal-network port scanner/proxy for the caller (classic SSRF). An architect/security review flagged exactly this pattern.

**How to apply:** for confidence/verdict claims (e.g. "is this IP the real origin behind a CDN/proxy?"), never infer a verdict from a single signal (e.g. "no CDN signature detected" or "TLS cert matches"). Combine independent signals: differential fetch of the public hostname vs. the direct IP (compare status code, header set overlap, response body similarity), plus explicit detection of proxy-indicator headers (`Via`, `X-Cache`, `X-Served-By`, `X-Forwarded-*`, `CF-Ray`, etc.) in the direct response. Watch for degenerate comparisons: if both responses are redirects with empty/near-empty bodies, body-similarity scoring falsely returns 0 — detect that case and fall back to status+header comparison instead of treating it as a mismatch. Report an explicit `indeterminate` verdict rather than defaulting to a confident one when signals are missing or unreachable.
