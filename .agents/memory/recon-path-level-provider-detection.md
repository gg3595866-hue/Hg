---
name: Recon path-level embedded-provider detection
description: DNS/hostname-only scanning misses backend providers embedded at the path level under a shared domain.
---

Reverse-proxy/origin-detection tools that only resolve the hostname (stripping the URL path before scanning) will return identical results no matter which path on a domain is pasted in. This misses embedded third-party backends that are reverse-proxied under a shared domain with no separate DNS entry at all (e.g. a gambling site's `/games-frame/*` or `/en/games` paths transparently proxying to a game-provider platform like 1xGames via `v3.traincdn.com`).

**Why:** DNS/CNAME/CDN-signature analysis can only ever reveal infrastructure that has its own DNS presence. Path-based reverse proxying (same hostname, different backend per path) is invisible to that layer — the only way to detect it is to fetch the *exact* URL/path requested and inspect the live response (status, Server/Via/X-Powered-By headers, Set-Cookie domains, and third-party domains referenced in embedded iframe/script/API URLs in the body).

**How to apply:** Keep hostname-level DNS/CDN detection and path-level content analysis as two distinct, parallel checks. Preserve the full path when a user pastes a URL (don't normalize it away early), fetch that exact URL, and surface any distinct third-party domains found in the response as "embedded providers" separate from the CDN/origin-IP findings.
