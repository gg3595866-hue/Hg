---
name: Recon CDN detection fallback bug
description: Signature-based CDN detection needs a strict "no evidence = not detected" default, not a permissive fallback.
---

When building CDN/reverse-proxy detection logic (matching cert issuer, CNAME chain, edge IP org against known CDN signatures), the fallback for "no signature matched" must be `detected: false`, not `detected: (cnames.length > 0 || edgeOrgHaystacks.length > 0)`.

**Why:** A permissive fallback treats "we found some CNAME or resolved some IP org" as CDN evidence, even though nearly every domain has *some* CNAME or resolvable IP owner. This silently mislabels direct-origin hosts (no CDN in front at all) as CDN-protected, which is the opposite of what a recon tool should report — and hides the single most useful finding (the origin is already exposed, unproxied).

**How to apply:** Only mark `cdnDetected: true` when a real signature match occurs (known CDN provider pattern in cert issuer / CNAME / edge org). When no CDN is detected, surface the edge IP itself as the likely origin (high confidence, "no CDN/proxy signature detected" as the source) rather than leaving results empty.
