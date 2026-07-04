---
name: Recon header forwarding from pasted snippets
description: Custom headers (auth tokens) from a pasted fetch()/curl/raw-HTTP snippet must be replayed on the analysis fetch, not just the URL.
---

When a scanning/analysis tool lets users paste a fetch()/curl/raw-HTTP snippet to identify a target, extracting only the URL and discarding the headers silently breaks any authenticated endpoint: the analysis fetch gets a 401 with no way to distinguish "not a real endpoint" from "auth was dropped by our own extractor."

**Why:** A user can verify their own token works via direct curl (200 + real data) while the tool's own re-fetch of the exact same URL fails, because the tool never forwarded the `Authorization`/`x-auth`/cookie headers embedded in the pasted snippet — only the hostname+path made it through.

**How to apply:** When parsing pasted request snippets (raw HTTP, `fetch(url, {headers: {...}})`, `curl -H "..."`), extract headers alongside the URL and thread them through to the actual analysis request, merged on top of default safety headers (User-Agent/Accept) so custom headers add/override rather than replace. Block-list browser-managed/connection-breaking headers (`host`, `content-length`, `connection`, `origin`, `sec-fetch-*`) from replay. Surface which header *names* (never values) were applied in the response so the UI can confirm forwarding without echoing sensitive tokens back.
