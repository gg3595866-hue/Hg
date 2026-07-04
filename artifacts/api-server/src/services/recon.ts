import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import type {
  CandidateOriginIp,
  DnsResolverResult,
  OriginVerifyResult,
  ScanResult,
  SslCertificateInfo,
  SubdomainRecord,
} from "@workspace/api-zod";
import { logger } from "../lib/logger";

const NETWORK_TIMEOUT_MS = 6000;

const ALLOWED_VERIFY_PORTS = new Set([80, 443, 8080, 8443, 8000, 8888, 8081, 3000]);

const PROXY_INDICATOR_HEADERS = [
  "via",
  "x-cache",
  "x-served-by",
  "x-forwarded-for",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-real-ip",
  "x-amz-cf-id",
  "cf-ray",
];

export function isPublicIpv4(ip: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!match) {
    return false;
  }
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((n) => n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = octets;

  if (a === 0) return false; // "this" network
  if (a === 10) return false; // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 127) return false; // loopback
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // RFC1918
  if (a === 192 && b === 0 && octets[2] === 0) return false; // IETF protocol assignments
  if (a === 192 && b === 0 && octets[2] === 2) return false; // TEST-NET-1
  if (a === 192 && b === 88 && octets[2] === 99) return false; // 6to4 relay anycast
  if (a === 192 && b === 168) return false; // RFC1918
  if (a === 198 && b >= 18 && b <= 19) return false; // benchmarking
  if (a === 198 && b === 51 && octets[2] === 100) return false; // TEST-NET-2
  if (a === 203 && b === 0 && octets[2] === 113) return false; // TEST-NET-3
  if (a >= 224) return false; // multicast + reserved (224-255)

  return true;
}

export function isSafeVerifyPort(port: number): boolean {
  return Number.isInteger(port) && ALLOWED_VERIFY_PORTS.has(port);
}

export function isValidHostnameForVerification(hostname: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$/i.test(hostname.trim());
}

function textTrigrams(text: string): Set<string> {
  const normalized = text.toLowerCase().replace(/\s+/g, " ").trim();
  const grams = new Set<string>();
  for (let i = 0; i < normalized.length - 2; i++) {
    grams.add(normalized.slice(i, i + 3));
  }
  return grams;
}

function trigramSimilarity(a: string, b: string): number {
  if (!a || !b) {
    return 0;
  }
  const gramsA = textTrigrams(a);
  const gramsB = textTrigrams(b);
  if (gramsA.size === 0 || gramsB.size === 0) {
    return 0;
  }
  let intersection = 0;
  for (const gram of gramsA) {
    if (gramsB.has(gram)) {
      intersection++;
    }
  }
  const union = gramsA.size + gramsB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function headerOverlapRatio(a: Headers | Record<string, unknown>, b: Record<string, unknown>): number {
  const ignored = new Set(["date", "expires", "etag", "last-modified", "x-request-id", "cf-ray", "set-cookie"]);
  const keysA = new Set(
    (a instanceof Headers ? Array.from(a.keys()) : Object.keys(a))
      .map((k) => k.toLowerCase())
      .filter((k) => !ignored.has(k)),
  );
  const keysB = new Set(
    Object.keys(b)
      .map((k) => k.toLowerCase())
      .filter((k) => !ignored.has(k)),
  );
  if (keysA.size === 0 && keysB.size === 0) {
    return 1;
  }
  let intersection = 0;
  for (const key of keysA) {
    if (keysB.has(key)) {
      intersection++;
    }
  }
  const union = new Set([...keysA, ...keysB]).size;
  return union === 0 ? 0 : intersection / union;
}

async function fetchPublicReference(
  hostname: string,
  useHttps: boolean,
): Promise<{ statusCode: number | null; headers: Headers | null; body: string | null } | null> {
  try {
    const url = `${useHttps ? "https" : "http"}://${hostname}/`;
    const res = await fetch(url, {
      headers: { "User-Agent": "recon-origin-verifier/1.0", Accept: "*/*" },
      redirect: "manual",
      signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
    });
    const body = await res.text().catch(() => "");
    return { statusCode: res.status, headers: res.headers, body: body.slice(0, 2000) };
  } catch (err) {
    logger.warn({ err, hostname }, "Public reference fetch failed");
    return null;
  }
}

const DOH_RESOLVERS: { name: string; buildUrl: (host: string) => string }[] = [
  {
    name: "Cloudflare (1.1.1.1)",
    buildUrl: (host) =>
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
  },
  {
    name: "Google (8.8.8.8)",
    buildUrl: (host) =>
      `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`,
  },
  {
    name: "Quad9 (9.9.9.9)",
    buildUrl: (host) =>
      `https://dns.quad9.net:5053/dns-query?name=${encodeURIComponent(host)}&type=A`,
  },
];

const CDN_SIGNATURES: { provider: string; patterns: RegExp[] }[] = [
  {
    provider: "Cloudflare",
    patterns: [/cloudflare/i, /\.cdn\.cloudflare\.net$/i],
  },
  { provider: "Akamai", patterns: [/akamai/i, /edgekey\.net$/i, /edgesuite\.net$/i] },
  { provider: "Fastly", patterns: [/fastly/i, /\.fastly\.net$/i] },
  { provider: "Amazon CloudFront", patterns: [/cloudfront/i, /\.cloudfront\.net$/i] },
  { provider: "Sucuri", patterns: [/sucuri/i] },
  { provider: "Imperva / Incapsula", patterns: [/imperva/i, /incapdns/i, /incapsula/i] },
  { provider: "StackPath", patterns: [/stackpath/i] },
  { provider: "Google Cloud CDN", patterns: [/googleusercontent/i, /ghs\.google\.com$/i] },
  { provider: "Azure Front Door / CDN", patterns: [/azureedge\.net$/i, /azurefd\.net$/i] },
  { provider: "DDoS-Guard", patterns: [/ddos-guard/i] },
  { provider: "Voxility", patterns: [/voxility/i] },
  { provider: "Qrator", patterns: [/qrator/i] },
  { provider: "Reblaze", patterns: [/reblaze/i] },
  { provider: "BitNinja", patterns: [/bitninja/i] },
  { provider: "Vercel", patterns: [/vercel/i] },
  { provider: "Netlify", patterns: [/netlify/i] },
];

const CDN_ORG_KEYWORDS = [
  "cloudflare",
  "akamai",
  "fastly",
  "amazon",
  "aws",
  "google",
  "microsoft",
  "azure",
  "incapsula",
  "imperva",
  "sucuri",
  "stackpath",
  "edgecast",
  "limelight",
  "level 3",
  "level3",
  "centurylink",
  "ddos-guard",
  "ddos guard",
  "voxility",
  "qrator",
  "reblaze",
  "cachefly",
  "keycdn",
  "vercel",
  "netlify",
  "highwinds",
  "cdn77",
  "g-core",
  "gcore",
];

const ORIGIN_HINT_KEYWORDS = [
  "origin",
  "direct",
  "direct-connect",
  "backend",
  "server",
  "app",
  "api",
  "cpanel",
  "webmail",
  "ftp",
  "ssh",
  "internal",
  "real",
  "host",
  "mail",
  "smtp",
  "admin",
  "portal",
  "vpn",
  "remote",
  "old",
  "legacy",
  "dev",
  "staging",
  "test",
  "backup",
];

const COMMON_SUBDOMAIN_WORDLIST = [
  "origin",
  "origin-www",
  "direct",
  "direct-connect",
  "www",
  "mail",
  "webmail",
  "smtp",
  "ftp",
  "cpanel",
  "admin",
  "portal",
  "vpn",
  "remote",
  "api",
  "app",
  "backend",
  "server",
  "old",
  "legacy",
  "dev",
  "staging",
  "test",
  "beta",
  "m",
  "mobile",
  "cdn",
  "static",
  "assets",
  "media",
  "img",
  "images",
  "secure",
  "login",
  "internal",
  "backup",
  "host",
  "web",
  "web1",
  "web2",
];

const SENSITIVE_ENDPOINT_PATHS = [
  "/admin",
  "/admin/login",
  "/administrator",
  "/admin.php",
  "/admin/index.php",
  "/wp-admin",
  "/wp-login.php",
  "/staff",
  "/staff/login",
  "/staff-login",
  "/employee",
  "/employees",
  "/manage",
  "/management",
  "/manager",
  "/backend",
  "/backend/login",
  "/cpanel",
  "/control-panel",
  "/dashboard",
  "/dashboard/login",
  "/moderator",
  "/panel",
  "/adminpanel",
  "/admincp",
  "/useradmin",
  "/superadmin",
  "/internal",
];

async function probeEndpoint(
  hostname: string,
  useHttps: boolean,
  path: string,
): Promise<{ path: string; url: string; reachable: boolean; statusCode: number | null; found: boolean; error: string | null }> {
  const url = `${useHttps ? "https" : "http"}://${hostname}${path}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "User-Agent": "recon-origin-verifier/1.0", Accept: "*/*" },
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
    const found = res.status !== 404 && res.status < 500;
    return { path, url, reachable: true, statusCode: res.status, found, error: null };
  } catch (err) {
    return {
      path,
      url,
      reachable: false,
      statusCode: null,
      found: false,
      error: err instanceof Error ? err.message : "Request failed",
    };
  }
}

async function probeSensitiveEndpoints(
  hostname: string,
  useHttps: boolean,
): Promise<
  { path: string; url: string; reachable: boolean; statusCode: number | null; found: boolean; error: string | null }[]
> {
  const results = await Promise.all(
    SENSITIVE_ENDPOINT_PATHS.map((path) => probeEndpoint(hostname, useHttps, path)),
  );
  return results;
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("Operation timed out")), ms),
    ),
  ]);
}

export type TargetDetails = {
  hostname: string;
  path: string;
  useHttps: boolean;
  headers: Record<string, string>;
};

// Headers that are unsafe or meaningless to replay verbatim from a pasted
// snippet (either browser-managed, or would break the outbound request).
const UNSAFE_REPLAY_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "origin",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
]);

function extractHeadersFromObjectLiteral(headersSource: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const pairRegex = /["']?([a-zA-Z0-9-]+)["']?\s*:\s*["']((?:\\.|[^"'\\])*)["']/g;
  let match: RegExpExecArray | null;
  while ((match = pairRegex.exec(headersSource)) !== null) {
    const key = match[1].toLowerCase();
    if (UNSAFE_REPLAY_HEADERS.has(key)) continue;
    headers[match[1]] = match[2].replace(/\\(.)/g, "$1");
  }
  return headers;
}

function extractHeadersFromRawHttp(input: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = input.split(/\r?\n/).slice(1);
  for (const line of lines) {
    if (!line.trim()) break;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!key || UNSAFE_REPLAY_HEADERS.has(key.toLowerCase())) continue;
    headers[key] = value;
  }
  return headers;
}

function extractHeadersFromCurl(input: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const headerFlagRegex = /(?:-H|--header)\s+["']([^"']+)["']/g;
  let match: RegExpExecArray | null;
  while ((match = headerFlagRegex.exec(input)) !== null) {
    const idx = match[1].indexOf(":");
    if (idx === -1) continue;
    const key = match[1].slice(0, idx).trim();
    const value = match[1].slice(idx + 1).trim();
    if (!key || UNSAFE_REPLAY_HEADERS.has(key.toLowerCase())) continue;
    headers[key] = value;
  }
  return headers;
}

/**
 * Extracts both the hostname AND the request path/query from the raw input.
 * This matters because the same hostname can route different paths to
 * completely different backends at the application layer (e.g. a betting
 * site's main pages vs. a `/games-frame/service-api/...` path that is
 * actually served by a third-party game provider). DNS/CDN-level analysis
 * alone cannot see that distinction — it only ever "sees" the hostname.
 */
export function extractTargetDetails(rawInput: string): TargetDetails {
  const input = rawInput.trim();
  if (!input) {
    throw new Error("Input is empty.");
  }

  const httpMethodMatch = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP\/\d(\.\d)?/i;
  const httpMethodExec = httpMethodMatch.exec(input);
  if (httpMethodExec) {
    const hostHeaderMatch = input.match(/^Host:\s*(.+)$/im);
    if (!hostHeaderMatch || !hostHeaderMatch[1]) {
      throw new Error("Raw HTTP request did not contain a Host header.");
    }
    const hostValue = hostHeaderMatch[1].trim().replace(/\r$/, "");
    const hostname = hostValue.split(":")[0];
    if (!hostname) {
      throw new Error("Could not parse hostname from Host header.");
    }
    const requestTarget = httpMethodExec[2] || "/";
    return {
      hostname: hostname.toLowerCase(),
      path: requestTarget.startsWith("/") ? requestTarget : `/${requestTarget}`,
      useHttps: true,
      headers: extractHeadersFromRawHttp(input),
    };
  }

  if (/^curl\s/i.test(input)) {
    const urlMatch = input.match(/curl\s+(?:-\S+\s+\S+\s+)*["']?(https?:\/\/[^\s"']+)["']?/i);
    if (urlMatch && urlMatch[1]) {
      try {
        const url = new URL(urlMatch[1]);
        if (url.hostname) {
          return {
            hostname: url.hostname.toLowerCase(),
            path: `${url.pathname}${url.search}` || "/",
            useHttps: url.protocol === "https:",
            headers: extractHeadersFromCurl(input),
          };
        }
      } catch {
        // fall through to generic parsing below
      }
    }
  }

  // JS fetch()/axios/curl-style snippets: pull the first quoted http(s) URL out of the blob.
  const looksLikeCode = /^(fetch|axios|curl|const|let|var|await)\b/i.test(input) || input.includes("fetch(");
  if (looksLikeCode) {
    const urlMatch = input.match(/["'`](https?:\/\/[^\s"'`]+)["'`]/i);
    if (urlMatch && urlMatch[1]) {
      try {
        const url = new URL(urlMatch[1]);
        if (url.hostname) {
          // Pull out the `headers: { ... }` object literal (if any) that
          // typically follows the URL in a fetch() call copied from DevTools,
          // so auth/session headers actually get replayed on the real fetch
          // instead of being silently dropped.
          let headers: Record<string, string> = {};
          const headersBlockMatch = input.match(/headers["']?\s*:\s*\{([^}]*)\}/is);
          if (headersBlockMatch && headersBlockMatch[1]) {
            headers = extractHeadersFromObjectLiteral(headersBlockMatch[1]);
          }
          return {
            hostname: url.hostname.toLowerCase(),
            path: `${url.pathname}${url.search}` || "/",
            useHttps: url.protocol === "https:",
            headers,
          };
        }
      } catch {
        // fall through to generic parsing below
      }
    }
  }

  let candidate = input;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  try {
    const url = new URL(candidate);
    if (!url.hostname) {
      throw new Error("No hostname found in URL.");
    }
    return {
      hostname: url.hostname.toLowerCase(),
      path: `${url.pathname}${url.search}` || "/",
      useHttps: url.protocol === "https:",
      headers: {},
    };
  } catch {
    throw new Error(
      "Could not parse a hostname from the input. Provide a URL (e.g. https://example.com) or a raw HTTP request with a Host header.",
    );
  }
}

export function extractHostname(rawInput: string): string {
  return extractTargetDetails(rawInput).hostname;
}

async function queryDohResolver(
  resolverName: string,
  url: string,
): Promise<DnsResolverResult> {
  try {
    const res = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(NETWORK_TIMEOUT_MS),
    });
    if (!res.ok) {
      return { resolver: resolverName, addresses: [], error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as {
      Answer?: { type: number; data: string }[];
    };
    const addresses = (data.Answer ?? [])
      .filter((a) => a.type === 1)
      .map((a) => a.data);
    return { resolver: resolverName, addresses };
  } catch (err) {
    return {
      resolver: resolverName,
      addresses: [],
      error: err instanceof Error ? err.message : "DNS query failed",
    };
  }
}

async function fetchSslCertificate(hostname: string): Promise<SslCertificateInfo> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: NETWORK_TIMEOUT_MS,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          if (!cert || Object.keys(cert).length === 0) {
            resolve({
              subject: null,
              issuer: null,
              validFrom: null,
              validTo: null,
              altNames: [],
              fingerprint: null,
              error: "No certificate returned by server.",
            });
          } else {
            const altNames = (cert.subjectaltname ?? "")
              .split(",")
              .map((s) => s.trim().replace(/^DNS:/, ""))
              .filter(Boolean);
            const subjectCn = cert.subject?.CN;
            const issuerCn = cert.issuer?.CN;
            resolve({
              subject: Array.isArray(subjectCn) ? (subjectCn[0] ?? null) : (subjectCn ?? null),
              issuer: Array.isArray(issuerCn) ? (issuerCn[0] ?? null) : (issuerCn ?? null),
              validFrom: cert.valid_from ?? null,
              validTo: cert.valid_to ?? null,
              altNames,
              fingerprint: cert.fingerprint256 ?? cert.fingerprint ?? null,
            });
          }
        } catch (err) {
          resolve({
            subject: null,
            issuer: null,
            validFrom: null,
            validTo: null,
            altNames: [],
            fingerprint: null,
            error: err instanceof Error ? err.message : "Failed to read certificate.",
          });
        } finally {
          socket.end();
          socket.destroy();
        }
      },
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        altNames: [],
        fingerprint: null,
        error: "Connection timed out.",
      });
    });

    socket.on("error", (err) => {
      resolve({
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        altNames: [],
        fingerprint: null,
        error: err instanceof Error ? err.message : "TLS connection failed.",
      });
    });
  });
}

async function fetchMxRecords(hostname: string): Promise<string[]> {
  try {
    const records = await withTimeout(dns.resolveMx(hostname), NETWORK_TIMEOUT_MS);
    return records
      .sort((a, b) => a.priority - b.priority)
      .map((r) => `${r.exchange} (priority ${r.priority})`);
  } catch {
    return [];
  }
}

async function fetchTxtRecords(hostname: string): Promise<string[]> {
  try {
    const records = await withTimeout(dns.resolveTxt(hostname), NETWORK_TIMEOUT_MS);
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

async function fetchCname(hostname: string): Promise<string[]> {
  try {
    return await withTimeout(dns.resolveCname(hostname), NETWORK_TIMEOUT_MS);
  } catch {
    return [];
  }
}

async function fetchCrtShSubdomains(hostname: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(`%.${hostname}`)}&output=json`,
      { signal: AbortSignal.timeout(15000) },
    );
    if (!res.ok) {
      return [];
    }
    const data = (await res.json()) as { name_value?: string }[];
    const names = new Set<string>();
    for (const entry of data) {
      const nameValue = entry.name_value ?? "";
      for (const line of nameValue.split("\n")) {
        const cleaned = line.trim().toLowerCase().replace(/^\*\./, "");
        if (
          cleaned &&
          cleaned.endsWith(hostname) &&
          cleaned !== hostname &&
          !cleaned.includes(" ") &&
          !cleaned.includes("*")
        ) {
          names.add(cleaned);
        }
      }
    }
    return Array.from(names).slice(0, 40);
  } catch (err) {
    logger.warn({ err, hostname }, "crt.sh lookup failed");
    return [];
  }
}

async function fetchCertSpotterSubdomains(hostname: string): Promise<string[]> {
  try {
    const res = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(hostname)}&include_subdomains=true&expand=dns_names`,
      { signal: AbortSignal.timeout(15000) },
    );
    if (!res.ok) {
      return [];
    }
    const data = (await res.json()) as { dns_names?: string[] }[];
    const names = new Set<string>();
    for (const entry of data) {
      for (const name of entry.dns_names ?? []) {
        const cleaned = name.trim().toLowerCase().replace(/^\*\./, "");
        if (
          cleaned &&
          cleaned.endsWith(hostname) &&
          cleaned !== hostname &&
          !cleaned.includes(" ") &&
          !cleaned.includes("*")
        ) {
          names.add(cleaned);
        }
      }
    }
    return Array.from(names).slice(0, 40);
  } catch (err) {
    logger.warn({ err, hostname }, "certspotter lookup failed");
    return [];
  }
}

async function resolveSubdomains(hostnames: string[]): Promise<SubdomainRecord[]> {
  const results = await Promise.all(
    hostnames.map(async (host): Promise<SubdomainRecord | null> => {
      try {
        const addresses = await withTimeout(dns.resolve4(host), 4000);
        if (addresses.length === 0) {
          return null;
        }
        return { hostname: host, addresses };
      } catch {
        return null;
      }
    }),
  );
  return results.filter((r): r is SubdomainRecord => r !== null);
}

type IpOrgInfo = {
  isp: string | null;
  org: string | null;
  asName: string | null;
  city: string | null;
  region: string | null;
  country: string | null;
};

const ipOrgCache = new Map<string, { info: IpOrgInfo | null; expiresAt: number }>();

async function lookupIpOrg(ip: string): Promise<IpOrgInfo | null> {
  const cached = ipOrgCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.info;
  }
  try {
    const res = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,isp,org,as,city,regionName,country`,
      { signal: AbortSignal.timeout(4000) },
    );
    if (!res.ok) {
      ipOrgCache.set(ip, { info: null, expiresAt: Date.now() + 5 * 60 * 1000 });
      return null;
    }
    const data = (await res.json()) as {
      status?: string;
      isp?: string;
      org?: string;
      as?: string;
      city?: string;
      regionName?: string;
      country?: string;
    };
    if (data.status !== "success") {
      ipOrgCache.set(ip, { info: null, expiresAt: Date.now() + 5 * 60 * 1000 });
      return null;
    }
    const info: IpOrgInfo = {
      isp: data.isp ?? null,
      org: data.org ?? null,
      asName: data.as ?? null,
      city: data.city ?? null,
      region: data.regionName ?? null,
      country: data.country ?? null,
    };
    ipOrgCache.set(ip, { info, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });
    return info;
  } catch {
    return null;
  }
}

function isCdnOrg(info: IpOrgInfo | null): boolean {
  if (!info) {
    return false;
  }
  const haystack = `${info.isp ?? ""} ${info.org ?? ""} ${info.asName ?? ""}`.toLowerCase();
  return CDN_ORG_KEYWORDS.some((keyword) => haystack.includes(keyword));
}

function formatOrg(info: IpOrgInfo | null): string | null {
  if (!info) {
    return null;
  }
  return info.org || info.isp || info.asName || null;
}

function formatLocation(info: IpOrgInfo | null): string | null {
  if (!info) {
    return null;
  }
  const parts = [info.city, info.region, info.country].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : null;
}

function detectCdn(
  cnames: string[],
  certIssuer: string | null,
  edgeOrgHaystacks: string[],
): { detected: boolean; provider: string | null } {
  const haystacks = [...cnames, certIssuer ?? "", ...edgeOrgHaystacks].filter(Boolean);
  for (const signature of CDN_SIGNATURES) {
    for (const haystack of haystacks) {
      if (signature.patterns.some((pattern) => pattern.test(haystack))) {
        return { detected: true, provider: signature.provider };
      }
    }
  }
  // No known CDN signature matched in cert issuer, CNAME chain, or edge IP ownership.
  // Do not guess: absence of evidence means we treat this as a direct, unproxied origin.
  return { detected: false, provider: null };
}

const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 } as const;

async function buildCandidateOriginIps(
  edgeIps: Set<string>,
  subdomains: SubdomainRecord[],
): Promise<CandidateOriginIp[]> {
  const candidates = new Map<string, CandidateOriginIp>();
  const uniqueCandidateIps = new Set<string>();
  for (const subdomain of subdomains) {
    for (const ip of subdomain.addresses) {
      if (!edgeIps.has(ip)) {
        uniqueCandidateIps.add(ip);
      }
    }
  }

  const orgByIp = new Map<string, IpOrgInfo | null>();
  await Promise.all(
    Array.from(uniqueCandidateIps)
      .slice(0, 25)
      .map(async (ip) => {
        orgByIp.set(ip, await lookupIpOrg(ip));
      }),
  );

  for (const subdomain of subdomains) {
    const looksLikeOrigin = ORIGIN_HINT_KEYWORDS.some((keyword) =>
      subdomain.hostname.includes(keyword),
    );
    for (const ip of subdomain.addresses) {
      if (edgeIps.has(ip)) {
        continue;
      }
      const orgInfo = orgByIp.get(ip) ?? null;
      const cdnOrg = isCdnOrg(orgInfo);
      const orgLabel = formatOrg(orgInfo);
      const locationLabel = formatLocation(orgInfo);
      const source = `subdomain: ${subdomain.hostname}${orgLabel ? ` (${orgLabel})` : ""}`;
      const confidence: CandidateOriginIp["confidence"] = cdnOrg
        ? "low"
        : looksLikeOrigin
          ? "high"
          : "medium";

      const existing = candidates.get(ip);
      if (existing) {
        if (!existing.sources.includes(source)) {
          existing.sources.push(source);
        }
        if (CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[existing.confidence]) {
          existing.confidence = confidence;
        }
      } else {
        candidates.set(ip, {
          ip,
          confidence,
          sources: [source],
          org: orgLabel,
          location: locationLabel,
        });
      }
    }
  }

  return Array.from(candidates.values()).sort(
    (a, b) => CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence],
  );
}

type RawVerifyOutcome = {
  reachable: boolean;
  statusCode: number | null;
  statusText: string | null;
  server: string | null;
  responseTimeMs: number | null;
  tlsCertMatchesHost: boolean | null;
  tlsCertSubject: string | null;
  tlsCertIssuer: string | null;
  bodyPreview: string | null;
  bodyFull: string | null;
  headers: Record<string, unknown>;
  error: string | null;
};

function directRequest(hostname: string, ip: string, port: number, useHttps: boolean): Promise<RawVerifyOutcome> {
  const startedAt = Date.now();

  return new Promise((resolve) => {
    let tlsCertMatchesHost: boolean | null = null;
    let tlsCertSubject: string | null = null;
    let tlsCertIssuer: string | null = null;
    let settled = false;

    const finish = (result: RawVerifyOutcome) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };

    const requestOptions: http.RequestOptions & { servername?: string; rejectUnauthorized?: boolean } = {
      host: ip,
      port,
      path: "/",
      method: "GET",
      headers: {
        Host: hostname,
        "User-Agent": "recon-origin-verifier/1.0",
        Accept: "*/*",
      },
      timeout: NETWORK_TIMEOUT_MS,
    };

    if (useHttps) {
      requestOptions.servername = hostname;
      requestOptions.rejectUnauthorized = false;
    }

    const transport = useHttps ? https : http;
    const req = transport.request(requestOptions, (res) => {
      if (useHttps) {
        const socket = res.socket as tls.TLSSocket;
        try {
          const cert = socket.getPeerCertificate?.();
          if (cert && Object.keys(cert).length > 0) {
            const subjectCn = cert.subject?.CN;
            const issuerCn = cert.issuer?.CN;
            tlsCertSubject = Array.isArray(subjectCn) ? (subjectCn[0] ?? null) : (subjectCn ?? null);
            tlsCertIssuer = Array.isArray(issuerCn) ? (issuerCn[0] ?? null) : (issuerCn ?? null);
            const altNames = (cert.subjectaltname ?? "")
              .split(",")
              .map((s) => s.trim().replace(/^DNS:/, "").toLowerCase());
            tlsCertMatchesHost =
              altNames.includes(hostname.toLowerCase()) ||
              (tlsCertSubject?.toLowerCase() === hostname.toLowerCase()) ||
              altNames.some((name) => name.startsWith("*.") && hostname.toLowerCase().endsWith(name.slice(1)));
          }
        } catch {
          // Certificate inspection failed; leave TLS fields null rather than guessing.
        }
      }

      const chunks: Buffer[] = [];
      let collected = 0;
      res.on("data", (chunk: Buffer) => {
        if (collected < 4096) {
          chunks.push(chunk);
          collected += chunk.length;
        }
      });
      res.on("end", () => {
        const bodyFull = Buffer.concat(chunks).toString("utf8");
        finish({
          reachable: true,
          statusCode: res.statusCode ?? null,
          statusText: res.statusMessage ?? null,
          server: (res.headers["server"] as string) ?? null,
          responseTimeMs: Date.now() - startedAt,
          tlsCertMatchesHost,
          tlsCertSubject,
          tlsCertIssuer,
          bodyPreview: bodyFull.slice(0, 500) || null,
          bodyFull: bodyFull || null,
          headers: res.headers,
          error: null,
        });
      });
    });

    req.on("timeout", () => {
      req.destroy();
      finish({
        reachable: false,
        statusCode: null,
        statusText: null,
        server: null,
        responseTimeMs: null,
        tlsCertMatchesHost: null,
        tlsCertSubject: null,
        tlsCertIssuer: null,
        bodyPreview: null,
        bodyFull: null,
        headers: {},
        error: "Connection timed out.",
      });
    });

    req.on("error", (err) => {
      finish({
        reachable: false,
        statusCode: null,
        statusText: null,
        server: null,
        responseTimeMs: null,
        tlsCertMatchesHost: null,
        tlsCertSubject: null,
        tlsCertIssuer: null,
        bodyPreview: null,
        bodyFull: null,
        headers: {},
        error: err instanceof Error ? err.message : "Connection failed.",
      });
    });

    req.end();
  });
}

export async function verifyOrigin(
  hostname: string,
  ip: string,
  port: number = 443,
  useHttps: boolean = true,
): Promise<OriginVerifyResult> {
  const [direct, publicReference] = await Promise.all([
    directRequest(hostname, ip, port, useHttps),
    fetchPublicReference(hostname, useHttps),
  ]);

  const proxyHeadersDetected = PROXY_INDICATOR_HEADERS.filter(
    (h) => direct.headers[h] !== undefined,
  );

  if (!direct.reachable) {
    return {
      hostname,
      ip,
      reachable: false,
      statusCode: null,
      statusText: null,
      server: null,
      responseTimeMs: null,
      tlsCertMatchesHost: null,
      tlsCertSubject: null,
      tlsCertIssuer: null,
      bodyPreview: null,
      proxyHeadersDetected,
      publicStatusCode: publicReference?.statusCode ?? null,
      publicBodySimilarity: null,
      publicHeaderOverlap: null,
      verdict: "indeterminate",
      verdictReason:
        "Direct connection failed, so no independent signals could be compared. This does not rule out the IP being the origin — it may simply be firewalled against non-standard clients.",
      error: direct.error,
    };
  }

  let publicBodySimilarity: number | null = null;
  let publicHeaderOverlap: number | null = null;
  let statusMatches: boolean | null = null;

  const directBodyLen = (direct.bodyFull ?? "").trim().length;
  const publicBodyLen = (publicReference?.body ?? "").trim().length;
  const bothBodiesTooShortToCompare = directBodyLen < 10 && publicBodyLen < 10;

  if (publicReference) {
    publicBodySimilarity = bothBodiesTooShortToCompare
      ? null
      : trigramSimilarity(direct.bodyFull ?? "", publicReference.body ?? "");
    publicHeaderOverlap = publicReference.headers
      ? headerOverlapRatio(publicReference.headers, direct.headers)
      : null;
    statusMatches = publicReference.statusCode === direct.statusCode;
  }

  const reasons: string[] = [];
  let verdict: OriginVerifyResult["verdict"] = "indeterminate";

  if (proxyHeadersDetected.length > 0) {
    verdict = "possible_proxy";
    reasons.push(
      `Response carries intermediary-proxy headers (${proxyHeadersDetected.join(", ")}), which are not typically added by an application origin.`,
    );
  } else if (publicReference && publicHeaderOverlap !== null && bothBodiesTooShortToCompare) {
    const strongMatch = statusMatches && publicHeaderOverlap > 0.5;
    if (strongMatch) {
      verdict = "likely_origin";
      reasons.push(
        `Both responses had empty/minimal bodies (e.g. redirects), so body content could not be compared. Status match: ${statusMatches}, header overlap: ${(publicHeaderOverlap * 100).toFixed(0)}%, with no proxy-indicative headers.`,
      );
    } else {
      verdict = "indeterminate";
      reasons.push(
        `Response bodies were too short to compare (likely redirects). Status match: ${statusMatches}, header overlap: ${(publicHeaderOverlap * 100).toFixed(0)}% — not enough signal to confirm a match.`,
      );
    }
  } else if (publicReference && publicBodySimilarity !== null && publicHeaderOverlap !== null) {
    const strongMatch = statusMatches && publicBodySimilarity > 0.6 && publicHeaderOverlap > 0.5;
    const weakMatch = publicBodySimilarity < 0.25 || statusMatches === false;
    if (strongMatch) {
      verdict = "likely_origin";
      reasons.push(
        `Direct-IP response closely matches the public hostname's response (status match: ${statusMatches}, body similarity: ${(publicBodySimilarity * 100).toFixed(0)}%, header overlap: ${(publicHeaderOverlap * 100).toFixed(0)}%) with no proxy-indicative headers.`,
      );
    } else if (weakMatch) {
      verdict = "possible_proxy";
      reasons.push(
        `Direct-IP response diverges from the public hostname's response (status match: ${statusMatches}, body similarity: ${(publicBodySimilarity * 100).toFixed(0)}%) — this IP may be a different backend, proxy hop, or serving a different vhost.`,
      );
    } else {
      verdict = "indeterminate";
      reasons.push("Signals are mixed — some similarity to the public response, but not enough to confirm a match.");
    }
  } else {
    reasons.push(
      "Could not fetch the public hostname for comparison, so origin status could not be cross-checked. Reachability and TLS cert match were confirmed independently.",
    );
  }

  if (direct.tlsCertMatchesHost === false) {
    verdict = "possible_proxy";
    reasons.push("TLS certificate presented by this IP does not match the target hostname.");
  }

  return {
    hostname,
    ip,
    reachable: true,
    statusCode: direct.statusCode,
    statusText: direct.statusText,
    server: direct.server,
    responseTimeMs: direct.responseTimeMs,
    tlsCertMatchesHost: direct.tlsCertMatchesHost,
    tlsCertSubject: direct.tlsCertSubject,
    tlsCertIssuer: direct.tlsCertIssuer,
    bodyPreview: direct.bodyPreview,
    proxyHeadersDetected,
    publicStatusCode: publicReference?.statusCode ?? null,
    publicBodySimilarity,
    publicHeaderOverlap,
    verdict,
    verdictReason: reasons.join(" "),
    error: null,
  };
}

const PROXY_REQUEST_BODY_LIMIT_BYTES = 512 * 1024; // 512KB

export type ProxyRequestOptions = {
  hostname: string;
  ip: string;
  port: number;
  useHttps: boolean;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string | null;
};

export type ProxyRequestOutcome = {
  reachable: boolean;
  statusCode: number | null;
  statusText: string | null;
  responseTimeMs: number | null;
  headers: Record<string, string>;
  body: string | null;
  bodyTruncated: boolean;
  error: string | null;
};

export function sendProxyRequest(options: ProxyRequestOptions): Promise<ProxyRequestOutcome> {
  const { hostname, ip, port, useHttps, method, path, headers, body } = options;
  const startedAt = Date.now();
  const normalizedMethod = method.toUpperCase();
  const hasBody = body != null && body.length > 0 && normalizedMethod !== "GET" && normalizedMethod !== "HEAD";
  const bodyBuffer = hasBody ? Buffer.from(body as string, "utf8") : undefined;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: ProxyRequestOutcome) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const requestHeaders: Record<string, string> = {
      "User-Agent": "recon-request-tool/1.0",
      Accept: "*/*",
      ...(headers ?? {}),
      Host: hostname,
    };
    if (bodyBuffer) {
      requestHeaders["Content-Length"] = String(bodyBuffer.length);
    }

    const requestOptions: http.RequestOptions & { servername?: string; rejectUnauthorized?: boolean } = {
      host: ip,
      port,
      path: path.startsWith("/") ? path : `/${path}`,
      method: normalizedMethod,
      headers: requestHeaders,
      timeout: NETWORK_TIMEOUT_MS,
    };

    if (useHttps) {
      requestOptions.servername = hostname;
      requestOptions.rejectUnauthorized = false;
    }

    const transport = useHttps ? https : http;
    const req = transport.request(requestOptions, (res) => {
      const chunks: Buffer[] = [];
      let collected = 0;
      let truncated = false;
      res.on("data", (chunk: Buffer) => {
        if (collected < PROXY_REQUEST_BODY_LIMIT_BYTES) {
          const remaining = PROXY_REQUEST_BODY_LIMIT_BYTES - collected;
          chunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
          collected += chunk.length;
          if (collected >= PROXY_REQUEST_BODY_LIMIT_BYTES) {
            truncated = true;
          }
        } else {
          truncated = true;
        }
      });
      res.on("end", () => {
        const responseHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value === undefined) continue;
          responseHeaders[key] = Array.isArray(value) ? value.join(", ") : String(value);
        }
        finish({
          reachable: true,
          statusCode: res.statusCode ?? null,
          statusText: res.statusMessage ?? null,
          responseTimeMs: Date.now() - startedAt,
          headers: responseHeaders,
          body: Buffer.concat(chunks).toString("utf8"),
          bodyTruncated: truncated,
          error: null,
        });
      });
    });

    req.on("timeout", () => {
      req.destroy();
      finish({
        reachable: false,
        statusCode: null,
        statusText: null,
        responseTimeMs: null,
        headers: {},
        body: null,
        bodyTruncated: false,
        error: "Connection timed out.",
      });
    });

    req.on("error", (err) => {
      finish({
        reachable: false,
        statusCode: null,
        statusText: null,
        responseTimeMs: null,
        headers: {},
        body: null,
        bodyTruncated: false,
        error: err instanceof Error ? err.message : "Connection failed.",
      });
    });

    if (bodyBuffer) {
      req.write(bodyBuffer);
    }
    req.end();
  });
}

const PAGE_ANALYSIS_BODY_LIMIT_BYTES = 1_500_000; // 1.5MB, enough for most HTML/JSON payloads

// Infra/CDN/tracking domains that show up on almost every site and are noise
// for the purpose of finding a *distinct backend provider*.
const EMBEDDED_PROVIDER_NOISE_SUFFIXES = [
  "googleapis.com",
  "gstatic.com",
  "google.com",
  "google-analytics.com",
  "googletagmanager.com",
  "doubleclick.net",
  "facebook.com",
  "facebook.net",
  "cloudflare.com",
  "cloudflareinsights.com",
  "jsdelivr.net",
  "cdnjs.cloudflare.com",
  "fontawesome.com",
  "gravatar.com",
  "w3.org",
  "schema.org",
  "sentry.io",
  "recaptcha.net",
];

function isNoiseDomain(domain: string, rootHostname: string): boolean {
  if (domain === rootHostname || domain.endsWith(`.${rootHostname}`) || rootHostname.endsWith(`.${domain}`)) {
    return true;
  }
  return EMBEDDED_PROVIDER_NOISE_SUFFIXES.some((suffix) => domain === suffix || domain.endsWith(`.${suffix}`));
}

// Path/extension patterns typical of static frontend assets (JS/CSS bundles,
// fonts, images, i18n dictionaries, version manifests) served off a CDN —
// these are NOT the backend that processes requests, just files the browser
// downloads. Distinguishing this from a real API/backend host is the whole
// point of classification: a domain serving only `*.js`/`*.css`/`version.json`
// is an asset CDN, not "the provider actually running the game/bet logic".
const STATIC_ASSET_PATH_PATTERNS = [
  /\.(js|mjs|css|map)(\?|$)/i,
  /\.(png|jpe?g|gif|svg|webp|ico|avif)(\?|$)/i,
  /\.(woff2?|ttf|eot|otf)(\?|$)/i,
  /\.(mp3|mp4|webm|ogg)(\?|$)/i,
  /\/(main-static|sys-static|static|assets|genfiles|dist|build)\//i,
  /\/version\.json(\?|$)/i,
  /\.json(\?|$)/i, // generic JSON dictionaries/locale files served alongside the above are usually static too, but is de-prioritized vs API path hints below
];

// Path patterns that indicate a real API/backend/game-logic endpoint rather
// than a static file — these override the static-asset classification even
// if the URL also happens to end in `.json`.
const API_BACKEND_PATH_PATTERNS = [
  /\/api\//i,
  /\/service-api\//i,
  /\/graphql/i,
  /\bws:\/\/|wss:\/\//i,
  /\/socket\.io/i,
  /\/(ws|websocket)\//i,
  /\/(auth|login|session|bet|wager|game-engine|gameengine|notifications?)\//i,
];

function classifyProviderPath(matchedUrl: string): "static-asset-cdn" | "api-or-backend" | "unknown" {
  if (API_BACKEND_PATH_PATTERNS.some((re) => re.test(matchedUrl))) return "api-or-backend";
  if (STATIC_ASSET_PATH_PATTERNS.some((re) => re.test(matchedUrl))) return "static-asset-cdn";
  return "unknown";
}

function classifyProvider(matchedUrls: string[]): "static-asset-cdn" | "api-or-backend" | "unknown" {
  if (matchedUrls.length === 0) return "unknown";
  const classifications = matchedUrls.map(classifyProviderPath);
  // Any single API/backend-looking hit is enough to flag the domain as a
  // real backend, even if most other requests to it are static assets.
  if (classifications.some((c) => c === "api-or-backend")) return "api-or-backend";
  // Otherwise, if we have ANY static-asset signal (and no backend signal),
  // treat it as a static-asset CDN — a bare/no-path reference alongside real
  // `.css`/`.js` hits shouldn't dilute that classification down to "unknown".
  if (classifications.some((c) => c === "static-asset-cdn")) return "static-asset-cdn";
  return "unknown";
}

/**
 * Fetches the EXACT path the user pasted (not just the hostname root) and
 * inspects the live response for signs that it is actually served by a
 * different backend/provider than the main site — e.g. a `Server` header
 * that doesn't match the main site, or other domains referenced inside the
 * JSON/HTML body (game asset CDNs, iframe sources, provider API hosts).
 * This is what lets the tool tell "1xbet.com the website" apart from
 * "1xgames, the third party actually serving /games-frame/service-api/...".
 */
export async function analyzePageForEmbeddedProviders(
  hostname: string,
  path: string,
  useHttps: boolean,
  customHeaders: Record<string, string> = {},
): Promise<{
  fetchedUrl: string;
  reachable: boolean;
  statusCode: number | null;
  contentType: string | null;
  serverHeader: string | null;
  poweredByHeader: string | null;
  viaHeader: string | null;
  setCookieDomains: string[];
  embeddedProviders: {
    domain: string;
    occurrences: number;
    sources: string[];
    sampleContext: string | null;
    providerType: "static-asset-cdn" | "api-or-backend" | "unknown";
    matchedPaths: string[];
  }[];
  requestHeadersApplied: string[];
  error: string | null;
}> {
  const scheme = useHttps ? "https" : "http";
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const fetchedUrl = `${scheme}://${hostname}${normalizedPath}`;
  const requestHeadersApplied = Object.keys(customHeaders);

  try {
    const res = await fetch(fetchedUrl, {
      method: "GET",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        Accept: "*/*",
        // Custom headers extracted from a pasted fetch()/curl/raw-HTTP snippet
        // (e.g. an `x-auth`/`Authorization` bearer token) are replayed here —
        // without this, authenticated API/game-backend endpoints just 401 and
        // reveal nothing, even though the user supplied valid credentials.
        ...customHeaders,
      },
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });

    const contentType = res.headers.get("content-type");
    const serverHeader = res.headers.get("server");
    const poweredByHeader = res.headers.get("x-powered-by");
    const viaHeader = res.headers.get("via");

    const setCookieDomains = new Set<string>();
    const setCookieHeader =
      typeof (res.headers as any).getSetCookie === "function"
        ? ((res.headers as any).getSetCookie() as string[])
        : res.headers.get("set-cookie")
          ? [res.headers.get("set-cookie") as string]
          : [];
    for (const cookie of setCookieHeader) {
      const domainMatch = /domain=([^;]+)/i.exec(cookie);
      if (domainMatch && domainMatch[1]) {
        setCookieDomains.add(domainMatch[1].trim().replace(/^\./, "").toLowerCase());
      }
    }

    const buffer = await res.arrayBuffer();
    const truncated = buffer.byteLength > PAGE_ANALYSIS_BODY_LIMIT_BYTES;
    const body = Buffer.from(
      truncated ? buffer.slice(0, PAGE_ANALYSIS_BODY_LIMIT_BYTES) : buffer,
    ).toString("utf8");

    const domainHits = new Map<
      string,
      { count: number; sources: Set<string>; sample: string | null; paths: Set<string> }
    >();

    const recordHit = (domain: string, source: string, context: string | null, matchedUrl: string | null) => {
      const clean = domain.toLowerCase().replace(/^\.+/, "");
      if (!clean || isNoiseDomain(clean, hostname)) return;
      const existing = domainHits.get(clean);
      if (existing) {
        existing.count += 1;
        existing.sources.add(source);
        if (!existing.sample && context) existing.sample = context;
        if (matchedUrl) existing.paths.add(matchedUrl);
      } else {
        domainHits.set(clean, {
          count: 1,
          sources: new Set([source]),
          sample: context,
          paths: new Set(matchedUrl ? [matchedUrl] : []),
        });
      }
    };

    for (const domain of setCookieDomains) {
      recordHit(domain, "Set-Cookie domain", null, null);
    }

    const iframeRegex = /<iframe[^>]+src=["']([^"']+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = iframeRegex.exec(body)) !== null) {
      try {
        const url = new URL(match[1], fetchedUrl);
        recordHit(url.hostname, "<iframe> src", match[0].slice(0, 200), url.toString());
      } catch {
        // ignore unparsable src (relative/data URIs etc.)
      }
    }

    const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    while ((match = scriptRegex.exec(body)) !== null) {
      try {
        const url = new URL(match[1], fetchedUrl);
        recordHit(url.hostname, "<script> src", match[0].slice(0, 200), url.toString());
      } catch {
        // ignore
      }
    }

    // Absolute URLs referenced anywhere in HTML/JSON/JS (API endpoints, asset
    // CDNs, provider hosts embedded in inline scripts or JSON payloads).
    const urlRegex =
      /https?:\/\/([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s"'<>)]*)?/gi;
    while ((match = urlRegex.exec(body)) !== null) {
      try {
        const url = new URL(match[0]);
        recordHit(url.hostname, "Referenced URL in response body", null, match[0]);
      } catch {
        // ignore
      }
    }

    const embeddedProviders = Array.from(domainHits.entries())
      .map(([domain, info]) => {
        const matchedPaths = Array.from(info.paths).slice(0, 10);
        return {
          domain,
          occurrences: info.count,
          sources: Array.from(info.sources),
          sampleContext: info.sample,
          providerType: classifyProvider(matchedPaths),
          matchedPaths,
        };
      })
      .sort((a, b) => {
        const priority = { "api-or-backend": 2, unknown: 1, "static-asset-cdn": 0 } as const;
        const priorityDiff = priority[b.providerType] - priority[a.providerType];
        if (priorityDiff !== 0) return priorityDiff;
        return b.occurrences - a.occurrences;
      })
      .slice(0, 20);

    return {
      fetchedUrl,
      reachable: true,
      statusCode: res.status,
      contentType,
      serverHeader,
      poweredByHeader,
      viaHeader,
      setCookieDomains: Array.from(setCookieDomains),
      embeddedProviders,
      requestHeadersApplied,
      error: null,
    };
  } catch (err) {
    return {
      fetchedUrl,
      reachable: false,
      statusCode: null,
      contentType: null,
      serverHeader: null,
      poweredByHeader: null,
      viaHeader: null,
      setCookieDomains: [],
      embeddedProviders: [],
      requestHeadersApplied,
      error: err instanceof Error ? err.message : "Failed to fetch the requested path.",
    };
  }
}

export async function scanTarget(rawInput: string): Promise<ScanResult> {
  const { hostname, path, useHttps: requestedUseHttps, headers: requestedHeaders } = extractTargetDetails(rawInput);

  const [dnsResults, sslCertificate, mxRecords, mxHosts, txtRecords, cnames, crtShHosts, certSpotterHosts] =
    await Promise.all([
      Promise.all(
        DOH_RESOLVERS.map((resolver) =>
          queryDohResolver(resolver.name, resolver.buildUrl(hostname)),
        ),
      ),
      fetchSslCertificate(hostname),
      fetchMxRecords(hostname),
      dns.resolveMx(hostname).catch(() => []),
      fetchTxtRecords(hostname),
      fetchCname(hostname),
      fetchCrtShSubdomains(hostname),
      fetchCertSpotterSubdomains(hostname),
    ]);

  const useHttpsForProbes = !sslCertificate.error;
  const [sensitiveEndpoints, pageAnalysis] = await Promise.all([
    probeSensitiveEndpoints(hostname, useHttpsForProbes),
    analyzePageForEmbeddedProviders(hostname, path, requestedUseHttps, requestedHeaders),
  ]);

  const bruteForceHosts = COMMON_SUBDOMAIN_WORDLIST.map((word) => `${word}.${hostname}`);
  const mxExchangeHosts = mxHosts
    .map((r) => r.exchange.toLowerCase().replace(/\.$/, ""))
    .filter((host) => host && host !== hostname);

  const candidateHostnames = Array.from(
    new Set([...crtShHosts, ...certSpotterHosts, ...bruteForceHosts, ...mxExchangeHosts]),
  );

  const subdomains = await resolveSubdomains(candidateHostnames);

  const edgeIps = new Set(dnsResults.flatMap((r) => r.addresses));

  const edgeIpList = Array.from(edgeIps).slice(0, 5);
  const edgeOrgInfos = await Promise.all(edgeIpList.map((ip) => lookupIpOrg(ip)));
  const edgeOrgHaystacks = edgeOrgInfos
    .map((info) => `${info?.isp ?? ""} ${info?.org ?? ""} ${info?.asName ?? ""}`)
    .filter(Boolean);
  const edgeIpDetails = edgeIpList.map((ip, i) => ({
    ip,
    org: formatOrg(edgeOrgInfos[i] ?? null),
    location: formatLocation(edgeOrgInfos[i] ?? null),
  }));

  const { detected: cdnDetected, provider: cdnProvider } = detectCdn(
    cnames,
    sslCertificate.issuer ?? null,
    edgeOrgHaystacks,
  );

  const spfRecord = txtRecords.find((record) => record.toLowerCase().startsWith("v=spf1")) ?? null;

  const candidateOriginIps = cdnDetected
    ? await buildCandidateOriginIps(edgeIps, subdomains)
    : edgeIpList.map((ip, i) => ({
        ip,
        confidence: "medium" as const,
        sources: [
          "No known CDN/proxy signature detected on this edge IP — it is directly reachable and not confirmed as an origin. Use Verify & Reach Origin for stronger evidence.",
        ],
        org: formatOrg(edgeOrgInfos[i] ?? null),
        location: formatLocation(edgeOrgInfos[i] ?? null),
      }));

  return {
    originalInput: rawInput,
    hostname,
    requestedPath: path,
    cdnDetected,
    cdnProvider,
    edgeIps: Array.from(edgeIps),
    edgeIpDetails,
    dnsResults,
    sslCertificate,
    mxRecords,
    spfRecord,
    txtRecords,
    subdomains,
    candidateOriginIps,
    pageAnalysis,
    sensitiveEndpoints,
    scannedAt: new Date().toISOString(),
  };
}
