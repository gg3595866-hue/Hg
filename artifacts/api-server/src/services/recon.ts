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

export function extractHostname(rawInput: string): string {
  const input = rawInput.trim();
  if (!input) {
    throw new Error("Input is empty.");
  }

  const httpMethodMatch = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP\/\d(\.\d)?/i;
  if (httpMethodMatch.test(input)) {
    const hostHeaderMatch = input.match(/^Host:\s*(.+)$/im);
    if (!hostHeaderMatch || !hostHeaderMatch[1]) {
      throw new Error("Raw HTTP request did not contain a Host header.");
    }
    const hostValue = hostHeaderMatch[1].trim().replace(/\r$/, "");
    const hostname = hostValue.split(":")[0];
    if (!hostname) {
      throw new Error("Could not parse hostname from Host header.");
    }
    return hostname.toLowerCase();
  }

  // JS fetch()/axios/curl-style snippets: pull the first quoted http(s) URL out of the blob.
  const looksLikeCode = /^(fetch|axios|curl|const|let|var|await)\b/i.test(input) || input.includes("fetch(");
  if (looksLikeCode) {
    const urlMatch = input.match(/["'`](https?:\/\/[^\s"'`]+)["'`]/i);
    if (urlMatch && urlMatch[1]) {
      try {
        const url = new URL(urlMatch[1]);
        if (url.hostname) {
          return url.hostname.toLowerCase();
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
    return url.hostname.toLowerCase();
  } catch {
    throw new Error(
      "Could not parse a hostname from the input. Provide a URL (e.g. https://example.com) or a raw HTTP request with a Host header.",
    );
  }
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

export async function scanTarget(rawInput: string): Promise<ScanResult> {
  const hostname = extractHostname(rawInput);

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
  const sensitiveEndpoints = await probeSensitiveEndpoints(hostname, useHttpsForProbes);

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
    sensitiveEndpoints,
    scannedAt: new Date().toISOString(),
  };
}
