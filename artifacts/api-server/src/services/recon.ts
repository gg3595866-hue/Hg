import dns from "node:dns/promises";
import tls from "node:tls";
import type {
  CandidateOriginIp,
  DnsResolverResult,
  ScanResult,
  SslCertificateInfo,
  SubdomainRecord,
} from "@workspace/api-zod";
import { logger } from "../lib/logger";

const NETWORK_TIMEOUT_MS = 6000;

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

type IpOrgInfo = { isp: string | null; org: string | null; asName: string | null };

const ipOrgCache = new Map<string, { info: IpOrgInfo | null; expiresAt: number }>();

async function lookupIpOrg(ip: string): Promise<IpOrgInfo | null> {
  const cached = ipOrgCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.info;
  }
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,isp,org,as`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) {
      ipOrgCache.set(ip, { info: null, expiresAt: Date.now() + 5 * 60 * 1000 });
      return null;
    }
    const data = (await res.json()) as {
      status?: string;
      isp?: string;
      org?: string;
      as?: string;
    };
    if (data.status !== "success") {
      ipOrgCache.set(ip, { info: null, expiresAt: Date.now() + 5 * 60 * 1000 });
      return null;
    }
    const info: IpOrgInfo = {
      isp: data.isp ?? null,
      org: data.org ?? null,
      asName: data.as ?? null,
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
  return { detected: cnames.length > 0 || edgeOrgHaystacks.length > 0, provider: null };
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
        candidates.set(ip, { ip, confidence, sources: [source] });
      }
    }
  }

  return Array.from(candidates.values()).sort(
    (a, b) => CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence],
  );
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

  const bruteForceHosts = COMMON_SUBDOMAIN_WORDLIST.map((word) => `${word}.${hostname}`);
  const mxExchangeHosts = mxHosts
    .map((r) => r.exchange.toLowerCase().replace(/\.$/, ""))
    .filter((host) => host && host !== hostname);

  const candidateHostnames = Array.from(
    new Set([...crtShHosts, ...certSpotterHosts, ...bruteForceHosts, ...mxExchangeHosts]),
  );

  const subdomains = await resolveSubdomains(candidateHostnames);

  const edgeIps = new Set(dnsResults.flatMap((r) => r.addresses));

  const edgeOrgInfos = await Promise.all(
    Array.from(edgeIps)
      .slice(0, 5)
      .map((ip) => lookupIpOrg(ip)),
  );
  const edgeOrgHaystacks = edgeOrgInfos
    .map((info) => `${info?.isp ?? ""} ${info?.org ?? ""} ${info?.asName ?? ""}`)
    .filter(Boolean);

  const { detected: cdnDetected, provider: cdnProvider } = detectCdn(
    cnames,
    sslCertificate.issuer ?? null,
    edgeOrgHaystacks,
  );

  const spfRecord = txtRecords.find((record) => record.toLowerCase().startsWith("v=spf1")) ?? null;

  const candidateOriginIps = await buildCandidateOriginIps(edgeIps, subdomains);

  return {
    originalInput: rawInput,
    hostname,
    cdnDetected,
    cdnProvider,
    edgeIps: Array.from(edgeIps),
    dnsResults,
    sslCertificate,
    mxRecords,
    spfRecord,
    txtRecords,
    subdomains,
    candidateOriginIps,
    scannedAt: new Date().toISOString(),
  };
}
