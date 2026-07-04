import { useState } from "react";
import { ScanResult, CandidateOriginIp, CandidateOriginIpConfidence, DnsResolverResult, SslCertificateInfo, SubdomainRecord, useVerifyOrigin, OriginVerifyResult } from "@workspace/api-client-react";
import { Shield, ShieldAlert, ShieldCheck, Server, Globe, Lock, Mail, Database, ChevronRight, AlertCircle, Fingerprint, Zap, CheckCircle2, XCircle, Loader2, Puzzle, LinkIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import RequestTool from "@/components/RequestTool";

export default function ScanResults({ result }: { result: ScanResult }) {
  const useHttps = result.sslCertificate && !result.sslCertificate.error;

  
  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      
      {/* Target Summary */}
      <section className="bg-card border border-border p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Target Host</div>
          <div className="text-2xl font-bold flex items-center gap-3">
            {result.hostname}
            {result.cdnDetected ? (
              <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500/50 rounded-none uppercase text-xs tracking-wider">
                Proxy Detected
              </Badge>
            ) : (
              <Badge variant="outline" className="bg-primary/10 text-primary border-primary/50 rounded-none uppercase text-xs tracking-wider">
                Direct Origin
              </Badge>
            )}
          </div>
          {result.requestedPath && result.requestedPath !== "/" && (
            <div className="text-xs font-mono text-muted-foreground mt-1 break-all">
              Path analyzed: <span className="text-foreground">{result.requestedPath}</span>
            </div>
          )}
        </div>
        
        {result.cdnDetected && result.cdnProvider && (
          <div className="md:text-right">
             <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Provider</div>
             <div className="font-mono text-lg">{result.cdnProvider}</div>
          </div>
        )}
      </section>

      {/* Embedded / Third-Party Providers found on the exact path requested */}
      {result.pageAnalysis && (
        <section className="space-y-4">
          <h2 className="text-xl font-bold uppercase tracking-wider border-b border-border pb-2 flex items-center gap-2">
            <Puzzle className="w-5 h-5 text-primary" />
            Embedded / Third-Party Providers
          </h2>
          <p className="text-xs text-muted-foreground max-w-3xl">
            DNS and CDN analysis only ever sees the hostname (<span className="font-mono">{result.hostname}</span>) — it cannot tell that
            a specific path is actually served or powered by a completely different backend. This section fetches the exact URL you
            submitted and looks for other domains referenced in its response (iframes, scripts, API hosts, cookies) — this is how a
            game/service provider embedded under the main site's domain (e.g. a games platform like 1xGames living inside a betting
            site's pages) can be surfaced.
          </p>

          {result.pageAnalysis.error ? (
            <div className="p-4 bg-destructive/10 border border-destructive/50 text-destructive text-sm flex items-start gap-2">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
              Could not fetch <span className="font-mono">{result.pageAnalysis.fetchedUrl}</span>: {result.pageAnalysis.error}
            </div>
          ) : (
            <>
              {result.pageAnalysis.requestHeadersApplied.length > 0 && (
                <div className="p-3 bg-primary/10 border border-primary/40 text-xs flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0 text-primary" />
                  <span>
                    Forwarded custom header{result.pageAnalysis.requestHeadersApplied.length > 1 ? "s" : ""} from your
                    pasted request:{" "}
                    <span className="font-mono text-primary">
                      {result.pageAnalysis.requestHeadersApplied.join(", ")}
                    </span>{" "}
                    (values are used, never displayed).
                  </span>
                </div>
              )}
              <div className="bg-card border border-border p-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div>
                  <div className="text-muted-foreground uppercase tracking-wider mb-1">Status</div>
                  <div className="font-mono text-foreground">{result.pageAnalysis.statusCode ?? "—"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground uppercase tracking-wider mb-1">Content-Type</div>
                  <div className="font-mono text-foreground break-all">{result.pageAnalysis.contentType ?? "—"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground uppercase tracking-wider mb-1">Server</div>
                  <div className="font-mono text-foreground break-all">{result.pageAnalysis.serverHeader ?? "—"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground uppercase tracking-wider mb-1">X-Powered-By</div>
                  <div className="font-mono text-foreground break-all">{result.pageAnalysis.poweredByHeader ?? "—"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground uppercase tracking-wider mb-1">Via</div>
                  <div className="font-mono text-foreground break-all">{result.pageAnalysis.viaHeader ?? "—"}</div>
                </div>
                <div>
                  <div className="text-muted-foreground uppercase tracking-wider mb-1">Cookie Domains</div>
                  <div className="font-mono text-foreground break-all">
                    {result.pageAnalysis.setCookieDomains.length > 0
                      ? result.pageAnalysis.setCookieDomains.join(", ")
                      : "—"}
                  </div>
                </div>
              </div>

              {result.pageAnalysis.embeddedProviders.length === 0 ? (
                <div className="p-6 text-center bg-card border border-border/50 text-muted-foreground border-dashed text-sm">
                  No distinct third-party domains found referenced in this response. The requested path appears to be served
                  entirely by {result.hostname} itself (or the response is minified/obfuscated JS the scanner can't parse).
                </div>
              ) : (
                <>
                  {result.pageAnalysis.embeddedProviders.some((p) => p.providerType === "api-or-backend") && (
                    <p className="text-xs text-muted-foreground">
                      Providers are sorted with likely <span className="text-primary font-semibold">API / backend</span> hosts
                      first — those are the ones actually processing requests, as opposed to static-asset CDNs that only serve
                      files like JS/CSS/images to the browser.
                    </p>
                  )}
                  <div className="grid gap-3 md:grid-cols-2">
                    {result.pageAnalysis.embeddedProviders.map((provider, i) => {
                      const typeMeta = {
                        "api-or-backend": {
                          label: "API / Backend",
                          className: "bg-primary/10 text-primary border-primary/50",
                        },
                        "static-asset-cdn": {
                          label: "Static Asset CDN",
                          className: "bg-secondary text-muted-foreground border-border",
                        },
                        unknown: {
                          label: "Unclassified",
                          className: "bg-amber-500/10 text-amber-500 border-amber-500/40",
                        },
                      }[provider.providerType];
                      const isBackend = provider.providerType === "api-or-backend";
                      return (
                        <div
                          key={i}
                          className={`bg-card border p-4 space-y-2 ${isBackend ? "border-primary/40" : "border-border/50"}`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span
                              className={`font-mono text-base font-bold break-all ${isBackend ? "text-primary" : "text-foreground"}`}
                            >
                              {provider.domain}
                            </span>
                            <Badge variant="outline" className="rounded-none text-[10px] uppercase tracking-wider shrink-0">
                              {provider.occurrences}x
                            </Badge>
                          </div>
                          <Badge
                            variant="outline"
                            className={`rounded-none text-[10px] uppercase tracking-wider ${typeMeta.className}`}
                          >
                            {typeMeta.label}
                          </Badge>
                          <div className="flex flex-wrap gap-1.5">
                            {provider.sources.map((src, j) => (
                              <span key={j} className="text-[10px] bg-secondary px-1.5 py-0.5 flex items-center gap-1 font-mono">
                                <LinkIcon className="w-2.5 h-2.5 text-muted-foreground" />
                                {src}
                              </span>
                            ))}
                          </div>
                          {provider.matchedPaths.length > 0 && (
                            <div className="space-y-1">
                              {provider.matchedPaths.slice(0, 3).map((p, j) => (
                                <div
                                  key={j}
                                  className="font-mono text-[10px] text-muted-foreground break-all bg-secondary/30 p-2 border border-border/30"
                                >
                                  {p}
                                </div>
                              ))}
                            </div>
                          )}
                          {provider.sampleContext && (
                            <div className="font-mono text-[10px] text-muted-foreground break-all bg-secondary/30 p-2 border border-border/30">
                              {provider.sampleContext}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </>
          )}
        </section>
      )}

      {/* Edge IP Details */}
      {result.edgeIpDetails && result.edgeIpDetails.length > 0 && (
        <section className="space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider border-b border-border/50 pb-2 text-muted-foreground flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Edge IP Ownership
          </h3>
          <div className="grid gap-3 sm:grid-cols-2">
            {result.edgeIpDetails.map((detail) => (
              <div key={detail.ip} className="bg-card border border-border/50 p-3 flex flex-col gap-1">
                <span className="font-mono text-sm text-foreground">{detail.ip}</span>
                <span className="text-xs text-muted-foreground">
                  {detail.org || "Unknown org"}
                  {detail.location ? ` · ${detail.location}` : ""}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Headline: Candidate Origins */}
      <section className="space-y-4">
        <h2 className="text-xl font-bold uppercase tracking-wider border-b border-border pb-2 flex items-center gap-2">
          <Server className="w-5 h-5 text-primary" />
          Candidate Origin IPs
        </h2>
        
        {result.candidateOriginIps.length === 0 ? (
          <div className="p-8 text-center bg-card border border-border/50 text-muted-foreground border-dashed">
            No origin IPs discovered. Target is securely shielded.
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {result.candidateOriginIps.sort((a, b) => {
              const weight = { high: 3, medium: 2, low: 1 };
              return weight[b.confidence] - weight[a.confidence];
            }).map((ip, i) => (
              <OriginIpCard key={i} candidate={ip} hostname={result.hostname} useHttps={!!useHttps} />
            ))}
          </div>
        )}
      </section>

      {/* Supporting Evidence Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* DNS Results */}
        <section className="space-y-4">
          <h3 className="text-sm font-bold uppercase tracking-wider border-b border-border/50 pb-2 text-muted-foreground flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Resolver Analysis
          </h3>
          <div className="bg-card border border-border divide-y divide-border">
            {result.dnsResults.map((dns, i) => (
              <div key={i} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="font-mono text-sm">{dns.resolver}</div>
                <div className="flex flex-col items-end gap-1">
                  {dns.error ? (
                    <span className="text-destructive text-xs">{dns.error}</span>
                  ) : dns.addresses.length > 0 ? (
                    dns.addresses.map(addr => (
                      <span key={addr} className="font-mono text-sm text-foreground bg-secondary/50 px-2 py-0.5">{addr}</span>
                    ))
                  ) : (
                    <span className="text-muted-foreground text-xs">NO DATA</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* SSL Certificate */}
        <section className="space-y-4">
          <h3 className="text-sm font-bold uppercase tracking-wider border-b border-border/50 pb-2 text-muted-foreground flex items-center gap-2">
            <Lock className="w-4 h-4" />
            SSL Certificate
          </h3>
          <div className="bg-card border border-border p-4 space-y-4">
            {result.sslCertificate.error ? (
              <div className="text-destructive text-sm flex items-center gap-2">
                <AlertCircle className="w-4 h-4" />
                {result.sslCertificate.error}
              </div>
            ) : (
              <>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Subject</div>
                  <div className="font-mono text-sm mt-0.5">{result.sslCertificate.subject || "Unknown"}</div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Issuer</div>
                  <div className="font-mono text-sm mt-0.5">{result.sslCertificate.issuer || "Unknown"}</div>
                </div>
                {result.sslCertificate.fingerprint && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider flex items-center gap-1">
                      <Fingerprint className="w-3 h-3" /> Fingerprint
                    </div>
                    <div className="font-mono text-xs mt-0.5 break-all text-primary/80">{result.sslCertificate.fingerprint}</div>
                  </div>
                )}
                {result.sslCertificate.altNames && result.sslCertificate.altNames.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Subject Alternative Names</div>
                    <div className="flex flex-wrap gap-2">
                      {result.sslCertificate.altNames.map(name => (
                        <span key={name} className="text-xs font-mono bg-secondary/50 px-1.5 py-0.5">{name}</span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </section>
        
        {/* Mail Records */}
        <section className="space-y-4">
          <h3 className="text-sm font-bold uppercase tracking-wider border-b border-border/50 pb-2 text-muted-foreground flex items-center gap-2">
            <Mail className="w-4 h-4" />
            Mail & TXT Records
          </h3>
          <div className="bg-card border border-border p-4 space-y-4">
            <div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">MX Records</div>
              {result.mxRecords.length > 0 ? (
                <div className="space-y-1">
                  {result.mxRecords.map((mx, i) => (
                    <div key={i} className="font-mono text-sm">{mx}</div>
                  ))}
                </div>
              ) : <div className="text-xs text-muted-foreground">None found</div>}
            </div>
            
            <div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">SPF Record</div>
              {result.spfRecord ? (
                <div className="font-mono text-xs break-all bg-secondary/30 p-2 border border-border/50">{result.spfRecord}</div>
              ) : <div className="text-xs text-muted-foreground">None found</div>}
            </div>
          </div>
        </section>

        {/* Subdomains */}
        <section className="space-y-4">
          <h3 className="text-sm font-bold uppercase tracking-wider border-b border-border/50 pb-2 text-muted-foreground flex items-center gap-2">
            <Database className="w-4 h-4" />
            Discovered Subdomains
          </h3>
          <div className="bg-card border border-border divide-y divide-border max-h-[300px] overflow-y-auto">
            {result.subdomains.length > 0 ? (
              result.subdomains.map((sub, i) => (
                <div key={i} className="p-3 flex flex-col gap-1">
                  <div className="font-mono text-sm text-primary">{sub.hostname}</div>
                  <div className="flex flex-wrap gap-2">
                    {sub.addresses.map(addr => (
                      <span key={addr} className="font-mono text-xs text-muted-foreground">{addr}</span>
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <div className="p-4 text-center text-xs text-muted-foreground">No subdomains discovered</div>
            )}
          </div>
        </section>

      </div>
    </div>
  );
}

function OriginIpCard({
  candidate,
  hostname,
  useHttps,
}: {
  candidate: CandidateOriginIp;
  hostname: string;
  useHttps: boolean;
}) {
  const isHigh = candidate.confidence === "high";
  const isMed = candidate.confidence === "medium";
  const verifyMutation = useVerifyOrigin();
  const verifyResult = verifyMutation.data as OriginVerifyResult | undefined;

  const handleVerify = () => {
    verifyMutation.mutate({
      data: { hostname, ip: candidate.ip, port: useHttps ? 443 : 80, useHttps },
    });
  };

  return (
    <div className={`p-5 border flex flex-col gap-4 bg-card ${isHigh ? 'border-primary shadow-[0_0_15px_rgba(0,255,128,0.1)]' : isMed ? 'border-amber-500/50' : 'border-border/50'}`}>
      <div className="flex items-start justify-between">
        <div>
          <div className="font-mono text-2xl font-bold tracking-tight">
            {candidate.ip}
          </div>
          {(candidate.org || candidate.location) && (
            <div className="text-xs text-muted-foreground mt-1">
              {candidate.org || "Unknown org"}
              {candidate.location ? ` · ${candidate.location}` : ""}
            </div>
          )}
        </div>
        <Badge 
          variant="outline" 
          className={`rounded-none uppercase text-[10px] tracking-widest font-bold px-2 py-0.5 shrink-0 ${
            isHigh ? 'bg-primary/20 text-primary border-primary' : 
            isMed ? 'bg-amber-500/20 text-amber-500 border-amber-500' : 
            'bg-muted text-muted-foreground border-border'
          }`}
        >
          {candidate.confidence} confidence
        </Badge>
      </div>
      
      <div>
        <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Evidence Sources</div>
        <div className="flex flex-wrap gap-2">
          {candidate.sources.map((src, i) => (
            <span key={i} className="text-xs bg-secondary px-2 py-1 flex items-center gap-1 font-mono">
              <ChevronRight className="w-3 h-3 text-muted-foreground" />
              {src}
            </span>
          ))}
        </div>
      </div>

      <div className="border-t border-border/50 pt-4 flex flex-col gap-3">
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="rounded-none uppercase text-xs tracking-wider font-bold self-start"
          onClick={handleVerify}
          disabled={verifyMutation.isPending}
        >
          {verifyMutation.isPending ? (
            <span className="flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              Reaching origin...
            </span>
          ) : (
            <span className="flex items-center gap-2">
              <Zap className="w-3.5 h-3.5" />
              Verify &amp; Reach Origin
            </span>
          )}
        </Button>

        {verifyMutation.isError && (
          <div className="text-xs text-destructive flex items-start gap-2">
            <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            {(verifyMutation.error as any)?.message || "Verification request failed."}
          </div>
        )}

        {verifyResult && (
          <div
            className={`text-xs p-3 border flex flex-col gap-3 font-mono ${
              verifyResult.verdict === "likely_origin"
                ? "border-primary/50 bg-primary/5"
                : verifyResult.verdict === "possible_proxy"
                  ? "border-amber-500/50 bg-amber-500/5"
                  : "border-border/50 bg-secondary/20"
            }`}
          >
            <div className="flex items-center gap-2">
              {verifyResult.verdict === "likely_origin" ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-primary shrink-0" />
              ) : verifyResult.verdict === "possible_proxy" ? (
                <AlertCircle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
              ) : (
                <XCircle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              )}
              <span className="font-bold uppercase tracking-wide">
                {verifyResult.verdict === "likely_origin"
                  ? "Likely origin"
                  : verifyResult.verdict === "possible_proxy"
                    ? "Possible intermediary proxy"
                    : "Indeterminate"}
              </span>
            </div>

            {verifyResult.verdictReason && (
              <div className="text-muted-foreground leading-relaxed normal-case">{verifyResult.verdictReason}</div>
            )}

            {verifyResult.reachable && (
              <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-muted-foreground border-t border-border/40 pt-2">
                <span>Status: <span className="text-foreground">{verifyResult.statusCode} {verifyResult.statusText}</span></span>
                {verifyResult.publicStatusCode != null && (
                  <span>Public status: <span className="text-foreground">{verifyResult.publicStatusCode}</span></span>
                )}
                {verifyResult.responseTimeMs != null && (
                  <span>Latency: <span className="text-foreground">{verifyResult.responseTimeMs}ms</span></span>
                )}
                {verifyResult.server && (
                  <span>Server: <span className="text-foreground">{verifyResult.server}</span></span>
                )}
                {verifyResult.publicBodySimilarity != null && (
                  <span>Body similarity: <span className="text-foreground">{Math.round(verifyResult.publicBodySimilarity * 100)}%</span></span>
                )}
                {verifyResult.publicHeaderOverlap != null && (
                  <span>Header overlap: <span className="text-foreground">{Math.round(verifyResult.publicHeaderOverlap * 100)}%</span></span>
                )}
                {verifyResult.tlsCertMatchesHost != null && (
                  <span className="col-span-2">
                    TLS cert matches host:{" "}
                    <span className={verifyResult.tlsCertMatchesHost ? "text-primary" : "text-amber-500"}>
                      {verifyResult.tlsCertMatchesHost ? "Yes" : "No"}
                    </span>
                  </span>
                )}
                {verifyResult.proxyHeadersDetected.length > 0 && (
                  <span className="col-span-2">
                    Proxy headers found: <span className="text-amber-500">{verifyResult.proxyHeadersDetected.join(", ")}</span>
                  </span>
                )}
              </div>
            )}

            {verifyResult.error && (
              <div className="text-destructive">{verifyResult.error}</div>
            )}
          </div>
        )}

        <RequestTool hostname={hostname} ip={candidate.ip} port={useHttps ? 443 : 80} useHttps={useHttps} />
      </div>
    </div>
  );
}
