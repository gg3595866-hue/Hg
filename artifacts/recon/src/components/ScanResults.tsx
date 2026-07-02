import { ScanResult, CandidateOriginIp, CandidateOriginIpConfidence, DnsResolverResult, SslCertificateInfo, SubdomainRecord } from "@workspace/api-client-react";
import { Shield, ShieldAlert, ShieldCheck, Server, Globe, Lock, Mail, Database, ChevronRight, AlertCircle, Fingerprint } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export default function ScanResults({ result }: { result: ScanResult }) {
  
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
        </div>
        
        {result.cdnDetected && result.cdnProvider && (
          <div className="md:text-right">
             <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Provider</div>
             <div className="font-mono text-lg">{result.cdnProvider}</div>
          </div>
        )}
      </section>

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
              <OriginIpCard key={i} candidate={ip} />
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

function OriginIpCard({ candidate }: { candidate: CandidateOriginIp }) {
  const isHigh = candidate.confidence === "high";
  const isMed = candidate.confidence === "medium";
  
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
    </div>
  );
}
