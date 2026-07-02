import { useState } from "react";
import { useScanTarget, useHealthCheck } from "@workspace/api-client-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Terminal, Activity, ChevronRight, AlertTriangle } from "lucide-react";
import ScanResults from "@/components/ScanResults";

export default function Home() {
  const [inputMode, setInputMode] = useState<"url" | "raw">("url");
  const [target, setTarget] = useState("");
  
  const { data: health } = useHealthCheck();
  const scanMutation = useScanTarget();

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    scanMutation.mutate({ data: { input: target } });
  };

  return (
    <div className="min-h-screen w-full flex flex-col items-center py-12 px-4 sm:px-6 lg:px-8 relative">
      {/* System Status */}
      <div className="absolute top-4 right-4 flex items-center gap-2 text-xs font-mono">
        <div className={`w-2 h-2 rounded-full ${health?.status === 'ok' ? 'bg-primary animate-pulse' : 'bg-destructive'}`} />
        <span className="text-muted-foreground uppercase tracking-widest">{health?.status === 'ok' ? 'SYSTEM ONLINE' : 'SYSTEM OFFLINE'}</span>
      </div>

      <div className="w-full max-w-6xl space-y-8">
        
        {/* Header */}
        <header className="space-y-2 border-b border-border pb-6">
          <div className="flex items-center gap-3">
            <Terminal className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold tracking-tight uppercase">Reverse Proxy Detector</h1>
          </div>
          <p className="text-muted-foreground text-sm max-w-2xl">
            Unmask origin servers hidden behind CDNs (Cloudflare, Akamai, Fastly). 
            Analyzes DNS histories, SSL transparency logs, and edge infrastructure to expose real IPs.
          </p>
        </header>

        {/* Input Area */}
        <section className="space-y-4">
          <div className="flex gap-4 border-b border-border/50 pb-2">
            <button 
              className={`text-sm font-semibold uppercase tracking-wider pb-2 border-b-2 transition-colors ${inputMode === 'url' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
              onClick={() => setInputMode('url')}
            >
              URL Target
            </button>
            <button 
              className={`text-sm font-semibold uppercase tracking-wider pb-2 border-b-2 transition-colors ${inputMode === 'raw' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
              onClick={() => setInputMode('raw')}
            >
              Raw HTTP Request
            </button>
          </div>

          <form onSubmit={handleScan} className="space-y-4">
            {inputMode === 'url' ? (
              <Input
                placeholder="https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="font-mono text-lg py-6 bg-card border-border focus-visible:ring-primary focus-visible:border-primary rounded-none"
                disabled={scanMutation.isPending}
              />
            ) : (
              <Textarea
                placeholder={"GET / HTTP/1.1\nHost: example.com\nUser-Agent: curl/7.81.0\nAccept: */*"}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="font-mono min-h-[200px] bg-card border-border focus-visible:ring-primary focus-visible:border-primary rounded-none"
                disabled={scanMutation.isPending}
              />
            )}
            
            <div className="flex flex-wrap items-center gap-4">
              <Button 
                type="submit" 
                size="lg" 
                className="rounded-none uppercase font-bold tracking-wider px-8"
                disabled={scanMutation.isPending || !target.trim()}
              >
                {scanMutation.isPending ? (
                  <span className="flex items-center gap-2">
                    <Activity className="w-4 h-4 animate-pulse" />
                    Scanning...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Initialize Recon
                  </span>
                )}
              </Button>
              
              {scanMutation.isPending && (
                <div className="text-xs text-primary font-mono flex items-center gap-2 ml-4">
                  <ChevronRight className="w-3 h-3 animate-pulse" />
                  <span className="animate-pulse">Querying global resolver nodes...</span>
                </div>
              )}
            </div>
          </form>
        </section>

        {/* Error State */}
        {scanMutation.isError && (
          <div className="bg-destructive/10 border border-destructive/50 p-4 text-destructive flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" />
            <div>
              <h3 className="font-bold uppercase tracking-wider text-sm">Scan Failed</h3>
              <p className="text-sm mt-1">{(scanMutation.error as any)?.message || "An unknown error occurred during reconnaissance."}</p>
            </div>
          </div>
        )}

        {/* Results Area */}
        {scanMutation.data && !scanMutation.isPending && (
          <ScanResults result={scanMutation.data} />
        )}

      </div>
    </div>
  );
}
