import { useState } from "react";
import { useSendProxyRequest, ProxyRequestResult, ProxyRequestBodyMethod } from "@workspace/api-client-react";
import { Send, Loader2, XCircle, ChevronDown, ChevronUp, Copy, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const METHODS: ProxyRequestBodyMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export default function RequestTool({
  hostname,
  ip,
  port,
  useHttps,
}: {
  hostname: string;
  ip: string;
  port: number;
  useHttps: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [method, setMethod] = useState<ProxyRequestBodyMethod>("GET");
  const [path, setPath] = useState("/");
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");
  const [copied, setCopied] = useState(false);

  const mutation = useSendProxyRequest();
  const result = mutation.data as ProxyRequestResult | undefined;

  const parseHeaders = (): Record<string, string> | undefined => {
    const lines = headersText.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) return undefined;
    const headers: Record<string, string> = {};
    for (const line of lines) {
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      const key = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (key) headers[key] = value;
    }
    return Object.keys(headers).length > 0 ? headers : undefined;
  };

  const handleSend = () => {
    mutation.mutate({
      data: {
        hostname,
        ip,
        port,
        useHttps,
        method,
        path: path.trim() || "/",
        headers: parseHeaders(),
        body: method === "GET" || method === "HEAD" ? undefined : body || undefined,
      },
    });
  };

  const handleCopy = () => {
    if (!result?.body) return;
    navigator.clipboard.writeText(result.body);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="border-t border-border/50 pt-4 flex flex-col gap-3">
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="rounded-none uppercase text-xs tracking-wider font-bold self-start"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="flex items-center gap-2">
          <Send className="w-3.5 h-3.5" />
          Send Request to Origin
          {open ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </span>
      </Button>

      {open && (
        <div className="flex flex-col gap-3 bg-secondary/20 border border-border/50 p-3">
          <div className="flex gap-2">
            <Select value={method} onValueChange={(v) => setMethod(v as ProxyRequestBodyMethod)}>
              <SelectTrigger className="w-[110px] rounded-none font-mono text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="rounded-none">
                {METHODS.map((m) => (
                  <SelectItem key={m} value={m} className="font-mono text-xs">
                    {m}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              placeholder="/api/users?id=1"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="font-mono text-xs rounded-none bg-card"
            />
          </div>

          <div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
              Headers (one per line, Key: Value)
            </div>
            <Textarea
              placeholder={"Content-Type: application/json\nAuthorization: Bearer ..."}
              value={headersText}
              onChange={(e) => setHeadersText(e.target.value)}
              className="font-mono text-xs min-h-[60px] rounded-none bg-card"
            />
          </div>

          {method !== "GET" && method !== "HEAD" && (
            <div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Body</div>
              <Textarea
                placeholder={'{"key": "value"}'}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                className="font-mono text-xs min-h-[80px] rounded-none bg-card"
              />
            </div>
          )}

          <Button
            type="button"
            size="sm"
            className="rounded-none uppercase text-xs tracking-wider font-bold self-start"
            onClick={handleSend}
            disabled={mutation.isPending}
          >
            {mutation.isPending ? (
              <span className="flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Sending...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <Send className="w-3.5 h-3.5" />
                Send
              </span>
            )}
          </Button>

          {mutation.isError && (
            <div className="text-xs text-destructive flex items-start gap-2">
              <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
              {(mutation.error as any)?.message || "Request failed."}
            </div>
          )}

          {result && (
            <div className="flex flex-col gap-2 font-mono text-xs">
              {result.reachable ? (
                <div className="flex items-center gap-3 flex-wrap">
                  <span
                    className={`font-bold ${
                      result.statusCode && result.statusCode < 400 ? "text-primary" : "text-destructive"
                    }`}
                  >
                    {result.statusCode} {result.statusText}
                  </span>
                  {result.responseTimeMs != null && (
                    <span className="text-muted-foreground">{result.responseTimeMs}ms</span>
                  )}
                  {result.bodyTruncated && <span className="text-amber-500">body truncated (512KB limit)</span>}
                </div>
              ) : (
                <div className="text-destructive flex items-center gap-2">
                  <XCircle className="w-3.5 h-3.5" />
                  {result.error || "Origin unreachable."}
                </div>
              )}

              {Object.keys(result.headers).length > 0 && (
                <details className="bg-card border border-border/50">
                  <summary className="px-2 py-1.5 cursor-pointer text-muted-foreground uppercase text-[10px] tracking-wider">
                    Response Headers ({Object.keys(result.headers).length})
                  </summary>
                  <div className="px-2 pb-2 space-y-0.5 max-h-[150px] overflow-y-auto">
                    {Object.entries(result.headers).map(([k, v]) => (
                      <div key={k} className="break-all">
                        <span className="text-primary/80">{k}</span>: <span className="text-muted-foreground">{v}</span>
                      </div>
                    ))}
                  </div>
                </details>
              )}

              {result.body != null && result.body.length > 0 && (
                <div className="bg-card border border-border/50 relative">
                  <div className="flex items-center justify-between px-2 py-1.5 border-b border-border/50">
                    <span className="text-muted-foreground uppercase text-[10px] tracking-wider">Response Body</span>
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-[10px] uppercase"
                    >
                      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      {copied ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre className="px-2 py-2 whitespace-pre-wrap break-all max-h-[300px] overflow-y-auto text-foreground/90">
                    {result.body}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
