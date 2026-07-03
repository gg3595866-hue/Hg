export type ParsedFetchRequest = {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
};

function findMatchingParen(text: string, openIndex: number): number {
  let depth = 0;
  let inString: '"' | "'" | "`" | null = null;
  for (let i = openIndex; i < text.length; i++) {
    const ch = text[i];
    const prev = text[i - 1];
    if (inString) {
      if (ch === inString && prev !== "\\") {
        inString = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      inString = ch;
      continue;
    }
    if (ch === "(") depth++;
    if (ch === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function splitTopLevelArgs(text: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let inString: '"' | "'" | "`" | null = null;
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const prev = text[i - 1];
    if (inString) {
      current += ch;
      if (ch === inString && prev !== "\\") {
        inString = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      inString = ch;
      current += ch;
      continue;
    }
    if (ch === "{" || ch === "[" || ch === "(") depth++;
    if (ch === "}" || ch === "]" || ch === ")") depth--;
    if (ch === "," && depth === 0) {
      args.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) args.push(current.trim());
  return args;
}

function parseJsStringLiteral(text: string): string | null {
  const trimmed = text.trim();
  const quote = trimmed[0];
  if (quote !== '"' && quote !== "'" && quote !== "`") return null;
  if (trimmed[trimmed.length - 1] !== quote) return null;
  const inner = trimmed.slice(1, -1);
  try {
    return JSON.parse(`"${inner.replace(/\\`/g, "`").replace(/"/g, '\\"').replace(/\\'/g, "'")}"`);
  } catch {
    return inner.replace(/\\(.)/g, "$1");
  }
}

export function parseFetchSnippet(rawInput: string): ParsedFetchRequest | null {
  const text = rawInput.trim();
  const fetchIndex = text.indexOf("fetch(");
  if (fetchIndex === -1) return null;

  const openParenIndex = fetchIndex + "fetch".length;
  const closeParenIndex = findMatchingParen(text, openParenIndex);
  if (closeParenIndex === -1) return null;

  const callBody = text.slice(openParenIndex + 1, closeParenIndex);
  const args = splitTopLevelArgs(callBody);
  if (args.length === 0) return null;

  const url = parseJsStringLiteral(args[0]);
  if (!url) return null;

  let method = "GET";
  let headers: Record<string, string> = {};
  let body: string | null = null;

  if (args[1]) {
    let optionsObj: Record<string, unknown> | null = null;
    try {
      optionsObj = JSON.parse(args[1]);
    } catch {
      optionsObj = null;
    }
    if (optionsObj) {
      if (typeof optionsObj.method === "string") {
        method = optionsObj.method.toUpperCase();
      }
      if (optionsObj.headers && typeof optionsObj.headers === "object") {
        for (const [k, v] of Object.entries(optionsObj.headers as Record<string, unknown>)) {
          if (typeof v === "string") headers[k] = v;
        }
      }
      if (typeof optionsObj.body === "string") {
        body = optionsObj.body;
      } else if (optionsObj.body != null) {
        body = JSON.stringify(optionsObj.body);
      }
    }
  }

  return { url, method, headers, body };
}

export function parseCurlSnippet(rawInput: string): ParsedFetchRequest | null {
  const text = rawInput.trim();
  if (!/^curl\s/i.test(text)) return null;

  const tokens: string[] = [];
  let current = "";
  let inString: '"' | "'" | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const prev = text[i - 1];
    if (inString) {
      if (ch === inString && prev !== "\\") {
        inString = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = ch;
      continue;
    }
    if (/\s/.test(ch) || ch === "\\" ) {
      if (ch === "\\" && text[i + 1] === "\n") {
        i++;
        continue;
      }
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);

  let url: string | null = null;
  let method = "GET";
  const headers: Record<string, string> = {};
  let body: string | null = null;

  for (let i = 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === "-X" || tok === "--request") {
      method = (tokens[++i] ?? "GET").toUpperCase();
    } else if (tok === "-H" || tok === "--header") {
      const headerLine = tokens[++i] ?? "";
      const idx = headerLine.indexOf(":");
      if (idx !== -1) {
        headers[headerLine.slice(0, idx).trim()] = headerLine.slice(idx + 1).trim();
      }
    } else if (tok === "-d" || tok === "--data" || tok === "--data-raw" || tok === "--data-binary") {
      body = tokens[++i] ?? "";
      if (method === "GET") method = "POST";
    } else if (!tok.startsWith("-") && !url) {
      url = tok;
    }
  }

  if (!url) return null;
  return { url, method, headers, body };
}
