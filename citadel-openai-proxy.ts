#!/usr/bin/env bun
/**
 * Citadel OpenAI Proxy
 *
 * A universal proxy that scans all OpenAI-compatible API requests through Citadel
 * before forwarding to the upstream API.
 *
 * Usage:
 *   CITADEL_URL=http://localhost:3333 \
 *   UPSTREAM_URL=http://localhost:18789 \
 *   UPSTREAM_TOKEN=test-token-123 \
 *   bun run citadel-openai-proxy.ts
 *
 * Then call: curl http://localhost:5050/v1/chat/completions -d '...'
 */

function parseBooleanEnv(
  value: string | undefined,
  defaultValue: boolean,
): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return defaultValue;
}

function parseIntEnv(value: string | undefined, defaultValue: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : defaultValue;
}

const CITADEL_URL = process.env.CITADEL_URL || "http://127.0.0.1:3333";
const UPSTREAM_URL = process.env.UPSTREAM_URL || "http://127.0.0.1:18789";
const UPSTREAM_TOKEN = process.env.UPSTREAM_TOKEN || "";
const PROXY_HOST = process.env.PROXY_HOST || "127.0.0.1";
const PROXY_PORT = parseIntEnv(process.env.PROXY_PORT, 5050);
const SCAN_TIMEOUT_MS = parseIntEnv(process.env.SCAN_TIMEOUT_MS, 2000);
const MAX_BODY_BYTES = parseIntEnv(process.env.MAX_BODY_BYTES, 1024 * 1024);
const FAIL_OPEN = parseBooleanEnv(process.env.FAIL_OPEN, false);
const BLOCK_MESSAGE =
  process.env.BLOCK_MESSAGE ||
  "🚫 Request blocked by Citadel (prompt injection detected).";
const OUTPUT_BLOCK_MESSAGE =
  process.env.OUTPUT_BLOCK_MESSAGE ||
  "🚫 Response blocked by Citadel (unsafe content detected).";
const SCAN_OUTPUT = parseBooleanEnv(process.env.SCAN_OUTPUT, true);
const SCAN_SYSTEM_MESSAGES = parseBooleanEnv(
  process.env.SCAN_SYSTEM_MESSAGES,
  true,
);
const SCAN_DEVELOPER_MESSAGES = parseBooleanEnv(
  process.env.SCAN_DEVELOPER_MESSAGES,
  true,
);
const CITADEL_BASE = CITADEL_URL.replace(/\/$/, "");
const UPSTREAM_BASE = UPSTREAM_URL.replace(/\/$/, "");

interface CitadelScanResult {
  decision?: string;
  heuristic_score?: number;
  is_safe?: boolean;
  risk_score?: number;
  reason?: string;
}

interface OpenAIContentPart {
  type?: string;
  text?: string;
}

interface OpenAIMessage {
  role?: string;
  content?: string | OpenAIContentPart[] | unknown;
}

interface OpenAIRequest {
  model?: string;
  messages?: OpenAIMessage[];
  stream?: boolean;
  // OpenResponses fields
  input?: string | OpenResponsesItem[];
  instructions?: string;
  // Tools invoke fields
  tool?: string;
  action?: string;
  args?: Record<string, unknown>;
}

interface OpenResponsesItem {
  type?: string;
  role?: string;
  content?: string | OpenResponsesContentPart[];
}

interface OpenResponsesContentPart {
  type?: string;
  text?: string;
}

function shouldScanRole(role: string | undefined): boolean {
  if (!role) return false;
  const normalized = role.toLowerCase();
  if (normalized === "user") return true;
  if (normalized === "system") return SCAN_SYSTEM_MESSAGES;
  if (normalized === "developer") return SCAN_DEVELOPER_MESSAGES;
  return false;
}

function extractTextParts(content: unknown, allowedTypes: string[]): string[] {
  if (typeof content === "string") return [content];

  const parts: string[] = [];

  if (Array.isArray(content)) {
    for (const part of content) {
      if (!part || typeof part !== "object") continue;
      const partObj = part as Record<string, unknown>;
      const type = typeof partObj.type === "string" ? partObj.type : "";
      const text = partObj.text;
      if (allowedTypes.includes(type) && typeof text === "string") {
        parts.push(text);
      }
    }
    return parts;
  }

  if (content && typeof content === "object") {
    const text = (content as Record<string, unknown>).text;
    if (typeof text === "string") parts.push(text);
  }

  return parts;
}

async function scanInput(
  text: string,
): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const resp = await fetch(`${CITADEL_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: "input" }),
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS),
    });

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }

    const result: CitadelScanResult = await resp.json();
    const decision =
      typeof result.decision === "string" ? result.decision.toUpperCase() : "";

    if (decision === "BLOCK" || result.is_safe === false) {
      return { allowed: false, reason: result.reason || "Blocked by Citadel" };
    }
    return { allowed: true };
  } catch (err) {
    console.error("[citadel-proxy] Citadel scan failed:", err);
    return FAIL_OPEN
      ? { allowed: true }
      : { allowed: false, reason: "citadel_unavailable" };
  }
}

async function scanOutput(
  text: string,
): Promise<{ safe: boolean; findings?: string[] }> {
  try {
    const resp = await fetch(`${CITADEL_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: "output" }),
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS),
    });

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }

    const result: CitadelScanResult = await resp.json();
    const decision =
      typeof result.decision === "string" ? result.decision.toUpperCase() : "";

    if (decision === "BLOCK" || result.is_safe === false) {
      return {
        safe: false,
        findings: [result.reason || "Unsafe content detected"],
      };
    }
    return { safe: true };
  } catch (err) {
    console.error("[citadel-proxy] Citadel output scan failed:", err);
    return FAIL_OPEN
      ? { safe: true }
      : { safe: false, findings: ["citadel_unavailable"] };
  }
}

function extractUserContentParts(
  body: OpenAIRequest,
  isResponses: boolean,
  isToolsInvoke: boolean,
): string[] {
  // Handle /tools/invoke format
  if (isToolsInvoke) {
    const parts: string[] = [];
    if (body.tool) parts.push(`Tool: ${body.tool}`);
    if (body.action) parts.push(`Action: ${body.action}`);
    if (body.args) {
      // Scan all string arguments for injection
      const scanArgs = (obj: unknown, prefix = ""): void => {
        if (typeof obj === "string") {
          parts.push(obj);
        } else if (Array.isArray(obj)) {
          obj.forEach((item, i) => scanArgs(item, `${prefix}[${i}]`));
        } else if (obj && typeof obj === "object") {
          for (const [key, value] of Object.entries(obj)) {
            scanArgs(value, `${prefix}.${key}`);
          }
        }
      };
      scanArgs(body.args);
    }
    return parts.filter((part) => part.trim().length > 0);
  }

  // Handle OpenResponses format (/v1/responses)
  if (isResponses) {
    const parts: string[] = [];

    // Check instructions
    if (
      (SCAN_SYSTEM_MESSAGES || SCAN_DEVELOPER_MESSAGES) &&
      body.instructions &&
      typeof body.instructions === "string"
    ) {
      parts.push(body.instructions);
    }

    // Check input
    if (typeof body.input === "string") {
      parts.push(body.input);
    } else if (Array.isArray(body.input)) {
      for (const item of body.input) {
        const itemObj = item as Record<string, unknown>;
        const itemType =
          typeof itemObj.type === "string" ? itemObj.type : undefined;
        const itemRole =
          typeof itemObj.role === "string" ? itemObj.role : undefined;

        if (itemType === "message" && shouldScanRole(itemRole)) {
          parts.push(
            ...extractTextParts(itemObj.content, ["input_text", "text"]),
          );
          continue;
        }

        if (
          (itemType === "input_text" || itemType === "text") &&
          typeof itemObj.text === "string"
        ) {
          parts.push(itemObj.text);
        }
      }
    }

    return parts.filter((part) => part.trim().length > 0);
  }

  // Handle OpenAI Chat Completions format (/v1/chat/completions)
  if (!body.messages || !Array.isArray(body.messages)) return [];

  const parts: string[] = [];
  for (const msg of body.messages) {
    if (!msg || typeof msg !== "object") continue;
    if (!shouldScanRole(msg.role)) continue;
    parts.push(...extractTextParts(msg.content, ["text", "input_text"]));
  }
  return parts.filter((part) => part.trim().length > 0);
}

async function readRequestBody(
  req: Request,
  maxBytes: number,
): Promise<string> {
  const contentLength = req.headers.get("content-length");
  if (contentLength) {
    const length = Number.parseInt(contentLength, 10);
    if (Number.isFinite(length) && length > maxBytes) {
      throw new Error("Payload too large");
    }
  }

  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (!value) continue;
    received += value.byteLength;
    if (received > maxBytes) {
      throw new Error("Payload too large");
    }
    chunks.push(value);
  }

  const buffer = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new TextDecoder().decode(buffer);
}

function createBlockedResponse(
  model: string,
  message: string = BLOCK_MESSAGE,
): Response {
  const body = {
    id: `chatcmpl_blocked_${Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: message },
        finish_reason: "stop",
      },
    ],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

interface OpenAIResponse {
  id?: string;
  object?: string;
  created?: number;
  model?: string;
  choices?: Array<{
    index?: number;
    message?: { role?: string; content?: string | OpenAIContentPart[] };
    finish_reason?: string;
  }>;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  // OpenResponses fields
  output?: OpenResponsesOutputItem[];
  status?: string;
}

interface OpenResponsesOutputItem {
  type?: string;
  role?: string;
  content?: Array<{ type?: string; text?: string }>;
}

function extractAssistantContent(
  response: OpenAIResponse,
  isResponses: boolean,
): string[] {
  // Handle OpenResponses format
  if (isResponses && response.output && Array.isArray(response.output)) {
    const parts: string[] = [];
    for (const item of response.output) {
      if (item.type === "message" && item.role === "assistant") {
        parts.push(...extractTextParts(item.content, ["output_text", "text"]));
      }
    }
    return parts.filter((part) => part.trim().length > 0);
  }

  // Handle OpenAI Chat Completions format
  if (!response.choices || !Array.isArray(response.choices)) return [];
  const parts: string[] = [];
  for (const choice of response.choices) {
    const content = choice.message?.content;
    if (!content) continue;
    parts.push(...extractTextParts(content, ["output_text", "text"]));
  }
  return parts.filter((part) => part.trim().length > 0);
}

const server = Bun.serve({
  hostname: PROXY_HOST,
  port: PROXY_PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // Health check - minimal response to avoid exposing internal URLs
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Proxy all OpenClaw HTTP endpoints that bypass hooks
    const isChatCompletions = url.pathname === "/v1/chat/completions";
    const isResponses = url.pathname === "/v1/responses";
    const isToolsInvoke = url.pathname === "/tools/invoke";

    if (!isChatCompletions && !isResponses && !isToolsInvoke) {
      return new Response("Not Found", { status: 404 });
    }

    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    try {
      let bodyText = "";
      try {
        bodyText = await readRequestBody(req, MAX_BODY_BYTES);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("Payload too large")) {
          return new Response("Payload Too Large", { status: 413 });
        }
        return new Response("Bad Request", { status: 400 });
      }

      if (!bodyText.trim()) {
        return new Response("Bad Request", { status: 400 });
      }

      let body: OpenAIRequest;
      try {
        body = JSON.parse(bodyText) as OpenAIRequest;
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      const userParts = extractUserContentParts(
        body,
        isResponses,
        isToolsInvoke,
      );

      // Scan input
      const endpoint = isToolsInvoke
        ? "/tools/invoke"
        : isResponses
          ? "/v1/responses"
          : "/v1/chat/completions";
      if (userParts.length > 0) {
        for (const part of userParts) {
          // FIX: Log content length only, not content itself
          console.log(
            `[citadel-proxy] [${endpoint}] Scanning input (${part.length} chars)`,
          );
          const inputScan = await scanInput(part);

          if (!inputScan.allowed) {
            console.log(`[citadel-proxy] BLOCKED: ${inputScan.reason}`);
            return createBlockedResponse(body.model || "unknown");
          }
        }
        console.log("[citadel-proxy] ALLOWED");
      }

      // Forward to upstream
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (UPSTREAM_TOKEN) {
        headers.Authorization = `Bearer ${UPSTREAM_TOKEN}`;
      }

      // If output scanning is enabled and streaming is requested, disable streaming
      // to allow us to scan the complete response before returning
      const requestBody =
        SCAN_OUTPUT && body.stream ? { ...body, stream: false } : body;

      // Forward to the correct upstream endpoint
      const upstreamEndpoint = isToolsInvoke
        ? "/tools/invoke"
        : isResponses
          ? "/v1/responses"
          : "/v1/chat/completions";
      const upstreamResp = await fetch(`${UPSTREAM_BASE}${upstreamEndpoint}`, {
        method: "POST",
        headers,
        body: JSON.stringify(requestBody),
      });

      // If output scanning is disabled, pass through response directly
      if (!SCAN_OUTPUT) {
        return new Response(upstreamResp.body, {
          status: upstreamResp.status,
          headers: {
            "Content-Type":
              upstreamResp.headers.get("Content-Type") || "application/json",
          },
        });
      }

      // Output scanning enabled - read and scan the response
      const responseText = await upstreamResp.text();
      let responseData: OpenAIResponse;

      try {
        responseData = JSON.parse(responseText);
      } catch {
        // If we can't parse the response, pass it through
        console.log(
          "[citadel-proxy] Could not parse response, passing through",
        );
        return new Response(responseText, {
          status: upstreamResp.status,
          headers: { "Content-Type": "application/json" },
        });
      }

      const assistantParts = extractAssistantContent(responseData, isResponses);

      if (assistantParts.length > 0) {
        for (const part of assistantParts) {
          // FIX: Log content length only, not content itself
          console.log(`[citadel-proxy] Scanning output (${part.length} chars)`);
          const outputScan = await scanOutput(part);

          if (!outputScan.safe) {
            console.log(
              `[citadel-proxy] OUTPUT BLOCKED: ${outputScan.findings?.join(", ")}`,
            );
            return createBlockedResponse(
              body.model || "unknown",
              OUTPUT_BLOCK_MESSAGE,
            );
          }
        }
        console.log("[citadel-proxy] OUTPUT SAFE");
      }

      // Return the (possibly modified) response
      return new Response(JSON.stringify(responseData), {
        status: upstreamResp.status,
        headers: { "Content-Type": "application/json" },
      });
    } catch (err) {
      console.error("[citadel-proxy] Error:", err);
      return new Response(JSON.stringify({ error: "Proxy error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
});

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║           Citadel OpenAI Proxy - Universal Protection         ║
╠═══════════════════════════════════════════════════════════════╣
║  Proxy listening:  http://${PROXY_HOST}:${PROXY_PORT}                     ║
║  Citadel scanner:  ${CITADEL_URL.padEnd(40)}║
║  Upstream API:     ${UPSTREAM_URL.padEnd(40)}║
╠═══════════════════════════════════════════════════════════════╣
║  Protected Endpoints:                                         ║
║    • /v1/chat/completions  (OpenAI Chat API)                  ║
║    • /v1/responses         (OpenResponses API)                ║
║    • /tools/invoke         (Direct Tool Invocation)           ║
╠═══════════════════════════════════════════════════════════════╣
║  Input scanning:   ✅ ENABLED                                  ║
║  Output scanning:  ${SCAN_OUTPUT ? "✅ ENABLED" : "❌ DISABLED"}                                  ║
╠═══════════════════════════════════════════════════════════════╣
║  ${SCAN_OUTPUT ? "Note: Streaming disabled when output scanning is enabled." : ""}     ║
╚═══════════════════════════════════════════════════════════════╝
`);
