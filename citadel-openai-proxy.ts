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

const CITADEL_URL = process.env.CITADEL_URL || "http://127.0.0.1:3333";
const UPSTREAM_URL = process.env.UPSTREAM_URL || "http://127.0.0.1:18789";
const UPSTREAM_TOKEN = process.env.UPSTREAM_TOKEN || "";
const PROXY_PORT = Number.parseInt(process.env.PROXY_PORT || "5050");
const BLOCK_MESSAGE =
  process.env.BLOCK_MESSAGE ||
  "🚫 Request blocked by Citadel (prompt injection detected).";
const OUTPUT_BLOCK_MESSAGE =
  process.env.OUTPUT_BLOCK_MESSAGE ||
  "🚫 Response blocked by Citadel (unsafe content detected).";
const SCAN_OUTPUT = process.env.SCAN_OUTPUT !== "false"; // Enable output scanning by default

interface CitadelScanResult {
  decision?: string;
  heuristic_score?: number;
  is_safe?: boolean;
  risk_score?: number;
  reason?: string;
}

interface OpenAIMessage {
  role: string;
  content: string;
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

async function scanInput(
  text: string,
): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const resp = await fetch(`${CITADEL_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: "input" }),
    });
    const result: CitadelScanResult = await resp.json();

    if (result.decision === "BLOCK") {
      return { allowed: false, reason: result.reason || "Blocked by Citadel" };
    }
    return { allowed: true };
  } catch (err) {
    console.error("[citadel-proxy] Citadel scan failed:", err);
    // Fail open or closed based on config
    return { allowed: true }; // Fail open for now
  }
}

async function scanOutput(
  text: string,
): Promise<{ safe: boolean; findings?: string[] }> {
  try {
    const resp = await fetch(`${CITADEL_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: "output" }),
    });
    const result: CitadelScanResult = await resp.json();

    if (result.is_safe === false) {
      return {
        safe: false,
        findings: [result.reason || "Unsafe content detected"],
      };
    }
    return { safe: true };
  } catch (err) {
    console.error("[citadel-proxy] Citadel output scan failed:", err);
    return { safe: true }; // Fail open
  }
}

function extractUserContent(
  body: OpenAIRequest,
  isResponses: boolean,
  isToolsInvoke: boolean,
): string {
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
    return parts.join("\n");
  }

  // Handle OpenResponses format (/v1/responses)
  if (isResponses) {
    const parts: string[] = [];

    // Check instructions
    if (body.instructions && typeof body.instructions === "string") {
      parts.push(body.instructions);
    }

    // Check input
    if (typeof body.input === "string") {
      parts.push(body.input);
    } else if (Array.isArray(body.input)) {
      for (const item of body.input) {
        if (item.type === "message" && item.role === "user") {
          if (typeof item.content === "string") {
            parts.push(item.content);
          } else if (Array.isArray(item.content)) {
            for (const part of item.content) {
              if (
                (part.type === "input_text" || part.type === "text") &&
                part.text
              ) {
                parts.push(part.text);
              }
            }
          }
        }
      }
    }

    return parts.join("\n");
  }

  // Handle OpenAI Chat Completions format (/v1/chat/completions)
  if (!body.messages || !Array.isArray(body.messages)) return "";

  // Get the last user message
  const userMessages = body.messages.filter((m) => m.role === "user");
  if (userMessages.length === 0) return "";

  const lastUserMsg = userMessages[userMessages.length - 1];
  return typeof lastUserMsg.content === "string" ? lastUserMsg.content : "";
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
    message?: { role?: string; content?: string };
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
): string {
  // Handle OpenResponses format
  if (isResponses && response.output && Array.isArray(response.output)) {
    const parts: string[] = [];
    for (const item of response.output) {
      if (
        item.type === "message" &&
        item.role === "assistant" &&
        Array.isArray(item.content)
      ) {
        for (const part of item.content) {
          if (part.type === "output_text" && part.text) {
            parts.push(part.text);
          }
        }
      }
    }
    return parts.join("\n");
  }

  // Handle OpenAI Chat Completions format
  if (!response.choices || !Array.isArray(response.choices)) return "";
  const firstChoice = response.choices[0];
  if (!firstChoice?.message?.content) return "";
  return typeof firstChoice.message.content === "string"
    ? firstChoice.message.content
    : "";
}

const server = Bun.serve({
  port: PROXY_PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          status: "ok",
          citadel: CITADEL_URL,
          upstream: UPSTREAM_URL,
        }),
        {
          headers: { "Content-Type": "application/json" },
        },
      );
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
      const body: OpenAIRequest = await req.json();
      const userContent = extractUserContent(body, isResponses, isToolsInvoke);

      // Scan input
      const endpoint = isToolsInvoke
        ? "/tools/invoke"
        : isResponses
          ? "/v1/responses"
          : "/v1/chat/completions";
      if (userContent) {
        console.log(
          `[citadel-proxy] [${endpoint}] Scanning input: "${userContent.slice(0, 50)}..."`,
        );
        const inputScan = await scanInput(userContent);

        if (!inputScan.allowed) {
          console.log(`[citadel-proxy] BLOCKED: ${inputScan.reason}`);
          return createBlockedResponse(body.model || "unknown");
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
      const upstreamResp = await fetch(`${UPSTREAM_URL}${upstreamEndpoint}`, {
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

      const assistantContent = extractAssistantContent(
        responseData,
        isResponses,
      );

      if (assistantContent) {
        console.log(
          `[citadel-proxy] Scanning output: "${assistantContent.slice(0, 50)}..."`,
        );
        const outputScan = await scanOutput(assistantContent);

        if (!outputScan.safe) {
          console.log(
            `[citadel-proxy] OUTPUT BLOCKED: ${outputScan.findings?.join(", ")}`,
          );
          return createBlockedResponse(
            body.model || "unknown",
            OUTPUT_BLOCK_MESSAGE,
          );
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
║  Proxy listening:  http://localhost:${PROXY_PORT}                     ║
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
