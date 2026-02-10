/**
 * Mock Citadel Server for Real-World Testing
 *
 * This server simulates Citadel responses for integration testing.
 * Run with: bun run tests/mock-citadel-server.ts
 *
 * Supports testing scenarios:
 * - Normal allow/block decisions
 * - Timeouts and errors
 * - Rate limiting
 * - Configurable responses
 */

const MOCK_PORT = Number.parseInt(process.env.MOCK_CITADEL_PORT || "3333");

// Configuration for mock behavior
interface MockConfig {
  // Delay before responding (ms)
  delay: number;
  // Force timeout (don't respond)
  forceTimeout: boolean;
  // Force error response
  forceError: string | null;
  // Force rate limit
  forceRateLimit: boolean;
  // Default decision
  defaultDecision: "ALLOW" | "BLOCK" | "WARN";
  // Default score
  defaultScore: number;
  // Keywords that trigger BLOCK
  blockKeywords: string[];
  // Keywords that trigger WARN
  warnKeywords: string[];
}

let config: MockConfig = {
  delay: 0,
  forceTimeout: false,
  forceError: null,
  forceRateLimit: false,
  defaultDecision: "ALLOW",
  defaultScore: 10,
  blockKeywords: [
    // Direct injection
    "drop table",
    "ignore previous",
    "system prompt",
    "jailbreak",
    "ignore all",
    "forget your",
    "developer mode",
    "override safety",
    "new instructions",
    "reveal secrets",
    "admin override",
    "disable all",
    // Role play attacks
    "dan (do anything",
    "without restrictions",
    "no ethical",
    // Delimiter attacks
    "begin override",
    "end override",
  ],
  warnKeywords: ["password", "api_key", "secret"],
};

function analyzeText(text: string): {
  decision: string;
  score: number;
  reason?: string;
} {
  const lowerText = text.toLowerCase();

  // Check for block keywords
  for (const keyword of config.blockKeywords) {
    if (lowerText.includes(keyword)) {
      return {
        decision: "BLOCK",
        score: 95,
        reason: `Detected blocked content: ${keyword}`,
      };
    }
  }

  // Check for warn keywords
  for (const keyword of config.warnKeywords) {
    if (lowerText.includes(keyword)) {
      return {
        decision: "WARN",
        score: 65,
        reason: `Detected suspicious content: ${keyword}`,
      };
    }
  }

  return {
    decision: config.defaultDecision,
    score: config.defaultScore,
  };
}

const server = Bun.serve({
  port: MOCK_PORT,
  async fetch(req) {
    const url = new URL(req.url);

    // Config endpoint - allows tests to modify behavior
    if (url.pathname === "/_config") {
      if (req.method === "POST") {
        const body = (await req.json()) as Partial<MockConfig>;
        config = { ...config, ...body };
        return new Response(JSON.stringify({ status: "ok", config }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (req.method === "GET") {
        return new Response(JSON.stringify(config), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (req.method === "DELETE") {
        // Reset to defaults
        config = {
          delay: 0,
          forceTimeout: false,
          forceError: null,
          forceRateLimit: false,
          defaultDecision: "ALLOW",
          defaultScore: 10,
          blockKeywords: [
            "drop table",
            "ignore previous",
            "system prompt",
            "jailbreak",
          ],
          warnKeywords: ["password", "api_key", "secret"],
        };
        return new Response(JSON.stringify({ status: "reset", config }), {
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    // Health check
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Scan endpoint (OSS format)
    if (url.pathname === "/scan" || url.pathname === "/v1/scan") {
      // Apply delay if configured
      if (config.delay > 0) {
        await new Promise((resolve) => setTimeout(resolve, config.delay));
      }

      // Force timeout - don't respond
      if (config.forceTimeout) {
        await new Promise((resolve) => setTimeout(resolve, 60000));
        return new Response("Timeout", { status: 504 });
      }

      // Force error
      if (config.forceError) {
        return new Response(JSON.stringify({ error: config.forceError }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Force rate limit
      if (config.forceRateLimit) {
        return new Response(JSON.stringify({ error: "Rate limited" }), {
          status: 429,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Parse request
      const body = (await req.json()) as { text?: string; mode?: string };
      const text = body.text || "";
      const mode = body.mode || "input";

      // Analyze and respond
      const analysis = analyzeText(text);

      const response = {
        decision: analysis.decision,
        heuristic_score: analysis.score / 100,
        is_safe: analysis.decision === "ALLOW",
        risk_level:
          analysis.score > 80 ? "HIGH" : analysis.score > 50 ? "MEDIUM" : "LOW",
        reason: analysis.reason,
        mode,
        timestamp: new Date().toISOString(),
      };

      console.log(
        `[mock-citadel] ${mode} scan: ${analysis.decision} (score: ${analysis.score})`,
      );

      return new Response(JSON.stringify(response), {
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`
╔══════════════════════════════════════════════════════════════════╗
║              Mock Citadel Server for Testing                     ║
╠══════════════════════════════════════════════════════════════════╣
║  Port: ${MOCK_PORT}                                                      ║
║                                                                  ║
║  Endpoints:                                                      ║
║    POST /scan           - Scan text (OSS format)                 ║
║    GET  /health         - Health check                           ║
║    POST /_config        - Update mock configuration              ║
║    GET  /_config        - Get current configuration              ║
║    DELETE /_config      - Reset to defaults                      ║
║                                                                  ║
║  Config options (POST to /_config):                              ║
║    delay: number        - Response delay in ms                   ║
║    forceTimeout: bool   - Never respond (simulate timeout)       ║
║    forceError: string   - Return error response                  ║
║    forceRateLimit: bool - Return 429 rate limit                  ║
║    defaultDecision: str - ALLOW/BLOCK/WARN                       ║
║    defaultScore: number - Default risk score                     ║
║    blockKeywords: []    - Keywords that trigger BLOCK            ║
║    warnKeywords: []     - Keywords that trigger WARN             ║
║                                                                  ║
║  Example test scenarios:                                         ║
║    curl -X POST http://localhost:${MOCK_PORT}/_config \\              ║
║      -d '{"forceTimeout": true}'                                 ║
║                                                                  ║
║    curl -X POST http://localhost:${MOCK_PORT}/scan \\                 ║
║      -d '{"text": "Hello", "mode": "input"}'                     ║
╚══════════════════════════════════════════════════════════════════╝
`);
