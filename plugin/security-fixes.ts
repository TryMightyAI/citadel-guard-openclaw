/**
 * Security Fixes for Citadel Guard
 *
 * This module contains fixes for vulnerabilities identified in the security audit.
 * Import and use these in the main plugin code.
 *
 * FIXES INCLUDED:
 * 1. Sidecar binary path validation
 * 2. Configurable fail-open behavior for all scan types
 * 3. Streaming response handling
 * 4. Secure logging (no content leakage)
 */

// ============================================================================
// FIX 1: Sidecar Binary Path Validation
// ============================================================================

/**
 * Allowed binary path patterns for citadel sidecar.
 * Prevents arbitrary binary execution via config.
 */
const ALLOWED_BINARY_PATTERNS = [
  /^citadel$/, // From PATH
  /^\.\/citadel$/, // Local directory
  /^\/[\w.\/-]+\/citadel$/, // Absolute path ending in "citadel"
];

/**
 * Characters that indicate shell injection attempts
 */
const SHELL_METACHARACTERS = /[;&|`$(){}[\]<>!\n\r]/;

/**
 * Validate a binary path is safe to execute.
 *
 * @param bin - The binary path from config
 * @returns true if the path is safe, false otherwise
 */
export function isAllowedBinaryPath(bin: string): boolean {
  // Reject empty or whitespace
  if (!bin || !bin.trim()) return false;

  // Reject shell metacharacters
  if (SHELL_METACHARACTERS.test(bin)) return false;

  // Reject path traversal
  if (bin.includes("..")) return false;

  // Check against allowed patterns
  return ALLOWED_BINARY_PATTERNS.some((pattern) => pattern.test(bin));
}

/**
 * Validate citadel arguments are safe.
 *
 * @param args - Array of arguments from config
 * @returns Filtered array with dangerous args removed
 */
export function validateCitadelArgs(args: string[]): string[] {
  return args.filter((arg) => {
    // Reject args with shell metacharacters
    if (SHELL_METACHARACTERS.test(arg)) {
      console.warn(`[citadel-guard] Rejected unsafe argument: ${arg.slice(0, 20)}...`);
      return false;
    }
    return true;
  });
}

// ============================================================================
// FIX 2: Configurable Fail-Open Behavior
// ============================================================================

/**
 * Extended config options for granular fail-open control
 */
export interface FailOpenConfig {
  /** Global fail-open setting (default: false) */
  failOpen: boolean;

  /** Fail-open for inbound scanning (default: same as failOpen) */
  failOpenInbound?: boolean;

  /** Fail-open for outbound scanning (default: true for backwards compat) */
  failOpenOutbound?: boolean;

  /** Fail-open for tool result scanning (default: true for backwards compat) */
  failOpenToolResults?: boolean;

  /** Block streaming responses when output scanning required (default: false) */
  blockStreamingResponses?: boolean;
}

/**
 * Determine if we should fail-open for a specific scan type.
 *
 * @param config - The fail-open configuration
 * @param scanType - The type of scan being performed
 * @returns true if we should allow through on failure, false to block
 */
export function shouldFailOpen(
  config: FailOpenConfig,
  scanType: "inbound" | "outbound" | "tool_args" | "tool_results",
): boolean {
  switch (scanType) {
    case "inbound":
    case "tool_args":
      // Inbound and tool args use failOpenInbound or fall back to failOpen
      return config.failOpenInbound ?? config.failOpen;

    case "outbound":
      // Outbound uses failOpenOutbound or falls back to failOpen
      // Default to true for backwards compatibility
      return config.failOpenOutbound ?? config.failOpen;

    case "tool_results":
      // Tool results use failOpenToolResults or fall back to failOpen
      // Default to true for backwards compatibility
      return config.failOpenToolResults ?? config.failOpen;

    default:
      return config.failOpen;
  }
}

/**
 * Handle a scan error according to config.
 *
 * @param config - The fail-open configuration
 * @param scanType - The type of scan that failed
 * @param error - The error message
 * @param context - Context for logging
 * @returns Object indicating whether to block and why
 */
export function handleScanFailure(
  config: FailOpenConfig,
  scanType: "inbound" | "outbound" | "tool_args" | "tool_results",
  error: string,
  context: string,
): { block: boolean; reason?: string } {
  const failOpen = shouldFailOpen(config, scanType);

  if (failOpen) {
    console.warn(
      `[citadel-guard] ${context}: scan failed (${error}), failing OPEN`,
    );
    return { block: false };
  }

  console.warn(
    `[citadel-guard] ${context}: scan failed (${error}), failing CLOSED`,
  );
  return { block: true, reason: "security_scan_unavailable" };
}

// ============================================================================
// FIX 3: Streaming Response Handling
// ============================================================================

/**
 * Handle streaming response for output scanning.
 *
 * @param isStreaming - Whether the response is streaming
 * @param config - Configuration including blockStreamingResponses
 * @param logger - Logger for warnings
 * @returns undefined to continue, or block object to stop
 */
export function handleStreamingResponse(
  isStreaming: boolean,
  config: { blockStreamingResponses?: boolean },
  logger?: { warn?: (msg: string) => void },
): { block: true; reason: string } | undefined {
  if (!isStreaming) {
    return undefined; // Not streaming, proceed with normal scanning
  }

  if (config.blockStreamingResponses) {
    return {
      block: true,
      reason: "streaming_responses_cannot_be_scanned",
    };
  }

  // Log warning when streaming bypasses scan
  logger?.warn?.(
    "[citadel-guard] WARNING: Streaming response bypassing output scan. " +
      "Set blockStreamingResponses=true to block streaming when output scanning is required.",
  );

  return undefined; // Allow streaming through (with warning)
}

// ============================================================================
// FIX 4: Secure Logging
// ============================================================================

/**
 * Log a scan operation without leaking content.
 *
 * @param operation - The operation being performed
 * @param contentLength - Length of the content being scanned
 * @param endpoint - The endpoint (optional)
 */
export function logScanOperation(
  operation: "input" | "output",
  contentLength: number,
  endpoint?: string,
): void {
  const endpointStr = endpoint ? ` [${endpoint}]` : "";
  console.log(
    `[citadel-guard]${endpointStr} Scanning ${operation} (${contentLength} chars)`,
  );
}

/**
 * Log a scan result without leaking sensitive details.
 *
 * @param operation - The operation performed
 * @param decision - The scan decision
 * @param score - The risk score (optional)
 */
export function logScanResult(
  operation: "input" | "output",
  decision: "ALLOW" | "BLOCK" | "WARN",
  score?: number,
): void {
  const scoreStr = score !== undefined ? ` (score: ${score})` : "";
  console.log(`[citadel-guard] ${operation} scan result: ${decision}${scoreStr}`);
}

/**
 * Log a block event with sanitized reason.
 *
 * @param context - Where the block occurred
 * @param reason - The reason for blocking (sanitized)
 */
export function logBlockEvent(context: string, reason: string): void {
  // Truncate and sanitize reason to prevent log injection
  const sanitizedReason = reason
    .slice(0, 100)
    .replace(/[\n\r]/g, " ")
    .replace(/[^\x20-\x7E]/g, "");

  console.log(`[citadel-guard] BLOCKED at ${context}: ${sanitizedReason}`);
}

// ============================================================================
// FIX 5: Minimal Health Response
// ============================================================================

/**
 * Generate a minimal health response that doesn't expose internal URLs.
 */
export function generateHealthResponse(): { status: string } {
  return { status: "ok" };
}

/**
 * Generate a detailed health response for authenticated internal use.
 *
 * @param citadelUrl - The Citadel URL
 * @param upstreamUrl - The upstream URL
 * @param authenticated - Whether the request is authenticated
 */
export function generateDetailedHealthResponse(
  citadelUrl: string,
  upstreamUrl: string,
  authenticated: boolean,
): { status: string; citadel?: string; upstream?: string } {
  if (!authenticated) {
    return { status: "ok" };
  }

  return {
    status: "ok",
    citadel: citadelUrl,
    upstream: upstreamUrl,
  };
}

// ============================================================================
// Integration Example: How to use these fixes in the main plugin
// ============================================================================

/**
 * Example of how to integrate these fixes into plugin/index.ts:
 *
 * 1. Sidecar binary validation:
 *    ```typescript
 *    import { isAllowedBinaryPath, validateCitadelArgs } from "./security-fixes";
 *
 *    function startCitadelSidecar(ctx, cfg) {
 *      const bin = cfg.citadelBin ?? "citadel";
 *
 *      if (!isAllowedBinaryPath(bin)) {
 *        ctx.logger.error(`[citadel-guard] Blocked unsafe binary: ${bin}`);
 *        return;
 *      }
 *
 *      const args = validateCitadelArgs(cfg.citadelArgs);
 *      citadelProcess = spawn(bin, args, { ... });
 *    }
 *    ```
 *
 * 2. Fail-open behavior:
 *    ```typescript
 *    import { handleScanFailure } from "./security-fixes";
 *
 *    // In message_sending hook:
 *    if (!result.ok || !result.data) {
 *      const { block, reason } = handleScanFailure(
 *        cfg,
 *        "outbound",
 *        result.error || "unknown",
 *        "message_sending",
 *      );
 *      if (block) {
 *        return { content: cfg.outboundBlockMessage };
 *      }
 *      return; // fail-open
 *    }
 *    ```
 *
 * 3. Streaming handling:
 *    ```typescript
 *    import { handleStreamingResponse } from "./security-fixes";
 *
 *    // In http_response_sending hook:
 *    const streamingResult = handleStreamingResponse(
 *      event.isStreaming,
 *      cfg,
 *      api.logger,
 *    );
 *    if (streamingResult) {
 *      return streamingResult;
 *    }
 *    // Continue with normal scanning...
 *    ```
 *
 * 4. Secure logging:
 *    ```typescript
 *    import { logScanOperation, logScanResult } from "./security-fixes";
 *
 *    // Instead of: console.log(`Scanning: "${content.slice(0, 50)}..."`);
 *    logScanOperation("input", content.length, "/v1/chat/completions");
 *    ```
 */
