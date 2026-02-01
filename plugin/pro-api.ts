/**
 * Citadel Pro API Client
 *
 * Handles communication with both Citadel OSS and Pro APIs,
 * with automatic detection and response normalization.
 */

export const PRO_ENDPOINT = "https://gateway.trymighty.ai/v1/scan";

/**
 * Normalized scan result that works with both OSS and Pro responses
 */
export interface NormalizedScanResult {
  decision: "ALLOW" | "BLOCK" | "WARN";
  score: number; // 0-100
  sessionId?: string;
  turnNumber?: number;
  scanGroupId?: string; // For linking output scans to input scans
  reason?: string;
  isSafe?: boolean;
  riskLevel?: string;
  rawResponse: unknown;
}

/**
 * Raw scan result from API request
 */
export interface RawScanResult {
  ok: boolean;
  data?: NormalizedScanResult;
  error?: string;
  rateLimited?: boolean;
  isPro?: boolean;
}

/**
 * Check if an API key indicates Pro mode
 * Pro keys have format: mc_live_* or mc_test_*
 */
export function isProApiKey(apiKey: string | undefined): boolean {
  if (!apiKey) return false;
  return /^mc_(live|test)_/.test(apiKey);
}

/**
 * Resolve API key from config or environment
 */
export function resolveApiKey(
  configApiKey: string | undefined,
): string | undefined {
  return configApiKey || process.env.CITADEL_API_KEY || undefined;
}

/**
 * Normalize response from either OSS or Pro API
 *
 * OSS returns: { decision: "BLOCK", heuristic_score: 0.95, is_safe: false, risk_level: "HIGH" }
 * Pro returns: { action: "BLOCK", risk_score: 95, session_id: "sess_...", turn_number: 1 }
 */
export function normalizeScanResult(
  response: unknown,
  isPro: boolean,
): NormalizedScanResult {
  const res = response as Record<string, unknown>;

  if (isPro) {
    // Pro API format
    const action = String(res.action ?? "ALLOW").toUpperCase();
    const decision =
      action === "BLOCK" ? "BLOCK" : action === "WARN" ? "WARN" : "ALLOW";

    return {
      decision: decision as "ALLOW" | "BLOCK" | "WARN",
      score: typeof res.risk_score === "number" ? res.risk_score : 0,
      sessionId: res.session_id as string | undefined,
      turnNumber: res.turn_number as number | undefined,
      scanGroupId: res.scan_group_id as string | undefined,
      reason: res.reason as string | undefined,
      isSafe: res.is_safe as boolean | undefined,
      riskLevel: res.risk_level as string | undefined,
      rawResponse: response,
    };
  }

  // OSS API format
  const decision = String(res.decision ?? "ALLOW").toUpperCase();
  const normalizedDecision =
    decision === "BLOCK" ? "BLOCK" : decision === "WARN" ? "WARN" : "ALLOW";

  // Convert heuristic_score (0-1) to score (0-100)
  let score = 0;
  if (typeof res.heuristic_score === "number") {
    score = Math.round(res.heuristic_score * 100);
  } else if (typeof res.risk_score === "number") {
    score = res.risk_score;
  }

  return {
    decision: normalizedDecision as "ALLOW" | "BLOCK" | "WARN",
    score,
    reason: res.reason as string | undefined,
    isSafe: res.is_safe as boolean | undefined,
    riskLevel: res.risk_level as string | undefined,
    rawResponse: response,
  };
}

/**
 * Request scan from Pro API
 */
export async function requestScanPro(params: {
  content: string;
  scanPhase: "input" | "output";
  sessionId?: string;
  scanGroupId?: string; // Required for output scans to link to input scan
  apiKey: string;
  timeoutMs: number;
}): Promise<RawScanResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);

  try {
    const res = await fetch(PRO_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": params.apiKey,
      },
      body: JSON.stringify({
        content: params.content,
        scan_phase: params.scanPhase,
        ...(params.sessionId && { session_id: params.sessionId }),
        ...(params.scanGroupId && { scan_group_id: params.scanGroupId }),
      }),
      signal: controller.signal,
    });

    if (res.status === 401) {
      return {
        ok: false,
        error: "Invalid API key (401 Unauthorized)",
        isPro: true,
      };
    }
    if (res.status === 429) {
      return {
        ok: false,
        error: "Rate limited (429)",
        rateLimited: true,
        isPro: true,
      };
    }
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}`, isPro: true };
    }

    const data = await res.json();
    const normalized = normalizeScanResult(data, true);
    return { ok: true, data: normalized, isPro: true };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    if (errorMsg.includes("abort")) {
      return { ok: false, error: "Request timeout", isPro: true };
    }
    return { ok: false, error: errorMsg, isPro: true };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Request scan from OSS API
 */
export async function requestScanOss(params: {
  endpoint: string;
  text: string;
  mode: "input" | "output";
  sessionId?: string;
  timeoutMs: number;
}): Promise<RawScanResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs);

  try {
    const res = await fetch(`${params.endpoint.replace(/\/$/, "")}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: params.text,
        mode: params.mode,
        ...(params.sessionId && { session_id: params.sessionId }),
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status}`, isPro: false };
    }

    const data = await res.json();
    const normalized = normalizeScanResult(data, false);
    return { ok: true, data: normalized, isPro: false };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    if (errorMsg.includes("abort")) {
      return { ok: false, error: "Request timeout", isPro: false };
    }
    return { ok: false, error: errorMsg, isPro: false };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Rate limit handler with exponential backoff
 */
export class RateLimitHandler {
  private backoffMs = 1000;
  private maxBackoffMs = 60000;
  private lastRateLimited = 0;

  /**
   * Check if we should back off
   */
  shouldBackoff(): boolean {
    const timeSince = Date.now() - this.lastRateLimited;
    return timeSince < this.backoffMs;
  }

  /**
   * Record a rate limit event
   */
  recordRateLimit(): void {
    this.lastRateLimited = Date.now();
    this.backoffMs = Math.min(this.backoffMs * 2, this.maxBackoffMs);
  }

  /**
   * Record a successful request
   */
  recordSuccess(): void {
    // Gradually reduce backoff on success
    this.backoffMs = Math.max(1000, Math.floor(this.backoffMs / 2));
  }

  /**
   * Get current backoff time in ms
   */
  getBackoffMs(): number {
    return this.backoffMs;
  }

  /**
   * Reset backoff state
   */
  reset(): void {
    this.backoffMs = 1000;
    this.lastRateLimited = 0;
  }
}
