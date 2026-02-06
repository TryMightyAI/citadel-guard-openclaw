/**
 * Security utilities for Citadel Guard
 *
 * Contains hardening measures identified in security audit:
 * - Circuit breaker pattern
 * - Prototype pollution prevention
 * - Constant-time string comparison
 * - Session ID validation
 * - Tenant-isolated rate limiting
 */

import { timingSafeEqual } from "node:crypto";

// ============================================================================
// Circuit Breaker
// ============================================================================

export type CircuitState = "closed" | "open" | "half-open";

export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  resetTimeoutMs: number; // Time before attempting half-open
  halfOpenMaxAttempts: number; // Max attempts in half-open state
}

const DEFAULT_CIRCUIT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  resetTimeoutMs: 30000, // 30 seconds
  halfOpenMaxAttempts: 3,
};

export class CircuitBreaker {
  private failures = 0;
  private lastFailure = 0;
  private state: CircuitState = "closed";
  private halfOpenAttempts = 0;
  private config: CircuitBreakerConfig;

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = { ...DEFAULT_CIRCUIT_CONFIG, ...config };
  }

  /**
   * Execute a function with circuit breaker protection
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === "open") {
      if (Date.now() - this.lastFailure > this.config.resetTimeoutMs) {
        this.state = "half-open";
        this.halfOpenAttempts = 0;
      } else {
        throw new CircuitOpenError(
          `Circuit breaker open. Retry after ${this.getRemainingResetTime()}ms`,
        );
      }
    }

    if (this.state === "half-open") {
      this.halfOpenAttempts++;
      if (this.halfOpenAttempts > this.config.halfOpenMaxAttempts) {
        this.state = "open";
        this.lastFailure = Date.now();
        throw new CircuitOpenError(
          "Circuit breaker re-opened after half-open failures",
        );
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = "closed";
    this.halfOpenAttempts = 0;
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailure = Date.now();
    if (this.failures >= this.config.failureThreshold) {
      this.state = "open";
    }
  }

  private getRemainingResetTime(): number {
    return Math.max(
      0,
      this.config.resetTimeoutMs - (Date.now() - this.lastFailure),
    );
  }

  /**
   * Get current circuit state
   */
  getState(): CircuitState {
    // Check if we should transition from open to half-open
    if (
      this.state === "open" &&
      Date.now() - this.lastFailure > this.config.resetTimeoutMs
    ) {
      return "half-open";
    }
    return this.state;
  }

  /**
   * Force circuit to closed state (for testing/admin)
   */
  reset(): void {
    this.failures = 0;
    this.lastFailure = 0;
    this.state = "closed";
    this.halfOpenAttempts = 0;
  }

  /**
   * Get circuit breaker stats
   */
  getStats(): {
    state: CircuitState;
    failures: number;
    lastFailure: number;
    halfOpenAttempts: number;
  } {
    return {
      state: this.getState(),
      failures: this.failures,
      lastFailure: this.lastFailure,
      halfOpenAttempts: this.halfOpenAttempts,
    };
  }
}

export class CircuitOpenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CircuitOpenError";
  }
}

// ============================================================================
// Prototype Pollution Prevention
// ============================================================================

const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);

/**
 * Sanitize an object to prevent prototype pollution attacks
 */
export function sanitizeObject<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeObject(item)) as T;
  }

  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    // Skip dangerous keys
    if (DANGEROUS_KEYS.has(key)) {
      console.warn(`[citadel-guard] Blocked prototype pollution key: ${key}`);
      continue;
    }
    clean[key] = sanitizeObject(value);
  }
  return clean as T;
}

/**
 * Safe JSON parse that prevents prototype pollution
 */
export function safeJsonParse<T = unknown>(input: string): T {
  const parsed = JSON.parse(input);
  return sanitizeObject(parsed) as T;
}

// ============================================================================
// Constant-Time String Comparison
// ============================================================================

/**
 * Compare two strings in constant time to prevent timing attacks
 * This is important for API key validation
 * Uses Node's crypto.timingSafeEqual for cryptographically safe comparison
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const aBuffer = Buffer.from(a, "utf-8");
  const bBuffer = Buffer.from(b, "utf-8");

  // Different lengths = not equal, but we must still do constant-time
  // comparison to avoid leaking length information through timing
  const maxLen = Math.max(aBuffer.length, bBuffer.length);

  // Pad shorter buffer to prevent length leak via timingSafeEqual
  // (timingSafeEqual requires equal length buffers)
  const aPadded = Buffer.alloc(maxLen);
  const bPadded = Buffer.alloc(maxLen);

  aBuffer.copy(aPadded);
  bBuffer.copy(bPadded);

  // Use Node's cryptographically safe timing comparison
  const lengthsEqual = aBuffer.length === bBuffer.length;
  const contentsEqual = timingSafeEqual(aPadded, bPadded);

  // Both conditions must be true - lengths must match AND contents must match
  return lengthsEqual && contentsEqual;
}

// ============================================================================
// Session ID Validation
// ============================================================================

// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Also allow session IDs like "sess_xxx" or alphanumeric with underscores/hyphens
const SAFE_SESSION_ID_REGEX = /^[a-zA-Z0-9_-]{1,128}$/;

/**
 * Validate a session ID format
 * Returns true if the session ID is safe to use
 */
export function isValidSessionId(sessionId: string | undefined): boolean {
  if (!sessionId) return true; // undefined is valid (no session)
  if (sessionId.length > 128) return false; // Too long

  return UUID_V4_REGEX.test(sessionId) || SAFE_SESSION_ID_REGEX.test(sessionId);
}

/**
 * Sanitize a session ID - returns undefined if invalid
 */
export function sanitizeSessionId(
  sessionId: string | undefined,
): string | undefined {
  if (!sessionId) return undefined;
  if (!isValidSessionId(sessionId)) {
    console.warn(
      `[citadel-guard] Invalid session ID format, ignoring: ${sessionId.slice(0, 20)}...`,
    );
    return undefined;
  }
  return sessionId;
}

// ============================================================================
// Tenant-Isolated Rate Limiting
// ============================================================================

interface TenantRateLimitState {
  backoffMs: number;
  lastRateLimited: number;
}

/**
 * Rate limit handler with per-tenant isolation
 * Prevents one tenant's rate limits from affecting others
 */
export class TenantRateLimitHandler {
  private tenants = new Map<string, TenantRateLimitState>();
  private maxBackoffMs: number;
  private initialBackoffMs: number;
  private maxTenants: number;

  constructor(options?: {
    maxBackoffMs?: number;
    initialBackoffMs?: number;
    maxTenants?: number;
  }) {
    this.maxBackoffMs = options?.maxBackoffMs ?? 60000;
    this.initialBackoffMs = options?.initialBackoffMs ?? 1000;
    this.maxTenants = options?.maxTenants ?? 10000;
  }

  private getTenantState(tenantId: string): TenantRateLimitState {
    let state = this.tenants.get(tenantId);
    if (!state) {
      // Evict oldest tenant if at capacity
      if (this.tenants.size >= this.maxTenants) {
        const firstKey = this.tenants.keys().next().value;
        if (firstKey) this.tenants.delete(firstKey);
      }

      state = {
        backoffMs: this.initialBackoffMs,
        lastRateLimited: 0,
      };
      this.tenants.set(tenantId, state);
    }
    return state;
  }

  /**
   * Check if a tenant should back off
   */
  shouldBackoff(tenantId: string): boolean {
    const state = this.getTenantState(tenantId);
    const timeSince = Date.now() - state.lastRateLimited;
    return timeSince < state.backoffMs;
  }

  /**
   * Record a rate limit event for a tenant
   */
  recordRateLimit(tenantId: string): void {
    const state = this.getTenantState(tenantId);
    state.lastRateLimited = Date.now();
    state.backoffMs = Math.min(state.backoffMs * 2, this.maxBackoffMs);
  }

  /**
   * Record a successful request for a tenant
   */
  recordSuccess(tenantId: string): void {
    const state = this.tenants.get(tenantId);
    if (state) {
      state.backoffMs = Math.max(
        this.initialBackoffMs,
        Math.floor(state.backoffMs / 2),
      );
    }
  }

  /**
   * Get backoff time for a tenant
   */
  getBackoffMs(tenantId: string): number {
    return this.getTenantState(tenantId).backoffMs;
  }

  /**
   * Reset a tenant's rate limit state
   */
  resetTenant(tenantId: string): void {
    this.tenants.delete(tenantId);
  }

  /**
   * Reset all tenants
   */
  resetAll(): void {
    this.tenants.clear();
  }

  /**
   * Get stats
   */
  getStats(): { tenantCount: number; maxTenants: number } {
    return {
      tenantCount: this.tenants.size,
      maxTenants: this.maxTenants,
    };
  }
}

// ============================================================================
// Payload Size Validation
// ============================================================================

const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB

/**
 * Check if a payload is within size limits
 */
export function isPayloadWithinLimits(
  payload: string | object,
  maxSize = MAX_PAYLOAD_SIZE,
): boolean {
  const size =
    typeof payload === "string"
      ? payload.length
      : JSON.stringify(payload).length;
  return size <= maxSize;
}

/**
 * Truncate a payload to max size
 */
export function truncatePayload(
  payload: string,
  maxSize = MAX_PAYLOAD_SIZE,
): string {
  if (payload.length <= maxSize) return payload;
  return `${payload.slice(0, maxSize - 20)}... [truncated]`;
}

// ============================================================================
// CVE Local Pattern Detection (Defense-in-Depth)
// ============================================================================

/**
 * Known dangerous patterns that should be blocked locally,
 * regardless of what the upstream scanner returns.
 *
 * These provide defense-in-depth for known CVEs where the
 * heuristic scanner might miss vague natural-language variants.
 */

export interface LocalDetectionResult {
  blocked: boolean;
  cve?: string;
  reason?: string;
}

/**
 * CVE-2026-25253: gatewayUrl injection leading to 1-click RCE in OpenClaw.
 * Any user input referencing `gatewayUrl` is suspicious — there's no
 * legitimate reason for end-user messages to contain this parameter.
 */
const GATEWAY_URL_PATTERN = /\bgatewayUrl\b/i;

/**
 * Scan text for locally-known CVE patterns.
 * Returns a detection result if a pattern matches, null otherwise.
 */
export function detectLocalPatterns(
  text: string,
  mode: "input" | "output",
): LocalDetectionResult | null {
  // Only scan inbound text — outbound scanning for these patterns
  // would cause false positives on legitimate security discussions
  if (mode !== "input") return null;

  if (GATEWAY_URL_PATTERN.test(text)) {
    return {
      blocked: true,
      cve: "CVE-2026-25253",
      reason: "gatewayUrl injection attempt detected",
    };
  }

  return null;
}

// ============================================================================
// Hook Result Validation
// ============================================================================

const MAX_BLOCK_REASON_LENGTH = 500;
const MAX_MODIFIED_CONTENT_LENGTH = 1024 * 1024; // 1MB

export interface ValidatedHookResult {
  block: boolean;
  blockReason?: string;
  blockResponse?: string;
  modifiedContent?: string;
}

/**
 * Validate and sanitize a hook result to prevent abuse
 */
export function validateHookResult(result: unknown): ValidatedHookResult {
  if (!result || typeof result !== "object") {
    return { block: false };
  }

  const r = result as Record<string, unknown>;

  return {
    block: typeof r.block === "boolean" ? r.block : false,
    blockReason:
      typeof r.blockReason === "string"
        ? r.blockReason.slice(0, MAX_BLOCK_REASON_LENGTH)
        : undefined,
    blockResponse:
      typeof r.blockResponse === "string"
        ? r.blockResponse.slice(0, MAX_BLOCK_REASON_LENGTH)
        : undefined,
    modifiedContent:
      typeof r.modifiedContent === "string"
        ? r.modifiedContent.slice(0, MAX_MODIFIED_CONTENT_LENGTH)
        : undefined,
  };
}
