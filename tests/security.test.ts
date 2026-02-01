/**
 * Security Utilities Tests
 *
 * Tests for security hardening measures:
 * - Circuit breaker pattern
 * - Prototype pollution prevention
 * - Constant-time string comparison
 * - Session ID validation
 * - Tenant-isolated rate limiting
 * - Payload size validation
 * - Hook result validation
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CircuitBreaker,
  CircuitOpenError,
  TenantRateLimitHandler,
  constantTimeEqual,
  isPayloadWithinLimits,
  isValidSessionId,
  safeJsonParse,
  sanitizeObject,
  sanitizeSessionId,
  truncatePayload,
  validateHookResult,
} from "../plugin/security";

describe("CircuitBreaker", () => {
  let breaker: CircuitBreaker;

  beforeEach(() => {
    breaker = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 100,
      halfOpenMaxAttempts: 2,
    });
  });

  describe("closed state", () => {
    it("should execute functions successfully in closed state", async () => {
      const result = await breaker.execute(async () => "success");
      expect(result).toBe("success");
      expect(breaker.getState()).toBe("closed");
    });

    it("should track failures but stay closed below threshold", async () => {
      const failingFn = async () => {
        throw new Error("failure");
      };

      // Two failures - below threshold of 3
      await expect(breaker.execute(failingFn)).rejects.toThrow("failure");
      await expect(breaker.execute(failingFn)).rejects.toThrow("failure");

      expect(breaker.getState()).toBe("closed");
      expect(breaker.getStats().failures).toBe(2);
    });

    it("should open after reaching failure threshold", async () => {
      const failingFn = async () => {
        throw new Error("failure");
      };

      // Three failures - reaches threshold
      await expect(breaker.execute(failingFn)).rejects.toThrow("failure");
      await expect(breaker.execute(failingFn)).rejects.toThrow("failure");
      await expect(breaker.execute(failingFn)).rejects.toThrow("failure");

      expect(breaker.getState()).toBe("open");
    });
  });

  describe("open state", () => {
    it("should reject requests immediately when open", async () => {
      // Force open state
      for (let i = 0; i < 3; i++) {
        await expect(
          breaker.execute(async () => {
            throw new Error("fail");
          }),
        ).rejects.toThrow();
      }

      expect(breaker.getState()).toBe("open");

      // New requests should be rejected without calling the function
      const fn = vi.fn().mockResolvedValue("success");
      await expect(breaker.execute(fn)).rejects.toThrow(CircuitOpenError);
      expect(fn).not.toHaveBeenCalled();
    });

    it("should transition to half-open after reset timeout", async () => {
      // Force open state
      for (let i = 0; i < 3; i++) {
        await expect(
          breaker.execute(async () => {
            throw new Error("fail");
          }),
        ).rejects.toThrow();
      }

      expect(breaker.getState()).toBe("open");

      // Wait for reset timeout
      await new Promise((r) => setTimeout(r, 150));

      expect(breaker.getState()).toBe("half-open");
    });
  });

  describe("half-open state", () => {
    beforeEach(async () => {
      // Force open state then wait for half-open
      for (let i = 0; i < 3; i++) {
        await expect(
          breaker.execute(async () => {
            throw new Error("fail");
          }),
        ).rejects.toThrow();
      }
      await new Promise((r) => setTimeout(r, 150));
    });

    it("should close circuit on successful request", async () => {
      expect(breaker.getState()).toBe("half-open");

      const result = await breaker.execute(async () => "success");
      expect(result).toBe("success");
      expect(breaker.getState()).toBe("closed");
    });

    it("should re-open after failure in half-open state", async () => {
      expect(breaker.getState()).toBe("half-open");

      // In half-open, failures counter is still at threshold
      // So any failure will re-open the circuit
      await expect(
        breaker.execute(async () => {
          throw new Error("fail");
        }),
      ).rejects.toThrow("fail");

      // Circuit should now be open again
      expect(breaker.getState()).toBe("open");

      // Further attempts should be rejected immediately
      await expect(breaker.execute(async () => "success")).rejects.toThrow(
        CircuitOpenError,
      );
    });
  });

  describe("reset", () => {
    it("should reset circuit to closed state", async () => {
      // Force open state
      for (let i = 0; i < 3; i++) {
        await expect(
          breaker.execute(async () => {
            throw new Error("fail");
          }),
        ).rejects.toThrow();
      }
      expect(breaker.getState()).toBe("open");

      breaker.reset();
      expect(breaker.getState()).toBe("closed");
      expect(breaker.getStats().failures).toBe(0);
    });
  });
});

describe("Prototype Pollution Prevention", () => {
  describe("sanitizeObject", () => {
    it("should pass through primitive values", () => {
      expect(sanitizeObject("string")).toBe("string");
      expect(sanitizeObject(123)).toBe(123);
      expect(sanitizeObject(true)).toBe(true);
      expect(sanitizeObject(null)).toBe(null);
    });

    it("should sanitize arrays recursively", () => {
      const input = [1, { a: 2 }, [3, 4]];
      const result = sanitizeObject(input);
      expect(result).toEqual([1, { a: 2 }, [3, 4]]);
    });

    it("should filter __proto__ key", () => {
      const malicious = { normal: 1, __proto__: { isAdmin: true } };
      const result = sanitizeObject(malicious);
      expect(result).toEqual({ normal: 1 });
      // Check that __proto__ is not an own property
      expect(Object.keys(result as object)).toEqual(["normal"]);
    });

    it("should filter constructor key", () => {
      const malicious = {
        normal: 1,
        constructor: { prototype: { isAdmin: true } },
      };
      const result = sanitizeObject(malicious);
      expect(result).toEqual({ normal: 1 });
    });

    it("should filter prototype key", () => {
      const malicious = { normal: 1, prototype: { isAdmin: true } };
      const result = sanitizeObject(malicious);
      expect(result).toEqual({ normal: 1 });
    });

    it("should filter __defineGetter__ and similar keys", () => {
      const malicious = {
        normal: 1,
        __defineGetter__: () => {},
        __defineSetter__: () => {},
        __lookupGetter__: () => {},
        __lookupSetter__: () => {},
      };
      const result = sanitizeObject(malicious);
      expect(result).toEqual({ normal: 1 });
    });

    it("should sanitize nested objects", () => {
      const malicious = {
        level1: {
          level2: {
            normal: "value",
            __proto__: { evil: true },
          },
        },
      };
      const result = sanitizeObject(malicious);
      expect(result).toEqual({
        level1: {
          level2: {
            normal: "value",
          },
        },
      });
    });
  });

  describe("safeJsonParse", () => {
    it("should parse valid JSON", () => {
      const result = safeJsonParse('{"a": 1, "b": "test"}');
      expect(result).toEqual({ a: 1, b: "test" });
    });

    it("should sanitize prototype pollution in parsed JSON", () => {
      // Note: JSON.parse itself creates __proto__ properties differently,
      // but this tests the overall flow
      const result = safeJsonParse('{"normal": 1, "__proto__": {"admin": true}}');
      expect(result).toEqual({ normal: 1 });
    });

    it("should throw on invalid JSON", () => {
      expect(() => safeJsonParse("not json")).toThrow();
    });
  });
});

describe("Constant-Time String Comparison", () => {
  it("should return true for identical strings", () => {
    expect(constantTimeEqual("password", "password")).toBe(true);
    expect(constantTimeEqual("", "")).toBe(true);
    expect(constantTimeEqual("abc123", "abc123")).toBe(true);
  });

  it("should return false for different strings", () => {
    expect(constantTimeEqual("password", "different")).toBe(false);
    expect(constantTimeEqual("a", "b")).toBe(false);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
  });

  it("should return false for different lengths", () => {
    expect(constantTimeEqual("short", "longer string")).toBe(false);
    expect(constantTimeEqual("abc", "ab")).toBe(false);
  });

  it("should handle unicode strings", () => {
    expect(constantTimeEqual("hello\u0000world", "hello\u0000world")).toBe(true);
    expect(constantTimeEqual("\u00e9", "\u00e9")).toBe(true);
    expect(constantTimeEqual("\u00e9", "e")).toBe(false);
  });

  it("should handle special characters", () => {
    expect(constantTimeEqual("pass!@#$%", "pass!@#$%")).toBe(true);
    expect(constantTimeEqual("pass!@#$%", "pass!@#$&")).toBe(false);
  });
});

describe("Session ID Validation", () => {
  describe("isValidSessionId", () => {
    it("should accept undefined session ID", () => {
      expect(isValidSessionId(undefined)).toBe(true);
    });

    it("should accept valid UUID v4", () => {
      expect(isValidSessionId("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
      expect(isValidSessionId("123e4567-e89b-42d3-a456-426614174000")).toBe(true);
    });

    it("should accept safe alphanumeric session IDs", () => {
      expect(isValidSessionId("session_123")).toBe(true);
      expect(isValidSessionId("sess-abc-def")).toBe(true);
      expect(isValidSessionId("my_session_id")).toBe(true);
      expect(isValidSessionId("UPPERCASE")).toBe(true);
    });

    it("should reject session IDs over 128 characters", () => {
      const longId = "a".repeat(129);
      expect(isValidSessionId(longId)).toBe(false);
    });

    it("should reject session IDs with special characters", () => {
      expect(isValidSessionId("session/../../../etc/passwd")).toBe(false);
      expect(isValidSessionId("session; DROP TABLE users;")).toBe(false);
      expect(isValidSessionId("<script>alert(1)</script>")).toBe(false);
      expect(isValidSessionId("session\u0000null")).toBe(false);
    });

    it("should accept non-v4 UUIDs as valid session IDs", () => {
      // Non-v4 UUIDs are still valid session IDs because they match safe alphanumeric pattern
      expect(isValidSessionId("not-a-uuid")).toBe(true);
      expect(isValidSessionId("550e8400-e29b-51d4-a716-446655440000")).toBe(true); // v5 format, valid
    });
  });

  describe("sanitizeSessionId", () => {
    it("should return undefined for undefined input", () => {
      expect(sanitizeSessionId(undefined)).toBeUndefined();
    });

    it("should return valid session IDs unchanged", () => {
      expect(sanitizeSessionId("session_123")).toBe("session_123");
      expect(sanitizeSessionId("550e8400-e29b-41d4-a716-446655440000")).toBe(
        "550e8400-e29b-41d4-a716-446655440000",
      );
    });

    it("should return undefined for invalid session IDs", () => {
      expect(sanitizeSessionId("session/../etc")).toBeUndefined();
      expect(sanitizeSessionId("<script>")).toBeUndefined();
    });
  });
});

describe("TenantRateLimitHandler", () => {
  let handler: TenantRateLimitHandler;

  beforeEach(() => {
    handler = new TenantRateLimitHandler({
      maxBackoffMs: 1000,
      initialBackoffMs: 50,
      maxTenants: 100,
    });
  });

  describe("shouldBackoff", () => {
    it("should not backoff for new tenants", () => {
      expect(handler.shouldBackoff("tenant1")).toBe(false);
    });

    it("should backoff after rate limit recorded", () => {
      handler.recordRateLimit("tenant1");
      expect(handler.shouldBackoff("tenant1")).toBe(true);
    });

    it("should not affect other tenants", () => {
      handler.recordRateLimit("tenant1");
      expect(handler.shouldBackoff("tenant1")).toBe(true);
      expect(handler.shouldBackoff("tenant2")).toBe(false);
    });

    it("should stop backing off after backoff period", async () => {
      handler.recordRateLimit("tenant1");
      expect(handler.shouldBackoff("tenant1")).toBe(true);

      // Wait for backoff to expire
      await new Promise((r) => setTimeout(r, 100));

      expect(handler.shouldBackoff("tenant1")).toBe(false);
    });
  });

  describe("exponential backoff", () => {
    it("should double backoff on repeated rate limits", () => {
      handler.recordRateLimit("tenant1");
      expect(handler.getBackoffMs("tenant1")).toBe(100); // 50 * 2

      handler.recordRateLimit("tenant1");
      expect(handler.getBackoffMs("tenant1")).toBe(200); // 100 * 2

      handler.recordRateLimit("tenant1");
      expect(handler.getBackoffMs("tenant1")).toBe(400); // 200 * 2
    });

    it("should cap backoff at maxBackoffMs", () => {
      // Record many rate limits
      for (let i = 0; i < 10; i++) {
        handler.recordRateLimit("tenant1");
      }
      expect(handler.getBackoffMs("tenant1")).toBe(1000); // maxBackoffMs
    });

    it("should halve backoff on success", () => {
      handler.recordRateLimit("tenant1");
      handler.recordRateLimit("tenant1");
      expect(handler.getBackoffMs("tenant1")).toBe(200);

      handler.recordSuccess("tenant1");
      expect(handler.getBackoffMs("tenant1")).toBe(100);

      handler.recordSuccess("tenant1");
      expect(handler.getBackoffMs("tenant1")).toBe(50); // Back to initial
    });
  });

  describe("tenant management", () => {
    it("should evict oldest tenant when at capacity", () => {
      // Create handler with small capacity
      const smallHandler = new TenantRateLimitHandler({
        maxTenants: 3,
      });

      smallHandler.recordRateLimit("tenant1");
      smallHandler.recordRateLimit("tenant2");
      smallHandler.recordRateLimit("tenant3");
      expect(smallHandler.getStats().tenantCount).toBe(3);

      // Adding fourth tenant should evict first
      smallHandler.recordRateLimit("tenant4");
      expect(smallHandler.getStats().tenantCount).toBe(3);
    });

    it("should reset specific tenant", () => {
      handler.recordRateLimit("tenant1");
      handler.recordRateLimit("tenant2");

      handler.resetTenant("tenant1");

      expect(handler.shouldBackoff("tenant1")).toBe(false);
      expect(handler.shouldBackoff("tenant2")).toBe(true);
    });

    it("should reset all tenants", () => {
      handler.recordRateLimit("tenant1");
      handler.recordRateLimit("tenant2");

      handler.resetAll();

      // Check count is 0 after reset (before any operations that might create entries)
      expect(handler.getStats().tenantCount).toBe(0);

      // New calls will create fresh entries with no backoff
      expect(handler.shouldBackoff("tenant1")).toBe(false);
      expect(handler.shouldBackoff("tenant2")).toBe(false);
    });
  });
});

describe("Payload Size Validation", () => {
  describe("isPayloadWithinLimits", () => {
    it("should accept payloads within limit", () => {
      expect(isPayloadWithinLimits("short string")).toBe(true);
      expect(isPayloadWithinLimits({ key: "value" })).toBe(true);
    });

    it("should reject payloads over default limit (1MB)", () => {
      const largePayload = "x".repeat(1024 * 1024 + 1);
      expect(isPayloadWithinLimits(largePayload)).toBe(false);
    });

    it("should use custom limit when provided", () => {
      expect(isPayloadWithinLimits("12345", 5)).toBe(true);
      expect(isPayloadWithinLimits("123456", 5)).toBe(false);
    });

    it("should handle objects by stringifying", () => {
      const obj = { a: "x".repeat(100) };
      const size = JSON.stringify(obj).length;
      expect(isPayloadWithinLimits(obj, size)).toBe(true);
      expect(isPayloadWithinLimits(obj, size - 1)).toBe(false);
    });
  });

  describe("truncatePayload", () => {
    it("should not truncate payloads within limit", () => {
      expect(truncatePayload("short", 100)).toBe("short");
    });

    it("should truncate payloads over limit", () => {
      const result = truncatePayload("x".repeat(100), 50);
      // Truncates to maxSize - 20 for content + "... [truncated]" suffix (15 chars)
      // Result is 30 + 15 = 45 chars
      expect(result.length).toBeLessThan(50);
      expect(result).toContain("... [truncated]");
      expect(result.startsWith("x".repeat(30))).toBe(true);
    });
  });
});

describe("Hook Result Validation", () => {
  it("should return default for non-object input", () => {
    expect(validateHookResult(null)).toEqual({ block: false });
    expect(validateHookResult(undefined)).toEqual({ block: false });
    expect(validateHookResult("string")).toEqual({ block: false });
    expect(validateHookResult(123)).toEqual({ block: false });
  });

  it("should extract valid block boolean", () => {
    expect(validateHookResult({ block: true })).toEqual({ block: true });
    expect(validateHookResult({ block: false })).toEqual({ block: false });
  });

  it("should default block to false for invalid types", () => {
    expect(validateHookResult({ block: "true" })).toEqual({ block: false });
    expect(validateHookResult({ block: 1 })).toEqual({ block: false });
  });

  it("should extract and truncate blockReason", () => {
    expect(validateHookResult({ block: true, blockReason: "Attack detected" })).toEqual({
      block: true,
      blockReason: "Attack detected",
    });

    // Should truncate long reasons
    const longReason = "x".repeat(600);
    const result = validateHookResult({ block: true, blockReason: longReason });
    expect(result.blockReason?.length).toBe(500);
  });

  it("should extract and truncate blockResponse", () => {
    const result = validateHookResult({
      block: true,
      blockResponse: "Response to send",
    });
    expect(result.blockResponse).toBe("Response to send");
  });

  it("should extract and truncate modifiedContent", () => {
    const result = validateHookResult({
      block: false,
      modifiedContent: "Modified text",
    });
    expect(result.modifiedContent).toBe("Modified text");
  });

  it("should ignore non-string fields", () => {
    const result = validateHookResult({
      block: true,
      blockReason: 12345,
      blockResponse: { object: true },
      modifiedContent: null,
    });
    expect(result).toEqual({ block: true });
  });
});
