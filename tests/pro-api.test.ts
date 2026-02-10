/**
 * Pro API Tests
 *
 * Tests for Citadel Pro API integration including:
 * - API key detection
 * - Response normalization
 * - Rate limiting
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  PRO_ENDPOINT,
  RateLimitHandler,
  isProApiKey,
  normalizeScanResult,
  resolveApiKey,
} from "../plugin/pro-api";

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch as unknown as typeof fetch;

describe("Pro API", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    // Clear env var - must use Reflect.deleteProperty, not assignment (process.env coerces undefined to "undefined")
    Reflect.deleteProperty(process.env, "CITADEL_API_KEY");
  });

  describe("isProApiKey", () => {
    it("should identify live Pro API keys", () => {
      expect(isProApiKey("mc_live_abc123xyz")).toBe(true);
      expect(isProApiKey("mc_live_D08NkSWBMDdQxQ4spbaEaLfoj4W5YweZ")).toBe(
        true,
      );
    });

    it("should identify test Pro API keys", () => {
      expect(isProApiKey("mc_test_abc123xyz")).toBe(true);
      expect(isProApiKey("mc_test_testkey123")).toBe(true);
    });

    it("should reject invalid API keys", () => {
      expect(isProApiKey(undefined)).toBe(false);
      expect(isProApiKey("")).toBe(false);
      expect(isProApiKey("sk_live_123")).toBe(false);
      expect(isProApiKey("random_key")).toBe(false);
      expect(isProApiKey("mc_invalid_key")).toBe(false);
    });
  });

  describe("resolveApiKey", () => {
    it("should prefer config over env var", () => {
      process.env.CITADEL_API_KEY = "mc_live_env_key";
      expect(resolveApiKey("mc_live_config_key")).toBe("mc_live_config_key");
    });

    it("should fall back to env var", () => {
      process.env.CITADEL_API_KEY = "mc_live_env_key";
      expect(resolveApiKey(undefined)).toBe("mc_live_env_key");
    });

    it("should return undefined when no key available", () => {
      expect(resolveApiKey(undefined)).toBeUndefined();
    });
  });

  describe("normalizeScanResult", () => {
    describe("Pro API format", () => {
      it("should normalize BLOCK action", () => {
        const proResponse = {
          action: "BLOCK",
          risk_score: 95,
          session_id: "sess_123",
          turn_number: 1,
          reason: "Injection detected",
        };

        const normalized = normalizeScanResult(proResponse, true);

        expect(normalized.decision).toBe("BLOCK");
        expect(normalized.score).toBe(95);
        expect(normalized.sessionId).toBe("sess_123");
        expect(normalized.turnNumber).toBe(1);
        expect(normalized.reason).toBe("Injection detected");
      });

      it("should normalize ALLOW action", () => {
        const proResponse = {
          action: "ALLOW",
          risk_score: 5,
        };

        const normalized = normalizeScanResult(proResponse, true);

        expect(normalized.decision).toBe("ALLOW");
        expect(normalized.score).toBe(5);
      });

      it("should normalize WARN action", () => {
        const proResponse = {
          action: "WARN",
          risk_score: 50,
        };

        const normalized = normalizeScanResult(proResponse, true);

        expect(normalized.decision).toBe("WARN");
        expect(normalized.score).toBe(50);
      });

      it("should handle missing fields", () => {
        const proResponse = {};

        const normalized = normalizeScanResult(proResponse, true);

        expect(normalized.decision).toBe("ALLOW");
        expect(normalized.score).toBe(0);
        expect(normalized.sessionId).toBeUndefined();
      });
    });

    describe("OSS API format", () => {
      it("should normalize BLOCK decision", () => {
        const ossResponse = {
          decision: "BLOCK",
          heuristic_score: 0.95,
          reason: "High score",
        };

        const normalized = normalizeScanResult(ossResponse, false);

        expect(normalized.decision).toBe("BLOCK");
        expect(normalized.score).toBe(95); // 0.95 * 100
        expect(normalized.reason).toBe("High score");
      });

      it("should normalize ALLOW decision", () => {
        const ossResponse = {
          decision: "ALLOW",
          heuristic_score: 0.1,
        };

        const normalized = normalizeScanResult(ossResponse, false);

        expect(normalized.decision).toBe("ALLOW");
        expect(normalized.score).toBe(10);
      });

      it("should handle is_safe and risk_level", () => {
        const ossResponse = {
          decision: "ALLOW",
          is_safe: true,
          risk_level: "LOW",
        };

        const normalized = normalizeScanResult(ossResponse, false);

        expect(normalized.isSafe).toBe(true);
        expect(normalized.riskLevel).toBe("LOW");
      });

      it("should handle risk_score field (alternative to heuristic_score)", () => {
        const ossResponse = {
          decision: "BLOCK",
          risk_score: 85,
        };

        const normalized = normalizeScanResult(ossResponse, false);

        expect(normalized.score).toBe(85);
      });
    });
  });

  describe("RateLimitHandler", () => {
    let handler: RateLimitHandler;

    beforeEach(() => {
      handler = new RateLimitHandler();
    });

    it("should not back off initially", () => {
      expect(handler.shouldBackoff()).toBe(false);
    });

    it("should back off after rate limit", () => {
      handler.recordRateLimit();
      expect(handler.shouldBackoff()).toBe(true);
    });

    it("should increase backoff exponentially", () => {
      expect(handler.getBackoffMs()).toBe(1000);

      handler.recordRateLimit();
      expect(handler.getBackoffMs()).toBe(2000);

      handler.recordRateLimit();
      expect(handler.getBackoffMs()).toBe(4000);

      handler.recordRateLimit();
      expect(handler.getBackoffMs()).toBe(8000);
    });

    it("should cap backoff at maxBackoffMs", () => {
      // Record many rate limits to hit the cap
      for (let i = 0; i < 10; i++) {
        handler.recordRateLimit();
      }

      expect(handler.getBackoffMs()).toBe(60000);
    });

    it("should decrease backoff on success", () => {
      // Build up backoff
      handler.recordRateLimit();
      handler.recordRateLimit();
      expect(handler.getBackoffMs()).toBe(4000);

      // Success should reduce it
      handler.recordSuccess();
      expect(handler.getBackoffMs()).toBe(2000);

      handler.recordSuccess();
      expect(handler.getBackoffMs()).toBe(1000);

      // Should not go below 1000
      handler.recordSuccess();
      expect(handler.getBackoffMs()).toBe(1000);
    });

    it("should reset state", () => {
      handler.recordRateLimit();
      handler.recordRateLimit();

      handler.reset();

      expect(handler.shouldBackoff()).toBe(false);
      expect(handler.getBackoffMs()).toBe(1000);
    });
  });

  describe("PRO_ENDPOINT", () => {
    it("should be the correct Pro API URL", () => {
      expect(PRO_ENDPOINT).toBe("https://gateway.trymighty.ai/v1/scan");
    });
  });
});

describe("Pro API Integration (Mocked)", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("should use Pro endpoint with API key header", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ action: "ALLOW", risk_score: 5 }),
    });

    await fetch(PRO_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "mc_live_test123",
      },
      body: JSON.stringify({
        content: "Hello",
        scan_phase: "input",
      }),
    });

    expect(mockFetch).toHaveBeenCalledWith(
      "https://gateway.trymighty.ai/v1/scan",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "X-API-Key": "mc_live_test123",
        }),
      }),
    );
  });

  it("should handle 401 authentication error", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
    });

    const res = await fetch(PRO_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "mc_invalid_key",
      },
      body: JSON.stringify({ content: "test", scan_phase: "input" }),
    });

    expect(res.status).toBe(401);
  });

  it("should handle 429 rate limit", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
    });

    const res = await fetch(PRO_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "mc_live_test123",
      },
      body: JSON.stringify({ content: "test", scan_phase: "input" }),
    });

    expect(res.status).toBe(429);
  });

  it("should send session_id for multi-turn tracking", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        action: "ALLOW",
        risk_score: 10,
        session_id: "sess_123",
        turn_number: 2,
      }),
    });

    await fetch(PRO_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "mc_live_test123",
      },
      body: JSON.stringify({
        content: "Hello again",
        scan_phase: "input",
        session_id: "sess_123",
      }),
    });

    expect(mockFetch).toHaveBeenCalledWith(
      PRO_ENDPOINT,
      expect.objectContaining({
        body: expect.stringContaining("session_id"),
      }),
    );
  });
});
