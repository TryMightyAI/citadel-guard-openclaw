/**
 * Tests for Security Fixes
 *
 * Validates the security fix implementations work correctly.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  isAllowedBinaryPath,
  validateCitadelArgs,
  shouldFailOpen,
  handleScanFailure,
  handleStreamingResponse,
  logScanOperation,
  logScanResult,
  logBlockEvent,
  generateHealthResponse,
  generateDetailedHealthResponse,
  type FailOpenConfig,
} from "../plugin/security-fixes";

// ============================================================================
// FIX 1: Binary Path Validation Tests
// ============================================================================

describe("FIX: Binary Path Validation", () => {
  describe("isAllowedBinaryPath", () => {
    it("allows 'citadel' from PATH", () => {
      expect(isAllowedBinaryPath("citadel")).toBe(true);
    });

    it("allows ./citadel", () => {
      expect(isAllowedBinaryPath("./citadel")).toBe(true);
    });

    it("allows absolute paths ending in citadel", () => {
      expect(isAllowedBinaryPath("/usr/local/bin/citadel")).toBe(true);
      expect(isAllowedBinaryPath("/opt/citadel/bin/citadel")).toBe(true);
      expect(isAllowedBinaryPath("/home/user/.local/bin/citadel")).toBe(true);
    });

    it("blocks shell interpreters", () => {
      expect(isAllowedBinaryPath("/bin/sh")).toBe(false);
      expect(isAllowedBinaryPath("/bin/bash")).toBe(false);
      expect(isAllowedBinaryPath("/usr/bin/python")).toBe(false);
      expect(isAllowedBinaryPath("/usr/bin/node")).toBe(false);
    });

    it("blocks path traversal", () => {
      expect(isAllowedBinaryPath("../citadel")).toBe(false);
      expect(isAllowedBinaryPath("../../bin/citadel")).toBe(false);
      expect(isAllowedBinaryPath("/usr/../bin/sh")).toBe(false);
    });

    it("blocks shell metacharacters", () => {
      expect(isAllowedBinaryPath("citadel; rm -rf /")).toBe(false);
      expect(isAllowedBinaryPath("citadel && evil")).toBe(false);
      expect(isAllowedBinaryPath("citadel | cat /etc/passwd")).toBe(false);
      expect(isAllowedBinaryPath("$(whoami)")).toBe(false);
      expect(isAllowedBinaryPath("`whoami`")).toBe(false);
    });

    it("blocks empty or whitespace", () => {
      expect(isAllowedBinaryPath("")).toBe(false);
      expect(isAllowedBinaryPath("   ")).toBe(false);
    });
  });

  describe("validateCitadelArgs", () => {
    it("allows safe arguments", () => {
      const args = ["serve", "3333", "--log-level", "info"];
      expect(validateCitadelArgs(args)).toEqual(args);
    });

    it("filters arguments with shell metacharacters", () => {
      const args = ["serve", "3333; rm -rf /", "--port", "$(whoami)"];
      const filtered = validateCitadelArgs(args);

      expect(filtered).toContain("serve");
      expect(filtered).toContain("--port");
      expect(filtered).not.toContain("3333; rm -rf /");
      expect(filtered).not.toContain("$(whoami)");
    });

    it("filters newlines", () => {
      const args = ["serve", "3333\nmalicious"];
      const filtered = validateCitadelArgs(args);

      expect(filtered).not.toContain("3333\nmalicious");
    });
  });
});

// ============================================================================
// FIX 2: Configurable Fail-Open Tests
// ============================================================================

describe("FIX: Configurable Fail-Open", () => {
  describe("shouldFailOpen", () => {
    it("uses failOpenInbound for inbound scans", () => {
      const config: FailOpenConfig = { failOpen: false, failOpenInbound: true };
      expect(shouldFailOpen(config, "inbound")).toBe(true);

      const config2: FailOpenConfig = { failOpen: true, failOpenInbound: false };
      expect(shouldFailOpen(config2, "inbound")).toBe(false);
    });

    it("uses failOpenOutbound for outbound scans", () => {
      const config: FailOpenConfig = { failOpen: false, failOpenOutbound: true };
      expect(shouldFailOpen(config, "outbound")).toBe(true);

      const config2: FailOpenConfig = { failOpen: true, failOpenOutbound: false };
      expect(shouldFailOpen(config2, "outbound")).toBe(false);
    });

    it("uses failOpenToolResults for tool_results scans", () => {
      const config: FailOpenConfig = { failOpen: false, failOpenToolResults: true };
      expect(shouldFailOpen(config, "tool_results")).toBe(true);

      const config2: FailOpenConfig = { failOpen: true, failOpenToolResults: false };
      expect(shouldFailOpen(config2, "tool_results")).toBe(false);
    });

    it("falls back to failOpen when specific option not set", () => {
      const configOpen: FailOpenConfig = { failOpen: true };
      expect(shouldFailOpen(configOpen, "inbound")).toBe(true);
      expect(shouldFailOpen(configOpen, "outbound")).toBe(true);
      expect(shouldFailOpen(configOpen, "tool_results")).toBe(true);

      const configClosed: FailOpenConfig = { failOpen: false };
      expect(shouldFailOpen(configClosed, "inbound")).toBe(false);
      expect(shouldFailOpen(configClosed, "outbound")).toBe(false);
      expect(shouldFailOpen(configClosed, "tool_results")).toBe(false);
    });
  });

  describe("handleScanFailure", () => {
    it("returns block=false when failing open", () => {
      const config: FailOpenConfig = { failOpen: true };
      const result = handleScanFailure(config, "inbound", "timeout", "test");

      expect(result.block).toBe(false);
    });

    it("returns block=true when failing closed", () => {
      const config: FailOpenConfig = { failOpen: false };
      const result = handleScanFailure(config, "inbound", "timeout", "test");

      expect(result.block).toBe(true);
      expect(result.reason).toBe("security_scan_unavailable");
    });

    it("respects per-type config", () => {
      const config: FailOpenConfig = {
        failOpen: false,
        failOpenOutbound: true,
      };

      // Inbound should block (uses failOpen)
      expect(handleScanFailure(config, "inbound", "error", "test").block).toBe(true);

      // Outbound should allow (uses failOpenOutbound)
      expect(handleScanFailure(config, "outbound", "error", "test").block).toBe(false);
    });
  });
});

// ============================================================================
// FIX 3: Streaming Response Handling Tests
// ============================================================================

describe("FIX: Streaming Response Handling", () => {
  describe("handleStreamingResponse", () => {
    it("returns undefined for non-streaming responses", () => {
      const result = handleStreamingResponse(false, {});
      expect(result).toBeUndefined();
    });

    it("blocks streaming when blockStreamingResponses=true", () => {
      const result = handleStreamingResponse(true, { blockStreamingResponses: true });

      expect(result).not.toBeUndefined();
      expect(result?.block).toBe(true);
      expect(result?.reason).toContain("streaming");
    });

    it("allows streaming with warning when blockStreamingResponses=false", () => {
      const logger = { warn: vi.fn() };
      const result = handleStreamingResponse(
        true,
        { blockStreamingResponses: false },
        logger,
      );

      expect(result).toBeUndefined();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("Streaming response bypassing"),
      );
    });

    it("allows streaming with warning when blockStreamingResponses not set", () => {
      const logger = { warn: vi.fn() };
      const result = handleStreamingResponse(true, {}, logger);

      expect(result).toBeUndefined();
      expect(logger.warn).toHaveBeenCalled();
    });
  });
});

// ============================================================================
// FIX 4: Secure Logging Tests
// ============================================================================

describe("FIX: Secure Logging", () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe("logScanOperation", () => {
    it("logs only the content length, not content", () => {
      logScanOperation("input", 500, "/v1/chat");

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("500 chars"),
      );
      // Should not log any actual content
    });

    it("includes endpoint when provided", () => {
      logScanOperation("input", 100, "/v1/chat/completions");

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("/v1/chat/completions"),
      );
    });
  });

  describe("logScanResult", () => {
    it("logs decision and score", () => {
      logScanResult("input", "BLOCK", 95);

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("BLOCK"),
      );
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("95"),
      );
    });
  });

  describe("logBlockEvent", () => {
    it("sanitizes reason to prevent log injection", () => {
      logBlockEvent("test", "Attack\nwith\nnewlines");

      // Call should succeed and not throw
      expect(consoleLogSpy).toHaveBeenCalled();

      // The logged message should have newlines replaced
      const loggedMessage = consoleLogSpy.mock.calls[0][0];
      expect(loggedMessage).not.toContain("\n");
    });

    it("truncates long reasons", () => {
      const longReason = "x".repeat(200);
      logBlockEvent("test", longReason);

      const loggedMessage = consoleLogSpy.mock.calls[0][0] as string;
      // Should be truncated to 100 chars
      expect(loggedMessage.length).toBeLessThan(200);
    });
  });
});

// ============================================================================
// FIX 5: Health Response Tests
// ============================================================================

describe("FIX: Health Response", () => {
  describe("generateHealthResponse", () => {
    it("returns minimal response without internal URLs", () => {
      const response = generateHealthResponse();

      expect(response).toEqual({ status: "ok" });
      expect(response).not.toHaveProperty("citadel");
      expect(response).not.toHaveProperty("upstream");
    });
  });

  describe("generateDetailedHealthResponse", () => {
    it("returns minimal response when not authenticated", () => {
      const response = generateDetailedHealthResponse(
        "http://internal:3333",
        "http://internal:18789",
        false,
      );

      expect(response).toEqual({ status: "ok" });
    });

    it("returns full response when authenticated", () => {
      const response = generateDetailedHealthResponse(
        "http://internal:3333",
        "http://internal:18789",
        true,
      );

      expect(response.status).toBe("ok");
      expect(response.citadel).toBe("http://internal:3333");
      expect(response.upstream).toBe("http://internal:18789");
    });
  });
});

// ============================================================================
// Integration Tests: Verify fixes work together
// ============================================================================

describe("FIX: Integration Tests", () => {
  it("complete fail-closed flow works", () => {
    const config: FailOpenConfig = {
      failOpen: false,
      failOpenInbound: false,
      failOpenOutbound: false,
      failOpenToolResults: false,
      blockStreamingResponses: true,
    };

    // Inbound scan failure should block
    expect(handleScanFailure(config, "inbound", "error", "test").block).toBe(true);

    // Outbound scan failure should block
    expect(handleScanFailure(config, "outbound", "error", "test").block).toBe(true);

    // Tool results scan failure should block
    expect(handleScanFailure(config, "tool_results", "error", "test").block).toBe(true);

    // Streaming should block
    expect(handleStreamingResponse(true, config)?.block).toBe(true);
  });

  it("complete fail-open flow works", () => {
    const config: FailOpenConfig = {
      failOpen: true,
      failOpenInbound: true,
      failOpenOutbound: true,
      failOpenToolResults: true,
      blockStreamingResponses: false,
    };

    // All failures should allow through
    expect(handleScanFailure(config, "inbound", "error", "test").block).toBe(false);
    expect(handleScanFailure(config, "outbound", "error", "test").block).toBe(false);
    expect(handleScanFailure(config, "tool_results", "error", "test").block).toBe(false);
    expect(handleStreamingResponse(true, config)).toBeUndefined();
  });

  it("mixed config works correctly", () => {
    const config: FailOpenConfig = {
      failOpen: false,
      failOpenInbound: false, // Block on inbound failure
      failOpenOutbound: true, // Allow on outbound failure
      failOpenToolResults: true, // Allow on tool results failure
      blockStreamingResponses: true, // Block streaming
    };

    expect(handleScanFailure(config, "inbound", "error", "test").block).toBe(true);
    expect(handleScanFailure(config, "outbound", "error", "test").block).toBe(false);
    expect(handleScanFailure(config, "tool_results", "error", "test").block).toBe(false);
    expect(handleStreamingResponse(true, config)?.block).toBe(true);
  });
});
