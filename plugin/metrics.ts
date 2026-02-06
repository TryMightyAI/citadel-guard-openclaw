/**
 * Metrics collection for Citadel Guard
 *
 * Tracks scan counts, latencies, cache performance, and errors.
 * Provides periodic logging and a tool for on-demand metrics retrieval.
 */

import type { LRUCache } from "./cache";

export interface CitadelMetrics {
  // Scan counts
  scansTotal: number;
  blockedTotal: number;
  allowedTotal: number;
  warnedTotal: number;
  errorsTotal: number;

  // By mode
  inputScans: number;
  outputScans: number;

  // API type
  proScans: number;
  ossScans: number;

  // Cache
  cacheHits: number;
  cacheMisses: number;
  cacheSize: number;

  // Latency (calculated from samples)
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;

  // Sessions
  activeSessions: number;
  totalTurns: number;

  // Errors by type
  timeouts: number;
  rateLimits: number;
  authErrors: number;

  // Uptime
  startedAt: number;
  uptimeMs: number;
}

export interface RecordScanParams {
  decision: string;
  mode: "input" | "output";
  isPro: boolean;
  latencyMs: number;
  error?: string;
  sessionId?: string;
}

interface Logger {
  info: (msg: string) => void;
  warn?: (msg: string) => void;
  error?: (msg: string) => void;
}

export class MetricsCollector {
  private scansTotal = 0;
  private blockedTotal = 0;
  private allowedTotal = 0;
  private warnedTotal = 0;
  private errorsTotal = 0;
  private inputScans = 0;
  private outputScans = 0;
  private proScans = 0;
  private ossScans = 0;
  private cacheHits = 0;
  private cacheMisses = 0;
  private timeouts = 0;
  private rateLimits = 0;
  private authErrors = 0;
  private startedAt = Date.now();
  private latencySamples: number[] = [];
  private maxLatencySamples = 1000;
  // Cache sorted samples to avoid O(n log n) sort on every getMetrics() call
  private cachedSortedSamples: number[] | null = null;

  private cache?: LRUCache<unknown>;
  private logInterval?: ReturnType<typeof setInterval>;

  // Session tracking with bounded size to prevent memory leaks
  private sessions = new Map<
    string,
    { firstSeen: number; turnCount: number; blockedCount: number }
  >();
  private readonly maxSessions = 50000;

  /**
   * Record a scan result
   */
  recordScan(params: RecordScanParams): void {
    this.scansTotal++;

    if (params.mode === "input") this.inputScans++;
    else this.outputScans++;

    if (params.isPro) this.proScans++;
    else this.ossScans++;

    if (params.error) {
      this.errorsTotal++;
      const errLower = params.error.toLowerCase();
      if (errLower.includes("timeout") || errLower.includes("abort")) {
        this.timeouts++;
      }
      if (errLower.includes("429") || errLower.includes("rate")) {
        this.rateLimits++;
      }
      if (
        errLower.includes("401") ||
        errLower.includes("auth") ||
        errLower.includes("unauthorized")
      ) {
        this.authErrors++;
      }
    } else {
      const dec = params.decision.toUpperCase();
      if (dec === "BLOCK") this.blockedTotal++;
      else if (dec === "WARN") this.warnedTotal++;
      else this.allowedTotal++;
    }

    // Track latency (rolling window) - invalidate cache on change
    this.latencySamples.push(params.latencyMs);
    this.cachedSortedSamples = null; // Invalidate cache
    if (this.latencySamples.length > this.maxLatencySamples) {
      this.latencySamples.shift();
    }

    // Track session
    if (params.sessionId) {
      this.trackSession(params.sessionId, params.decision === "BLOCK");
    }
  }

  /**
   * Record a cache hit
   */
  recordCacheHit(): void {
    this.cacheHits++;
  }

  /**
   * Record a cache miss
   */
  recordCacheMiss(): void {
    this.cacheMisses++;
  }

  /**
   * Track session activity with bounded size
   * Uses LRU-style eviction to prevent unbounded memory growth
   */
  private trackSession(sessionId: string, blocked: boolean): void {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      existing.turnCount++;
      if (blocked) existing.blockedCount++;
      return; // Skip cleanup if just updating existing session
    }

    // Only cleanup when adding new sessions to avoid O(n) on every call
    if (this.sessions.size >= this.maxSessions) {
      // Evict oldest 10% of sessions
      const toEvict = Math.floor(this.maxSessions * 0.1);
      let evicted = 0;
      for (const [id] of this.sessions) {
        if (evicted >= toEvict) break;
        this.sessions.delete(id);
        evicted++;
      }
    }

    // Also clean up old sessions (>1 hour) but only when at capacity
    if (this.sessions.size >= this.maxSessions * 0.9) {
      const cutoff = Date.now() - 60 * 60 * 1000;
      for (const [id, data] of this.sessions) {
        if (data.firstSeen < cutoff) this.sessions.delete(id);
      }
    }

    this.sessions.set(sessionId, {
      firstSeen: Date.now(),
      turnCount: 1,
      blockedCount: blocked ? 1 : 0,
    });
  }

  /**
   * Get sorted samples with caching to avoid O(n log n) on every call
   */
  private getSortedSamples(): number[] {
    if (!this.cachedSortedSamples) {
      this.cachedSortedSamples = [...this.latencySamples].sort((a, b) => a - b);
    }
    return this.cachedSortedSamples;
  }

  /**
   * Calculate percentile from cached sorted array
   * O(1) for repeated calls until samples change
   */
  private percentile(p: number): number {
    const sorted = this.getSortedSamples();
    if (sorted.length === 0) return 0;
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
  }

  /**
   * Get all metrics
   */
  getMetrics(): CitadelMetrics {
    const samples = this.latencySamples;
    const avg =
      samples.length > 0
        ? samples.reduce((a, b) => a + b, 0) / samples.length
        : 0;

    // Calculate total turns across all sessions
    let totalTurns = 0;
    for (const session of this.sessions.values()) {
      totalTurns += session.turnCount;
    }

    return {
      scansTotal: this.scansTotal,
      blockedTotal: this.blockedTotal,
      allowedTotal: this.allowedTotal,
      warnedTotal: this.warnedTotal,
      errorsTotal: this.errorsTotal,
      inputScans: this.inputScans,
      outputScans: this.outputScans,
      proScans: this.proScans,
      ossScans: this.ossScans,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      cacheSize: this.cache?.size || 0,
      avgLatencyMs: Math.round(avg),
      p50LatencyMs: this.percentile(50),
      p95LatencyMs: this.percentile(95),
      p99LatencyMs: this.percentile(99),
      activeSessions: this.sessions.size,
      totalTurns,
      timeouts: this.timeouts,
      rateLimits: this.rateLimits,
      authErrors: this.authErrors,
      startedAt: this.startedAt,
      uptimeMs: Date.now() - this.startedAt,
    };
  }

  /**
   * Set cache reference for size tracking
   */
  setCache(cache: LRUCache<unknown>): void {
    this.cache = cache;
  }

  /**
   * Start periodic metrics logging
   */
  startPeriodicLogging(intervalMs: number, logger: Logger): void {
    if (intervalMs <= 0) return;

    this.logInterval = setInterval(() => {
      const m = this.getMetrics();
      const cacheTotal = m.cacheHits + m.cacheMisses;
      const hitRate =
        cacheTotal > 0 ? ((m.cacheHits / cacheTotal) * 100).toFixed(1) : "0";

      logger.info(
        `[citadel-guard] metrics: scans=${m.scansTotal} blocked=${m.blockedTotal} ` +
          `cache_hit_rate=${hitRate}% avg_latency=${m.avgLatencyMs}ms p95=${m.p95LatencyMs}ms`,
      );
    }, intervalMs);
  }

  /**
   * Stop periodic logging
   */
  stopPeriodicLogging(): void {
    if (this.logInterval) {
      clearInterval(this.logInterval);
      this.logInterval = undefined;
    }
  }

  /**
   * Reset all metrics (for testing)
   */
  reset(): void {
    this.scansTotal = 0;
    this.blockedTotal = 0;
    this.allowedTotal = 0;
    this.warnedTotal = 0;
    this.errorsTotal = 0;
    this.inputScans = 0;
    this.outputScans = 0;
    this.proScans = 0;
    this.ossScans = 0;
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.timeouts = 0;
    this.rateLimits = 0;
    this.authErrors = 0;
    this.latencySamples = [];
    this.cachedSortedSamples = null;
    this.sessions.clear();
    this.startedAt = Date.now();
  }

  /**
   * Format metrics as JSON for the citadel_metrics tool
   */
  formatForTool(): string {
    const m = this.getMetrics();
    const cacheTotal = m.cacheHits + m.cacheMisses;
    const cacheHitRate =
      cacheTotal > 0 ? ((m.cacheHits / cacheTotal) * 100).toFixed(1) : "0";
    const blockRate =
      m.scansTotal > 0
        ? ((m.blockedTotal / m.scansTotal) * 100).toFixed(1)
        : "0";

    return JSON.stringify(
      {
        summary: {
          totalScans: m.scansTotal,
          blocked: m.blockedTotal,
          allowed: m.allowedTotal,
          warned: m.warnedTotal,
          errors: m.errorsTotal,
          blockRate: `${blockRate}%`,
        },
        byMode: {
          input: m.inputScans,
          output: m.outputScans,
        },
        api: {
          proScans: m.proScans,
          ossScans: m.ossScans,
        },
        cache: {
          hits: m.cacheHits,
          misses: m.cacheMisses,
          hitRate: `${cacheHitRate}%`,
          size: m.cacheSize,
        },
        latency: {
          avgMs: m.avgLatencyMs,
          p50Ms: m.p50LatencyMs,
          p95Ms: m.p95LatencyMs,
          p99Ms: m.p99LatencyMs,
        },
        sessions: {
          active: m.activeSessions,
          totalTurns: m.totalTurns,
        },
        errors: {
          timeouts: m.timeouts,
          rateLimits: m.rateLimits,
          authErrors: m.authErrors,
        },
        uptime: {
          startedAt: new Date(m.startedAt).toISOString(),
          uptimeHours: (m.uptimeMs / 3600000).toFixed(2),
        },
      },
      null,
      2,
    );
  }
}
