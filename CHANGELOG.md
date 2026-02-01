# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-30

### Added

- **Pro API Integration**: Support for Citadel Pro API with automatic detection via API key format (mc_live_*, mc_test_*)
- **Response Normalization**: Unified response format for both OSS and Pro APIs
- **Multi-turn Session Detection**: Extract and pass session IDs for multi-turn attack detection
- **Configurable Fail Behavior**: `failOpen` option to control behavior when Citadel is unavailable
- **LRU Caching**: Configurable cache for scan results to reduce API calls
- **Metrics Collection**: Track scans, blocks, cache hits, latency percentiles
- **`citadel_metrics` Tool**: On-demand metrics retrieval
- **Skills Scanning at Startup**: Scan skills directory for malicious content before loading
- **Rate Limiting with Backoff**: Automatic exponential backoff on 429 responses
- **Session Extraction**: Extract session IDs from conversation metadata

### Changed

- **Package renamed** from `moltbot-citadel-guard` to `@trymightyai/citadel-guard-openclaw`
- **Default block messages** no longer include emoji for cleaner output
- **Modular architecture**: Split into `cache.ts`, `metrics.ts`, `pro-api.ts` modules

### Fixed

- Proper handling of timeout errors
- Cache key includes sessionId for session-specific caching

## [0.0.1] - 2025-01-15

### Added

- Initial release
- Basic inbound/outbound scanning
- Tool argument scanning
- Indirect injection detection in tool results
- OpenAI-compatible proxy
- Integration with Citadel OSS
