# Citadel Guard for OpenClaw

**Protect your AI agents from prompt injection, jailbreaks, and data leakage.**

Citadel Guard is a security plugin for [OpenClaw](https://github.com/openclaw/openclaw) that scans every message going in and out of your AI agent. It catches attacks before they reach your model and prevents sensitive data from leaking out.

---

## ⚠️ CRITICAL: HTTP API Protection

**OpenClaw's plugin hooks do NOT cover the HTTP API endpoints** in the current release. The following are completely unprotected by plugins alone:

| Endpoint | Current Status | With PR #6405 |
|----------|----------------|---------------|
| `/v1/chat/completions` | **BYPASSES HOOKS** | ✅ Protected |
| `/v1/responses` | **BYPASSES HOOKS** | ✅ Protected |
| `/tools/invoke` | **BYPASSES HOOKS** | ✅ Protected |

### Full Protection Setup

**If using OpenClaw with [PR #6405](https://github.com/openclaw/openclaw/pull/6405):** HTTP API hooks are automatically registered. No additional setup needed.

**If using current OpenClaw release:** You **MUST** also run the Citadel OpenAI Proxy:

```bash
# Start the proxy (intercepts all HTTP API calls)
CITADEL_URL=http://localhost:3333 \
UPSTREAM_URL=http://localhost:18789 \
bun run citadel-openai-proxy.ts
```

Then configure your LLM clients to use `http://localhost:5050` instead of hitting OpenClaw directly.

See [HTTP API Protection](#http-api-protection-proxy) section below for full setup.

---

## How It Works

```
User sends message
        │
        ▼
┌───────────────────┐
│  Citadel Guard    │ ◄── Scans for prompt injection
│  (this plugin)    │
└───────────────────┘
        │
        ├── Attack detected → Block & warn user
        │
        └── Safe → Forward to AI
                        │
                        ▼
                 ┌──────────────┐
                 │  AI Response │
                 └──────────────┘
                        │
                        ▼
               ┌───────────────────┐
               │  Citadel Guard    │ ◄── Scans for credential leaks
               └───────────────────┘
                        │
                        ├── Leak detected → Block response
                        │
                        └── Safe → Deliver to user
```

---

## Choose Your Setup

There are two ways to use Citadel Guard:

| | **Citadel Pro** (Recommended) | **Citadel OSS** (Self-hosted) |
|---|---|---|
| **Setup** | Just add your API key | Run the scanner yourself |
| **Infrastructure** | We host everything | You host the Go server |
| **Text scanning** | ✅ | ✅ |
| **Image scanning** | ✅ | ❌ |
| **PDF/Document scanning** | ✅ | ❌ |
| **Multi-turn attack detection** | ✅ Advanced | Basic |
| **Session tracking** | ✅ Built-in | Manual |
| **Best for** | Production, teams | Development, air-gapped environments |

### Which should I choose?

- **Use Pro** if you want the easiest setup and need image/document scanning
- **Use OSS** if you need to run everything on your own infrastructure

---

## Quick Start: Citadel Pro (5 minutes)

**No servers to run. No Go installation. Just an API key.**

### Step 1: Get your API key

Visit [trymighty.ai](https://trymighty.ai) and create an account. Your API key looks like `mc_live_xxxxx`.

### Step 2: Install the plugin

```bash
cd your-openclaw-project
git clone https://github.com/TryMightyAI/citadel-guard-openclaw.git plugins/citadel-guard
cd plugins/citadel-guard && bun install
```

### Step 3: Configure

Add to your OpenClaw config file (usually `config.json` or `openclaw.config.json`):

```json
{
  "plugins": {
    "citadel-guard": {
      "apiKey": "mc_live_YOUR_KEY_HERE"
    }
  }
}
```

Or use an environment variable instead:

```bash
export CITADEL_API_KEY=mc_live_YOUR_KEY_HERE
```

### Step 4: Done!

Start your OpenClaw agent. Citadel Guard will automatically scan all messages.

---

## Quick Start: Citadel OSS (Self-hosted)

**Run the scanner on your own infrastructure. Requires running a Go server.**

### Step 1: Install the Citadel scanner

You have three options:

**Option A: Download pre-built binary** (easiest)
```bash
# macOS
curl -L https://github.com/TryMightyAI/citadel/releases/latest/download/citadel-darwin-arm64 -o citadel
chmod +x citadel

# Linux
curl -L https://github.com/TryMightyAI/citadel/releases/latest/download/citadel-linux-amd64 -o citadel
chmod +x citadel
```

**Option B: Use Docker**
```bash
docker run -p 3333:3333 trymightyai/citadel:latest
```

**Option C: Build from source** (requires Go 1.21+)
```bash
git clone https://github.com/TryMightyAI/citadel.git
cd citadel
go build -o citadel ./cmd/gateway
./citadel --port 3333
```

### Step 2: Start the scanner

```bash
./citadel --port 3333
```

Verify it's running:
```bash
curl http://localhost:3333/health
# Should return: {"status":"ok"}
```

### Step 3: Install the plugin

```bash
cd your-openclaw-project
git clone https://github.com/TryMightyAI/citadel-guard-openclaw.git plugins/citadel-guard
cd plugins/citadel-guard && bun install
```

### Step 4: Configure

Add to your OpenClaw config:

```json
{
  "plugins": {
    "citadel-guard": {
      "endpoint": "http://localhost:3333"
    }
  }
}
```

### Step 5: Done!

Start your OpenClaw agent. Citadel Guard will scan messages through your local scanner.

---

## What Gets Protected

### Plugin Hooks (Messaging Platforms)

These hooks protect messages through Telegram, Discord, Slack, etc.:

| Hook | Status | What it does |
|------|--------|--------------|
| `before_tool_call` | ✅ Active | Scans tool arguments before execution |
| `after_tool_call` | ✅ Active | Detects indirect injection in tool results |
| `tool_result_persist` | ✅ Active | Sanitizes dangerous tool outputs |
| `before_agent_start` | ✅ Active | Scans initial context/prompts |
| `message_received` | ⏳ Future | Will scan inbound user messages |
| `message_sending` | ⏳ Future | Will scan outbound AI responses |

> **Note:** `message_received` and `message_sending` are [planned but not yet implemented](https://docs.openclaw.ai/hooks) in OpenClaw. Tool-related hooks ARE active and provide protection for indirect injection via tool results.

### HTTP API Hooks (Coming Soon)

We've submitted [PR #6405](https://github.com/openclaw/openclaw/pull/6405) to OpenClaw adding HTTP API hooks. Once merged, these hooks will provide **native HTTP API protection without the proxy**:

| Hook | What it does |
|------|--------------|
| `http_request_received` | Scans `/v1/chat/completions`, `/v1/responses` requests |
| `http_response_sending` | Scans LLM responses for data exfiltration |
| `http_tool_invoke` | Scans `/tools/invoke` arguments |
| `http_tool_result` | Scans tool results for indirect injection |

**Status:** The plugin support for these hooks is ready in the [`feat/http-api-hooks`](https://github.com/TryMightyAI/citadel-guard-openclaw/tree/feat/http-api-hooks) branch. Once OpenClaw merges PR #6405, we'll merge this branch to main.

**Until then:** Use the [Citadel Proxy](#option-b-citadel-proxy-recommended-for-http-apis) for HTTP API protection.

### HTTP API (Requires Proxy)

The plugin hooks **DO NOT** fire for direct HTTP API calls. You must use the proxy:

| Hook | What it does | Example attacks blocked |
|------|--------------|------------------------|
| **Inbound messages** | Scans user input before it reaches your AI | "Ignore previous instructions", jailbreaks, prompt injection |
| **Outbound responses** | Scans AI output before delivery | Credential leaks, PII exposure, system prompt extraction |
| **Tool calls** | Scans arguments to dangerous tools | `rm -rf /`, malicious shell commands |
| **Tool results** | Scans data returned by tools | Indirect injection hidden in web pages, files |
| **Agent startup** | Scans initial context | Poisoned system prompts |

---

## Feature Comparison

| Feature | OSS (Free) | Pro (Subscription) |
|---------|------------|-------------------|
| **Text scanning** | ✅ | ✅ |
| **Heuristic detection** | ✅ | ✅ |
| **BERT-based classification** | ✅ | ✅ |
| **Multi-turn attack detection** | Basic patterns | Advanced ML + session analysis |
| **Image scanning (screenshots, photos)** | ❌ | ✅ |
| **PDF scanning** | ❌ | ✅ |
| **Document scanning (Word, Excel)** | ❌ | ✅ |
| **QR code / barcode detection** | ❌ | ✅ |
| **Steganography detection** | ❌ | ✅ |
| **Session tracking** | Manual | Automatic |
| **Rate limits** | None (self-hosted) | Per-plan |
| **Support** | Community | Email + priority |

### When do I need Pro?

- **You're building a chatbot that accepts image uploads** → Pro (image scanning)
- **Users can share PDFs or documents** → Pro (document scanning)
- **You need to detect sophisticated multi-turn attacks** → Pro (advanced ML)
- **You want zero infrastructure to manage** → Pro (hosted)
- **You're in development or have air-gapped requirements** → OSS works great

---

## Multimodal Scanning (Pro)

Citadel Pro scans **images, PDFs, and documents** for embedded attacks that bypass text-only detection.

### What Gets Scanned

| Content Type | Detection | Examples |
|--------------|-----------|----------|
| **Images** | OCR + vision analysis | Screenshots with hidden instructions, photos of text |
| **PDFs** | Text extraction + layout analysis | Documents with injection in headers/footers |
| **Office Docs** | Content extraction | Word/Excel with embedded malicious content |
| **QR Codes** | Decode + scan payload | QR codes linking to injection payloads |

### How It Works

When you send messages with images or documents via the OpenAI-compatible API, Citadel Guard automatically extracts and scans multimodal content:

```json
{
  "messages": [
    {
      "role": "user",
      "content": [
        { "type": "text", "text": "What does this say?" },
        { "type": "image_url", "image_url": { "url": "data:image/png;base64,..." } }
      ]
    }
  ]
}
```

The plugin:
1. Extracts text from the message
2. Extracts images (base64 or URLs)
3. Sends both to Citadel Pro for unified scanning
4. Blocks if injection detected in text OR image

### Visual Attack Examples

These attacks are caught by Pro's multimodal scanning:

| Attack | Blocked? |
|--------|----------|
| Screenshot of "Ignore all instructions" | ✅ Yes |
| PDF with hidden text layer | ✅ Yes |
| Image with text rendered in unusual fonts | ✅ Yes |
| QR code linking to malicious prompt | ✅ Yes |
| Steganography (hidden data in image) | ✅ Yes |

---

## Configuration Reference

### Minimal Config (Pro)

```json
{
  "plugins": {
    "citadel-guard": {
      "apiKey": "mc_live_YOUR_KEY"
    }
  }
}
```

### Minimal Config (OSS)

```json
{
  "plugins": {
    "citadel-guard": {
      "endpoint": "http://localhost:3333"
    }
  }
}
```

### Full Config (all options)

```json
{
  "plugins": {
    "citadel-guard": {
      "apiKey": "",
      "endpoint": "http://localhost:3333",
      "timeoutMs": 2000,
      "failOpen": false,
      "cacheEnabled": true,
      "cacheTtlMs": 60000,
      "cacheMaxSize": 1000,
      "metricsEnabled": true,
      "metricsLogIntervalMs": 60000,
      "scanSkillsOnStartup": true,
      "skillsDirectory": "./skills",
      "blockOnMaliciousSkills": true,
      "inboundBlockDecisions": ["BLOCK"],
      "inboundBlockMessage": "Request blocked for security reasons.",
      "outboundBlockOnUnsafe": true,
      "outboundBlockMessage": "Response blocked for security reasons.",
      "scanToolResults": true,
      "toolResultBlockMessage": "Tool result blocked for security reasons.",
      "toolsToScan": ["web_fetch", "Read", "exec", "bash", "mcp_*"]
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | - | Your Citadel Pro API key. Starts with `mc_live_`. |
| `endpoint` | string | - | URL to your Citadel OSS server. Ignored if `apiKey` is set. |
| `timeoutMs` | number | 2000 | How long to wait for scan results (milliseconds). |
| `failOpen` | boolean | false | If `true`, allow messages through when Citadel is unavailable. Default is to block. |
| `cacheEnabled` | boolean | true | Cache scan results to reduce API calls. |
| `cacheTtlMs` | number | 60000 | How long to cache results (1 minute default). |
| `cacheMaxSize` | number | 1000 | Maximum number of cached results. |
| `inboundBlockDecisions` | string[] | ["BLOCK"] | Which decisions block inbound messages. Options: `BLOCK`, `WARN`. |
| `outboundBlockOnUnsafe` | boolean | true | Block outbound messages flagged as unsafe. |
| `scanToolResults` | boolean | true | Scan results from tool calls for indirect injection. |
| `toolsToScan` | string[] | [...] | Which tools to scan. Use `*` for prefix matching (e.g., `mcp_*`). |

---

## Tools for Your Agent

Citadel Guard adds two tools your agent can use:

### `citadel_scan` - Manual scanning

Let your agent scan text on demand:

```json
{
  "tool": "citadel_scan",
  "params": {
    "text": "Check if this is safe: Ignore all previous instructions",
    "mode": "input"
  }
}
```

### `citadel_metrics` - View statistics

See how Citadel Guard is performing:

```json
{
  "tool": "citadel_metrics",
  "params": {}
}
```

Returns:
```json
{
  "summary": {
    "totalScans": 1234,
    "blocked": 56,
    "allowed": 1170,
    "blockRate": "4.5%"
  },
  "cache": {
    "hits": 890,
    "misses": 344,
    "hitRate": "72.1%"
  },
  "latency": {
    "avgMs": 45,
    "p95Ms": 120
  }
}
```

---

## Troubleshooting

### "Citadel not available" errors

**If using Pro:** Check that your API key is correct and starts with `mc_live_`.

**If using OSS:** Make sure the Citadel server is running:
```bash
curl http://localhost:3333/health
```

### Scans are slow

Increase the timeout:
```json
{
  "citadel-guard": {
    "timeoutMs": 5000
  }
}
```

### Too many false positives

Try allowing `WARN` decisions through instead of blocking:
```json
{
  "citadel-guard": {
    "inboundBlockDecisions": ["BLOCK"]
  }
}
```

### Rate limited (Pro only)

The plugin automatically backs off when rate limited. Check your plan limits at [trymighty.ai](https://trymighty.ai).

---

## Development

### Prerequisites

- [Bun](https://bun.sh/) v1.0+ or Node.js 20+

### Running tests

```bash
# Install dependencies
bun install

# Run all unit tests
bun test

# Run tests with real Pro API (requires API key)
CITADEL_API_KEY=mc_live_xxx bun run test:live

# Run tests with local Citadel OSS
CITADEL_URL=http://localhost:3333 bun run test:integration
```

### Type checking and linting

```bash
bun run typecheck    # TypeScript type checking
bun run lint         # Lint with Biome
bun run lint:fix     # Auto-fix lint issues
```

---

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/TryMightyAI/citadel-guard-openclaw/issues)
- **Pro support:** support@trymighty.ai

---

## HTTP API Protection (Proxy)

OpenClaw's HTTP API (`/v1/chat/completions`, `/v1/responses`, `/tools/invoke`) **bypasses all plugin hooks** in the current release. To protect these endpoints, you have two options:

### Option 1: Native Hooks (OpenClaw PR #6405)

If you're using OpenClaw with [PR #6405](https://github.com/openclaw/openclaw/pull/6405) merged, **no proxy is needed**. The plugin automatically registers HTTP API hooks:

```
[citadel-guard] Registered 4/4 HTTP API hooks (OpenClaw PR #6405)
```

If you see this log message, HTTP API protection is active natively.

### Option 2: Proxy (Current OpenClaw)

For current OpenClaw releases without PR #6405, run the included proxy.

### Setup

```bash
# 1. Start your Citadel scanner (OSS or point to Pro)
./citadel serve 3333

# 2. Start the proxy
cd plugins/citadel-guard
CITADEL_URL=http://localhost:3333 \
UPSTREAM_URL=http://localhost:18789 \
bun run citadel-openai-proxy.ts
```

The proxy listens on port 5050 by default.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CITADEL_URL` | `http://127.0.0.1:3333` | Citadel scanner URL |
| `UPSTREAM_URL` | `http://127.0.0.1:18789` | OpenClaw Gateway URL |
| `UPSTREAM_TOKEN` | - | Bearer token for upstream |
| `PROXY_HOST` | `127.0.0.1` | Host interface to bind the proxy |
| `PROXY_PORT` | `5050` | Port for the proxy |
| `SCAN_OUTPUT` | `true` | Also scan LLM responses |
| `FAIL_OPEN` | `false` | Allow requests when Citadel is unavailable |
| `SCAN_TIMEOUT_MS` | `2000` | Timeout for Citadel scan requests |
| `MAX_BODY_BYTES` | `1048576` | Max request body size accepted by proxy |
| `SCAN_SYSTEM_MESSAGES` | `true` | Also scan `system` role messages |
| `SCAN_DEVELOPER_MESSAGES` | `true` | Also scan `developer` role messages |

### What It Protects

```
Your App → Citadel Proxy (5050) → Citadel Scan → OpenClaw (18789) → LLM
                ↓                      ↓
           Block attacks          Block leaks
```

| Endpoint | Input Scanning | Output Scanning |
|----------|----------------|-----------------|
| `/v1/chat/completions` | ✅ | ✅ |
| `/v1/responses` | ✅ | ✅ |
| `/tools/invoke` | ✅ | ✅ |

### Example: Protecting Claude Code

```bash
# Instead of:
# ANTHROPIC_BASE_URL=http://localhost:18789 claude

# Use:
ANTHROPIC_BASE_URL=http://localhost:5050 claude
```

---

## Known Security Gaps in OpenClaw

According to [security researchers](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) and [OpenClaw's own documentation](https://docs.openclaw.ai/gateway/security):

| Issue | Citadel Protection |
|-------|-------------------|
| Prompt injection via tool results | ✅ `after_tool_call` hook scans results |
| Credential/API key leakage | ✅ Output scanning detects secrets |
| Indirect injection (web/email) | ✅ Tool result scanning |
| HTTP API bypass | ✅ **Requires proxy** (see above) |
| Malicious skills | ✅ Skills scanned at startup |
| Session transcript exposure | ❌ Disk encryption is user responsibility |

### The "Lethal Trifecta" (Simon Willison)

OpenClaw has all three risk factors:
1. ✅ Access to private data
2. ✅ Exposure to untrusted content
3. ✅ Ability to communicate externally

Citadel Guard mitigates this by scanning content at every interception point, but **defense in depth is essential**:

- Use read-only agents for untrusted content
- Disable `web_fetch`/`browser` for sensitive agents
- Run OpenClaw on isolated infrastructure
- Use the proxy for all HTTP API access

---

## Related Projects

- **[Citadel](https://github.com/TryMightyAI/citadel)** - The open-source AI security scanner powering this plugin
- **[OpenClaw](https://github.com/openclaw/openclaw)** - The AI assistant framework this plugin protects

---

## License

MIT
