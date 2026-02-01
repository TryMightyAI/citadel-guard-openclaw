# Citadel Guard for OpenClaw

**Protect your AI agents from prompt injection, jailbreaks, and data leakage.**

Citadel Guard is a security plugin for [OpenClaw](https://github.com/openclaw/openclaw) that scans every message going in and out of your AI agent. It catches attacks before they reach your model and prevents sensitive data from leaking out.

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

Citadel Guard hooks into every stage of your agent's message flow:

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

## Related Projects

- **[Citadel](https://github.com/TryMightyAI/citadel)** - The open-source AI security scanner powering this plugin
- **[OpenClaw](https://github.com/openclaw/openclaw)** - The AI assistant framework this plugin protects

---

## License

MIT
