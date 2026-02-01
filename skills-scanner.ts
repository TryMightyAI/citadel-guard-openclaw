#!/usr/bin/env bun
/**
 * Skills File Scanner
 *
 * Scans skill files for potential injection patterns BEFORE they're loaded
 * into the agent's system prompt. This catches malicious skills like MedusaLocker.
 *
 * Usage:
 *   CITADEL_URL=http://localhost:3333 bun run skills-scanner.ts /path/to/skills
 *
 * Integration with OpenClaw:
 *   1. Run this before starting the gateway
 *   2. Or integrate into a pre-start hook
 *   3. Or add as a startup check in the plugin's service
 */

import fs from "node:fs";
import path from "node:path";

const CITADEL_URL = process.env.CITADEL_URL || "http://127.0.0.1:3333";
const SCAN_TIMEOUT_MS = 5000;

interface ScanResult {
  decision?: string;
  heuristic_score?: number;
  semantic_score?: number;
  semantic_category?: string;
  reason?: string;
}

interface SkillScanResult {
  filePath: string;
  skillName: string;
  decision: "SAFE" | "SUSPICIOUS" | "BLOCKED";
  score: number;
  reason?: string;
  category?: string;
}

async function scanText(text: string): Promise<ScanResult | null> {
  try {
    const res = await fetch(`${CITADEL_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: "input" }),
      signal: AbortSignal.timeout(SCAN_TIMEOUT_MS),
    });
    return await res.json();
  } catch (err) {
    console.error(`  ⚠️ Scan failed: ${err}`);
    return null;
  }
}

function extractSkillContent(
  filePath: string,
): { name: string; content: string } | null {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    const name = path.basename(path.dirname(filePath));
    return { name, content };
  } catch {
    return null;
  }
}

function findSkillFiles(dir: string): string[] {
  const files: string[] = [];

  function walk(currentDir: string) {
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
        } else if (entry.name.endsWith(".md") || entry.name === "skill.md") {
          files.push(fullPath);
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  walk(dir);
  return files;
}

async function scanSkillFile(filePath: string): Promise<SkillScanResult> {
  const skill = extractSkillContent(filePath);
  if (!skill) {
    return {
      filePath,
      skillName: "unknown",
      decision: "SUSPICIOUS",
      score: 0,
      reason: "Could not read file",
    };
  }

  const result = await scanText(skill.content);
  if (!result) {
    return {
      filePath,
      skillName: skill.name,
      decision: "SUSPICIOUS",
      score: 0,
      reason: "Scan failed - treating as suspicious",
    };
  }

  const score = result.heuristic_score ?? result.semantic_score ?? 0;

  let decision: "SAFE" | "SUSPICIOUS" | "BLOCKED";
  // Skills naturally contain instruction-like text, so we use SCORE-BASED thresholds
  // The decision field will often be BLOCK/WARN for normal skills, so we ignore it
  // and rely on score alone:
  //   - BLOCKED: score > 0.85 (high-confidence injection)
  //   - SUSPICIOUS: score > 0.70 (warrants manual review)
  //   - SAFE: score <= 0.70 (normal skill content)
  if (score > 0.85) {
    decision = "BLOCKED";
  } else if (score > 0.7) {
    decision = "SUSPICIOUS";
  } else {
    decision = "SAFE";
  }

  return {
    filePath,
    skillName: skill.name,
    decision,
    score,
    reason: result.reason,
    category: result.semantic_category,
  };
}

async function scanSkillsDirectory(skillsDir: string): Promise<{
  results: SkillScanResult[];
  summary: { safe: number; suspicious: number; blocked: number };
}> {
  console.log(`\n🔍 Scanning skills directory: ${skillsDir}\n`);

  const files = findSkillFiles(skillsDir);
  if (files.length === 0) {
    console.log("No skill files found.");
    return { results: [], summary: { safe: 0, suspicious: 0, blocked: 0 } };
  }

  console.log(`Found ${files.length} skill file(s)\n`);

  const results: SkillScanResult[] = [];
  const summary = { safe: 0, suspicious: 0, blocked: 0 };

  for (const file of files) {
    process.stdout.write(`  Scanning ${path.relative(skillsDir, file)}... `);
    const result = await scanSkillFile(file);
    results.push(result);

    if (result.decision === "SAFE") {
      summary.safe++;
      console.log("✅ SAFE");
    } else if (result.decision === "SUSPICIOUS") {
      summary.suspicious++;
      console.log(
        `⚠️ SUSPICIOUS (score: ${result.score.toFixed(2)}, category: ${result.category || "unknown"})`,
      );
    } else {
      summary.blocked++;
      console.log(
        `🚫 BLOCKED (score: ${result.score.toFixed(2)}, reason: ${result.reason})`,
      );
    }
  }

  return { results, summary };
}

function printReport(
  results: SkillScanResult[],
  summary: { safe: number; suspicious: number; blocked: number },
) {
  const total = summary.safe + summary.suspicious + summary.blocked;

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                    SKILLS SECURITY SCAN REPORT                   ║
╠══════════════════════════════════════════════════════════════════╣
║  Total skills scanned: ${total.toString().padEnd(40)}║
║  Safe:                 ${summary.safe.toString().padEnd(40)}║
║  Suspicious:           ${summary.suspicious.toString().padEnd(40)}║
║  Blocked:              ${summary.blocked.toString().padEnd(40)}║
╚══════════════════════════════════════════════════════════════════╝
`);

  if (summary.blocked > 0) {
    console.log("🚫 BLOCKED SKILLS (DO NOT LOAD):");
    for (const r of results.filter((r) => r.decision === "BLOCKED")) {
      console.log(`   - ${r.skillName}: ${r.reason || "Injection detected"}`);
      console.log(`     File: ${r.filePath}`);
    }
    console.log();
  }

  if (summary.suspicious > 0) {
    console.log("⚠️ SUSPICIOUS SKILLS (REVIEW MANUALLY):");
    for (const r of results.filter((r) => r.decision === "SUSPICIOUS")) {
      console.log(
        `   - ${r.skillName}: score=${r.score.toFixed(2)}, category=${r.category || "unknown"}`,
      );
      console.log(`     File: ${r.filePath}`);
    }
    console.log();
  }
}

// Main execution
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log(`
Usage: bun run skills-scanner.ts <skills-directory> [skills-directory2] ...

Environment:
  CITADEL_URL  Citadel scanner endpoint (default: http://127.0.0.1:3333)

Examples:
  bun run skills-scanner.ts ~/.clawdbot/skills
  bun run skills-scanner.ts ./skills /path/to/more/skills
`);
    process.exit(1);
  }

  // Check Citadel is running
  try {
    const health = await fetch(`${CITADEL_URL}/health`);
    if (!health.ok) throw new Error("Not healthy");
  } catch {
    console.error(`❌ Citadel scanner not available at ${CITADEL_URL}`);
    console.error("   Start it with: ./bin/citadel-gateway --port 3333");
    process.exit(1);
  }

  let totalBlocked = 0;
  let totalSuspicious = 0;

  for (const dir of args) {
    const resolved = path.resolve(dir);
    if (!fs.existsSync(resolved)) {
      console.error(`❌ Directory not found: ${resolved}`);
      continue;
    }

    const { results, summary } = await scanSkillsDirectory(resolved);
    printReport(results, summary);

    totalBlocked += summary.blocked;
    totalSuspicious += summary.suspicious;
  }

  // Exit with error if any blocked skills found
  if (totalBlocked > 0) {
    console.error(
      `\n❌ ${totalBlocked} skill(s) contain potential injection attacks and should NOT be loaded.`,
    );
    process.exit(2);
  }

  if (totalSuspicious > 0) {
    console.warn(
      `\n⚠️ ${totalSuspicious} skill(s) are suspicious and should be reviewed manually.`,
    );
    process.exit(1);
  }

  console.log("\n✅ All skills passed security scan.");
  process.exit(0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
