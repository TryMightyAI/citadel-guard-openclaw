#!/usr/bin/env node
/**
 * Citadel Binary Installer
 *
 * Automatically downloads the Citadel Go binary during npm install.
 * Falls back gracefully if download fails - Pro API doesn't need the binary.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
} from "node:fs";
import https from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Configuration
const REPO = "TryMightyAI/citadel";
const VERSION = process.env.CITADEL_VERSION || "latest";
const SKIP_DOWNLOAD = process.env.CITADEL_SKIP_BINARY === "1";
const FORCE_DOWNLOAD = process.env.CITADEL_FORCE_DOWNLOAD === "1";
const REQUIRE_CHECKSUM = process.env.CITADEL_REQUIRE_CHECKSUM === "1";

// Platform detection
const PLATFORMS = {
  "darwin-x64": "darwin-amd64",
  "darwin-arm64": "darwin-arm64",
  "linux-x64": "linux-amd64",
  "linux-arm64": "linux-arm64",
};

const PLATFORM = PLATFORMS[`${process.platform}-${process.arch}`];

// Colors for terminal output
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const RESET = "\x1b[0m";

const info = (msg) => console.log(`${GREEN}[citadel]${RESET} ${msg}`);
const warn = (msg) => console.log(`${YELLOW}[citadel]${RESET} ${msg}`);
const error = (msg) => console.log(`${RED}[citadel]${RESET} ${msg}`);

/**
 * Check if citadel is already installed globally
 */
function isAlreadyInstalled() {
  const result = spawnSync("which", ["citadel"], { encoding: "utf8" });
  if (result.status === 0 && result.stdout.trim()) {
    return result.stdout.trim();
  }

  // Also check common locations
  const commonPaths = [
    "/usr/local/bin/citadel",
    "/usr/bin/citadel",
    join(process.env.HOME || "", ".local/bin/citadel"),
    join(process.env.HOME || "", "go/bin/citadel"),
  ];

  for (const p of commonPaths) {
    if (existsSync(p)) return p;
  }

  return null;
}

/**
 * Get latest version from GitHub API
 */
async function getLatestVersion() {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "api.github.com",
      path: `/repos/${REPO}/releases/latest`,
      headers: { "User-Agent": "citadel-guard-installer" },
    };

    https
      .get(options, (res) => {
        if (res.statusCode === 404) {
          // No releases yet - this is expected for new repos
          reject(
            new Error("No releases found. Please create a release first."),
          );
          return;
        }

        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            resolve(json.tag_name);
          } catch (e) {
            reject(
              new Error(`Failed to parse GitHub API response: ${e.message}`),
            );
          }
        });
      })
      .on("error", reject);
  });
}

/**
 * Download file with redirect support
 */
async function download(url, dest) {
  return new Promise((resolve, reject) => {
    const request = (url) => {
      const parsedUrl = new URL(url);
      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        headers: { "User-Agent": "citadel-guard-installer" },
      };

      https
        .get(options, (res) => {
          // Handle redirects (GitHub releases redirect to S3)
          if (res.statusCode === 302 || res.statusCode === 301) {
            request(res.headers.location);
            return;
          }

          if (res.statusCode !== 200) {
            reject(new Error(`HTTP ${res.statusCode}: ${url}`));
            return;
          }

          const file = createWriteStream(dest);
          res.pipe(file);
          file.on("finish", () => {
            file.close();
            resolve();
          });
          file.on("error", (err) => {
            file.close();
            reject(err);
          });
        })
        .on("error", reject);
    };

    request(url);
  });
}

/**
 * Compute SHA256 hash of a file
 */
function computeSHA256(filePath) {
  const data = readFileSync(filePath);
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Download checksums.txt from GitHub release
 * Returns Map<filename, hash> or null if unavailable
 */
async function downloadChecksums(version) {
  const url = `https://github.com/${REPO}/releases/download/${version}/checksums.txt`;
  return new Promise((resolve) => {
    const request = (reqUrl) => {
      const parsedUrl = new URL(reqUrl);
      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        headers: { "User-Agent": "citadel-guard-installer" },
      };

      https
        .get(options, (res) => {
          if (res.statusCode === 302 || res.statusCode === 301) {
            request(res.headers.location);
            return;
          }
          if (res.statusCode !== 200) {
            resolve(null);
            return;
          }
          let data = "";
          res.on("data", (chunk) => {
            data += chunk;
          });
          res.on("end", () => {
            const checksums = new Map();
            for (const line of data.split("\n")) {
              const trimmed = line.trim();
              if (!trimmed) continue;
              // Format: "hash  filename" (two spaces)
              const match = trimmed.match(/^([a-f0-9]{64})\s+(.+)$/);
              if (match) {
                checksums.set(match[2], match[1]);
              }
            }
            resolve(checksums.size > 0 ? checksums : null);
          });
        })
        .on("error", () => resolve(null));
    };
    request(url);
  });
}

/**
 * Verify SHA256 checksum of downloaded binary
 * Returns true (verified), false (mismatch), or null (checksums unavailable)
 */
async function verifyChecksum(filePath, binaryName, version) {
  const checksums = await downloadChecksums(version);
  if (!checksums) return null;

  const expected = checksums.get(binaryName);
  if (!expected) return null;

  const actual = computeSHA256(filePath);
  return actual === expected;
}

/**
 * Main installation logic
 */
async function main() {
  // Skip if explicitly disabled
  if (SKIP_DOWNLOAD) {
    info("Skipping binary download (CITADEL_SKIP_BINARY=1)");
    info("Use Citadel Pro API instead: export CITADEL_API_KEY=mc_live_xxx");
    return;
  }

  // Check platform support
  if (!PLATFORM) {
    warn(`No prebuilt binary for ${process.platform}-${process.arch}`);
    info("Options:");
    info("  1. Use Citadel Pro API: export CITADEL_API_KEY=mc_live_xxx");
    info(
      "  2. Build from source: go install github.com/TryMightyAI/citadel@latest",
    );
    return;
  }

  // Check if already installed
  const existingPath = isAlreadyInstalled();
  if (existingPath && !FORCE_DOWNLOAD) {
    info(`Citadel already installed: ${existingPath}`);
    info("Set CITADEL_FORCE_DOWNLOAD=1 to re-download/upgrade");
    return;
  }
  if (existingPath && FORCE_DOWNLOAD) {
    info(`Force re-downloading (existing: ${existingPath})`);
  }

  info("Installing Citadel scanner...");

  try {
    // Resolve version
    let version = VERSION;
    if (version === "latest") {
      info("Fetching latest version...");
      version = await getLatestVersion();
    }
    info(`Version: ${version}`);
    info(`Platform: ${PLATFORM}`);

    // Determine install location
    const binDir = join(__dirname, "..", "node_modules", ".bin");
    const installPath = join(binDir, "citadel");

    // Download binary
    const binaryName = `citadel-${PLATFORM}`;
    const url = `https://github.com/${REPO}/releases/download/${version}/${binaryName}`;

    info("Downloading from GitHub Releases...");
    mkdirSync(binDir, { recursive: true });
    await download(url, installPath);

    // Verify SHA256 checksum
    info("Verifying checksum...");
    const checksumResult = await verifyChecksum(
      installPath,
      binaryName,
      version,
    );

    if (checksumResult === false) {
      unlinkSync(installPath);
      throw new Error(
        `SHA256 checksum mismatch! The downloaded binary may be corrupted or tampered with.\n  Please try again or install manually from:\n  https://github.com/${REPO}/releases/tag/${version}`,
      );
    }

    if (checksumResult === null && REQUIRE_CHECKSUM) {
      unlinkSync(installPath);
      throw new Error(
        "Checksum verification required (CITADEL_REQUIRE_CHECKSUM=1) but checksums.txt not available.\n" +
          "  The release may not include checksums yet.\n" +
          "  Remove CITADEL_REQUIRE_CHECKSUM=1 to install without verification.",
      );
    }

    if (checksumResult === null) {
      warn(
        "checksums.txt not available for this release — skipping verification",
      );
    } else {
      info("SHA256 checksum verified");
    }

    chmodSync(installPath, 0o755);

    info(`Installed to: ${installPath}`);

    // Download BERT model automatically
    info("Downloading BERT model (~685MB, first time only)...");
    const modelResult = spawnSync(installPath, ["scan", "test"], {
      encoding: "utf8",
      timeout: 600000, // 10 minute timeout for model download
      env: {
        ...process.env,
        CITADEL_AUTO_DOWNLOAD_MODEL: "true",
        CITADEL_ENABLE_HUGOT: "true",
      },
    });

    if (modelResult.status === 0) {
      info("BERT model ready");
    } else {
      warn("Could not download BERT model automatically");
      warn("Run with CITADEL_AUTO_DOWNLOAD_MODEL=true on first use:");
      console.log(
        "      CITADEL_AUTO_DOWNLOAD_MODEL=true CITADEL_ENABLE_HUGOT=true citadel serve 3333",
      );
      console.log("");
    }

    console.log("");
    info("Citadel scanner installed successfully!");
    console.log("");
    console.log("  Usage:");
    console.log("    OSS Mode (local scanner):");
    console.log("      citadel serve 3333");
    console.log("");
    console.log("    Pro Mode (cloud API):");
    console.log("      export CITADEL_API_KEY=mc_live_xxx");
    console.log("");
  } catch (err) {
    warn(`Could not download binary: ${err.message}`);
    console.log("");
    info("You can still use Citadel! Options:");
    console.log("");
    console.log("  1. Use Citadel Pro API (recommended, no binary needed):");
    console.log("     export CITADEL_API_KEY=mc_live_xxx");
    console.log("");
    console.log("  2. Install binary manually:");
    console.log(
      "     curl -fsSL https://raw.githubusercontent.com/TryMightyAI/citadel/main/install.sh | bash",
    );
    console.log("");
    console.log("  3. Build from source (requires Go):");
    console.log("     go install github.com/TryMightyAI/citadel@latest");
    console.log("");

    // Don't fail npm install - Pro API works without binary
    process.exit(0);
  }
}

main().catch((err) => {
  error(`Unexpected error: ${err.message}`);
  process.exit(0); // Don't fail npm install
});
