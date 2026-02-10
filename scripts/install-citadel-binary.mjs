#!/usr/bin/env node
/**
 * Citadel Binary Installer
 *
 * Automatically downloads the Citadel Go binary during npm install.
 * Falls back gracefully if download fails - Pro API doesn't need the binary.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  unlinkSync,
} from "node:fs";
import http from "node:http";
import https from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";

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

// BERT model download configuration
const SKIP_MODEL = process.env.CITADEL_SKIP_MODEL === "1";
const HF_REPO = "tihilya/modernbert-base-prompt-injection-detection";
const HF_BASE_URL = `https://huggingface.co/${HF_REPO}/resolve/main`;
const MODEL_DIR = join(__dirname, "..", "models", "modernbert-base");
const MODEL_FILES = [
  { name: "config.json", size: 1403 },
  { name: "model.onnx", size: 599000438 },
  { name: "tokenizer.json", size: 3583228 },
  { name: "tokenizer_config.json", size: 20840 },
  { name: "special_tokens_map.json", size: 694 },
];

/**
 * Check if citadel is already installed globally
 */
function isAlreadyInstalled() {
  try {
    const result = execSync("which citadel", { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    if (result) return result;
  } catch {
    // which returned non-zero
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
 * Download a file with progress reporting and redirect handling (301/302/307).
 * HuggingFace uses 307 for small files (relative redirect) and 302 for large files (absolute redirect).
 */
async function downloadWithProgress(url, dest, expectedSize, label) {
  return new Promise((resolve, reject) => {
    let lastPercent = -1;

    const request = (currentUrl, redirectCount = 0) => {
      if (redirectCount > 5) {
        reject(new Error(`Too many redirects for ${label}`));
        return;
      }

      const parsedUrl = new URL(currentUrl);
      const client = parsedUrl.protocol === "https:" ? https : http;
      const options = {
        hostname: parsedUrl.hostname,
        path: parsedUrl.pathname + parsedUrl.search,
        headers: { "User-Agent": "citadel-guard-installer" },
      };

      client
        .get(options, (res) => {
          // Handle 301, 302, and 307 redirects
          if (
            res.statusCode === 301 ||
            res.statusCode === 302 ||
            res.statusCode === 307
          ) {
            const location = res.headers.location;
            if (!location) {
              reject(new Error(`Redirect ${res.statusCode} without Location header for ${label}`));
              return;
            }
            // Resolve relative URLs against current URL
            const redirectUrl = new URL(location, currentUrl).toString();
            res.resume(); // Consume response to free up socket
            request(redirectUrl, redirectCount + 1);
            return;
          }

          if (res.statusCode !== 200) {
            res.resume();
            reject(new Error(`HTTP ${res.statusCode} downloading ${label}`));
            return;
          }

          const contentLength = parseInt(res.headers["content-length"], 10) || expectedSize;
          let downloaded = 0;

          const file = createWriteStream(dest);
          res.on("data", (chunk) => {
            downloaded += chunk.length;
            if (contentLength > 1024 * 1024) {
              // Show progress for files > 1MB
              const percent = Math.floor((downloaded / contentLength) * 100);
              const tenPercent = Math.floor(percent / 10) * 10;
              if (tenPercent > lastPercent) {
                lastPercent = tenPercent;
                const downloadedMB = (downloaded / 1024 / 1024).toFixed(1);
                const totalMB = (contentLength / 1024 / 1024).toFixed(1);
                process.stdout.write(
                  `\r${GREEN}[citadel]${RESET} ${label}: ${downloadedMB}MB / ${totalMB}MB (${tenPercent}%)`,
                );
              }
            }
          });

          res.pipe(file);
          file.on("finish", () => {
            file.close();
            if (contentLength > 1024 * 1024) {
              process.stdout.write("\n"); // Newline after progress
            }
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
 * Download BERT model files from HuggingFace.
 * Downloads sequentially with retry logic. Non-fatal on failure.
 */
async function downloadModelFiles() {
  if (SKIP_MODEL) {
    info("Skipping BERT model download (CITADEL_SKIP_MODEL=1)");
    return;
  }

  // Check if model is already downloaded
  const onnxPath = join(MODEL_DIR, "model.onnx");
  if (existsSync(onnxPath)) {
    try {
      const stat = statSync(onnxPath);
      if (stat.size === 599000438) {
        info("BERT model already downloaded, skipping");
        return;
      }
      // Wrong size - re-download
      warn("model.onnx has unexpected size, re-downloading...");
    } catch {
      // stat failed, re-download
    }
  }

  info("Downloading BERT model (~575MB, first time only)...");
  mkdirSync(MODEL_DIR, { recursive: true });

  for (const file of MODEL_FILES) {
    const url = `${HF_BASE_URL}/${file.name}`;
    const dest = join(MODEL_DIR, file.name);
    let success = false;

    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        await downloadWithProgress(url, dest, file.size, file.name);
        success = true;
        break;
      } catch (err) {
        // Clean up partial file
        try {
          if (existsSync(dest)) unlinkSync(dest);
        } catch {
          // ignore cleanup errors
        }
        if (attempt < 3) {
          const delay = Math.pow(2, attempt - 1) * 1000; // 1s, 2s, 4s
          warn(`${file.name} download failed (attempt ${attempt}/3): ${err.message}`);
          warn(`Retrying in ${delay / 1000}s...`);
          await new Promise((r) => setTimeout(r, delay));
        } else {
          error(`Failed to download ${file.name} after 3 attempts: ${err.message}`);
        }
      }
    }

    if (!success) {
      warn("BERT model download failed — ML detection will be unavailable");
      warn("You can retry later: node scripts/install-citadel-binary.mjs");
      return;
    }
  }

  info("BERT model downloaded successfully");
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
    await downloadModelFiles();
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

    await downloadModelFiles();

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
