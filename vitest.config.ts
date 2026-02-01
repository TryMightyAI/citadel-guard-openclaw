import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 30000,
    hookTimeout: 10000,
    // Run tests sequentially to avoid overwhelming the Citadel scanner
    sequence: {
      concurrent: false,
    },
    // Allow tests to be skipped if services are not available
    bail: 0,
  },
});
