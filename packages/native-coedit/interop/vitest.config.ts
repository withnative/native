import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["interop/**/*.test.ts"],
    environment: "node",
    maxWorkers: 1,
    fileParallelism: false,
    testTimeout: 15000,
    hookTimeout: 15000,
  },
});
