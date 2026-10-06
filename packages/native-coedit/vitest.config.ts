import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Actual Rust interop is opt-in through interop/vitest.config.ts.
    include: ["test/**/*.test.ts"],
  },
});
