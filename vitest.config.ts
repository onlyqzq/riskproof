import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/**/*.ts"],
      thresholds: {
        statements: 85,
        branches: 75,
        functions: 85,
        lines: 88,
      },
    },
  },
});
