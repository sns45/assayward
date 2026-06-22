import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    // Only include the workerd-compatible test file; gate-logic.test.ts uses
    // bun:test and must be run separately via `bun test:logic`.
    include: ["test/gate.test.ts"],
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
      },
    },
  },
});
