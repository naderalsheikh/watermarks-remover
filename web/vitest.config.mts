import { defineConfig } from "vitest/config";

// Pure-logic unit tests only (web/lib/**/*.test.ts) — no component
// rendering, no jsdom. Component/page behavior is verified live in the
// browser per this project's standing practice, not through a rendering
// test harness; this config exists for the class of bug that's cheap and
// valuable to pin down as a pure function (see productionReview.ts).
export default defineConfig({
  test: {
    include: ["lib/**/*.test.ts"],
    environment: "node",
  },
});
