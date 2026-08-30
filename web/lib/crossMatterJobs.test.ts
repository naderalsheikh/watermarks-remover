import { describe, expect, it } from "vitest";
import {
  DEFAULT_PROBLEM_JOB_FILTER,
  JOB_STATUS_ALLOWLIST,
  PROBLEM_JOB_TABS,
  resolveProblemJobFilter,
} from "./crossMatterJobs";

describe("PROBLEM_JOB_TABS", () => {
  it("every tab value decomposes into statuses the endpoint accepts", () => {
    // GET /v1/jobs validates each comma-separated word against its
    // allowlist and 400s on anything else — a tab value that slipped
    // outside it would break that tab for every operator.
    for (const tab of PROBLEM_JOB_TABS) {
      const words = tab.value.split(",");
      expect(words.length).toBeGreaterThan(0);
      for (const w of words) {
        expect(JOB_STATUS_ALLOWLIST).toContain(w);
      }
    }
  });

  it("default is the dashboard card's failed+refused destination", () => {
    expect(DEFAULT_PROBLEM_JOB_FILTER).toBe("refused,failed");
    expect(PROBLEM_JOB_TABS[0].value).toBe(DEFAULT_PROBLEM_JOB_FILTER);
  });

  it("offers the two fine-grained problem filters the dashboard's attention tabs use", () => {
    expect(PROBLEM_JOB_TABS.map((t) => t.value)).toContain("refused");
    expect(PROBLEM_JOB_TABS.map((t) => t.value)).toContain("failed");
  });
});

describe("resolveProblemJobFilter", () => {
  it("forwards a value the page itself would send", () => {
    expect(resolveProblemJobFilter("refused")).toBe("refused");
    expect(resolveProblemJobFilter("failed")).toBe("failed");
    expect(resolveProblemJobFilter("refused,failed")).toBe("refused,failed");
  });

  it("falls back to the default when the param is absent", () => {
    expect(resolveProblemJobFilter(null)).toBe(DEFAULT_PROBLEM_JOB_FILTER);
  });

  it("falls back rather than forwarding a value the endpoint would 400 on", () => {
    // A raw status word like "done" is legal server-side but not one of
    // this page's filters, and an arbitrary string isn't even that —
    // neither should reach the wire.
    expect(resolveProblemJobFilter("done")).toBe(DEFAULT_PROBLEM_JOB_FILTER);
    expect(resolveProblemJobFilter("refused,done")).toBe(DEFAULT_PROBLEM_JOB_FILTER);
    expect(resolveProblemJobFilter("all")).toBe(DEFAULT_PROBLEM_JOB_FILTER);
    expect(resolveProblemJobFilter("'; DROP TABLE jobs;--")).toBe(DEFAULT_PROBLEM_JOB_FILTER);
  });

  it("empty string (an explicit ?status=) falls back, not errors", () => {
    expect(resolveProblemJobFilter("")).toBe(DEFAULT_PROBLEM_JOB_FILTER);
  });
});
