import { describe, expect, it } from "vitest";
import {
  attentionMatterHref,
  attentionPrimaryHref,
  attentionScopeNote,
  attentionTabCounts,
  filterAttentionByTab,
  recentEmptyStateText,
  recentScopeNote,
} from "./dashboardAttention";
import type { AttentionItem } from "./types";

function item(overrides: Partial<AttentionItem> & Pick<AttentionItem, "type">): AttentionItem {
  return {
    matter_id: "m1",
    matter_name: "Matter One",
    detail: "detail",
    created_utc: "2026-08-25T00:00:00+00:00",
    ...overrides,
  };
}

describe("attentionPrimaryHref", () => {
  it("routes unreviewed_findings to the job, scrolled to the warning section", () => {
    const href = attentionPrimaryHref(
      item({ type: "unreviewed_findings", job_id: "j1", matter_id: "m1" }),
    );
    expect(href).toBe("/matters/job?matter=m1&job=j1&highlight=unreviewed");
  });

  it("routes refused/failed to the plain job page, no highlight param", () => {
    expect(attentionPrimaryHref(item({ type: "refused", job_id: "j1" }))).toBe(
      "/matters/job?matter=m1&job=j1",
    );
    expect(attentionPrimaryHref(item({ type: "failed", job_id: "j2" }))).toBe(
      "/matters/job?matter=m1&job=j2",
    );
  });

  it("routes stale (no job to point at) to the matter view", () => {
    expect(attentionPrimaryHref(item({ type: "stale" }))).toBe("/matters/view?id=m1");
  });

  it("falls back to the matter view for any type if job_id is absent", () => {
    // Shouldn't happen for unreviewed_findings/refused/failed in practice
    // (the backend always attaches a job_id for those types), but the
    // function must still degrade to a real destination, not a dangling link.
    expect(attentionPrimaryHref(item({ type: "refused" }))).toBe("/matters/view?id=m1");
  });
});

describe("attentionMatterHref", () => {
  it("includes the document highlight param when a document_id is present", () => {
    expect(attentionMatterHref(item({ type: "refused", document_id: "d1" }))).toBe(
      "/matters/view?id=m1&doc=d1",
    );
  });

  it("omits the doc param when there's no document (e.g. stale)", () => {
    expect(attentionMatterHref(item({ type: "stale" }))).toBe("/matters/view?id=m1");
  });
});

describe("filterAttentionByTab", () => {
  const items = [
    item({ type: "unreviewed_findings" }),
    item({ type: "refused" }),
    item({ type: "refused" }),
    item({ type: "stale" }),
  ];

  it("returns everything for the 'all' tab", () => {
    expect(filterAttentionByTab(items, "all")).toHaveLength(4);
  });

  it("returns only items matching the selected type", () => {
    const refused = filterAttentionByTab(items, "refused");
    expect(refused).toHaveLength(2);
    expect(refused.every((i) => i.type === "refused")).toBe(true);
  });

  it("returns an empty array for a type with no matches", () => {
    expect(filterAttentionByTab(items, "failed")).toEqual([]);
  });
});

describe("attentionTabCounts", () => {
  it("counts each type plus a total under 'all'", () => {
    const items = [
      item({ type: "unreviewed_findings" }),
      item({ type: "refused" }),
      item({ type: "refused" }),
      item({ type: "stale" }),
    ];
    expect(attentionTabCounts(items)).toEqual({
      all: 4,
      unreviewed_findings: 1,
      refused: 2,
      failed: 0,
      stale: 1,
    });
  });

  it("is all zeros for an empty list", () => {
    expect(attentionTabCounts([])).toEqual({
      all: 0,
      unreviewed_findings: 0,
      refused: 0,
      failed: 0,
      stale: 0,
    });
  });
});

describe("attentionScopeNote", () => {
  it("is null when the principal administers every readable matter", () => {
    expect(attentionScopeNote(3, 3)).toBeNull();
    expect(attentionScopeNote(0, 0)).toBeNull(); // empty corpus, nothing to scope
  });

  it("explains full omission when the principal administers none", () => {
    const note = attentionScopeNote(0, 3);
    expect(note).toContain("read access only");
    expect(note).toContain("stale-matter detection");
  });

  it("names the exact admin/total split when partially scoped", () => {
    expect(attentionScopeNote(1, 3)).toBe(
      "Stale-matter detection is shown only for the 1 of 3 matters you " +
        "administer — it's derived from audit activity, which requires admin.",
    );
  });

  it("uses singular \"matter\" for exactly one admin matter out of more than one total", () => {
    // totalMatters drives the pluralization, not adminMatters.
    expect(attentionScopeNote(1, 1)).toBeNull();
    const note = attentionScopeNote(1, 2);
    expect(note).toContain("2 matters");
  });
});

describe("recentScopeNote", () => {
  it("is null with full admin scope", () => {
    expect(recentScopeNote(2, 2)).toBeNull();
  });

  it("explains total omission when the principal administers none", () => {
    expect(recentScopeNote(0, 2)).toContain("requires admin");
  });

  it("names the admin/total split when partially scoped, with correct pluralization", () => {
    expect(recentScopeNote(1, 3)).toBe("Limited to the 1 of 3 matters you administer.");
    expect(recentScopeNote(1, 1)).toBeNull();
  });
});

describe("recentEmptyStateText", () => {
  it("distinguishes genuinely-empty from hidden-by-permission", () => {
    expect(recentEmptyStateText(0, 0)).toBe("No activity yet.");
    expect(recentEmptyStateText(2, 2)).toBe("No activity yet.");
    expect(recentEmptyStateText(0, 3)).toBe(
      "No activity visible — you have read access only, not admin, on these matters.",
    );
  });
});
