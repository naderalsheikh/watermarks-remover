import { describe, expect, it } from "vitest";
import { BULK_MAX_DOCUMENTS, bulkCapOverflow, isOverBulkCap } from "./bulkCap";

describe("isOverBulkCap", () => {
  it("matches the backend's cap exactly (service/app/main.py create_batch)", () => {
    expect(BULK_MAX_DOCUMENTS).toBe(100);
  });

  it("is not over the cap at 99 documents", () => {
    expect(isOverBulkCap(99)).toBe(false);
  });

  it("is not over the cap at exactly 100 documents (the cap itself is allowed)", () => {
    expect(isOverBulkCap(100)).toBe(false);
  });

  it("is over the cap at 101 documents", () => {
    expect(isOverBulkCap(101)).toBe(true);
  });

  it("is not over the cap for an empty or small selection", () => {
    expect(isOverBulkCap(0)).toBe(false);
    expect(isOverBulkCap(1)).toBe(false);
  });
});

describe("bulkCapOverflow", () => {
  it("is 0 at and under the cap -- nothing to deselect", () => {
    expect(bulkCapOverflow(99)).toBe(0);
    expect(bulkCapOverflow(100)).toBe(0);
  });

  it("is the exact number to deselect to get back under the cap", () => {
    expect(bulkCapOverflow(101)).toBe(1);
    expect(bulkCapOverflow(150)).toBe(50);
  });

  it("never goes negative for a selection far under the cap", () => {
    expect(bulkCapOverflow(0)).toBe(0);
  });
});
