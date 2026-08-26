import { describe, expect, it } from "vitest";
import { CANCELLED_ERROR, isCancelledResult } from "./batchCancel";

describe("isCancelledResult", () => {
  it("is true for a failed result carrying the exact cancel marker", () => {
    expect(isCancelledResult({ status: "failed", error: CANCELLED_ERROR })).toBe(true);
  });

  it("is false for a real worker failure, even with similar wording", () => {
    expect(isCancelledResult({ status: "failed", error: "worker exited rc=1" })).toBe(false);
    expect(isCancelledResult({ status: "failed", error: "operator cancelled this" })).toBe(false);
  });

  it("is false for a non-failed status regardless of error text", () => {
    expect(isCancelledResult({ status: "refused", error: CANCELLED_ERROR })).toBe(false);
    expect(isCancelledResult({ status: "done", error: "" })).toBe(false);
    expect(isCancelledResult({ status: "queued", error: "" })).toBe(false);
  });
});
