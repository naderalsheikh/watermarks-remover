import { describe, expect, it } from "vitest";
import { selectionSummary, toggleVisibleSelection } from "./documentSelection";

describe("document selection across filters", () => {
  it("selects only visible rows, keeping earlier explicit selections", () => {
    const original = new Set(["hidden"]);
    expect(toggleVisibleSelection(original, ["visible"], true)).toEqual(
      new Set(["hidden", "visible"]),
    );
    expect(original).toEqual(new Set(["hidden"]));
  });

  it("deselects the visible set without clearing hidden selections", () => {
    expect(toggleVisibleSelection(new Set(["a", "b", "c"]), ["a", "b"], false)).toEqual(
      new Set(["c"]),
    );
  });

  it("discloses selections outside a new search result", () => {
    expect(selectionSummary(new Set(["old", "a"]), ["a", "b"])).toEqual({
      visibleSelected: 1,
      hiddenSelected: 1,
      allVisibleSelected: false,
      someVisibleSelected: true,
    });
  });

  it("never checks select-all for an empty result", () => {
    expect(selectionSummary(new Set(["old"]), [])).toEqual({
      visibleSelected: 0,
      hiddenSelected: 1,
      allVisibleSelected: false,
      someVisibleSelected: false,
    });
  });

  it("reflects a complete visible selection even when others are hidden", () => {
    expect(selectionSummary(new Set(["a", "hidden"]), ["a"]).allVisibleSelected).toBe(true);
    expect(selectionSummary(new Set(["a"]), ["a"]).someVisibleSelected).toBe(false);
  });
});
