import { describe, expect, it } from "vitest";
import { hasMatterPerm, permissionGate, releaseGate } from "./matterPermissions";

describe("hasMatterPerm", () => {
  it("is true when the perm is present", () => {
    expect(hasMatterPerm(["read", "inspect"], "inspect")).toBe(true);
  });

  it("is false when the perm is absent", () => {
    expect(hasMatterPerm(["read"], "sanitize")).toBe(false);
  });

  it("is false, not a crash, when perms hasn't loaded yet", () => {
    // The safe default while the owning matter fetch is still in flight --
    // a gated control must never read as usable before the grant is
    // actually confirmed.
    expect(hasMatterPerm(undefined, "admin")).toBe(false);
  });

  it("is false for an empty grant list", () => {
    expect(hasMatterPerm([], "read")).toBe(false);
  });
});

describe("permissionGate", () => {
  it("allows with no title when the perm is present", () => {
    const gate = permissionGate(["sanitize"], "sanitize");
    expect(gate.allowed).toBe(true);
    expect(gate.title).toBeUndefined();
  });

  it("disallows with an explanatory title naming the exact missing perm", () => {
    const gate = permissionGate(["read"], "sanitize");
    expect(gate.allowed).toBe(false);
    expect(gate.title).toBe("You don't have sanitize permission on this matter");
  });

  it("disallows while perms hasn't loaded yet, same as hasMatterPerm", () => {
    const gate = permissionGate(undefined, "upload");
    expect(gate.allowed).toBe(false);
    expect(gate.title).toBe("You don't have upload permission on this matter");
  });

  it("names each permission distinctly, not a generic message", () => {
    expect(permissionGate([], "inspect").title).toContain("inspect");
    expect(permissionGate([], "admin").title).toContain("admin");
  });
});

describe("releaseGate", () => {
  it("is governed by the sanitize grant (what POST .../releases checks)", () => {
    expect(releaseGate(["read", "inspect"]).allowed).toBe(false);
    expect(releaseGate(["read", "sanitize"]).allowed).toBe(true);
  });

  it("names the release action in the denied tooltip, not the invisible 'sanitize' control", () => {
    const gate = releaseGate(["read"]);
    expect(gate.allowed).toBe(false);
    expect(gate.title).toContain("prepare a release");
    // Still tells the operator which grant to request.
    expect(gate.title).toContain("sanitize");
  });

  it("has no tooltip when the release action is allowed", () => {
    expect(releaseGate(["sanitize"]).title).toBeUndefined();
  });
});
