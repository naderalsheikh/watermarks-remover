import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api } from "./api";

// The one boundary every API error passes through: FastAPI sends
// `detail` as a string for HTTPException but as an array of {loc, msg}
// objects for request-validation 422s. The client must hand consumers a
// string Error.message in both shapes -- the 422 array previously
// flowed into JSX rendering and crashed React ("Objects are not valid
// as a React child").

function mockJsonResponse(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api error message normalization", () => {
  it("keeps the server's plain-string detail as-is", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockJsonResponse(400, { detail: "matter not found" })),
    );
    const err = await api.get("/v1/matters/nope").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(400);
    expect((err as ApiError).message).toBe("matter not found");
  });

  it("flattens a FastAPI 422 validation-array detail into one readable string", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        mockJsonResponse(422, {
          detail: [
            { type: "string_type", loc: ["body", "recipient_type"], msg: "Input should be a valid string" },
            { type: "missing", loc: ["body", "profile_id"], msg: "Field required" },
          ],
        }),
      ),
    );
    const err = await api.post("/v1/matters/m/documents/d/releases", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(422);
    const msg = (err as ApiError).message;
    expect(msg).toContain("body.recipient_type");
    expect(msg).toContain("valid string");
    expect(msg).toContain("body.profile_id");
    expect(msg).toContain("Field required");
    expect(typeof msg).toBe("string");
  });

  it("falls back to a non-detail JSON body's statusText-free message without crashing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(mockJsonResponse(500, { unexpected: true })),
    );
    const err = await api.get("/v1/matters").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(typeof (err as ApiError).message).toBe("string");
  });

  it("keeps statusText for a non-JSON error body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not json", { status: 502 })),
    );
    const err = await api.get("/v1/matters").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(502);
    expect(typeof (err as ApiError).message).toBe("string");
  });
});
