import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { safeLoginRedirect } from "./redirect";

describe("safeLoginRedirect", () => {
  it("keeps local paths and query strings", () => {
    assert.equal(safeLoginRedirect("/works/123?tab=editions#details"), "/works/123?tab=editions#details");
    assert.equal(safeLoginRedirect("/"), "/");
  });

  for (const target of [
    null,
    "https://example.org/",
    "javascript:alert(1)",
    "//example.org/",
    "/\\example.org/",
    "/%5cexample.org/",
    "/%2fexample.org/",
    "/\nexample.org/",
    "/%0aexample.org/",
    "/%ZZ",
  ]) {
    it(`rejects unsafe target ${JSON.stringify(target)}`, () => {
      assert.equal(safeLoginRedirect(target), "/");
    });
  }
});
