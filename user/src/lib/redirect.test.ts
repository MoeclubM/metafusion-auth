import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { safeLoginRedirect } from "./redirect";

describe("safeLoginRedirect", () => {
  const origin = "https://findverse.cc";

  it("keeps local paths and query strings", () => {
    assert.equal(safeLoginRedirect("/works/123?tab=editions#details", origin), "/works/123?tab=editions#details");
    assert.equal(safeLoginRedirect("/", origin), "/");
    assert.equal(safeLoginRedirect("https://findverse.cc/works/123?tab=editions", origin), "/works/123?tab=editions");
    assert.equal(safeLoginRedirect("https://findverse.cc:443/works/123", origin), "/works/123");
  });

  for (const target of [
    null,
    "https://example.org/",
    "http://findverse.cc/",
    "https://findverse.cc.evil.example/",
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
      assert.equal(safeLoginRedirect(target, origin), "/");
    });
  }
});
