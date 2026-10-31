import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { profileOf, stringClaim } from "../src/auth/claims.ts";
import { safeReturnTo } from "../src/auth/return-to.ts";
import { extractRoles } from "../src/auth/roles.ts";

const ORIGIN = "https://app.example.com";

describe("safeReturnTo", () => {
  it("keeps same-origin paths with their query", () => {
    expect(safeReturnTo("/", ORIGIN)).toBe("/");
    expect(safeReturnTo("/a/b?c=d&e=f", ORIGIN)).toBe("/a/b?c=d&e=f");
    expect(safeReturnTo("/%2F%2Fevil.example", ORIGIN)).toBe(
      "/%2F%2Fevil.example",
    );
  });

  it("falls back to / for everything else", () => {
    for (const raw of [
      undefined,
      null,
      42,
      ["/a"],
      "",
      "relative/path",
      "//evil.example",
      "///evil.example",
      "https://evil.example/",
      "http://app.example.com/",
      "/\\evil.example",
      "/a\\b",
      "/..//evil.example",
      "/.//evil.example",
      "/%2e%2e//evil.example",
      "/a\nb",
      "/a\rb",
      "/a\tb",
      "/a\u0000b",
      "/a\u007fb",
      "javascript:alert(1)",
      "data:text/html,x",
    ]) {
      expect(safeReturnTo(raw, ORIGIN)).toBe("/");
    }
  });
});

describe("claims", () => {
  it("reads string claims only", () => {
    expect(stringClaim({ a: "x" }, "a")).toBe("x");
    expect(stringClaim({ a: "" }, "a")).toBeNull();
    expect(stringClaim({ a: 1 }, "a")).toBeNull();
    expect(stringClaim({}, "a")).toBeNull();
  });

  it("derives the profile with name fallbacks", () => {
    expect(
      profileOf({
        sub: "s",
        sid: "i",
        name: "N",
        preferred_username: "p",
        email: "e@x",
      }),
    ).toEqual({
      sub: "s",
      sid: "i",
      name: "N",
      email: "e@x",
    });
    expect(profileOf({ sub: "s", preferred_username: "p" })).toEqual({
      sub: "s",
      sid: null,
      name: "p",
      email: null,
    });
    expect(profileOf({ sub: "s" }).name).toBe("s");
  });
});

describe("extractRoles", () => {
  it("reads Keycloak claims from the ID token", () => {
    expect(
      extractRoles(
        {
          realm_access: { roles: ["a"] },
          resource_access: { bff: { roles: ["b"] }, api: { roles: [] } },
        },
        "opaque",
      ),
    ).toEqual({ realm: ["a"], bff: ["b"], api: [] });
  });

  it("reads and merges the access token's claims without verifying them", async () => {
    const jwt = await new SignJWT({
      realm_access: { roles: ["a", "c"] },
      resource_access: { bff: { roles: ["x"] } },
    })
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("k".repeat(32)));
    expect(extractRoles({ realm_access: { roles: ["a", "b"] } }, jwt)).toEqual({
      realm: ["a", "c", "b"],
      bff: ["x"],
    });
  });

  it("ignores opaque tokens and malformed claims", () => {
    expect(extractRoles({}, "opaque-token")).toEqual({});
    expect(
      extractRoles({ realm_access: "admin", resource_access: [1] }, "x"),
    ).toEqual({});
  });
});
